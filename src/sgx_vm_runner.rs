use std::path::Path;
use std::io::{Write, Read, BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::net::TcpStream;
use serde::{Deserialize, Serialize};

#[cfg(feature = "use_sgx_vm")]
use std::sync::Arc;
#[cfg(feature = "use_sgx_vm")]
use rustls::ClientConfig;
#[cfg(feature = "use_sgx_vm")]
use rustls::pki_types::{ServerName, CertificateDer};

#[cfg(feature = "use_sgx_vm")]
const ENCLAVE_CA_PEM: &str = include_str!("../enclave_ca.pem");

pub const DEFAULT_VM_ENCLAVE_PATH: &str = "/usr/lib/scaphandre/sgx_vm.sgxs";

fn get_remote_sgx_host() -> Option<String> {
    std::env::var("SGX_REMOTE_HOST").ok()
}

#[cfg(feature = "use_sgx_vm")]
enum TlsStream {
    Rustls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
    Plain(TcpStream),
}

#[cfg(feature = "use_sgx_vm")]
impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsStream::Rustls(s) => s.read(buf),
            TlsStream::Plain(s) => s.read(buf),
        }
    }
}

#[cfg(feature = "use_sgx_vm")]
impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            TlsStream::Rustls(s) => s.write(buf),
            TlsStream::Plain(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            TlsStream::Rustls(s) => s.flush(),
            TlsStream::Plain(s) => s.flush(),
        }
    }
}

#[cfg(feature = "use_sgx_vm")]
struct VmEnclaveConnection {
    stream: TlsStream,
    child: Option<std::process::Child>,
    is_remote: bool,
}

#[cfg(not(feature = "use_sgx_vm"))]
struct VmEnclaveConnection {
    stream: TcpStream,
    child: Option<std::process::Child>,
    is_remote: bool,
}

lazy_static::lazy_static! {
    static ref VM_ENCLAVE_CONNECTION: Mutex<Option<VmEnclaveConnection>> = Mutex::new(None);
}

#[derive(Serialize)]
struct VerifyChainRequest {
    operation: String,
    vm_name: String,
    energy_value: u64,
    counter: u64,
    previous_hash: String,
    signature: String,
}

#[derive(Serialize)]
struct ComputeEnergyRequest {
    operation: String,
    vm_total_energy_uj: u64,
    cpu_percentage: f64,
}

#[derive(Serialize)]
struct DbExportRequest {
    operation: String,
    vm_name: String,
    energy_uj: u64,
    counter: u64,
    previous_hash: String,
    signature: String,
    energy_delta: u64,
    processes: Vec<(u32, u64)>,
    session_id: Option<String>,
}

#[cfg(feature = "use_sgx_vm")]
#[derive(Serialize)]
struct GpuProcReq {
    pid: u32,
    util: u64,
    cgroup: String,
}

#[cfg(feature = "use_sgx_vm")]
#[derive(Serialize)]
struct GpuTagReq {
    energy_uj: u64,
    timestamp_ns: u64,
    hash: u64,
}

#[cfg(feature = "use_sgx_vm")]
#[derive(Serialize)]
struct GpuGroupReq {
    gpu_index: u32,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    gpu_uuid: String,
    energy_uj: u64,
    procs: Vec<GpuProcReq>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<GpuTagReq>,
}

#[cfg(feature = "use_sgx_vm")]
#[derive(Serialize)]
struct GpuDbExportRequest {
    operation: String,
    node_id: String,
    gpus: Vec<GpuGroupReq>,

    immudb_addr: String,
    deployment_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    tag_key: Option<[u64; 2]>,
    tag_epoch: u32,
}

#[derive(Serialize)]
struct ImmudbInsertRequest {
    operation: String,
    session_id: String,
    body: String,
}

#[derive(Serialize)]
struct VerifyBootRequest {
    operation: String,
    pcr_values: String,
    ima_log: String,
    hostname: String,
    deployment_type: String,
    immudb_addr: String,
    ca_pem: String,

    quote_attest: String,
    quote_signature: String,
}

#[cfg(feature = "use_sgx_vm")]
pub fn request_nonce_from_enclave() -> Option<String> {
    #[derive(Serialize)]
    struct NonceReq { operation: String }
    let req = serde_json::to_string(&NonceReq { operation: "get_nonce".to_string() }).ok()?;
    match send_request_to_vm_enclave(&req) {
        Ok(r) if r.status == 0 => r.output_data,
        Ok(r) => {
            eprintln!("[SGX-VM-RUNNER] enclave refused to issue a nonce: {} ({})", r.message, r.status);
            None
        }
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] could not reach the enclave for a nonce: {}", e);
            None
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct VmEnclaveResponse {
    pub status: i32,
    pub message: String,
    #[serde(default)]
    pub output_data: Option<String>,
}

#[cfg(feature = "use_sgx_vm")]
pub fn check_sgx_hardware() -> Result<(), String> {

    if get_remote_sgx_host().is_some() {
        println!("[SGX-VM] Using REMOTE SGX enclave (no local hardware needed)");
        return Ok(());
    }

    if Path::new("/dev/isgx").exists() || Path::new("/dev/sgx_enclave").exists() {
        println!("[SGX-VM] SGX hardware detected and available");
        return Ok(());
    }

    Err("SGX hardware not available - /dev/isgx or /dev/sgx_enclave not found. Set SGX_REMOTE_HOST=ip:port to use remote enclave.".to_string())
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn check_sgx_hardware() -> Result<(), String> {
    Err("SGX VM feature not compiled".to_string())
}

#[cfg(feature = "use_sgx_vm")]
fn get_vm_enclave_path() -> Result<String, String> {

    if let Ok(path) = std::env::var("SGX_VM_ENCLAVE_PATH") {
        return if Path::new(&path).exists() {
            Ok(path)
        } else {
            Err(format!(
                "SGX_VM_ENCLAVE_PATH={} does not exist. Refusing to fall back to a discovered \
 enclave - that silently runs different code than you asked for.",
                path
            ))
        };
    }

    let paths = [
        "target/x86_64-fortanix-unknown-sgx/release/sgx_vm.sgxs",
        "../target/x86_64-fortanix-unknown-sgx/release/sgx_vm.sgxs",
        "/home/user/Desktop/scaphandre/target/x86_64-fortanix-unknown-sgx/release/sgx_vm.sgxs",
        DEFAULT_VM_ENCLAVE_PATH,
    ];

    for path in &paths {
        if Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    Err(format!(
        "SGX VM enclave binary not found. Tried:\n\
 - $SGX_VM_ENCLAVE_PATH environment variable\n\
 - {}\n\
 Build the enclave with: cargo build --release --target x86_64-fortanix-unknown-sgx -p sgx_vm",
        paths.join("\n-")
    ))
}

fn which_ftxsgx_runner() -> String {
    let paths = [
        "ftxsgx-runner",
        "/usr/bin/ftxsgx-runner",
        "/usr/local/bin/ftxsgx-runner",
        &format!("{}/.cargo/bin/ftxsgx-runner", std::env::var("HOME").unwrap_or_default()),
    ];

    for path in &paths {
        if Command::new(path)
            .arg("--version")
            .output()
            .is_ok()
        {
            return path.to_string();
        }
    }

    "ftxsgx-runner".to_string()
}

#[cfg(feature = "use_sgx_vm")]
fn spawn_vm_enclave_with_tcp(enclave_path: &str) -> Result<(TcpStream, std::process::Child), i32> {
    let runner_path = which_ftxsgx_runner();
    println!("[SGX-VM-RUNNER] Using runner: {}", runner_path);
    println!("[SGX-VM-RUNNER] Starting VM enclave process...");

    let mut child = match Command::new(&runner_path)
        .arg(enclave_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] Failed to spawn enclave: {}", e);
            return Err(-202);
        }
    };

    println!("[SGX-VM-RUNNER] Enclave process started (PID: {})", child.id());

    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut reader = BufReader::new(stdout);
    let mut port_line = String::new();

    match reader.read_line(&mut port_line) {
        Ok(0) => {
            eprintln!("[SGX-VM-RUNNER] Enclave closed without sending port");
            let _ = child.wait();
            return Err(-210);
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] Failed to read port from enclave: {}", e);
            let _ = child.wait();
            return Err(-211);
        }
    }

    let port_str = port_line.trim();
    let port: u16 = if let Some(p) = port_str.strip_prefix("PORT:") {
        match p.parse() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[SGX-VM-RUNNER] Invalid port number '{}': {}", p, e);
                let _ = child.wait();
                return Err(-212);
            }
        }
    } else {
        eprintln!("[SGX-VM-RUNNER] Unexpected enclave output: {}", port_str);
        let _ = child.wait();
        return Err(-213);
    };

    println!("[SGX-VM-RUNNER] Enclave listening on port {}", port);

    let stream = match TcpStream::connect(format!("127.0.0.1:{}", port)) {
        Ok(s) => {
            let _ = s.set_nodelay(true);
            s
        }
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] Failed to connect to enclave: {}", e);
            let _ = child.wait();
            return Err(-214);
        }
    };

    println!("[SGX-VM-RUNNER] Connected to enclave via TCP");
    Ok((stream, child))
}

#[cfg(feature = "use_sgx_vm")]
fn create_tls_config() -> Result<Arc<ClientConfig>, i32> {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();

    let certs = rustls_pemfile::certs(&mut ENCLAVE_CA_PEM.as_bytes())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();

    if certs.is_empty() {
        eprintln!("[SGX-VM-RUNNER] Failed to parse enclave CA certificate");
        return Err(-240);
    }

    for cert in certs {
        if let Err(e) = root_store.add(cert) {
            eprintln!("[SGX-VM-RUNNER] Failed to add CA cert: {:?}", e);
            return Err(-241);
        }
    }

    println!("[SGX-VM-RUNNER] Loaded enclave CA certificate");

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

#[cfg(feature = "use_sgx_vm")]
fn connect_to_remote_enclave(host_addr: &str) -> Result<TlsStream, i32> {
    println!("[SGX-VM-RUNNER] Connecting to REMOTE SGX enclave at {} with TLS...", host_addr);

    let tls_config = create_tls_config()?;

    let server_name = ServerName::try_from("sgx-enclave".to_string())
        .map_err(|e| {
            eprintln!("[SGX-VM-RUNNER] Invalid server name: {:?}", e);
            -242
        })?;

    let tcp_stream = TcpStream::connect(host_addr).map_err(|e| {
        eprintln!("[SGX-VM-RUNNER] Failed to connect to {}: {}", host_addr, e);
        -230
    })?;

    let _ = tcp_stream.set_nodelay(true);

    println!("[SGX-VM-RUNNER] TCP connected, starting TLS handshake...");

    let tls_conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| {
            eprintln!("[SGX-VM-RUNNER] TLS connection failed: {:?}", e);
            -243
        })?;

    let tls_stream = rustls::StreamOwned::new(tls_conn, tcp_stream);

    println!("[SGX-VM-RUNNER] TLS connection established to remote SGX enclave");
    println!("[SGX-VM-RUNNER] All communication is now encrypted");

    Ok(TlsStream::Rustls(tls_stream))
}

#[cfg(feature = "use_sgx_vm")]
fn get_vm_enclave_connection() -> Result<std::sync::MutexGuard<'static, Option<VmEnclaveConnection>>, i32> {
    let mut conn_guard = VM_ENCLAVE_CONNECTION.lock().unwrap();

    if conn_guard.is_some() {
        return Ok(conn_guard);
    }

    if let Some(remote_host) = get_remote_sgx_host() {
        println!("[SGX-VM-RUNNER] Creating REMOTE SGX enclave TLS connection...");
        println!("[SGX-VM-RUNNER] Remote host: {}", remote_host);

        let stream = connect_to_remote_enclave(&remote_host)?;

        *conn_guard = Some(VmEnclaveConnection {
            stream,
            child: None,
            is_remote: true,
        });
        println!("[SGX-VM-RUNNER] Remote TLS enclave connection established");

        return Ok(conn_guard);
    }

    println!("[SGX-VM-RUNNER] Creating persistent LOCAL VM enclave TLS connection...");

    let enclave_path = match get_vm_enclave_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] FATAL: {}", e);
            return Err(-201);
        }
    };
    crate::exporters::utils::log_enclave_identity("gpu/vm", &enclave_path);

    let (tcp_stream, child) = spawn_vm_enclave_with_tcp(&enclave_path)?;

    let tls_config = create_tls_config()?;
    let server_name = ServerName::try_from("sgx-enclave".to_string())
        .map_err(|_| -242)?;
    let tls_conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| {
            eprintln!("[SGX-VM-RUNNER] Local TLS connection failed: {:?}", e);
            -243
        })?;
    let tls_stream = rustls::StreamOwned::new(tls_conn, tcp_stream);

    *conn_guard = Some(VmEnclaveConnection {
        stream: TlsStream::Rustls(tls_stream),
        child: Some(child),
        is_remote: false,
    });
    println!("[SGX-VM-RUNNER] Persistent LOCAL TLS enclave connection established");

    Ok(conn_guard)
}

#[cfg(feature = "use_sgx_vm")]
fn send_tls_request(stream: &mut TlsStream, request_json: &str) -> Result<VmEnclaveResponse, i32> {
    let request_bytes = request_json.as_bytes();
    let len_bytes = (request_bytes.len() as u32).to_be_bytes();

    if let Err(e) = stream.write_all(&len_bytes) {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to send length: {}", e);
        return Err(-220);
    }
    if let Err(e) = stream.write_all(request_bytes) {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to send request: {}", e);
        return Err(-221);
    }
    if let Err(e) = stream.flush() {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to flush: {}", e);
        return Err(-222);
    }

    println!("[SGX-VM-RUNNER] TLS: Sent {} encrypted bytes to enclave", request_bytes.len());

    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to read response length: {}", e);
        return Err(-223);
    }

    let response_len = u32::from_be_bytes(len_buf) as usize;

    let mut response_data = vec![0u8; response_len];
    if let Err(e) = stream.read_exact(&mut response_data) {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to read response: {}", e);
        return Err(-224);
    }

    let response_str = match String::from_utf8(response_data) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] TLS: Invalid UTF-8 in response: {}", e);
            return Err(-225);
        }
    };

    match serde_json::from_str(&response_str) {
        Ok(r) => Ok(r),
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] TLS: Failed to parse response JSON: {}", e);
            Err(-226)
        }
    }
}

#[cfg(feature = "use_sgx_vm")]
fn send_request_to_vm_enclave(request_json: &str) -> Result<VmEnclaveResponse, i32> {
    let mut conn_guard = get_vm_enclave_connection()?;
    let conn = conn_guard.as_mut().ok_or(-250)?;
    send_tls_request(&mut conn.stream, request_json)
}

#[cfg(feature = "use_sgx_vm")]
pub fn verify_boot_in_sgx(
    pcr_values: &[u8],
    ima_log: &str,
    hostname: &str,
    deployment_type: &str,
    immudb_addr: &str,
    ca_pem: &str,
    quote_attest: &str,
    quote_signature: &str,
) -> Result<i32, i32> {
    println!("[SGX-VM-RUNNER] BOOT INTEGRITY VERIFICATION (inside SGX)");
    println!("[SGX-VM-RUNNER] Hostname: {}", hostname);
    println!("[SGX-VM-RUNNER] Deployment: {}", deployment_type);
    println!("[SGX-VM-RUNNER] IMA log size: {} bytes", ima_log.len());

    check_sgx_hardware().map_err(|_| -200)?;

    #[allow(unused_mut)]
    let mut pcr_values_owned = pcr_values.to_vec();
    #[allow(unused_mut)]
    let mut ima_log_owned = ima_log.to_string();
    #[allow(unused_mut)]
    let mut quote_attest_owned = quote_attest.to_string();
    #[allow(unused_mut)]
    let mut quote_signature_owned = quote_signature.to_string();

    #[cfg(feature = "tpm_attestation_vm")]
    {
        let snapshot_mode = std::env::var("IMA_PATH")
            .map(|d| !std::fs::canonicalize(&d)
                .map(|p| p.starts_with("/sys/kernel/security"))
                .unwrap_or_else(|_| d.starts_with("/sys/kernel/security")))
            .unwrap_or(false);
        if quote_attest_owned.is_empty() && !snapshot_mode {
            match request_nonce_from_enclave() {
                Some(nonce) => match crate::tpm_attestation::generate_signed_quote(&nonce) {
                    Ok((quoted_pcrs, attest, sig)) => {

                        pcr_values_owned = quoted_pcrs;
                        quote_attest_owned = hex::encode(attest);
                        quote_signature_owned = hex::encode(sig);
                        println!("[SGX-VM-RUNNER] TPM2_Quote (vTPM) over platform PCRs + PCR10, bound to the enclave's nonce");
                        match std::fs::read_to_string("/sys/kernel/security/ima/ascii_runtime_measurements") {
                            Ok(l) => {
                                println!("[SGX-VM-RUNNER] re-read IMA log after the quote ({} bytes) so it covers the quoted PCR10", l.len());
                                ima_log_owned = l;
                            }
                            Err(e) => eprintln!("[SGX-VM-RUNNER] could not re-read the live IMA log after the quote: {}", e),
                        }
                    }
                    Err(e) => println!("[SGX-VM-RUNNER] no TPM2_Quote ({}) - PCR values will be UNAUTHENTICATED", e),
                },
                None => println!("[SGX-VM-RUNNER] enclave issued no nonce - PCR values will be UNAUTHENTICATED"),
            }
        }
    }

    let request = VerifyBootRequest {
        operation: "verify_boot".to_string(),
        pcr_values: hex::encode(&pcr_values_owned),
        ima_log: ima_log_owned,
        hostname: hostname.to_string(),
        deployment_type: deployment_type.to_string(),
        immudb_addr: immudb_addr.to_string(),
        ca_pem: ca_pem.to_string(),
        quote_attest: quote_attest_owned,
        quote_signature: quote_signature_owned,
    };

    let request_json = serde_json::to_string(&request).unwrap();
    println!("[SGX-VM-RUNNER] Sending {} bytes to enclave...", request_json.len());

    let response = send_request_to_vm_enclave(&request_json)?;

    match response.status {
        0 => {
            println!("[SGX-VM-RUNNER] BOOT INTEGRITY VERIFIED");
        }
        -6 => {
            eprintln!("[SGX-VM-RUNNER] HASH MISMATCH - BINARY TAMPERED");
        }
        -7 => {
            eprintln!("[SGX-VM-RUNNER] PCR0 MISMATCH - BOOT TAMPERED");
        }
        -8 => {
            eprintln!("[SGX-VM-RUNNER] PCR7 MISMATCH - SECURE BOOT TAMPERED");
        }
        -9 => {
            eprintln!("[SGX-VM-RUNNER] PCR10 MISMATCH - IMA TAMPERED");
        }
        _ => {
            eprintln!("[SGX-VM-RUNNER] Boot verification failed: {} - {}", response.status, response.message);
        }
    }

    Ok(response.status)
}

#[cfg(feature = "use_sgx_vm")]
pub fn verify_chain_in_sgx(
    vm_name: &str,
    energy_value: u64,
    counter: u64,
    previous_hash: &[u8; 32],
    signature: &[u8; 32],
) -> Result<i32, i32> {
    println!("[SGX-VM-RUNNER] Verifying chain inside SGX enclave...");

    check_sgx_hardware().map_err(|_| -200)?;

    let request = VerifyChainRequest {
        operation: "verify_chain".to_string(),
        vm_name: vm_name.to_string(),
        energy_value,
        counter,
        previous_hash: hex::encode(previous_hash),
        signature: hex::encode(signature),
    };

    let request_json = serde_json::to_string(&request).unwrap();
    let response = send_request_to_vm_enclave(&request_json)?;

    println!("[SGX-VM-RUNNER] Chain verification result: {} - {}", response.status, response.message);

    Ok(response.status)
}

#[cfg(feature = "use_sgx_vm")]
pub fn compute_process_energy_in_sgx(
    vm_total_energy_uj: u64,
    cpu_percentage: f64,
) -> Result<u64, i32> {
    check_sgx_hardware().map_err(|_| -200)?;

    let request = ComputeEnergyRequest {
        operation: "compute_process_energy".to_string(),
        vm_total_energy_uj,
        cpu_percentage,
    };

    let request_json = serde_json::to_string(&request).unwrap();
    let response = send_request_to_vm_enclave(&request_json)?;

    if response.status != 0 {
        return Err(response.status);
    }

    let energy = response.output_data
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(-300)?;

    Ok(energy)
}

#[cfg(feature = "use_sgx_vm")]
pub fn db_export_in_sgx(
    vm_name: &str,
    energy_uj: u64,
    counter: u64,
    previous_hash: &[u8; 32],
    signature: &[u8; 32],
    energy_delta: u64,
    processes: &[(u32, u64)],
    session_id: Option<&str>,
) -> Result<Vec<(u32, u64)>, i32> {
    println!("[SGX-VM-RUNNER] Running DB export inside REAL SGX enclave");

    check_sgx_hardware().map_err(|_| -200)?;

    let request = DbExportRequest {
        operation: "db_export".to_string(),
        vm_name: vm_name.to_string(),
        energy_uj,
        counter,
        previous_hash: hex::encode(previous_hash),
        signature: hex::encode(signature),
        energy_delta,
        processes: processes.to_vec(),
        session_id: session_id.map(|s| s.to_string()),
    };

    let request_json = serde_json::to_string(&request).unwrap();
    println!("[SGX-VM-RUNNER] Request size: {} bytes", request_json.len());

    let response = send_request_to_vm_enclave(&request_json)?;

    println!("[SGX-VM-RUNNER] Enclave response:");
    println!("[SGX-VM-RUNNER] Status: {}", response.status);
    println!("[SGX-VM-RUNNER] Message: {}", response.message);

    if response.status != 0 {
        return Err(response.status);
    }

    let results: Vec<(u32, u64)> = response.output_data
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    println!("[SGX-VM-RUNNER] DB export completed inside REAL SGX enclave");
    println!("[SGX-VM-RUNNER] {} processes computed", results.len());

    Ok(results)
}

#[cfg(feature = "use_sgx_vm")]
pub fn gpu_db_export_in_sgx(
    node_id: &str,

    gpus: Vec<(
        u32,
        String,
        u64,
        Vec<(u32, u64, String)>,
        Option<(u64, u64, u64)>,
    )>,
) -> Result<Vec<(String, u64)>, i32> {
    println!("[SGX-VM-RUNNER] GPU DB export inside REAL SGX enclave (node={})", node_id);

    check_sgx_hardware().map_err(|_| -200)?;

    let immudb_addr = std::env::var("IMMUDB_ADDR").unwrap_or_else(|_| {
        if std::env::var("SGX_REMOTE_HOST").is_ok() {
            "127.0.0.1:8443".to_string()
        } else {
            "192.168.122.1:8443".to_string()
        }
    });
    let deployment_type = if cfg!(feature = "use_sgx") && std::env::var("SGX_REMOTE_HOST").is_err() {
        "host".to_string()
    } else {
        "vm".to_string()
    };

    let request = GpuDbExportRequest {
        operation: "gpu_db_export".to_string(),
        node_id: node_id.to_string(),
        immudb_addr,
        deployment_type,

        #[cfg(feature = "with_gpu_ebpf")]
        tag_key: Some({ let (a, b) = crate::sensors::gpu_nvml::tag_key(); [a, b] }),
        #[cfg(not(feature = "with_gpu_ebpf"))]
        tag_key: None,
        #[cfg(feature = "with_gpu_ebpf")]
        tag_epoch: crate::sensors::gpu_nvml::tag_epoch(),
        #[cfg(not(feature = "with_gpu_ebpf"))]
        tag_epoch: 0,
        gpus: gpus
            .into_iter()
            .map(|(gpu_index, gpu_uuid, energy_uj, procs, tag)| GpuGroupReq {
                gpu_index,
                gpu_uuid,
                energy_uj,
                procs: procs
                    .into_iter()
                    .map(|(pid, util, cgroup)| GpuProcReq { pid, util, cgroup })
                    .collect(),
                tag: tag.map(|(energy_uj, timestamp_ns, hash)| GpuTagReq {
                    energy_uj,
                    timestamp_ns,
                    hash,
                }),
            })
            .collect(),
    };

    let request_json = serde_json::to_string(&request).unwrap();
    println!("[SGX-VM-RUNNER] GPU request size: {} bytes", request_json.len());

    let response = send_request_to_vm_enclave(&request_json)?;

    println!("[SGX-VM-RUNNER] Status: {}", response.status);
    println!("[SGX-VM-RUNNER] Message: {}", response.message);

    if response.status != 0 {
        return Err(response.status);
    }

    let results: Vec<(String, u64)> = response
        .output_data
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    println!("[SGX-VM-RUNNER] GPU export completed: {} container row(s)", results.len());

    Ok(results)
}

#[cfg(feature = "use_sgx_vm")]
pub fn immudb_login_in_sgx() -> Result<String, i32> {
    println!("[SGX-VM-RUNNER] Logging into ImmuDB inside SGX enclave...");

    check_sgx_hardware().map_err(|_| -200)?;

    let request = serde_json::json!({
        "operation": "immudb_login"
    });

    let request_json = request.to_string();
    let response = send_request_to_vm_enclave(&request_json)?;

    if response.status != 0 {
        eprintln!("[SGX-VM-RUNNER] ImmuDB login failed: {}", response.message);
        return Err(response.status);
    }

    response.output_data.ok_or(-301)
}

#[cfg(feature = "use_sgx_vm")]
pub fn immudb_insert_in_sgx(session_id: &str, body: &str) -> Result<String, i32> {
    check_sgx_hardware().map_err(|_| -200)?;

    let request = ImmudbInsertRequest {
        operation: "immudb_insert".to_string(),
        session_id: session_id.to_string(),
        body: body.to_string(),
    };

    let request_json = serde_json::to_string(&request).unwrap();
    let response = send_request_to_vm_enclave(&request_json)?;

    if response.status != 0 {
        return Err(response.status);
    }

    Ok(response.output_data.unwrap_or_default())
}

#[cfg(feature = "use_sgx_vm")]
pub fn shutdown_vm_enclave() {
    let mut conn_guard = match VM_ENCLAVE_CONNECTION.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    if let Some(ref mut conn) = *conn_guard {
        if conn.is_remote {

            println!("[SGX-VM-RUNNER] Closing remote enclave connection");
        } else {

            let _ = conn.stream.write_all(&[0u8; 4]);
            let _ = conn.stream.flush();

            if let Some(ref mut child) = conn.child {
                let _ = child.wait();
            }
        }
    }

    *conn_guard = None;
    println!("[SGX-VM-RUNNER] VM enclave connection closed");
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn verify_boot_in_sgx(
    _pcr_values: &[u8],
    _ima_log: &str,
    _hostname: &str,
    _deployment_type: &str,
    _immudb_addr: &str,
    _ca_pem: &str,
    _quote_attest: &str,
    _quote_signature: &str,
) -> Result<i32, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn verify_chain_in_sgx(
    _vm_name: &str,
    _energy_value: u64,
    _counter: u64,
    _previous_hash: &[u8; 32],
    _signature: &[u8; 32],
) -> Result<i32, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn compute_process_energy_in_sgx(
    _vm_total_energy_uj: u64,
    _cpu_percentage: f64,
) -> Result<u64, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn db_export_in_sgx(
    _vm_name: &str,
    _energy_uj: u64,
    _counter: u64,
    _previous_hash: &[u8; 32],
    _signature: &[u8; 32],
    _energy_delta: u64,
    _processes: &[(u32, u64)],
    _session_id: Option<&str>,
) -> Result<Vec<(u32, u64)>, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn immudb_login_in_sgx() -> Result<String, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn immudb_insert_in_sgx(_session_id: &str, _body: &str) -> Result<String, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn shutdown_vm_enclave() {

}

pub fn print_sgx_vm_info() {

    #[cfg(feature = "use_sgx_vm")]
    {

        if let Some(remote_host) = get_remote_sgx_host() {
            println!("[SGX-VM-INFO] Mode: REMOTE SGX (connecting to host)");
            println!("[SGX-VM-INFO] Remote host: {}", remote_host);
            println!("[SGX-VM-INFO] No local SGX hardware required");
        } else {
            println!("[SGX-VM-INFO] Mode: LOCAL SGX HARDWARE");
            println!("[SGX-VM-INFO] No simulation fallback - hardware required");

            match check_sgx_hardware() {
                Ok(_) => println!("[SGX-VM-INFO] SGX hardware available"),
                Err(e) => {
                    println!("[SGX-VM-INFO] SGX hardware NOT available");
                    println!("[SGX-VM-INFO] Error: {}", e);
                    println!("[SGX-VM-INFO] Tip: Set SGX_REMOTE_HOST=host:port to use remote enclave");
                }
            }

            match get_vm_enclave_path() {
                Ok(p) => println!("[SGX-VM-INFO] Enclave binary: {}", p),
                Err(_) => println!("[SGX-VM-INFO] Enclave binary not found"),
            }
        }
    }

    #[cfg(not(feature = "use_sgx_vm"))]
    {
        println!("[SGX-VM-INFO] SGX VM feature not compiled");
        println!("[SGX-VM-INFO] Build with: cargo build --features use_sgx_vm");
    }

}
