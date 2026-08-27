#[cfg(feature = "use_sgx")]
use enclave_runner::EnclaveBuilder;
#[cfg(feature = "use_sgx")]
use sgxs_loaders::isgx::Device as IsgxDevice;

use std::path::Path;
use std::io::{Write, Read, BufRead, BufReader};
use std::process::{Command, Stdio};
use std::collections::HashMap;
use std::sync::Mutex;
use std::net::TcpStream;
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[cfg(feature = "use_sgx")]
use std::sync::Arc;
#[cfg(feature = "use_sgx")]
use rustls::ClientConfig;
#[cfg(feature = "use_sgx")]
use rustls::pki_types::{ServerName, CertificateDer};

#[cfg(feature = "use_sgx")]
const ENCLAVE_CA_PEM: &str = include_str!("../enclave_ca.pem");

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_ENCLAVE_PATH: &str = "/usr/lib/scaphandre/sgx.sgxs";

type OcallWriteVmEnergyFn = unsafe extern "C" fn(*const u8, usize, u64, u64, *const u8, *const u8) -> i32;
static mut OCALL_WRITE_VM_ENERGY: Option<OcallWriteVmEnergyFn> = None;

#[cfg(feature = "use_sgx")]
enum TlsStream {
    Rustls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
    Plain(TcpStream),
}

#[cfg(feature = "use_sgx")]
impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsStream::Rustls(s) => s.read(buf),
            TlsStream::Plain(s) => s.read(buf),
        }
    }
}

#[cfg(feature = "use_sgx")]
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

#[cfg(feature = "use_sgx")]
struct EnclaveConnection {
    stream: TlsStream,
    child: std::process::Child,
}

#[cfg(not(feature = "use_sgx"))]
struct EnclaveConnection {
    stream: TcpStream,
    child: std::process::Child,
}

lazy_static::lazy_static! {
    static ref ENCLAVE_CONNECTION: Mutex<Option<EnclaveConnection>> = Mutex::new(None);
}

struct VmChainState {
    hmac_key: [u8; 32],
    chain_state: [u8; 32],
    counter: u64,
    cumulative_energy_uj: u64,
}

lazy_static::lazy_static! {
    static ref VM_CHAINS: Mutex<HashMap<String, VmChainState>> = Mutex::new(HashMap::new());
    static ref MASTER_KEY: [u8; 32] = [0u8; 32];
}

fn derive_vm_key(master: &[u8; 32], vm_name: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(master).expect("HMAC key");
    mac.update(b"vm:");
    mac.update(vm_name.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[derive(Serialize)]
struct VerifyRequest {
    operation: String,
    pcr_values: String,
    ima_hash: String,
    ima_count: usize,
    scaphandre_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ima_log: Option<String>,
    hostname: String,
    deployment_type: String,
    immudb_addr: String,
    skip_ima: bool,

    quote_attest: String,
    quote_signature: String,
}

static BOOT_VERIFICATION: Mutex<Option<Result<(), i32>>> = Mutex::new(None);

#[cfg(feature = "use_sgx")]
pub fn request_nonce_from_enclave() -> Option<String> {
    #[derive(Serialize)]
    struct NonceReq { operation: String }
    let req = serde_json::to_string(&NonceReq { operation: "get_nonce".to_string() }).ok()?;
    match send_request_to_enclave(&req) {
        Ok(r) if r.status == 0 => r.output_data,
        Ok(r) => {
            eprintln!("[SGX-RUNNER] enclave refused to issue a nonce: {} ({})", r.message, r.status);
            None
        }
        Err(e) => {
            eprintln!("[SGX-RUNNER] could not reach the enclave for a nonce: {:?}", e);
            None
        }
    }
}

#[derive(Deserialize, Debug)]
struct EnclaveResponse {
    status: i32,
    message: String,
    ima_hash: Option<String>,
    #[serde(default)]
    output_data: Option<String>,
}

#[cfg(feature = "use_sgx")]
pub fn check_sgx_hardware() -> Result<(), String> {
    match IsgxDevice::new() {
        Ok(_) => {
            println!("[SGX] SGX hardware detected and available");
            Ok(())
        }
        Err(e) => {
            Err(format!(
                "SGX hardware NOT available: {:?}\n\
 Check that:\n\
 - SGX is enabled in BIOS\n\
 - /dev/isgx or /dev/sgx_enclave exists\n\
 - Intel SGX driver is loaded\n\
 - You have permission to access the device",
                e
            ))
        }
    }
}

#[cfg(not(feature = "use_sgx"))]
pub fn check_sgx_hardware() -> Result<(), String> {
    Err("SGX feature not compiled. Build with --features use_sgx".to_string())
}

pub fn get_enclave_path() -> Result<String, String> {

    if let Ok(path) = std::env::var("SGX_ENCLAVE_PATH") {
        return if Path::new(&path).exists() {
            Ok(path)
        } else {
            Err(format!(
                "SGX_ENCLAVE_PATH={} does not exist. Refusing to fall back to a discovered enclave \
 - that silently runs different code than you asked for.",
                path
            ))
        };
    }

    let workspace_path = "target/x86_64-fortanix-unknown-sgx/release/sgx.sgxs";
    if Path::new(workspace_path).exists() {
        return Ok(workspace_path.to_string());
    }

    let local_path = "sgx/target/x86_64-fortanix-unknown-sgx/release/sgx.sgxs";
    if Path::new(local_path).exists() {
        return Ok(local_path.to_string());
    }

    if Path::new(DEFAULT_ENCLAVE_PATH).exists() {
        return Ok(DEFAULT_ENCLAVE_PATH.to_string());
    }

    Err(format!(
        "SGX enclave binary not found. Tried:\n\
 - $SGX_ENCLAVE_PATH environment variable\n\
 - {}\n\
 - {}\n\
 - {}\n\
 Build the enclave with: cargo build --release --target x86_64-fortanix-unknown-sgx -p sgx",
        workspace_path, local_path, DEFAULT_ENCLAVE_PATH
    ))
}

fn extract_scaphandre_hash_from_ima(ima_log: &str) -> String {

    let current_exe = match std::env::current_exe() {
        Ok(path) => path.to_string_lossy().to_string(),
        Err(e) => {
            eprintln!("[SGX-RUNNER] Warning: Could not get current exe path: {}", e);
            return "current_exe_error".to_string();
        }
    };

    println!("[SGX-RUNNER] Looking for IMA entry for: {}", current_exe);

    let binary_hash = match std::fs::read(&current_exe) {
        Ok(binary_data) => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&binary_data);
            hex::encode(hasher.finalize())
        }
        Err(e) => {
            eprintln!("[SGX-RUNNER] Warning: Could not read binary to hash: {}", e);
            return "binary_read_error".to_string();
        }
    };

    println!("[SGX-RUNNER] Current binary hash: {}", binary_hash);

    let mut found_in_ima = false;

    for line in ima_log.lines() {

        if line.ends_with(&current_exe) {

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let hash_part = parts[3];
                let ima_entry_hash = if let Some(hash) = hash_part.strip_prefix("sha256:") {
                    hash
                } else if let Some(hash) = hash_part.strip_prefix("sha1:") {
                    hash
                } else {
                    hash_part
                };

                if ima_entry_hash == binary_hash {
                    found_in_ima = true;
                    println!("[SGX-RUNNER] Found matching IMA entry for current binary");
                    break;
                }
            }
        }
    }

    if found_in_ima {
        binary_hash
    } else {
        eprintln!("[SGX-RUNNER] Warning: Current binary hash not found in IMA log");
        eprintln!("[SGX-RUNNER] Binary may have changed since last measurement");

        binary_hash
    }
}

#[cfg(feature = "use_sgx")]
fn spawn_enclave_with_tcp(enclave_path: &str) -> Result<(TcpStream, std::process::Child), i32> {
    let runner_path = which_ftxsgx_runner();
    println!("[SGX-RUNNER] Using runner: {}", runner_path);
    println!("[SGX-RUNNER] Starting enclave process...");

    let mut child = match Command::new(&runner_path)
        .arg(enclave_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[SGX-RUNNER] Failed to spawn enclave: {}", e);
            eprintln!("[SGX-RUNNER] Make sure ftxsgx-runner is installed:");
            eprintln!("[SGX-RUNNER] cargo install fortanix-sgx-tools");
            return Err(-202);
        }
    };

    println!("[SGX-RUNNER] Enclave process started (PID: {})", child.id());

    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut reader = BufReader::new(stdout);
    let mut port_line = String::new();

    match reader.read_line(&mut port_line) {
        Ok(0) => {
            eprintln!("[SGX-RUNNER] Enclave closed without sending port");
            let _ = child.wait();
            return Err(-210);
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("[SGX-RUNNER] Failed to read port from enclave: {}", e);
            let _ = child.wait();
            return Err(-211);
        }
    }

    let port_str = port_line.trim();
    let port: u16 = if let Some(p) = port_str.strip_prefix("PORT:") {
        match p.parse() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[SGX-RUNNER] Invalid port number '{}': {}", p, e);
                let _ = child.wait();
                return Err(-212);
            }
        }
    } else {
        eprintln!("[SGX-RUNNER] Unexpected enclave output: {}", port_str);
        let _ = child.wait();
        return Err(-213);
    };

    println!("[SGX-RUNNER] Enclave listening on port {}", port);

    let tcp_stream = match TcpStream::connect(format!("127.0.0.1:{}", port)) {
        Ok(s) => {
            let _ = s.set_nodelay(true);
            s
        }
        Err(e) => {
            eprintln!("[SGX-RUNNER] Failed to connect to enclave: {}", e);
            let _ = child.wait();
            return Err(-214);
        }
    };

    println!("[SGX-RUNNER] Connected to enclave via TCP");
    Ok((tcp_stream, child))
}

#[cfg(feature = "use_sgx")]
fn create_tls_config() -> Result<Arc<ClientConfig>, i32> {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();

    let certs = rustls_pemfile::certs(&mut ENCLAVE_CA_PEM.as_bytes())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();

    if certs.is_empty() {
        eprintln!("[SGX-RUNNER] Failed to parse enclave CA certificate");
        return Err(-240);
    }

    for cert in certs {
        if let Err(e) = root_store.add(cert) {
            eprintln!("[SGX-RUNNER] Failed to add CA cert: {:?}", e);
            return Err(-241);
        }
    }

    println!("[SGX-RUNNER] Loaded enclave CA certificate");

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

#[cfg(feature = "use_sgx")]
fn get_enclave_connection() -> Result<std::sync::MutexGuard<'static, Option<EnclaveConnection>>, i32> {
    let mut conn_guard = ENCLAVE_CONNECTION.lock().unwrap();

    if conn_guard.is_some() {
        return Ok(conn_guard);
    }

    println!("[SGX-RUNNER] Creating persistent TLS enclave connection...");

    let enclave_path = match get_enclave_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[SGX-RUNNER] FATAL: {}", e);
            return Err(-201);
        }
    };
    crate::exporters::utils::log_enclave_identity("host-verify", &enclave_path);

    let (tcp_stream, child) = spawn_enclave_with_tcp(&enclave_path)?;

    println!("[SGX-RUNNER] Upgrading to TLS...");
    let tls_config = create_tls_config()?;
    let server_name = ServerName::try_from("sgx-enclave".to_string())
        .map_err(|e| {
            eprintln!("[SGX-RUNNER] Invalid server name: {:?}", e);
            -242
        })?;
    let tls_conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| {
            eprintln!("[SGX-RUNNER] TLS connection failed: {:?}", e);
            -243
        })?;
    let tls_stream = rustls::StreamOwned::new(tls_conn, tcp_stream);

    *conn_guard = Some(EnclaveConnection {
        stream: TlsStream::Rustls(tls_stream),
        child
    });
    println!("[SGX-RUNNER] Persistent TLS enclave connection established");
    println!("[SGX-RUNNER] All communication is now encrypted");

    Ok(conn_guard)
}

#[cfg(feature = "use_sgx")]
fn send_request_to_enclave(request_json: &str) -> Result<EnclaveResponse, i32> {
    let mut conn_guard = get_enclave_connection()?;

    let conn = conn_guard.as_mut().ok_or(-250)?;

    send_tls_request(&mut conn.stream, request_json)
}

#[cfg(feature = "use_sgx")]
fn send_tls_request(stream: &mut TlsStream, request_json: &str) -> Result<EnclaveResponse, i32> {
    let request_bytes = request_json.as_bytes();
    let len_bytes = (request_bytes.len() as u32).to_be_bytes();

    if let Err(e) = stream.write_all(&len_bytes) {
        eprintln!("[SGX-RUNNER] TLS: Failed to send length: {}", e);
        return Err(-220);
    }
    if let Err(e) = stream.write_all(request_bytes) {
        eprintln!("[SGX-RUNNER] TLS: Failed to send request: {}", e);
        return Err(-221);
    }
    if let Err(e) = stream.flush() {
        eprintln!("[SGX-RUNNER] TLS: Failed to flush: {}", e);
        return Err(-222);
    }

    println!("[SGX-RUNNER] TLS: Sent {} bytes to enclave", request_bytes.len());

    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        eprintln!("[SGX-RUNNER] TLS: Failed to read response length: {}", e);
        return Err(-223);
    }

    let response_len = u32::from_be_bytes(len_buf) as usize;
    println!("[SGX-RUNNER] TLS: Expecting {} bytes response", response_len);

    let mut response_data = vec![0u8; response_len];
    if let Err(e) = stream.read_exact(&mut response_data) {
        eprintln!("[SGX-RUNNER] TLS: Failed to read response: {}", e);
        return Err(-224);
    }

    let response_str = match String::from_utf8(response_data) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[SGX-RUNNER] TLS: Invalid UTF-8 in response: {}", e);
            return Err(-225);
        }
    };

    match serde_json::from_str(&response_str) {
        Ok(r) => Ok(r),
        Err(e) => {
            eprintln!("[SGX-RUNNER] TLS: Failed to parse response JSON: {}", e);
            eprintln!("[SGX-RUNNER] TLS: Raw response: {}", response_str);
            Err(-226)
        }
    }
}

#[cfg(feature = "use_sgx")]
pub fn verify_in_sgx_enclave(
    pcr_values: &[u8],
    ima_log: &str,
    hostname: &str,
    deployment_type: &str,
    immudb_addr: &str,
    _ca_pem: &str,
) -> Result<(), i32> {

    if let Ok(cached) = BOOT_VERIFICATION.lock() {
        if let Some(prev) = *cached {
            match prev {
                Ok(()) => println!("[SGX-RUNNER] boot already verified in this process - reusing that result"),
                Err(code) => eprintln!("[SGX-RUNNER] boot verification already FAILED in this process ({}), refusing again", code),
            }
            return prev;
        }
    }

    println!("[SGX-RUNNER] Sending verification request to SGX enclave");

    if let Err(e) = check_sgx_hardware() {
        eprintln!("[SGX-RUNNER] FATAL: {}", e);
        return Err(-200);
    }

    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(ima_log.as_bytes());
    let ima_hash = hex::encode(hasher.finalize());

    let ima_count = ima_log.lines().count();

    let scaphandre_hash = extract_scaphandre_hash_from_ima(ima_log);

    println!("[SGX-RUNNER] IMA log: {} entries, hash: {}...", ima_count, &ima_hash[..16]);
    println!("[SGX-RUNNER] Scaphandre hash from IMA: {}", &scaphandre_hash);

    let skip_ima = std::env::var("SKIP_IMA_VERIFY").map(|v| v == "1").unwrap_or(false);
    if skip_ima {
        println!("[SGX-RUNNER] SKIP_IMA_VERIFY=1 - IMA verification will be bypassed");
    }

    let snapshot_mode = std::env::var("IMA_PATH")
        .map(|d| !std::fs::canonicalize(&d)
            .map(|p| p.starts_with("/sys/kernel/security"))
            .unwrap_or_else(|_| d.starts_with("/sys/kernel/security")))
        .unwrap_or(false);

    let mut pcr_values = pcr_values.to_vec();
    let (quote_attest, quote_signature) = if snapshot_mode {
        println!("[SGX-RUNNER] IMA_PATH is a snapshot, not live securityfs - sending NO TPM2_Quote:");
        println!("[SGX-RUNNER] a quote signs PCR10 now, while the snapshot's PCR10 is older, so");
        println!("[SGX-RUNNER] the log could not reconcile. Run as root against live securityfs");
        println!("[SGX-RUNNER] for quote-backed PCRs. PCR values will be UNAUTHENTICATED.");
        (String::new(), String::new())
    } else {
        match request_nonce_from_enclave() {
        Some(nonce) => match crate::tpm_attestation::generate_signed_quote(&nonce) {
            Ok((quoted_pcrs, attest, sig)) => {

                pcr_values = quoted_pcrs;
                println!("[SGX-RUNNER] TPM2_Quote over PCR 0/7/10, bound to the enclave's nonce");
                (hex::encode(attest), hex::encode(sig))
            }
            Err(e) => {
                println!("[SGX-RUNNER] no TPM2_Quote ({}) - PCR values will be UNAUTHENTICATED", e);
                (String::new(), String::new())
            }
        },
        None => {
            println!("[SGX-RUNNER] enclave issued no nonce - PCR values will be UNAUTHENTICATED");
            (String::new(), String::new())
        }
        }
    };
    let pcr_values = &pcr_values[..];

    let relog;
    let ima_log = if snapshot_mode || quote_attest.is_empty() {
        ima_log
    } else {
        match std::fs::read_to_string("/sys/kernel/security/ima/ascii_runtime_measurements") {
            Ok(l) => {
                println!("[SGX-RUNNER] re-read the IMA log after the quote ({} bytes) so it covers the quoted PCR10", l.len());
                relog = l;
                &relog[..]
            }
            Err(e) => {
                eprintln!("[SGX-RUNNER] could not re-read the live IMA log after the quote: {}", e);
                ima_log
            }
        }
    };

    let request = VerifyRequest {
        operation: "verify".to_string(),
        pcr_values: hex::encode(pcr_values),
        ima_hash,
        ima_count,
        scaphandre_hash,

        ima_log: Some(ima_log.to_string()),
        hostname: hostname.to_string(),
        deployment_type: deployment_type.to_string(),
        immudb_addr: immudb_addr.to_string(),
        skip_ima,
        quote_attest: quote_attest.to_string(),
        quote_signature: quote_signature.to_string(),
    };

    let request_json = serde_json::to_string(&request).unwrap();
    println!("[SGX-RUNNER] Request JSON length: {} bytes", request_json.len());

    let response = send_request_to_enclave(&request_json)?;

    println!("[SGX-RUNNER] Enclave response:");
    println!("[SGX-RUNNER] Status: {}", response.status);
    println!("[SGX-RUNNER] Message: {}", response.message);
    if let Some(ref hash) = response.ima_hash {
        println!("[SGX-RUNNER] IMA Hash: {}", hash);
    }

    let verdict = if response.status == 0 {
        println!("[SGX-RUNNER] Verification PASSED inside real SGX enclave");
        Ok(())
    } else {
        eprintln!("[SGX-RUNNER] Verification FAILED: {}", response.message);
        Err(response.status)
    };

    if let Ok(mut slot) = BOOT_VERIFICATION.lock() {
        *slot = Some(verdict);
    }
    verdict
}

#[cfg(not(feature = "use_sgx"))]
pub fn verify_in_sgx_enclave(
    _pcr_values: &[u8],
    _ima_log: &str,
    _hostname: &str,
    _deployment_type: &str,
    _immudb_addr: &str,
    _ca_pem: &str,
) -> Result<(), i32> {
    eprintln!("[SGX-RUNNER] FATAL: SGX feature not enabled at compile time");
    eprintln!("[SGX-RUNNER] Rebuild with: cargo build --features use_sgx");
    Err(-999)
}

fn which_ftxsgx_runner() -> String {

    let paths = [
        "ftxsgx-runner",
        "/usr/bin/ftxsgx-runner",
        "/usr/local/bin/ftxsgx-runner",
        &format!("{}/.cargo/bin/ftxsgx-runner", std::env::var("HOME").unwrap_or_default()),
    ];

    for path in &paths {
        if std::process::Command::new(path)
            .arg("--version")
            .output()
            .is_ok()
        {
            return path.to_string();
        }
    }

    "ftxsgx-runner".to_string()
}

pub fn print_sgx_info() {
    println!("[SGX-INFO] Mode: REAL SGX HARDWARE ONLY");
    println!("[SGX-INFO] No simulation fallback - hardware required");

    #[cfg(feature = "use_sgx")]
    {
        match check_sgx_hardware() {
            Ok(_) => println!("[SGX-INFO] SGX hardware available"),
            Err(e) => {
                println!("[SGX-INFO] SGX hardware NOT available");
                println!("[SGX-INFO] Error: {}", e);
            }
        }

        match get_enclave_path() {
            Ok(p) => println!("[SGX-INFO] Enclave binary: {}", p),
            Err(_) => println!("[SGX-INFO] Enclave binary not found"),
        }
    }

    #[cfg(not(feature = "use_sgx"))]
    {
        println!("[SGX-INFO] SGX feature not compiled");
        println!("[SGX-INFO] Build with: cargo build --features use_sgx");
    }

}

pub struct SgxEnclave;

impl SgxEnclave {
    pub fn new(_enclave_path: &Path) -> Result<Self, String> {
        check_sgx_hardware()?;
        Ok(Self)
    }

    pub fn is_sgx_available() -> bool {
        check_sgx_hardware().is_ok()
    }
}

pub fn init_sgx_enclave() -> Result<SgxEnclave, String> {
    check_sgx_hardware()?;
    get_enclave_path()?;
    Ok(SgxEnclave)
}

pub fn is_real_sgx_mode() -> bool {
    check_sgx_hardware().is_ok()
}

#[no_mangle]
pub extern "C" fn ecall_compute_total_host_energy(
    pkg_ptr: *const u8,
    pkg_len: usize,
    dram_ptr: *const u8,
    dram_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    if pkg_ptr.is_null() || dram_ptr.is_null() || out_ptr.is_null() || out_len_ptr.is_null() {
        return 1;
    }

    let pkg_slice = unsafe { std::slice::from_raw_parts(pkg_ptr, pkg_len) };
    let dram_slice = unsafe { std::slice::from_raw_parts(dram_ptr, dram_len) };

    #[derive(Deserialize)]
    struct RawEnergyValue {
        value: String,
    }

    let pkg_values: Vec<RawEnergyValue> = match serde_json::from_slice(pkg_slice) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    let dram_values: Vec<RawEnergyValue> = match serde_json::from_slice(dram_slice) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    let mut total: i128 = 0;
    for r in &pkg_values {
        if let Ok(v) = r.value.trim().parse::<i128>() {
            total += v;
        }
    }
    for r in &dram_values {
        if let Ok(v) = r.value.trim().parse::<i128>() {
            total += v;
        }
    }

    let result_str = format!("{}", total);
    let result_bytes = result_str.as_bytes();

    if result_bytes.len() > out_cap {
        return 3;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), out_ptr, result_bytes.len());
        *out_len_ptr = result_bytes.len();
    }

    0
}

#[cfg(feature = "use_sgx")]
pub fn compute_vm_energy_in_sgx(
    topo_json: &[u8],
    proc_json: &[u8],
    hash_json: &[u8],
) -> Result<(), i32> {

    if let Err(e) = check_sgx_hardware() {
        eprintln!("[SGX-RUNNER] FATAL: {}", e);
        return Err(-200);
    }

    #[derive(Serialize)]
    struct ComputeRequest {
        operation: String,
        topo_data: String,
        proc_data: String,
        hash_data: String,

        tag_key: Option<[u64; 2]>,
        tag_epoch: u32,

        tag_producer: u16,
    }

    let request = ComputeRequest {
        operation: "compute_vm_energy".to_string(),
        topo_data: hex::encode(topo_json),
        proc_data: hex::encode(proc_json),
        hash_data: hex::encode(hash_json),
        #[cfg(feature = "with_ebpf_guard")]
        tag_key: Some({ let (a, b) = crate::sensors::tag_key(); [a, b] }),
        #[cfg(not(feature = "with_ebpf_guard"))]
        tag_key: None,
        #[cfg(feature = "with_ebpf_guard")]
        tag_epoch: crate::sensors::tag_epoch(),
        #[cfg(not(feature = "with_ebpf_guard"))]
        tag_epoch: 0,
        #[cfg(feature = "with_ebpf_kernel_read")]
        tag_producer: 2,
        #[cfg(not(feature = "with_ebpf_kernel_read"))]
        tag_producer: 1,
    };

    let request_json = serde_json::to_string(&request).unwrap();
    let request_size = request_json.len();
    println!("[SGX-RUNNER] Request size: {} bytes ({:.1} KB)", request_size, request_size as f64 / 1024.0);

    let response = send_request_to_enclave(&request_json)?;

    println!("[SGX-RUNNER] Enclave response: status={}, msg={}", response.status, response.message);

    if response.status == 0 {

        if let Some(output_hex) = response.output_data {
            if let Ok(output_bytes) = hex::decode(&output_hex) {
                #[derive(Deserialize)]
                struct SignedVmUpdate {
                    vm_name: String,
                    uj_value: u64,
                    counter: u64,
                    previous_hash: String,
                    signature: String,
                }

                if let Ok(updates) = serde_json::from_slice::<Vec<SignedVmUpdate>>(&output_bytes) {
                    println!("[SGX-RUNNER] Processing {} signed updates from enclave", updates.len());

                    unsafe {
                        if let Some(ocall_fn) = OCALL_WRITE_VM_ENERGY {
                            for update in &updates {
                                let prev_hash_bytes = hex::decode(&update.previous_hash).unwrap_or_default();
                                let sig_bytes = hex::decode(&update.signature).unwrap_or_default();

                                let mut prev_hash = [0u8; 32];
                                let mut sig = [0u8; 32];
                                if prev_hash_bytes.len() >= 32 {
                                    prev_hash.copy_from_slice(&prev_hash_bytes[..32]);
                                }
                                if sig_bytes.len() >= 32 {
                                    sig.copy_from_slice(&sig_bytes[..32]);
                                }

                                let vm_name_bytes = update.vm_name.as_bytes();
                                println!("[SGX-RUNNER] Writing VM '{}': {} µJ (counter={})",
                                        update.vm_name, update.uj_value, update.counter);

                                ocall_fn(
                                    vm_name_bytes.as_ptr(),
                                    vm_name_bytes.len(),
                                    update.uj_value,
                                    update.counter,
                                    prev_hash.as_ptr(),
                                    sig.as_ptr(),
                                );
                            }
                        } else {
                            println!("[SGX-RUNNER] Warning: No OCALL registered, can't write updates");
                        }
                    }
                }
            }
        }

        println!("[SGX-RUNNER] VM energy computed inside REAL SGX enclave");
        Ok(())
    } else {
        eprintln!("[SGX-RUNNER] Computation failed: {}", response.message);
        Err(response.status)
    }
}

fn should_use_sgx_enclave() -> bool {

    #[cfg(feature = "use_sgx")]
    {
        check_sgx_hardware().is_ok() && get_enclave_path().is_ok()
    }
    #[cfg(not(feature = "use_sgx"))]
    {
        false
    }
}

#[no_mangle]
pub extern "C" fn ecall_compute_vm_energy_simple(
    topo_ptr: *const u8,
    topo_len: usize,
    proc_ptr: *const u8,
    proc_len: usize,
    hash_ptr: *const u8,
    hash_len: usize,
    out_ptr: *mut u8,
    _out_cap: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    use crate::exporters::qemu::{QemuExporter, CompactProcessSample};

    if topo_ptr.is_null() || proc_ptr.is_null() || out_ptr.is_null() || out_len_ptr.is_null() {
        return 1;
    }

    let topo_slice = unsafe { std::slice::from_raw_parts(topo_ptr, topo_len) };
    let proc_slice = unsafe { std::slice::from_raw_parts(proc_ptr, proc_len) };
    let hash_slice = unsafe { std::slice::from_raw_parts(hash_ptr, hash_len) };

    #[cfg(feature = "use_sgx")]
    {
        if !should_use_sgx_enclave() {
            eprintln!("[SGX-RUNNER] Real SGX required, but SGX hardware/enclave is not available");
            return -200;
        }

        println!("[SGX-RUNNER] SGX hardware detected - forwarding to real enclave");
        match compute_vm_energy_in_sgx(topo_slice, proc_slice, hash_slice) {
            Ok(()) => {
                unsafe { *out_len_ptr = 0; }
                return 0;
            }
            Err(code) => {
                eprintln!("[SGX-RUNNER] Real enclave failed ({}) - refusing stub fallback", code);
                return code;
            }
        }
    }

    eprintln!("[SGX-STUB] Running VM energy computation in userspace (no SGX hardware)");

    let topo_energy_value: String = match serde_json::from_slice(topo_slice) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[SGX-STUB] Failed to deserialize topo_energy_value: {}", e);
            eprintln!("[SGX-STUB] Raw data: {:?}", String::from_utf8_lossy(topo_slice));
            return 2;
        }
    };

    let processes: Vec<Vec<CompactProcessSample>> = match serde_json::from_slice(proc_slice) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[SGX-STUB] Failed to deserialize processes: {}", e);
            return 3;
        }
    };

    eprintln!("[SGX-STUB] Computing VM energy for {} process groups, topo={}",
              processes.len(), topo_energy_value);

    let mut exporter = QemuExporter::new();
    let updates = exporter.iterate_compact(String::new(), topo_energy_value, processes);

    eprintln!("[SGX-STUB] Computed {} VM energy updates", updates.len());

    let mut vm_chains = VM_CHAINS.lock().unwrap();

    for update in &updates {

        let vm_state = vm_chains.entry(update.vm_name.clone()).or_insert_with(|| {
            let vm_key = derive_vm_key(&MASTER_KEY, &update.vm_name);
            VmChainState {
                hmac_key: vm_key,
                chain_state: [0u8; 32],
                counter: 0,
                cumulative_energy_uj: 0,
            }
        });

        vm_state.counter += 1;
        vm_state.cumulative_energy_uj = vm_state
            .cumulative_energy_uj
            .saturating_add(update.uj_to_add);

        let data_to_sign = format!(
            "{}|{}|{}|{}|{}",
            vm_state.counter,
            update.vm_name,
            vm_state.cumulative_energy_uj,
            update.uj_to_add,
            hex::encode(&vm_state.chain_state)
        );

        let signature = {
            let mut mac = HmacSha256::new_from_slice(&vm_state.hmac_key).expect("HMAC key");
            mac.update(data_to_sign.as_bytes());
            let result = mac.finalize().into_bytes();
            let mut sig = [0u8; 32];
            sig.copy_from_slice(&result);
            sig
        };

        let previous_hash = vm_state.chain_state;

        vm_state.chain_state.copy_from_slice(&signature);

        eprintln!("[SGX-STUB] Chain state for '{}': counter={}, prev_hash={}...",
                  update.vm_name, vm_state.counter, &hex::encode(&previous_hash)[..16]);

        unsafe {
            if let Some(ocall_fn) = OCALL_WRITE_VM_ENERGY {
                let vm_name_bytes = update.vm_name.as_bytes();
                ocall_fn(
                    vm_name_bytes.as_ptr(),
                    vm_name_bytes.len(),
                    update.uj_to_add,
                    vm_state.counter,
                    previous_hash.as_ptr(),
                    signature.as_ptr(),
                );
            } else {
                eprintln!("[SGX-STUB] Warning: No OCALL registered for VM energy write");
            }
        }
    }

    drop(vm_chains);

    unsafe {
        *out_len_ptr = 0;
    }

    0
}

#[no_mangle]
pub extern "C" fn ecall_compute_vm_energy_cgroup(
    topo_ptr: *const u8,
    topo_len: usize,
    cgroup_ptr: *const u8,
    cgroup_len: usize,
    hash_ptr: *const u8,
    hash_len: usize,
    out_ptr: *mut u8,
    _out_cap: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    use crate::exporters::qemu::{QemuExporter, VmCgroupSample};

    if topo_ptr.is_null() || cgroup_ptr.is_null() || out_ptr.is_null() || out_len_ptr.is_null() {
        return 1;
    }

    let topo_slice = unsafe { std::slice::from_raw_parts(topo_ptr, topo_len) };
    let cgroup_slice = unsafe { std::slice::from_raw_parts(cgroup_ptr, cgroup_len) };
    let hash_slice = unsafe { std::slice::from_raw_parts(hash_ptr, hash_len) };

    #[cfg(feature = "use_sgx")]
    {
        if !should_use_sgx_enclave() {
            eprintln!("[SGX-RUNNER] Real SGX required, but SGX hardware/enclave is not available");
            return -200;
        }

        println!("[SGX-RUNNER] SGX hardware detected - forwarding cgroup data to real enclave");
        match compute_vm_energy_cgroup_in_sgx(topo_slice, cgroup_slice, hash_slice) {
            Ok(()) => {
                unsafe { *out_len_ptr = 0; }
                return 0;
            }
            Err(code) => {
                eprintln!("[SGX-RUNNER] Real enclave failed ({}) - refusing stub fallback", code);
                return code;
            }
        }
    }

    #[cfg(not(feature = "use_sgx"))]
    {
        eprintln!("[SGX-STUB] Running cgroup-based VM energy computation in userspace");

        let topo_energy_value: String = match serde_json::from_slice(topo_slice) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[SGX-STUB] Failed to deserialize topo_energy_value: {}", e);
                return 2;
            }
        };

        let vm_samples: Vec<VmCgroupSample> = match serde_json::from_slice(cgroup_slice) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[SGX-STUB] Failed to deserialize cgroup samples: {}", e);
                return 3;
            }
        };

        eprintln!("[SGX-STUB] Cgroup mode: {} VMs, {} bytes (vs ~430KB for processes)",
                  vm_samples.len(), cgroup_len);

        let mut exporter = QemuExporter::new();
        let updates = exporter.iterate_cgroup(topo_energy_value, vm_samples);

        eprintln!("[SGX-STUB] Computed {} VM energy updates", updates.len());

        let mut vm_chains = VM_CHAINS.lock().unwrap();

        for update in &updates {
            let vm_state = vm_chains.entry(update.vm_name.clone()).or_insert_with(|| {
                let vm_key = derive_vm_key(&MASTER_KEY, &update.vm_name);
                VmChainState {
                    hmac_key: vm_key,
                    chain_state: [0u8; 32],
                    counter: 0,
                    cumulative_energy_uj: 0,
                }
            });

            vm_state.counter += 1;
            vm_state.cumulative_energy_uj = vm_state
                .cumulative_energy_uj
                .saturating_add(update.uj_to_add);

            let data_to_sign = format!(
                "{}|{}|{}|{}|{}",
                vm_state.counter,
                update.vm_name,
                vm_state.cumulative_energy_uj,
                update.uj_to_add,
                hex::encode(&vm_state.chain_state)
            );

            let signature = {
                let mut mac = HmacSha256::new_from_slice(&vm_state.hmac_key).expect("HMAC key");
                mac.update(data_to_sign.as_bytes());
                let result = mac.finalize().into_bytes();
                let mut sig = [0u8; 32];
                sig.copy_from_slice(&result);
                sig
            };

            let previous_hash = vm_state.chain_state;
            vm_state.chain_state.copy_from_slice(&signature);

            unsafe {
                if let Some(ocall_fn) = OCALL_WRITE_VM_ENERGY {
                    let vm_name_bytes = update.vm_name.as_bytes();
                    ocall_fn(
                        vm_name_bytes.as_ptr(),
                        vm_name_bytes.len(),
                        update.uj_to_add,
                        vm_state.counter,
                        previous_hash.as_ptr(),
                        signature.as_ptr(),
                    );
                }
            }
        }

        drop(vm_chains);
        unsafe { *out_len_ptr = 0; }
        0
    }
}

#[cfg(feature = "use_sgx")]
fn compute_vm_energy_cgroup_in_sgx(
    topo_slice: &[u8],
    cgroup_slice: &[u8],
    hash_slice: &[u8],
) -> Result<(), i32> {

    #[derive(Serialize)]
    struct CgroupComputeRequest {
        operation: String,
        topo_data: String,
        cgroup_data: String,
        hash_data: String,

        tag_key: Option<[u64; 2]>,
        tag_epoch: u32,
        tag_producer: u16,
    }

    let request = CgroupComputeRequest {
        operation: "compute_vm_energy_cgroup".to_string(),
        topo_data: hex::encode(topo_slice),
        cgroup_data: hex::encode(cgroup_slice),
        hash_data: hex::encode(hash_slice),
        #[cfg(feature = "with_ebpf_guard")]
        tag_key: Some({ let (a, b) = crate::sensors::tag_key(); [a, b] }),
        #[cfg(not(feature = "with_ebpf_guard"))]
        tag_key: None,
        #[cfg(feature = "with_ebpf_guard")]
        tag_epoch: crate::sensors::tag_epoch(),
        #[cfg(not(feature = "with_ebpf_guard"))]
        tag_epoch: 0,
        #[cfg(feature = "with_ebpf_kernel_read")]
        tag_producer: 2,
        #[cfg(not(feature = "with_ebpf_kernel_read"))]
        tag_producer: 1,
    };

    let request_json = serde_json::to_string(&request).unwrap();
    let request_size = request_json.len();
    println!("[SGX-RUNNER] Cgroup request size: {} bytes ({:.1} KB) - much smaller!",
             request_size, request_size as f64 / 1024.0);

    let response = send_request_to_enclave(&request_json)?;

    println!("[SGX-RUNNER] Enclave cgroup response: status={}, msg={}", response.status, response.message);

    if response.status == 0 {

        if let Some(output_hex) = response.output_data {
            if let Ok(output_bytes) = hex::decode(&output_hex) {
                #[derive(Deserialize)]
                struct SignedVmUpdate {
                    vm_name: String,
                    uj_value: u64,
                    counter: u64,
                    previous_hash: String,
                    signature: String,
                }

                if let Ok(updates) = serde_json::from_slice::<Vec<SignedVmUpdate>>(&output_bytes) {
                    println!("[SGX-RUNNER] Processing {} signed cgroup updates from enclave", updates.len());

                    unsafe {
                        if let Some(ocall_fn) = OCALL_WRITE_VM_ENERGY {
                            for update in &updates {
                                let prev_hash_bytes = hex::decode(&update.previous_hash).unwrap_or_default();
                                let sig_bytes = hex::decode(&update.signature).unwrap_or_default();

                                let mut prev_hash = [0u8; 32];
                                let mut sig = [0u8; 32];
                                if prev_hash_bytes.len() >= 32 {
                                    prev_hash.copy_from_slice(&prev_hash_bytes[..32]);
                                }
                                if sig_bytes.len() >= 32 {
                                    sig.copy_from_slice(&sig_bytes[..32]);
                                }

                                let vm_name_bytes = update.vm_name.as_bytes();
                                println!("[SGX-RUNNER] Writing VM '{}': {} µJ (counter={})",
                                        update.vm_name, update.uj_value, update.counter);

                                ocall_fn(
                                    vm_name_bytes.as_ptr(),
                                    vm_name_bytes.len(),
                                    update.uj_value,
                                    update.counter,
                                    prev_hash.as_ptr(),
                                    sig.as_ptr(),
                                );
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    } else if response.status == -2 {
        eprintln!("[SGX-RUNNER] Hash verification failed in cgroup computation!");
        Err(-2)
    } else {
        eprintln!("[SGX-RUNNER] Cgroup computation failed: {}", response.message);
        Err(response.status)
    }
}

#[no_mangle]
pub extern "C" fn ecall_initialize_sealed_key() -> i32 {
    println!("[SGX-STUB] ecall_initialize_sealed_key called (userspace stub)");
    0
}

#[no_mangle]
pub extern "C" fn ecall_register_ocall_write_vm_energy(
    ocall_fn: unsafe extern "C" fn(*const u8, usize, u64, u64, *const u8, *const u8) -> i32,
) -> i32 {
    println!("[SGX-STUB] ecall_register_ocall_write_vm_energy called - storing OCALL function");
    unsafe {
        OCALL_WRITE_VM_ENERGY = Some(ocall_fn);
    }
    0
}

#[no_mangle]
pub extern "C" fn ecall_register_ocall_fetch_expected_hash(
    _ocall_fn: unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> i32,
) -> i32 {
    println!("[SGX-STUB] ecall_register_ocall_fetch_expected_hash called (userspace stub)");
    0
}

#[no_mangle]
pub extern "C" fn ecall_register_sealed_storage_ocalls(
    _read_fn: unsafe extern "C" fn(*mut u8, usize) -> i32,
    _write_fn: unsafe extern "C" fn(*const u8, usize) -> i32,
) -> i32 {
    println!("[SGX-STUB] ecall_register_sealed_storage_ocalls called (userspace stub)");
    0
}

#[no_mangle]
#[cfg(feature = "use_sgx")]
pub extern "C" fn ecall_verify_binary_hash(
    pcr_values_ptr: *const u8,
    pcr_values_len: usize,
    ima_log_ptr: *const u8,
    ima_log_len: usize,
    hostname_ptr: *const u8,
    hostname_len: usize,
    deployment_type_ptr: *const u8,
    deployment_type_len: usize,
    immudb_addr_ptr: *const u8,
    immudb_addr_len: usize,
    ca_pem_ptr: *const u8,
    ca_pem_len: usize,
) -> i32 {

    let pcr_values = if pcr_values_ptr.is_null() {
        return -1;
    } else {
        unsafe { std::slice::from_raw_parts(pcr_values_ptr, pcr_values_len) }
    };

    let ima_log = if ima_log_ptr.is_null() {
        ""
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(ima_log_ptr, ima_log_len) }) {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let hostname = if hostname_ptr.is_null() {
        "unknown"
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(hostname_ptr, hostname_len) }) {
            Ok(s) => s,
            Err(_) => "unknown",
        }
    };

    let deployment_from_ptr = if deployment_type_ptr.is_null() {
        "host"
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(deployment_type_ptr, deployment_type_len) }) {
            Ok(s) => s,
            Err(_) => "host",
        }
    };

    let deployment_env = std::env::var("DEPLOYMENT_TYPE").ok()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| s == "vm" || s == "host");
    let deployment_type: &str = deployment_env.as_deref().unwrap_or(deployment_from_ptr);

    let immudb_addr = if immudb_addr_ptr.is_null() {
        "127.0.0.1:3322"
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(immudb_addr_ptr, immudb_addr_len) }) {
            Ok(s) => s,
            Err(_) => "127.0.0.1:3322",
        }
    };

    let ca_pem = if ca_pem_ptr.is_null() {
        ""
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(ca_pem_ptr, ca_pem_len) }) {
            Ok(s) => s,
            Err(_) => "",
        }
    };

    match verify_in_sgx_enclave(pcr_values, ima_log, hostname, deployment_type, immudb_addr, ca_pem) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

#[no_mangle]
#[cfg(not(feature = "use_sgx"))]
pub extern "C" fn ecall_verify_binary_hash(
    _pcr_values_ptr: *const u8,
    _pcr_values_len: usize,
    _ima_log_ptr: *const u8,
    _ima_log_len: usize,
    _hostname_ptr: *const u8,
    _hostname_len: usize,
    _deployment_type_ptr: *const u8,
    _deployment_type_len: usize,
    _immudb_addr_ptr: *const u8,
    _immudb_addr_len: usize,
    _ca_pem_ptr: *const u8,
    _ca_pem_len: usize,
) -> i32 {
    eprintln!("[SGX-STUB] ecall_verify_binary_hash called but SGX not enabled");
    -999
}
