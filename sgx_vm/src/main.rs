use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "use_mbedtls")]
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(feature = "use_mbedtls")]
use mbedtls::ssl::{Config, Context};
#[cfg(feature = "use_mbedtls")]
use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
#[cfg(feature = "use_mbedtls")]
use mbedtls::x509::Certificate;
#[cfg(feature = "use_mbedtls")]
use mbedtls::pk::Pk;
#[cfg(feature = "use_mbedtls")]
use mbedtls::rng::Rdrand;
#[cfg(feature = "use_mbedtls")]
use mbedtls::alloc::List as MbedtlsList;

use sgx_vm::{
    ecall_verify_energy_chain,
    ecall_sign_energy_chain,
    ecall_verify_binary_hash,
    merkle,
    blockchain,
    redis_store,
    checkpoint,
    pure,
};

use sgx_vm::pure::{ResumeDecision, RefusalReason, is_valid_tenant_label};
use sgx_vm::fetch_expected_hash_from_immudb;

#[cfg(feature = "use_mbedtls")]
use sgx_vm::{
    ecall_immudb_login,
    ecall_immudb_insert,
};

#[cfg(feature = "use_mbedtls")]
const ENCLAVE_CERT_PEM: &str = include_str!("../enclave_cert.pem");
#[cfg(feature = "use_mbedtls")]
const ENCLAVE_KEY_PEM: &str = include_str!("../enclave_key.pem");

static mut PREV_CYCLE_AT: Option<std::time::Instant> = None;

static mut ITERATION_COUNT: u64 = 0;
static mut ACCUMULATED_RECORDS: Vec<merkle::EnergyRecord> = Vec::new();
static mut BLOCK_NUMBER: u64 = 0;
static mut LATEST_CHAINED_ROOT: [u8; 32] = [0u8; 32];
static mut STATE_INITIALIZED: bool = false;

static mut CHAIN_RESUME_REFUSED: bool = false;
const BATCH_SIZE: u64 = 100;

static mut GPU_ENERGY_STATE: Option<BTreeMap<String, u64>> = None;

const TIMING_LOG_FILE: &str = "/tmp/sgx_timing.csv";

fn debug_msg(msg: &str) {
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
    let _ = std::io::stderr().flush();
}

fn log_timing(entry: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(TIMING_LOG_FILE)
    {
        let _ = writeln!(file, "{}", entry);
    }
}

fn init_timing_log() {
    if let Ok(mut file) = File::create(TIMING_LOG_FILE) {
        let _ = writeln!(file, "timestamp,event_type,iteration,block_num,parse_ms,chain_verify_ms,energy_calc_ms,iter_total_ms,clone_ms,merkle_ms,pg_connect_ms,pg_insert_ms,batch_total_ms,records,merkle_nodes,block_row_ms,records_ms,merkle_nodes_ms,commit_ms,pg_total_ms");
    }
    debug_msg(&format!("[TIMING] Initialized timing log: {}", TIMING_LOG_FILE));
}

#[derive(Deserialize)]
struct EnclaveRequest {
    operation: String,
    #[serde(flatten)]
    data: Value,
}

#[derive(Serialize)]
struct EnclaveResponse {
    status: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_data: Option<String>,
}

fn main() {

    debug_msg("[SGX-VM-ENCLAVE] STARTING...");
    debug_msg("[SGX-VM-ENCLAVE] Running inside REAL SGX hardware enclave");
    debug_msg("[SGX-VM-ENCLAVE] Memory is encrypted by CPU");
    #[cfg(feature = "use_mbedtls")]
    debug_msg("[SGX-VM-ENCLAVE] Using TLS-encrypted TCP for communication");
    #[cfg(not(feature = "use_mbedtls"))]
    debug_msg("[SGX-VM-ENCLAVE] Using plain TCP (mbedtls not enabled)");
    debug_msg("[SGX-VM-ENCLAVE] PERSISTENT MODE - handles multiple requests");

    #[cfg(feature = "use_mbedtls")]
    match checkpoint::public_anchor_key_hex() {
        Ok(pk) => {
            debug_msg("[SGX-VM-ENCLAVE] ANCHOR PUBLIC KEY (pin this out of band):");
            debug_msg(&format!("[SGX-VM-ENCLAVE] anchor-pubkey-der-hex: {}", pk));
            debug_msg("[SGX-VM-ENCLAVE] verify_redis_gpu.py --pubkey <the value above>");
            debug_msg("[SGX-VM-ENCLAVE] Bound to MRENCLAVE: it changes on every rebuild.");
        }
        Err(e) => {

            debug_msg(&format!(
                "[SGX-VM-ENCLAVE] WARNING: could not derive the anchor public key ({}). \
 Anchors will still be signed, but no one can pin the key, so offline \
 verification degrades to 'internally consistent'.",
                e
            ));
        }
    }

    let args: Vec<String> = std::env::args().collect();
    let bind_addr = if args.len() > 1 {
        let addr = &args[1];

        if !addr.contains(':') {
            format!("{}:0", addr)
        } else {
            addr.clone()
        }
    } else {
        "127.0.0.1:0".to_string()
    };

    debug_msg(&format!("[SGX-VM-ENCLAVE] Binding to {}", bind_addr));

    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] Failed to bind TCP to {}: {}", bind_addr, e));
            return;
        }
    };

    let local_addr = listener.local_addr().unwrap();
    let port = local_addr.port();
    debug_msg(&format!("[SGX-VM-ENCLAVE] TCP server listening on {}", local_addr));

    println!("PORT:{}", port);
    let _ = io::stdout().flush();

    debug_msg("[SGX-VM-ENCLAVE] Waiting for connection...");
    let (tcp_stream, addr) = match listener.accept() {
        Ok((s, a)) => {
            let _ = s.set_nodelay(true);
            debug_msg(&format!("[SGX-VM-ENCLAVE] TCP connection from {}", a));
            (s, a)
        }
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] Accept failed: {}", e));
            return;
        }
    };

    let mut tcp_stream = tcp_stream;

    #[cfg(feature = "use_mbedtls")]
    {
        debug_msg("[SGX-VM-ENCLAVE] Setting up TLS server...");

        let cert_pem = format!("{}\0", ENCLAVE_CERT_PEM);
        let key_pem = format!("{}\0", ENCLAVE_KEY_PEM);

        let cert = match Certificate::from_pem(cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                debug_msg(&format!("[SGX-VM-ENCLAVE] Failed to parse certificate: {:?}", e));
                return;
            }
        };

        let key = match Pk::from_private_key(key_pem.as_bytes(), None) {
            Ok(k) => k,
            Err(e) => {
                debug_msg(&format!("[SGX-VM-ENCLAVE] Failed to parse private key: {:?}", e));
                return;
            }
        };

        let rng = Arc::new(Rdrand);

        let mut cert_list = MbedtlsList::new();
        cert_list.push(cert);
        let cert_list = Arc::new(cert_list);
        let key = Arc::new(key);

        let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
        config.set_rng(rng);
        config.set_authmode(AuthMode::None);
        if let Err(e) = config.push_cert(cert_list, key) {
            debug_msg(&format!("[SGX-VM-ENCLAVE] Failed to set certificate: {:?}", e));
            return;
        }

        let config = Arc::new(config);

        let mut tls_ctx = Context::new(config);

        if let Err(e) = tls_ctx.establish(&mut tcp_stream, None) {
            debug_msg(&format!("[SGX-VM-ENCLAVE] TLS handshake failed: {:?}", e));
            return;
        }

        debug_msg("[SGX-VM-ENCLAVE] TLS connection established");
        debug_msg("[SGX-VM-ENCLAVE] All communication is now encrypted");

        let mut request_count = 0u64;
        loop {
            request_count += 1;
            debug_msg(&format!("[SGX-VM-ENCLAVE] Waiting for TLS request #{}...", request_count));

            match handle_single_tls_request(&mut tls_ctx) {
                Ok(should_continue) => {
                    if !should_continue {
                        debug_msg("[SGX-VM-ENCLAVE] Received shutdown signal");
                        break;
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS connection error: {}", e));
                    break;
                }
            }
        }

        debug_msg(&format!("[SGX-VM-ENCLAVE] Handled {} TLS requests total", request_count - 1));
    }

    #[cfg(not(feature = "use_mbedtls"))]
    {
        debug_msg("[SGX-VM-ENCLAVE] WARNING: Running without TLS encryption!");

        let mut request_count = 0u64;
        loop {
            request_count += 1;
            debug_msg(&format!("[SGX-VM-ENCLAVE] Waiting for request #{}...", request_count));

            match handle_single_request(&mut tcp_stream) {
                Ok(should_continue) => {
                    if !should_continue {
                        debug_msg("[SGX-VM-ENCLAVE] Received shutdown signal");
                        break;
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-VM-ENCLAVE] Connection error: {}", e));
                    break;
                }
            }
        }

        debug_msg(&format!("[SGX-VM-ENCLAVE] Handled {} requests total", request_count - 1));
    }

    debug_msg("[SGX-VM-ENCLAVE] Enclave shutting down");
}

#[cfg(feature = "use_mbedtls")]
fn handle_single_tls_request<T: std::io::Read + std::io::Write>(ctx: &mut Context<T>) -> Result<bool, String> {

    let mut len_buf = [0u8; 4];
    if let Err(e) = ctx.read_exact(&mut len_buf) {

        return Err(format!("TLS read failed: {:?}", e));
    }

    let request_len = u32::from_be_bytes(len_buf) as usize;

    if request_len == 0 {
        return Ok(false);
    }

    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS: Expecting {} bytes of request data", request_len));

    if request_len > 10 * 1024 * 1024 {
        debug_msg("[SGX-VM-ENCLAVE] TLS: Request too large!");
        return Err("Request too large".to_string());
    }

    let mut request_data = vec![0u8; request_len];
    if let Err(e) = ctx.read_exact(&mut request_data) {
        return Err(format!("TLS: Failed to read request: {:?}", e));
    }

    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS: Received {} bytes", request_data.len()));

    let line = match String::from_utf8(request_data) {
        Ok(s) => s,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] TLS: Invalid UTF-8: {}", e));
            let err_response = EnclaveResponse {
                status: -50,
                message: "Invalid UTF-8 in request".to_string(),
                output_data: None,
            };
            send_tls_response(ctx, &err_response);
            return Ok(true);
        }
    };

    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS Request: {}", &line.chars().take(200).collect::<String>()));

    let request: EnclaveRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] TLS: JSON parse error: {}", e));
            let response = EnclaveResponse {
                status: -100,
                message: format!("Failed to parse request: {}", e),
                output_data: None,
            };
            send_tls_response(ctx, &response);
            return Ok(true);
        }
    };

    if request.operation == "shutdown" {
        let response = EnclaveResponse {
            status: 0,
            message: "Shutting down".to_string(),
            output_data: None,
        };
        send_tls_response(ctx, &response);
        return Ok(false);
    }

    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS Operation: {}", request.operation));

    let response = match request.operation.as_str() {
        "get_nonce" => handle_get_nonce(),
        "verify_boot" => handle_verify_boot(&line),
        "verify_chain" => handle_verify_chain(&line),
        "compute_process_energy" => handle_compute_process_energy(&line),
        "db_export" => handle_db_export(&line),
        "gpu_db_export" => handle_gpu_db_export(&line),
        "immudb_login" => handle_immudb_login(),
        "immudb_insert" => handle_immudb_insert(&line),
        _ => EnclaveResponse {
            status: -1000,
            message: format!("Unknown operation: {}", request.operation),
            output_data: None,
        },
    };

    send_tls_response(ctx, &response);
    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS Operation complete, status: {}", response.status));

    Ok(true)
}

#[cfg(feature = "use_mbedtls")]
fn send_tls_response<T: std::io::Read + std::io::Write>(ctx: &mut Context<T>, response: &EnclaveResponse) {
    let response_json = serde_json::to_string(response).unwrap();
    let response_bytes = response_json.as_bytes();
    let len_bytes = (response_bytes.len() as u32).to_be_bytes();

    let _ = ctx.write_all(&len_bytes);
    let _ = ctx.write_all(response_bytes);
    let _ = ctx.flush();
}

#[cfg(not(feature = "use_mbedtls"))]
fn handle_single_request(stream: &mut TcpStream) -> Result<bool, String> {

    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(false);
        }
        return Err(format!("Failed to read length: {}", e));
    }

    let request_len = u32::from_be_bytes(len_buf) as usize;

    if request_len == 0 {
        return Ok(false);
    }

    debug_msg(&format!("[SGX-VM-ENCLAVE] Expecting {} bytes of request data", request_len));

    if request_len > 10 * 1024 * 1024 {
        debug_msg("[SGX-VM-ENCLAVE] Request too large!");
        return Err("Request too large".to_string());
    }

    let mut request_data = vec![0u8; request_len];
    if let Err(e) = stream.read_exact(&mut request_data) {
        return Err(format!("Failed to read request: {}", e));
    }

    debug_msg(&format!("[SGX-VM-ENCLAVE] Received {} bytes", request_data.len()));

    let line = match String::from_utf8(request_data) {
        Ok(s) => s,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] Invalid UTF-8: {}", e));
            let err_response = EnclaveResponse {
                status: -50,
                message: "Invalid UTF-8 in request".to_string(),
                output_data: None,
            };
            send_response(stream, &err_response);
            return Ok(true);
        }
    };

    debug_msg(&format!("[SGX-VM-ENCLAVE] Request: {}", &line.chars().take(200).collect::<String>()));

    let request: EnclaveRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] JSON parse error: {}", e));
            let response = EnclaveResponse {
                status: -100,
                message: format!("Failed to parse request: {}", e),
                output_data: None,
            };
            send_response(stream, &response);
            return Ok(true);
        }
    };

    if request.operation == "shutdown" {
        let response = EnclaveResponse {
            status: 0,
            message: "Shutting down".to_string(),
            output_data: None,
        };
        send_response(stream, &response);
        return Ok(false);
    }

    debug_msg(&format!("[SGX-VM-ENCLAVE] Operation: {}", request.operation));

    let response = match request.operation.as_str() {
        "get_nonce" => handle_get_nonce(),
        "verify_boot" => handle_verify_boot(&line),
        "verify_chain" => handle_verify_chain(&line),
        "compute_process_energy" => handle_compute_process_energy(&line),
        "db_export" => handle_db_export(&line),
        "gpu_db_export" => handle_gpu_db_export(&line),
        "immudb_login" => handle_immudb_login(),
        "immudb_insert" => handle_immudb_insert(&line),
        _ => EnclaveResponse {
            status: -1000,
            message: format!("Unknown operation: {}", request.operation),
            output_data: None,
        },
    };

    send_response(stream, &response);
    debug_msg(&format!("[SGX-VM-ENCLAVE] Operation complete, status: {}", response.status));

    Ok(true)
}

#[cfg(not(feature = "use_mbedtls"))]
fn send_response(stream: &mut TcpStream, response: &EnclaveResponse) {
    let response_json = serde_json::to_string(response).unwrap();
    let response_bytes = response_json.as_bytes();
    let len_bytes = (response_bytes.len() as u32).to_be_bytes();

    let _ = stream.write_all(&len_bytes);
    let _ = stream.write_all(response_bytes);
    let _ = stream.flush();
}

static ISSUED_NONCE: Mutex<Option<[u8; 32]>> = Mutex::new(None);

fn verify_tpm_quote(
    attest: &[u8],
    signature: &[u8],
    pcr_values: &[u8],
    expected_nonce: &[u8],
    ak_pem: &str,
) -> Result<(), String> {
    let rsa_sig = sgx_vm::verify_quote_structure(attest, signature, pcr_values, expected_nonce)?;
    verify_rsa_pkcs1_sha256(ak_pem, attest, rsa_sig)
}

#[cfg(feature = "use_mbedtls")]
fn verify_rsa_pkcs1_sha256(ak_pem: &str, message: &[u8], signature: &[u8]) -> Result<(), String> {
    use sha2::{Digest, Sha256};

    let trimmed = ak_pem.trim();
    let mut pem = if trimmed.starts_with("-----BEGIN") {
        trimmed.to_string()
    } else {
        let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in trimmed.as_bytes().chunks(64) {
            out.push_str(core::str::from_utf8(chunk).map_err(|_| "AK key is not ASCII".to_string())?);
            out.push('\n');
        }
        out.push_str("-----END PUBLIC KEY-----\n");
        out
    };
    pem.push('\0');
    let mut pk = mbedtls::pk::Pk::from_public_key(pem.as_bytes())
        .map_err(|e| format!("AK public key not loadable: {:?}", e))?;
    let digest = Sha256::digest(message);
    pk.verify(mbedtls::hash::Type::Sha256, &digest, signature)
        .map_err(|e| format!("quote signature INVALID: {:?}", e))
}

#[cfg(not(feature = "use_mbedtls"))]
fn verify_rsa_pkcs1_sha256(_ak_pem: &str, _message: &[u8], _signature: &[u8]) -> Result<(), String> {

    Err("built without use_mbedtls - cannot verify the quote signature".to_string())
}

fn handle_get_nonce() -> EnclaveResponse {

    let mut nonce = [0u8; 32];
    #[cfg(not(feature = "use_mbedtls"))]
    {

        let _ = &nonce;
        return EnclaveResponse {
            status: -120,
            message: "built without use_mbedtls - no in-enclave RNG to issue a nonce".to_string(),
            output_data: None,
        };
    }
    #[cfg(feature = "use_mbedtls")]
    {
        use mbedtls::rng::{CtrDrbg, Rdseed};
        use std::sync::Arc as StdArc;
        let entropy = StdArc::new(Rdseed);
        let mut rng = match CtrDrbg::new(entropy, None) {
            Ok(r) => r,
            Err(e) => {
                return EnclaveResponse {
                    status: -120,
                    message: format!("no RNG available inside the enclave: {:?}", e),
                    output_data: None,
                }
            }
        };
        use mbedtls::rng::Random;
        if let Err(e) = rng.random(&mut nonce) {
            return EnclaveResponse {
                status: -120,
                message: format!("RNG failed while issuing a nonce: {:?}", e),
                output_data: None,
            };
        }
    }
    {
        if let Ok(mut slot) = ISSUED_NONCE.lock() {
            *slot = Some(nonce);
        }
        debug_msg("[SGX-VM-QUOTE] issued a fresh single-use nonce for TPM2_Quote");
        EnclaveResponse {
            status: 0,
            message: "nonce issued".to_string(),
            output_data: Some(hex::encode(nonce)),
        }
    }
}

fn handle_verify_boot(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct VerifyBootReq {
        #[allow(dead_code)]
        operation: String,
        pcr_values: String,
        ima_log: String,
        hostname: String,
        deployment_type: String,
        immudb_addr: String,
        ca_pem: String,

        #[serde(default)]
        quote_attest: String,
        #[serde(default)]
        quote_signature: String,
    }

    let request: VerifyBootReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse verify_boot request: {}", e),
                output_data: None,
            };
        }
    };

    debug_msg("[SGX-VM-BOOT] Boot integrity verification inside SGX");
    debug_msg(&format!("[SGX-VM-BOOT] Hostname: {}", request.hostname));
    debug_msg(&format!("[SGX-VM-BOOT] Deployment: {}", request.deployment_type));
    debug_msg(&format!("[SGX-VM-BOOT] IMA log size: {} bytes", request.ima_log.len()));

    let pcr_values = match hex::decode(&request.pcr_values) {
        Ok(v) if v.len() == 96 => v,
        Ok(v) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Invalid PCR values length: {} (expected 96 bytes)", v.len()),
                output_data: None,
            };
        }
        Err(e) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Invalid PCR hex: {}", e),
                output_data: None,
            };
        }
    };

    const ENCLAVE_IMMUD_CA_PEM: &str = include_str!("../../immudb_ca.pem");
    match fetch_expected_hash_from_immudb(
        "ak_pub",
        &request.hostname,
        &request.deployment_type,
        &request.immudb_addr,
        ENCLAVE_IMMUD_CA_PEM,
    ) {
        Ok((ak_pem, _, _, _)) if !ak_pem.is_empty() => {
            let attest = hex::decode(request.quote_attest.trim()).unwrap_or_default();
            let sig = hex::decode(request.quote_signature.trim()).unwrap_or_default();
            if attest.is_empty() || sig.is_empty() {
                debug_msg("[SGX-VM-QUOTE] AK is registered but the node sent no quote");
                return EnclaveResponse {
                    status: -122,
                    message: "an AK is registered for this node, so PCR values must be \
 accompanied by a TPM2_Quote. None was supplied."
                        .to_string(),
                    output_data: None,
                };
            }
            let nonce = match ISSUED_NONCE.lock().ok().and_then(|mut n| n.take()) {
                Some(n) => n,
                None => {
                    debug_msg("[SGX-VM-QUOTE] no nonce outstanding - call get_nonce first");
                    return EnclaveResponse {
                        status: -121,
                        message: "AK registered, so a fresh quote is required, but this enclave \
 has no outstanding nonce. Request get_nonce, then verify_boot."
                            .to_string(),
                        output_data: None,
                    };
                }
            };
            match verify_tpm_quote(&attest, &sig, &pcr_values, &nonce, &ak_pem) {
                Ok(()) => {
                    debug_msg("[SGX-VM-QUOTE] TPM2_Quote verified - PCR values are TPM-signed, \
 bound to this enclave's nonce, and cover sha256:0,7,10");
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-VM-QUOTE] QUOTE REJECTED: {}", e));
                    return EnclaveResponse {
                        status: -123,
                        message: format!("TPM2_Quote verification failed: {}", e),
                        output_data: None,
                    };
                }
            }
        }

        Err(-8) | Ok(_) => {
            debug_msg("[SGX-VM-QUOTE] no AK registered for this node - PCR values are \
 UNAUTHENTICATED (the node asserts them). Register one with \
 scripts/register_ak.sh to make quotes mandatory.");
        }
        Err(code) => {
            debug_msg(&format!(
                "[SGX-VM-QUOTE] could not reach the AK registry (error {}) - refusing rather \
 than assuming no AK is registered",
                code
            ));
            return EnclaveResponse {
                status: -124,
                message: format!(
                    "could not determine whether an AK is registered for this node \
 (ImmuDB lookup failed with {}). Refusing: treating an unreachable \
 registry as 'unregistered' would let a node downgrade itself.",
                    code
                ),
                output_data: None,
            };
        }
    }

    match fetch_expected_hash_from_immudb(
        "parent_host",
        &request.hostname,
        &request.deployment_type,
        &request.immudb_addr,
        ENCLAVE_IMMUD_CA_PEM,
    ) {
        Ok((parent, _, _, _)) if !parent.is_empty() => {
            match fetch_expected_hash_from_immudb(
                "host_attested",
                parent.trim(),
                "host",
                &request.immudb_addr,
                ENCLAVE_IMMUD_CA_PEM,
            ) {
                Ok((state, _, _, _)) if !state.is_empty() => {
                    debug_msg(&format!(
                        "[SGX-VM-HOST] host '{}' attested first (state {}...)",
                        parent.trim(),
                        &state.chars().take(16).collect::<String>()
                    ));
                }
                Err(-8) | Ok(_) => {
                    debug_msg(&format!(
                        "[SGX-VM-HOST] host '{}' has NOT been attested - refusing",
                        parent.trim()
                    ));
                    return EnclaveResponse {
                        status: -125,
                        message: format!(
                            "this guest's host '{}' has no attestation on record. The guest's vTPM, \
 its attestation key and its PCR values are all produced by software on \
 that host, so attesting the guest first would be meaningless.",
                            parent.trim()
                        ),
                        output_data: None,
                    };
                }
                Err(code) => {
                    debug_msg(&format!(
                        "[SGX-VM-HOST] could not check whether host '{}' was attested (error {})",
                        parent.trim(), code
                    ));
                    return EnclaveResponse {
                        status: -126,
                        message: format!(
                            "could not determine whether host '{}' was attested (lookup failed \
 with {}). Refusing rather than assuming it was.",
                            parent.trim(), code
                        ),
                        output_data: None,
                    };
                }
            }
        }
        _ => {
            debug_msg("[SGX-VM-HOST] no parent host registered for this guest - cannot check \
 whether the host beneath it was attested. Register one with \
 scripts/register_parent_host.sh.");
        }
    }

    let result = unsafe {
        ecall_verify_binary_hash(
            pcr_values.as_ptr(),
            pcr_values.len(),
            request.ima_log.as_ptr(),
            request.ima_log.len(),
            request.hostname.as_ptr(),
            request.hostname.len(),
            request.deployment_type.as_ptr(),
            request.deployment_type.len(),
            request.immudb_addr.as_ptr(),
            request.immudb_addr.len(),
            request.ca_pem.as_ptr(),
            request.ca_pem.len(),
        )
    };

    match result {
        0 => {
            debug_msg("[SGX-VM-BOOT] BOOT INTEGRITY VERIFIED");
            EnclaveResponse {
                status: 0,
                message: "Boot integrity verified - binary hash and PCRs match".to_string(),
                output_data: None,
            }
        }
        -6 => EnclaveResponse {
            status: -6,
            message: "HASH MISMATCH - Binary has been tampered!".to_string(),
            output_data: None,
        },
        -7 => EnclaveResponse {
            status: -7,
            message: "PCR0 MISMATCH - Boot process tampered!".to_string(),
            output_data: None,
        },
        -8 => EnclaveResponse {
            status: -8,
            message: "PCR7 MISMATCH - Secure Boot tampered!".to_string(),
            output_data: None,
        },

        -9 => EnclaveResponse {
            status: -9,
            message: "IMA log does not reconcile with PCR10 - the log is edited, truncated, from a \
 different boot, or PCR10 was sampled AFTER the log was read"
                .to_string(),
            output_data: None,
        },
        -4 => EnclaveResponse {
            status: -4,
            message: "Scaphandre binary not found in the TPM-attested portion of the IMA log"
                .to_string(),
            output_data: None,
        },
        -5 => EnclaveResponse {
            status: -5,
            message: "ImmuDB connection failed".to_string(),
            output_data: None,
        },
        _ => EnclaveResponse {
            status: result,
            message: format!("Boot verification failed with code {}", result),
            output_data: None,
        },
    }
}

fn handle_verify_chain(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct VerifyChainReq {
        #[allow(dead_code)]
        operation: String,
        vm_name: String,
        energy_value: u64,
        #[serde(default)]
        energy_delta: u64,
        counter: u64,
        previous_hash: String,
        signature: String,
    }

    let request: VerifyChainReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse verify_chain request: {}", e),
                output_data: None,
            };
        }
    };

    debug_msg(&format!("[SGX-VM-VERIFY] Verifying chain for VM '{}', counter={}",
                       request.vm_name, request.counter));

    let previous_hash = match hex::decode(&request.previous_hash) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return EnclaveResponse {
                status: -102,
                message: "Invalid previous_hash (must be 64 hex chars)".to_string(),
                output_data: None,
            };
        }
    };

    let signature = match hex::decode(&request.signature) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return EnclaveResponse {
                status: -103,
                message: "Invalid signature (must be 64 hex chars)".to_string(),
                output_data: None,
            };
        }
    };

    let result = unsafe {
        ecall_verify_energy_chain(
            request.vm_name.as_ptr(),
            request.vm_name.len(),
            request.energy_value,
            request.energy_delta,
            request.counter,
            previous_hash.as_ptr(),
            signature.as_ptr(),
        )
    };

    match result {
        0 => EnclaveResponse {
            status: 0,
            message: format!("Chain verified successfully (counter={})", request.counter),
            output_data: None,
        },
        1 => EnclaveResponse {
            status: 1,
            message: "Chain initialized (first verification)".to_string(),
            output_data: None,
        },
        2 => EnclaveResponse {
            status: 2,
            message: "Skipped (same counter, host not updated)".to_string(),
            output_data: None,
        },
        -2 => EnclaveResponse {
            status: -2,
            message: "TAMPERING DETECTED - signature mismatch!".to_string(),
            output_data: None,
        },
        -3 => EnclaveResponse {
            status: -3,
            message: "REPLAY/ROLLBACK ATTACK - counter discontinuity!".to_string(),
            output_data: None,
        },
        -4 => EnclaveResponse {
            status: -4,
            message: "FORK ATTACK - previous hash mismatch!".to_string(),
            output_data: None,
        },
        _ => EnclaveResponse {
            status: result,
            message: format!("Chain verification failed with code {}", result),
            output_data: None,
        },
    }
}

fn handle_compute_process_energy(_json: &str) -> EnclaveResponse {
    EnclaveResponse {
        status: -107,
        message: "compute_process_energy is REFUSED: per-process attribution cannot \
 conserve energy one process at a time. Use db_export, which splits \
 the delta across all processes with the verified attribute_by_weight."
            .to_string(),
        output_data: None,
    }
}

fn get_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();

    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut year = 1970;
    let mut remaining_days = days_since_epoch as i64;

    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_months = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days in days_in_months.iter() {
        if remaining_days < *days as i64 {
            break;
        }
        remaining_days -= *days as i64;
        month += 1;
    }
    let day = remaining_days + 1;

    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            year, month, day, hours, minutes, seconds)
}

fn handle_db_export(json: &str) -> EnclaveResponse {
    let iter_start = std::time::Instant::now();

    #[derive(Deserialize)]
    struct DbExportReq {
        #[allow(dead_code)]
        operation: String,
        vm_name: String,
        energy_uj: u64,
        counter: u64,
        previous_hash: String,
        signature: String,
        energy_delta: u64,
        processes: Vec<(u32, u64)>,
        #[allow(dead_code)]
        session_id: Option<String>,
    }

    let parse_start = std::time::Instant::now();
    let request: DbExportReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse db_export request: {}", e),
                output_data: None,
            };
        }
    };
    let parse_time = parse_start.elapsed().as_secs_f64() * 1000.0;

    let current_iter = unsafe { ITERATION_COUNT + 1 };
    debug_msg(&format!("[SGX-VM-DB] Processing {} processes for VM '{}' (iteration {})",
                       request.processes.len(), request.vm_name, current_iter));

    let chain_verify_start = std::time::Instant::now();
    let previous_hash = match hex::decode(&request.previous_hash) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return EnclaveResponse {
                status: -102,
                message: "Invalid previous_hash".to_string(),
                output_data: None,
            };
        }
    };

    let signature = match hex::decode(&request.signature) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return EnclaveResponse {
                status: -103,
                message: "Invalid signature".to_string(),
                output_data: None,
            };
        }
    };

    let verify_result = unsafe {
        ecall_verify_energy_chain(
            request.vm_name.as_ptr(),
            request.vm_name.len(),
            request.energy_uj,
            request.energy_delta,
            request.counter,
            previous_hash.as_ptr(),
            signature.as_ptr(),
        )
    };

    if verify_result < 0 {
        return EnclaveResponse {
            status: verify_result,
            message: format!("Chain verification failed: {}", verify_result),
            output_data: None,
        };
    }

    if verify_result == 2 {
        return EnclaveResponse {
            status: 2,
            message: "Skipped (same counter, host not updated)".to_string(),
            output_data: None,
        };
    }

    let chain_verify_time = chain_verify_start.elapsed().as_secs_f64() * 1000.0;

    debug_msg(&format!("[SGX-VM-DB] Chain verified (result={})", verify_result));

    let energy_calc_start = std::time::Instant::now();

    if request.processes.len() >= 0xFFFF_FFFF {
        return EnclaveResponse {
            status: -104,
            message: format!("process list too large: {}", request.processes.len()),
            output_data: None,
        };
    }

    let mut buckets: Vec<(u32, u64, bool)> = request
        .processes
        .iter()
        .map(|(pid, ticks)| (*pid, *ticks, false))
        .collect();

    if buckets.iter().all(|(_, ticks, _)| *ticks == 0) {
        buckets.push((0, 1, true));
        debug_msg(&format!(
            "[SGX-VM-DB] {} uJ burned with no CPU activity to attribute it to - recorded against pid 0",
            request.energy_delta
        ));
    }

    let weights: Vec<u64> = buckets.iter().map(|(_, w, _)| *w).collect();
    let shares = match pure::attribute_by_weight(request.energy_delta, &weights) {
        Some(s) => s,
        None => {

            return EnclaveResponse {
                status: -105,
                message: "attribution failed: weights sum to zero".to_string(),
                output_data: None,
            };
        }
    };

    let attributed: u64 = shares.iter().fold(0u64, |a, s| a.saturating_add(*s));
    if attributed != request.energy_delta {
        return EnclaveResponse {
            status: -106,
            message: format!(
                "conservation violated: shares sum to {} but delta is {}",
                attributed, request.energy_delta
            ),
            output_data: None,
        };
    }

    let now = std::time::Instant::now();
    let cycle_interval_s = unsafe {
        let dt = PREV_CYCLE_AT
            .map(|prev| now.duration_since(prev).as_secs_f64())
            .unwrap_or(0.0);
        PREV_CYCLE_AT = Some(now);
        dt
    };

    let mut results: Vec<(u32, u64)> = Vec::new();
    let timestamp = get_timestamp();

    for (i, (pid, ticks, is_placeholder)) in buckets.into_iter().enumerate() {
        let out_energy = shares[i];
        if out_energy == 0 {
            continue;
        }
        results.push((pid, out_energy));

        let cpu_time_seconds = if is_placeholder { 0.0 } else { ticks as f64 / 100.0 };
        let energy_joules = out_energy as f64 / 1_000_000.0;

        let power_watts = if cycle_interval_s > 0.0 {
            energy_joules / cycle_interval_s
        } else {
            0.0
        };

        unsafe {
            ACCUMULATED_RECORDS.push(merkle::EnergyRecord::new(
                pid,
                cpu_time_seconds,
                energy_joules,
                power_watts,
                request.vm_name.clone(),
                timestamp.clone(),
            ));
        }
    }
    let energy_calc_time = energy_calc_start.elapsed().as_secs_f64() * 1000.0;

    unsafe {
        ITERATION_COUNT += 1;
    }

    let current_iter = unsafe { ITERATION_COUNT };
    let accumulated_count = unsafe { ACCUMULATED_RECORDS.len() };

    let iter_elapsed = iter_start.elapsed().as_secs_f64() * 1000.0;
    debug_msg(&format!("[TIMING-VM] Iter {}: parse={:.2}ms, chain_verify={:.2}ms, energy_calc={:.2}ms, total={:.2}ms",
                       current_iter, parse_time, chain_verify_time, energy_calc_time, iter_elapsed));

    debug_msg(&format!("[SGX-VM-DB] Calculated energy for {} processes (iteration {}/{})",
                       results.len(), current_iter, BATCH_SIZE));
    debug_msg(&format!("[SGX-VM-DB] Total accumulated: {} records", accumulated_count));

    if current_iter == BATCH_SIZE {
        debug_msg(&format!("[SGX-VM-DB] Batch size reached! Creating block with {} records...", accumulated_count));

        const REDIS_CA_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIFBzCCAu+gAwIBAgIUClqKfzeZ5MXU0+ugyLSnJWQGLfgwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIUmVkaXMgQ0EwHhcNMjYwNDA0MDI0MDQ5WhcNMzYwNDAx
MDI0MDQ5WjATMREwDwYDVQQDDAhSZWRpcyBDQTCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBALdxqTgMyMjhtfbOHQp7XIT8+GP0hGkNwANCxkt4P/xdBikt
K6BtykH7eXP59KhSij4pi5pAC5TpOb+fysFfu/VWL4Et4fVzusTXyKc7zhznScAv
gpNk1zzRTVH0oNlS18noc12ZBC3/U8ADAJGSFSgkVzwpsGuw0hivfVcvGh5+iyL3
fuUeh367a9ITmwYAfXgqjXxSURA7/Y7NYUJt0SepZUL/D2kiIEA1lB7I6LbadifU
Ydg2Fw9WoUAgn4nUNifFUu8KP+uEn64ThnjI77bA7tzf45xHKodwIyNZ6tL6lbYF
PrI6UQ3dMaw30vojC7XV0lqQLUM6e/GvXvHESanaYZ5vf23esrVZuRVifjgdbcGb
U1QX0KoT+Gn+TWdCyXn8AUmFzG9q8fYH89os8Ie2sPfJJJphN25y7EhqLDAUwfH2
rRX6c3bOp6zHDrRdcbSbnAwYd8wIdXWG7VkBwz5N8vKamnCR73PcRIOX2AyBcQs9
Lv2mlpyo8K5TFf7g/JuNG7nOrO9g4oYJOyCieJNskzmtXsOMxGK5pb1tXFIE1xwH
o3+o3Ds7+N+iQ1f0bsEm5orLeV/QAGFkhaviX6qGMvMopTlxXikcqEBG0fU2Lely
odu8m0gQBmoG/6YxknhxadJTUhsngAVtuX7fSPQ0Gz8+GLSKoyTxXcGOLMGDAgMB
AAGjUzBRMB0GA1UdDgQWBBQ9M3YTu7STyGREcKYb9eGxFNPMqDAfBgNVHSMEGDAW
gBQ9M3YTu7STyGREcKYb9eGxFNPMqDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4ICAQAYOlFjOa5M1gmUAZC6AQcvTckTXO8Z2Y8HWMw8+r80gYN4Z1x6
mhc5ss08HZRQuisresOykVIKTbipdwz7KK0JAdRy4DfAx/IFSfu6ZP5J3/9FtJ1j
qlowgCPbr5v3nuCpwIiBNSSYVGCL0/K5ch6+YdGV4RnTxoaFQYpRsLfxCZimUjMR
HZ/ez4PuesSygCOIDyRnXW8e5LIpd9eTOr7LQLvwpt+wPv5nGd/DD1jm6CCRUyk+
hHsPwyou/Ik49Tr0TJGrz3BEfWFRtO+CkK+S2cyc6JecGQpvvp+XyaT8XUluyhgH
zf9vQNXhfwLtEnKMkm/d7VFQMVWroktWKnfW/HAH5Z/9urL4E733sXvZ6Iy3/5Jz
is0ZXIg8V/vMdq151XnpjzNV7X5fmwhZcHwkpqeYsxtjIJNUcwgkxtM4nHdhzQwF
oU2XMttjEKi25j4+A1ScErAXTh/1LIkY0urGzdefeDAjDiFRgXSNQQ1u/BQTfxr3
XVgS3rH7bStRstcINlcRN3/KCYL5XX7uQDOrGcFCeOsUWFRkPuA9GnvMAvbrRMjG
7PWWo8Hc8yC/SmueueJTPnSF9MfSuVwwz4nmteibDEh+30hYaImqswOXHVXmOLIh
0KkPerovsWDDVHnn5+Ze2ZQNl9QjT3gOjns75gZXHbZOCN1kgadTVqjfWQ==
-----END CERTIFICATE-----"#;

        const REDIS_USER: &str = "sgx";
        const REDIS_PASS: &str = "changeme";

        let needs_init = unsafe { !STATE_INITIALIZED };
        if needs_init {
            debug_msg("[SGX-VM-DB] First batch - checking Redis for existing chain state...");
            let init_config = redis_store::RedisConfig::new_with_tls_auth(
                "192.168.122.1", 6379, REDIS_CA_CERT, REDIS_USER, REDIS_PASS
            );
            match redis_store::RedisConnection::connect(init_config) {
                Ok(mut init_conn) => {
                    match init_conn.get_latest_block_state(&request.vm_name) {
                        Ok(Some((block_num, chained_root))) => {
                            debug_msg(&format!("[SGX-VM-DB] Resuming from Redis state: block_number={}, chained_root={}...",
                                              block_num, hex::encode(&chained_root[..8])));
                            unsafe {
                                BLOCK_NUMBER = block_num + 1;
                                LATEST_CHAINED_ROOT = chained_root;
                                STATE_INITIALIZED = true;
                            }
                        }
                        Ok(None) => {
                            debug_msg("[SGX-VM-DB] No existing state found in Redis - starting fresh");
                            unsafe { STATE_INITIALIZED = true; }
                        }
                        Err(e) => {
                            debug_msg(&format!("[SGX-VM-DB] Failed to retrieve state from Redis: {:?}", e));

                            unsafe { STATE_INITIALIZED = true; }
                        }
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-VM-DB] Failed to connect to Redis for state init: {:?}", e));

                }
            }
        }

        let batch_start = std::time::Instant::now();
        let records: Vec<merkle::EnergyRecord> = unsafe { ACCUMULATED_RECORDS.clone() };
        let block_num = unsafe { BLOCK_NUMBER };
        let prev_root = unsafe { LATEST_CHAINED_ROOT };
        let clone_time = batch_start.elapsed().as_secs_f64() * 1000.0;

        let merkle_start = std::time::Instant::now();
        let block = blockchain::Block::new(
            block_num,
            request.vm_name.clone(),
            prev_root,
            records,
            timestamp,
        );
        let merkle_time = merkle_start.elapsed().as_secs_f64() * 1000.0;

        debug_msg(&format!("[TIMING-VM] Block creation: clone={:.2}ms, merkle_tree={:.2}ms", clone_time, merkle_time));
        debug_msg(&format!("[SGX-VM-DB] Block {} created:", block.block_number));
        debug_msg(&format!("[SGX-VM-DB] Merkle root: {}...", &block.merkle_root_hex()[..16]));
        debug_msg(&format!("[SGX-VM-DB] Chained root: {}...", &block.chained_root_hex()[..16]));
        debug_msg(&format!("[SGX-VM-DB] Records: {}", block.record_count));

        let redis_connect_start = std::time::Instant::now();

        let redis_config = redis_store::RedisConfig::new_with_tls_auth(
            "192.168.122.1",
            6379,
            REDIS_CA_CERT,
            REDIS_USER,
            REDIS_PASS
        );

        match redis_store::RedisConnection::connect(redis_config) {
            Ok(mut redis_conn) => {
                let redis_connect_time = redis_connect_start.elapsed().as_secs_f64() * 1000.0;
                let redis_insert_start = std::time::Instant::now();
                match redis_conn.insert_block(&block) {
                    Ok(block_id) => {
                        let redis_insert_time = redis_insert_start.elapsed().as_secs_f64() * 1000.0;
                        let batch_total = batch_start.elapsed().as_secs_f64() * 1000.0;
                        debug_msg(&format!("[TIMING-VM] Redis: connect={:.2}ms, insert={:.2}ms", redis_connect_time, redis_insert_time));
                        debug_msg(&format!("[TIMING-VM] BATCH TOTAL: {:.2}ms (clone={:.2}, merkle={:.2}, redis_connect={:.2}, redis_insert={:.2})",
                                          batch_total, clone_time, merkle_time, redis_connect_time, redis_insert_time));
                        debug_msg(&format!("[SGX-VM-DB] Block inserted to Redis (id={})", block_id));

                        unsafe {
                            BLOCK_NUMBER += 1;
                            LATEST_CHAINED_ROOT = block.chained_root;
                        }
                    }
                    Err(e) => {
                        debug_msg(&format!("[SGX-VM-DB] Failed to insert block to Redis: {:?}", e));
                    }
                }
            }
            Err(e) => {
                debug_msg(&format!("[SGX-VM-DB] Failed to connect to Redis: {:?}", e));
            }
        }

        unsafe {
            ITERATION_COUNT = 0;
            ACCUMULATED_RECORDS.clear();
        }
    }

    let output = serde_json::to_string(&results).unwrap_or_default();

    EnclaveResponse {
        status: 0,
        message: format!("Processed {} processes, {} with energy",
                        request.processes.len(), results.len()),
        output_data: Some(output),
    }
}

fn gpu_energy_state_mut() -> &'static mut BTreeMap<String, u64> {
    unsafe {
        if GPU_ENERGY_STATE.is_none() {
            GPU_ENERGY_STATE = Some(BTreeMap::new());
        }
        GPU_ENERGY_STATE.as_mut().expect("GPU energy state initialized")
    }
}

fn extract_container_id_from_cgroup(content: &str) -> Option<String> {
    for line in content.lines() {
        let path = line.rsplit(':').next().unwrap_or(line);
        for seg in path.split('/') {
            let s = seg.strip_suffix(".scope").unwrap_or(seg);
            let candidate = s.rsplit('-').next().unwrap_or(s);
            if candidate.len() >= 12 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(candidate.chars().take(12).collect());
            }
            if seg.len() >= 32 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(seg.chars().take(12).collect());
            }
        }
    }
    None
}

fn extract_vm_name_from_cgroup(content: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for line in content.lines() {
        let path = line.rsplit(':').next().unwrap_or(line);
        let segs: Vec<&str> = path.split('/').collect();
        for (i, seg) in segs.iter().enumerate() {

            if i == 0 || segs[i - 1] != "machine.slice" {
                continue;
            }

            let decoded = seg.replace("\\x2d", "-");
            let without_scope = match decoded.strip_suffix(".scope") {
                Some(s) => s,
                None => continue,
            };
            let name = if let Some(rest) = without_scope.strip_prefix("machine-qemu-") {

                rest.splitn(2, '-').nth(1).unwrap_or(rest).to_string()
            } else if let Some(rest) = without_scope.strip_prefix("vm-") {
                rest.to_string()
            } else {
                continue;
            };

            if !is_valid_tenant_label(name.as_bytes()) {
                continue;
            }
            found = Some(name);
        }
    }
    found
}

fn resolve_gpu_owner(cgroup: &str, node_id: &str) -> String {
    if let Some(vm) = extract_vm_name_from_cgroup(cgroup) {
        return format!("vm:{}", vm);
    }
    if let Some(ctr) = extract_container_id_from_cgroup(cgroup) {
        return format!("ctr:{}", ctr);
    }
    format!("node:{}", node_id)
}

const GPU_BATCH_SIZE: u64 = 100;

fn handle_gpu_db_export(json: &str) -> EnclaveResponse {
    let iter_start = std::time::Instant::now();

    #[derive(Deserialize)]
    struct GpuProcSample {
        pid: u32,
        util: u64,
        cgroup: String,
    }
    #[derive(Deserialize)]
    struct GpuTagReq {
        energy_uj: u64,
        timestamp_ns: u64,
        hash: u64,
    }
    #[derive(Deserialize)]
    struct GpuGroup {
        gpu_index: u32,

        #[serde(default)]
        gpu_uuid: String,
        energy_uj: u64,
        procs: Vec<GpuProcSample>,
        #[serde(default)]
        tag: Option<GpuTagReq>,
    }
    #[derive(Deserialize)]
    struct GpuDbExportReq {
        #[allow(dead_code)]
        operation: String,
        node_id: String,
        gpus: Vec<GpuGroup>,

        #[serde(default)]
        immudb_addr: String,
        #[serde(default)]
        deployment_type: String,

        #[serde(default)]
        tag_key: Option<[u64; 2]>,
        #[serde(default)]
        tag_epoch: u32,
    }

    let parse_start = std::time::Instant::now();
    let request: GpuDbExportReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse gpu_db_export request: {}", e),
                output_data: None,
            };
        }
    };
    let parse_ms = parse_start.elapsed().as_secs_f64() * 1000.0;

    if !is_valid_tenant_label(request.node_id.as_bytes()) {
        return EnclaveResponse {
            status: -102,
            message: "node_id is not a valid tenant label".to_string(),
            output_data: None,
        };
    }

    let current_iter = unsafe { ITERATION_COUNT + 1 };
    debug_msg(&format!(
        "[SGX-VM-GPU] Processing {} GPU group(s) for node '{}' (iteration {})",
        request.gpus.len(),
        request.node_id,
        current_iter
    ));

    let timestamp = get_timestamp();
    let mut results: Vec<(String, u64)> = Vec::new();
    let mut node_energy_uj: u64 = 0;
    let mut node_delta: u64 = 0;

    let attrib_start = std::time::Instant::now();

    {
        let mut seen: Vec<u32> = Vec::with_capacity(request.gpus.len());
        for gpu in &request.gpus {
            if seen.contains(&gpu.gpu_index) {
                debug_msg(&format!(
                    "[SGX-VM-GPU] duplicate gpu_index {} in request - rejecting",
                    gpu.gpu_index
                ));
                return EnclaveResponse {
                    status: -103,
                    message: format!("duplicate gpu_index {} in request", gpu.gpu_index),
                    output_data: None,
                };
            }
            seen.push(gpu.gpu_index);
        }
    }

    let mut tag_enforced = false;

    if !request.immudb_addr.is_empty() {
        const BIND_CA_PEM: &str = include_str!("../../immudb_ca.pem");
        static BINDINGS: Mutex<Option<BTreeMap<String, bool>>> = Mutex::new(None);

        let lookup = |key: &str| -> bool {
            matches!(
                fetch_expected_hash_from_immudb(
                    key,
                    &request.node_id,
                    &request.deployment_type,
                    &request.immudb_addr,
                    BIND_CA_PEM,
                ),
                Ok((ref h, _, _, _)) if !h.is_empty()
            )
        };
        let cached_or = |key: String, f: &dyn Fn(&str) -> bool| -> bool {
            if let Ok(c) = BINDINGS.lock() {
                if let Some(v) = c.as_ref().and_then(|m| m.get(&key).copied()) {
                    return v;
                }
            }
            let v = f(&key);
            if let Ok(mut c) = BINDINGS.lock() {
                c.get_or_insert_with(BTreeMap::new).insert(key, v);
            }
            v
        };

        let enforced = cached_or("gpu_binding_enforced".to_string(), &lookup);

        tag_enforced = cached_or("gpu_tag_enforced".to_string(), &lookup);

        for gpu in &request.gpus {
            let uuid_key: String = gpu.gpu_uuid.chars().take(48).collect();
            let bound = cached_or(format!("gpu:{}", uuid_key), &lookup);
            if !bound && enforced {
                debug_msg(&format!(
                    "[SGX-VM-GPU] gpu{} {} is NOT bound to '{}' - refusing",
                    gpu.gpu_index, uuid_key, request.node_id
                ));
                return EnclaveResponse {
                    status: -13,
                    message: format!(
                        "GPU {} is not registered to node '{}'. Under passthrough the host chooses \
 which physical card a node sees, so an unbound device means this energy \
 would be attributed to a tenant that may not have burned it.",
                        uuid_key, request.node_id
                    ),
                    output_data: None,
                };
            }
            if !bound {
                debug_msg(&format!(
                    "[SGX-VM-GPU] gpu{} {} has no registered binding to '{}' - which physical \
 card this is remains UNVERIFIED (scripts/register_gpu_binding.sh)",
                    gpu.gpu_index, uuid_key, request.node_id
                ));
            } else {
                debug_msg(&format!(
                    "[SGX-VM-GPU] gpu{} {} bound to '{}'",
                    gpu.gpu_index, uuid_key, request.node_id
                ));
            }
        }
    }

    let mut untagged_gpus: usize = 0;

    for gpu in &request.gpus {

        if let Some(t) = &gpu.tag {

            let (k0, k1) = match request.tag_key {
                Some([a, b]) => (a, b),
                None => {
                    return EnclaveResponse {

                        status: -127,
                        message: format!(
                            "gpu{} presented an integrity tag but no SipTag key was supplied - \
 the tag cannot be checked, so it is not evidence",
                            gpu.gpu_index
                        ),
                        output_data: None,
                    };
                }
            };
            let expected = pure::siptag(
                k0, k1,
                t.energy_uj, t.timestamp_ns, gpu.gpu_index, pure::TAG_PRODUCER_GPU,
                pure::SIPTAG_VERSION, pure::SIPTAG_PRODUCER_GPU_NVML, request.tag_epoch,
            );
            let tag_ok = pure::admit_measurement_tag(t.hash, expected).is_some();
            if !tag_ok || t.energy_uj != gpu.energy_uj {
                debug_msg(&format!(
                    "[SGX-VM-GPU] GPU TAG VERIFICATION FAILED gpu{} (fwd {} vs tagged {}, hash {})",
                    gpu.gpu_index, gpu.energy_uj, t.energy_uj,
                    if expected == t.hash { "ok" } else { "MISMATCH" }
                ));
                return EnclaveResponse {
                    status: -102,
                    message: format!("GPU tag verification failed for gpu{}", gpu.gpu_index),
                    output_data: None,
                };
            }
            debug_msg(&format!("[SGX-VM-GPU] GPU tag verified gpu{} ({} uJ)", gpu.gpu_index, t.energy_uj));
        } else {

            if tag_enforced {
                debug_msg(&format!(
                    "[SGX-VM-GPU] gpu{} carries NO integrity tag while gpu_tag_enforced is set",
                    gpu.gpu_index
                ));
                return EnclaveResponse {

                    status: -105,
                    message: format!(
                        "gpu{} sent no eBPF integrity tag while enforcement is provisioned for \
 node '{}'. Energy with no tag has no evidence of kernel origin.",
                        gpu.gpu_index, request.node_id
                    ),
                    output_data: None,
                };
            }
            untagged_gpus += 1;
        }

        node_energy_uj = node_energy_uj.saturating_add(gpu.energy_uj);

        let uuid_key: String = gpu.gpu_uuid.chars().take(48).collect();

        let uuid_tag: String = uuid_key
            .trim_start_matches("GPU-")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(8)
            .collect();
        let state_key = format!("{}:idx{}:{}", request.node_id, gpu.gpu_index, uuid_key);
        let delta = {
            let states = gpu_energy_state_mut();
            let previous = states.get(&state_key).copied();
            let d = match previous {
                Some(last) if gpu.energy_uj >= last => gpu.energy_uj - last,
                Some(last) => {
                    debug_msg(&format!(
                        "[SGX-VM-GPU] gpu{} counter went backwards ({} -> {}): reset/rollback, delta=0",
                        gpu.gpu_index, last, gpu.energy_uj
                    ));
                    0
                }
                None => {

                    debug_msg(&format!(
                        "[SGX-VM-GPU] gpu{} first sample for '{}': baseline set, delta=0",
                        gpu.gpu_index, state_key
                    ));
                    0
                }
            };

            let baseline = previous.map_or(gpu.energy_uj, |last| last.max(gpu.energy_uj));
            states.insert(state_key, baseline);
            d
        };
        node_delta = node_delta.saturating_add(delta);
        if delta == 0 {
            continue;
        }

        const MAX_UJ_PER_CYCLE: u64 = 400 * 10 * 1_000_000;
        let bracketed = delta <= MAX_UJ_PER_CYCLE;
        if !bracketed {
            debug_msg(&format!(
                "[SGX-VM-GPU] gpu{} delta {} uJ exceeds one cycle's worth ({}) - the device went \
 unreported and this energy cannot be bracketed; recording it as unattributed \
 rather than charging it to whoever is running now",
                gpu.gpu_index, delta, MAX_UJ_PER_CYCLE
            ));
        }

        let mut buckets: Vec<(String, u64, u32)> = Vec::new();
        for p in &gpu.procs {
            if !bracketed {
                break;
            }
            if p.util == 0 {
                continue;
            }

            let util = p.util.min(100);
            let owner = resolve_gpu_owner(&p.cgroup, &request.node_id);

            buckets.push((
                format!("pid:{}@{}@gpu{}:{}", p.pid, owner, gpu.gpu_index, uuid_tag),
                util,
                p.pid,
            ));
        }

        let mut total_util: u64 = buckets.iter().map(|(_, u, _)| *u).sum();
        if total_util == 0 {
            let kind = if bracketed { "idle" } else { "unattributed" };
            buckets.push((
                format!("pid:0@{}@gpu{}:{}", kind, gpu.gpu_index, uuid_tag),
                1,
                0,
            ));
            total_util = 1;
            debug_msg(&format!(
                "[SGX-VM-GPU] gpu{} burned {} uJ with no attributable process - recorded as {}",
                gpu.gpu_index, delta, kind
            ));
        }

        let weights: Vec<u64> = buckets.iter().map(|(_, util, _)| *util).collect();
        let shares = match pure::attribute_by_weight(delta, &weights) {
            Some(s) => s,
            None => continue,
        };
        debug_assert_eq!(shares.iter().sum::<u64>(), delta);

        for (i, (label, util, pid)) in buckets.into_iter().enumerate() {
            let out_energy = shares[i];
            if out_energy == 0 {
                continue;
            }
            results.push((label.clone(), out_energy));
            let energy_joules = out_energy as f64 / 1_000_000.0;
            unsafe {
                ACCUMULATED_RECORDS.push(merkle::EnergyRecord::new(
                    pid,
                    util as f64,
                    energy_joules,
                    0.0,
                    label,
                    timestamp.clone(),
                ));
            }
        }
    }
    let attrib_ms = attrib_start.elapsed().as_secs_f64() * 1000.0;

    if untagged_gpus > 0 {
        debug_msg(&format!(
            "[SGX-VM-GPU] {}/{} GPU readings carried NO integrity tag (gpu_tag_enforced not \
 provisioned for '{}') - their kernel origin is UNVERIFIED",
            untagged_gpus, request.gpus.len(), request.node_id
        ));
    }

    let chain_tenant = format!("gpu:{}", request.node_id);
    let mut chain_counter: u64 = 0;
    let mut chain_sig = [0u8; 32];
    let mut chain_prev = [0u8; 32];
    let sign_start = std::time::Instant::now();
    let sign_result = unsafe {
        ecall_sign_energy_chain(
            chain_tenant.as_ptr(),
            chain_tenant.len(),
            node_energy_uj,
            node_delta,
            &mut chain_counter as *mut u64,
            chain_sig.as_mut_ptr(),
            chain_prev.as_mut_ptr(),
        )
    };
    if sign_result < 0 {
        return EnclaveResponse {
            status: sign_result,
            message: format!("GPU chain signing failed: {}", sign_result),
            output_data: None,
        };
    }
    let chain_sign_ms = sign_start.elapsed().as_secs_f64() * 1000.0;
    debug_msg(&format!(
        "[SGX-VM-GPU] Chain signed (counter={}, node_delta={} uJ, sig={}...)",
        chain_counter,
        node_delta,
        hex::encode(&chain_sig[..8])
    ));

    unsafe {
        ITERATION_COUNT += 1;
    }
    let current_iter = unsafe { ITERATION_COUNT };
    let accumulated = unsafe { ACCUMULATED_RECORDS.len() };

    let mut flush_ms = 0.0_f64;
    if current_iter == GPU_BATCH_SIZE {
        let flush_start = std::time::Instant::now();
        flush_gpu_block_to_redis(&request.node_id, &timestamp);
        flush_ms = flush_start.elapsed().as_secs_f64() * 1000.0;
    }

    let iter_total_ms = iter_start.elapsed().as_secs_f64() * 1000.0;
    debug_msg(&format!(
        "[SGX-VM-GPU] Attributed {} container row(s), accumulated {} (iter {}/{}), {:.2}ms",
        results.len(),
        accumulated,
        current_iter,
        GPU_BATCH_SIZE,
        iter_total_ms
    ));

    debug_msg(&format!(
        "[TIMING] gpu_iter #{}: parse={:.3} attribution={:.3} chain_sign={:.3} flush={:.3} total={:.3} ms (records={})",
        current_iter, parse_ms, attrib_ms, chain_sign_ms, flush_ms, iter_total_ms, results.len()
    ));

    let output = serde_json::to_string(&results).unwrap_or_default();
    EnclaveResponse {
        status: 0,
        message: format!(
            "GPU: attributed {} container rows across {} GPU(s)",
            results.len(),
            request.gpus.len()
        ),
        output_data: Some(output),
    }
}

fn flush_gpu_block_to_redis(tenant: &str, timestamp: &str) {

    if unsafe { CHAIN_RESUME_REFUSED } {
        debug_msg(
            "[SGX-VM-GPU] chain resume was refused for this tenant; not extending the chain",
        );
        return;
    }

    const REDIS_CA_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIFBzCCAu+gAwIBAgIUClqKfzeZ5MXU0+ugyLSnJWQGLfgwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIUmVkaXMgQ0EwHhcNMjYwNDA0MDI0MDQ5WhcNMzYwNDAx
MDI0MDQ5WjATMREwDwYDVQQDDAhSZWRpcyBDQTCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBALdxqTgMyMjhtfbOHQp7XIT8+GP0hGkNwANCxkt4P/xdBikt
K6BtykH7eXP59KhSij4pi5pAC5TpOb+fysFfu/VWL4Et4fVzusTXyKc7zhznScAv
gpNk1zzRTVH0oNlS18noc12ZBC3/U8ADAJGSFSgkVzwpsGuw0hivfVcvGh5+iyL3
fuUeh367a9ITmwYAfXgqjXxSURA7/Y7NYUJt0SepZUL/D2kiIEA1lB7I6LbadifU
Ydg2Fw9WoUAgn4nUNifFUu8KP+uEn64ThnjI77bA7tzf45xHKodwIyNZ6tL6lbYF
PrI6UQ3dMaw30vojC7XV0lqQLUM6e/GvXvHESanaYZ5vf23esrVZuRVifjgdbcGb
U1QX0KoT+Gn+TWdCyXn8AUmFzG9q8fYH89os8Ie2sPfJJJphN25y7EhqLDAUwfH2
rRX6c3bOp6zHDrRdcbSbnAwYd8wIdXWG7VkBwz5N8vKamnCR73PcRIOX2AyBcQs9
Lv2mlpyo8K5TFf7g/JuNG7nOrO9g4oYJOyCieJNskzmtXsOMxGK5pb1tXFIE1xwH
o3+o3Ds7+N+iQ1f0bsEm5orLeV/QAGFkhaviX6qGMvMopTlxXikcqEBG0fU2Lely
odu8m0gQBmoG/6YxknhxadJTUhsngAVtuX7fSPQ0Gz8+GLSKoyTxXcGOLMGDAgMB
AAGjUzBRMB0GA1UdDgQWBBQ9M3YTu7STyGREcKYb9eGxFNPMqDAfBgNVHSMEGDAW
gBQ9M3YTu7STyGREcKYb9eGxFNPMqDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4ICAQAYOlFjOa5M1gmUAZC6AQcvTckTXO8Z2Y8HWMw8+r80gYN4Z1x6
mhc5ss08HZRQuisresOykVIKTbipdwz7KK0JAdRy4DfAx/IFSfu6ZP5J3/9FtJ1j
qlowgCPbr5v3nuCpwIiBNSSYVGCL0/K5ch6+YdGV4RnTxoaFQYpRsLfxCZimUjMR
HZ/ez4PuesSygCOIDyRnXW8e5LIpd9eTOr7LQLvwpt+wPv5nGd/DD1jm6CCRUyk+
hHsPwyou/Ik49Tr0TJGrz3BEfWFRtO+CkK+S2cyc6JecGQpvvp+XyaT8XUluyhgH
zf9vQNXhfwLtEnKMkm/d7VFQMVWroktWKnfW/HAH5Z/9urL4E733sXvZ6Iy3/5Jz
is0ZXIg8V/vMdq151XnpjzNV7X5fmwhZcHwkpqeYsxtjIJNUcwgkxtM4nHdhzQwF
oU2XMttjEKi25j4+A1ScErAXTh/1LIkY0urGzdefeDAjDiFRgXSNQQ1u/BQTfxr3
XVgS3rH7bStRstcINlcRN3/KCYL5XX7uQDOrGcFCeOsUWFRkPuA9GnvMAvbrRMjG
7PWWo8Hc8yC/SmueueJTPnSF9MfSuVwwz4nmteibDEh+30hYaImqswOXHVXmOLIh
0KkPerovsWDDVHnn5+Ze2ZQNl9QjT3gOjns75gZXHbZOCN1kgadTVqjfWQ==
-----END CERTIFICATE-----"#;
    const REDIS_USER: &str = "sgx";
    const REDIS_PASS: &str = "changeme";

    let redis_host = "127.0.0.1";

    let accumulated = unsafe { ACCUMULATED_RECORDS.len() };
    debug_msg(&format!(
        "[SGX-VM-GPU] Batch reached, creating block with {} records (tenant={})...",
        accumulated, tenant
    ));

    let needs_init = unsafe { !STATE_INITIALIZED };
    if needs_init {
        let init_config = redis_store::RedisConfig::new_with_tls_auth(
            redis_host,
            6379,
            REDIS_CA_CERT,
            REDIS_USER,
            REDIS_PASS,
        );
        if let Ok(mut init_conn) = redis_store::RedisConnection::connect(init_config) {
            let anchor = init_conn
                .get(&format!("gpu_checkpoint:{}", tenant))
                .ok()
                .flatten()
                .and_then(|line| checkpoint::verify_checkpoint_line(tenant, &line));

            let stored = init_conn.get_latest_block_state(tenant).ok().flatten();

            let (have_anchor, anchor_block, anchor_root) = match anchor {
                Some((b, r)) => (true, b, r),
                None => (false, 0u64, [0u8; 32]),
            };
            let (have_stored, stored_block, stored_root) = match stored {
                Some((b, r)) => (true, b, r),
                None => (false, 0u64, [0u8; 32]),
            };
            let roots_equal = pure::slices_eq(&anchor_root, &stored_root);

            match pure::decide_resume(
                have_anchor, anchor_block, have_stored, stored_block, roots_equal,
            ) {
                ResumeDecision::Resume { block_number } => {
                    unsafe {
                        BLOCK_NUMBER = block_number + 1;
                        LATEST_CHAINED_ROOT = anchor_root;
                        STATE_INITIALIZED = true;
                    }
                    debug_msg(&format!(
                        "[SGX-VM-GPU] Resumed '{}' at block {} (anchor verified)",
                        tenant, block_number
                    ));
                }
                ResumeDecision::Fresh => unsafe {
                    STATE_INITIALIZED = true;
                },
                ResumeDecision::Refuse { reason } => {
                    let why = match reason {
                        RefusalReason::AnchorStorageMismatch =>
                            "anchor and storage disagree (rollback or rewrite)",
                        RefusalReason::MissingAnchor =>
                            "storage offers a chain with no anchor we signed",
                        RefusalReason::MissingBlocks =>
                            "anchor attests to blocks that are gone",
                    };
                    debug_msg(&format!(
                        "[SGX-VM-GPU] REFUSING to resume '{}': {} -- not extending an unauthenticated chain",
                        tenant, why
                    ));
                    unsafe { CHAIN_RESUME_REFUSED = true };
                    return;
                }
            }
        }
    }

    let records: Vec<merkle::EnergyRecord> = unsafe { ACCUMULATED_RECORDS.clone() };
    let block_num = unsafe { BLOCK_NUMBER };
    let prev_root = unsafe { LATEST_CHAINED_ROOT };

    let block = blockchain::Block::new(
        block_num,
        tenant.to_string(),
        prev_root,
        records,
        timestamp.to_string(),
    );
    debug_msg(&format!(
        "[SGX-VM-GPU] Block {} merkle_root={}... chained_root={}... records={}",
        block.block_number,
        &block.merkle_root_hex()[..16],
        &block.chained_root_hex()[..16],
        block.record_count
    ));

    let redis_config = redis_store::RedisConfig::new_with_tls_auth(
        redis_host,
        6379,
        REDIS_CA_CERT,
        REDIS_USER,
        REDIS_PASS,
    );
    match redis_store::RedisConnection::connect(redis_config) {
        Ok(mut conn) => match conn.insert_block(&block) {
            Ok(block_id) => {
                debug_msg(&format!("[SGX-VM-GPU] Block inserted to Redis (id={})", block_id));
                unsafe {
                    BLOCK_NUMBER += 1;
                    LATEST_CHAINED_ROOT = block.chained_root;
                }

                #[cfg(feature = "use_mbedtls")]
                match checkpoint::public_anchor_signature(tenant, block.block_number, &block.chained_root) {
                    Ok((sig_hex, pub_hex)) => {

                        let line = format!(
                            "anchor-ecdsa-p256-v2|{}|{}|{}|{}|{}",
                            tenant,
                            block.block_number,
                            hex::encode(block.chained_root),
                            sig_hex,
                            pub_hex
                        );
                        match conn.set(&format!("gpu_anchor_sig:{}", tenant), &line) {
                            Ok(_) => debug_msg(&format!(
                                "[SGX-VM-GPU] public anchor signature stored (gpu_anchor_sig:{})",
                                tenant
                            )),
                            Err(e) => debug_msg(&format!(
                                "[SGX-VM-GPU] could not store the public anchor signature: {}", e
                            )),
                        }
                    }
                    Err(e) => debug_msg(&format!(
                        "[SGX-VM-GPU] public anchor signing failed: {} - the HMAC anchor still \
 protects resume, but nothing offline can verify this block", e
                    )),
                }

                let anchor = checkpoint::checkpoint_line(tenant, block.block_number, &block.chained_root);
                match conn.set(&format!("gpu_checkpoint:{}", tenant), &anchor) {
                    Ok(_) => debug_msg(&format!(
                        "[SGX-VM-GPU] Chain-head anchor stored (gpu_checkpoint:{})",
                        tenant
                    )),
                    Err(e) => debug_msg(&format!("[SGX-VM-GPU] anchor store failed: {:?}", e)),
                }
            }
            Err(e) => debug_msg(&format!("[SGX-VM-GPU] Redis insert failed: {:?}", e)),
        },
        Err(e) => debug_msg(&format!("[SGX-VM-GPU] Redis connect failed: {:?}", e)),
    }

    unsafe {
        ITERATION_COUNT = 0;
        ACCUMULATED_RECORDS.clear();
    }
}

fn handle_immudb_login() -> EnclaveResponse {
    #[cfg(feature = "use_mbedtls")]
    {
        debug_msg("[SGX-VM-DB] Logging into ImmuDB via TLS (inside SGX)...");

        let mut response_buf = vec![0u8; 8192];
        let mut response_len: usize = 0;

        let result = unsafe {
            ecall_immudb_login(
                response_buf.as_mut_ptr(),
                response_buf.len(),
                &mut response_len as *mut usize,
            )
        };

        if result == 0 {
            response_buf.truncate(response_len);
            let response_str = String::from_utf8_lossy(&response_buf);

            if let Some(start) = response_str.find("\"sessionID\":\"") {
                let start = start + 13;
                if let Some(end) = response_str[start..].find('"') {
                    let session_id = &response_str[start..start+end];
                    debug_msg(&format!("[SGX-VM-DB] Got session ID: {}...", &session_id[..16.min(session_id.len())]));
                    return EnclaveResponse {
                        status: 0,
                        message: "Login successful".to_string(),
                        output_data: Some(session_id.to_string()),
                    };
                }
            }

            EnclaveResponse {
                status: -10,
                message: "Failed to extract session ID".to_string(),
                output_data: Some(response_str.to_string()),
            }
        } else {
            EnclaveResponse {
                status: result,
                message: format!("ImmuDB login failed: {}", result),
                output_data: None,
            }
        }
    }

    #[cfg(not(feature = "use_mbedtls"))]
    EnclaveResponse {
        status: -99,
        message: "mbedtls feature not enabled".to_string(),
        output_data: None,
    }
}

fn handle_immudb_insert(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct InsertReq {
        #[allow(dead_code)]
        operation: String,
        session_id: String,
        body: String,
    }

    #[cfg(feature = "use_mbedtls")]
    {
        let request: InsertReq = match serde_json::from_str(json) {
            Ok(r) => r,
            Err(e) => {
                return EnclaveResponse {
                    status: -101,
                    message: format!("Failed to parse insert request: {}", e),
                    output_data: None,
                };
            }
        };

        debug_msg("[SGX-VM-DB] Inserting into ImmuDB via TLS (inside SGX)...");

        let mut response_buf = vec![0u8; 4096];
        let mut response_len: usize = 0;

        let result = unsafe {
            ecall_immudb_insert(
                request.session_id.as_ptr(),
                request.session_id.len(),
                request.body.as_ptr(),
                request.body.len(),
                response_buf.as_mut_ptr(),
                response_buf.len(),
                &mut response_len as *mut usize,
            )
        };

        if result == 0 {
            response_buf.truncate(response_len);
            let response_str = String::from_utf8_lossy(&response_buf);
            debug_msg("[SGX-VM-DB] Insert successful");
            EnclaveResponse {
                status: 0,
                message: "Insert successful".to_string(),
                output_data: Some(response_str.to_string()),
            }
        } else {
            EnclaveResponse {
                status: result,
                message: format!("ImmuDB insert failed: {}", result),
                output_data: None,
            }
        }
    }

    #[cfg(not(feature = "use_mbedtls"))]
    {
        let _ = json;
        EnclaveResponse {
            status: -99,
            message: "mbedtls feature not enabled".to_string(),
            output_data: None,
        }
    }
}
