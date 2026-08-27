use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "use_mbedtls")]
use std::sync::{Arc, Mutex};
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

#[cfg(feature = "use_mbedtls")]
const ENCLAVE_CERT_PEM: &str = include_str!("../enclave_cert.pem");
#[cfg(feature = "use_mbedtls")]
const ENCLAVE_KEY_PEM: &str = include_str!("../enclave_key.pem");

use sgx::pure;
use sgx::{
    parse_ima_log,
    reconcile_ima_against_pcr10,
    ecall_compute_vm_energy_simple,
    ecall_compute_total_host_energy,
    extract_scaphandre_hash_from_ima,
    extract_gpu_stack_hashes_from_ima,
    extract_hypervisor_hashes_from_ima,
    verify_ima_log_against_pcr10,
    fetch_expected_hash_from_immudb,
    hashes_match,
};

fn debug_msg(msg: &str) {
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
    let _ = std::io::stderr().flush();
}

#[derive(Deserialize)]
struct EnclaveRequest {
    operation: String,
    #[serde(flatten)]
    data: Value,
}

#[derive(Deserialize)]
struct VerifyRequest {
    pcr_values: String,
    ima_hash: String,
    ima_count: usize,
    ima_log: Option<String>,
    scaphandre_hash: String,
    hostname: String,
    deployment_type: String,
    immudb_addr: String,
    #[serde(default)]
    skip_ima: bool,
}

static ISSUED_NONCE: Mutex<Option<[u8; 32]>> = Mutex::new(None);

fn handle_get_nonce() -> EnclaveResponse {

    let mut nonce = [0u8; 32];
    #[cfg(not(feature = "use_mbedtls"))]
    {
        let _ = &nonce;
        return EnclaveResponse {
            status: -120,
            message: "built without use_mbedtls - no in-enclave RNG to issue a nonce".to_string(),
            ima_hash: None,
            output_data: None,
        };
    }
    #[cfg(feature = "use_mbedtls")]
    {
        use mbedtls::rng::{CtrDrbg, Random, Rdseed};
        use std::sync::Arc as StdArc;
        let mut rng = match CtrDrbg::new(StdArc::new(Rdseed), None) {
            Ok(r) => r,
            Err(e) => {
                return EnclaveResponse {
                    status: -120,
                    message: format!("no RNG available inside the enclave: {:?}", e),
                    ima_hash: None,
                    output_data: None,
                }
            }
        };
        if let Err(e) = rng.random(&mut nonce) {
            return EnclaveResponse {
                status: -120,
                message: format!("RNG failed while issuing a nonce: {:?}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    }
    if let Ok(mut slot) = ISSUED_NONCE.lock() {
        *slot = Some(nonce);
    }
    debug_msg("[SGX-VERIFY] issued a fresh single-use nonce for TPM2_Quote");
    EnclaveResponse {
        status: 0,
        message: "nonce issued".to_string(),
        ima_hash: None,
        output_data: Some(hex::encode(nonce)),
    }
}

fn verify_tpm_quote(
    attest: &[u8],
    signature: &[u8],
    pcr_values: &[u8],
    expected_nonce: &[u8],
    ak_pem: &str,
) -> Result<(), String> {
    let rsa_sig = sgx::verify_quote_structure(attest, signature, pcr_values, expected_nonce)?;
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

#[derive(Deserialize)]
struct ComputeVmEnergyRequest {
    topo_data: String,
    proc_data: String,
    hash_data: String,
}

#[derive(Deserialize)]
struct ComputeHostEnergyRequest {
    topo_data: String,
}

#[derive(Serialize)]
struct EnclaveResponse {
    status: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ima_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_data: Option<String>,
}

fn main() {

    debug_msg("[SGX-ENCLAVE] STARTING...");
    debug_msg("[SGX-ENCLAVE] Running inside REAL SGX hardware enclave");
    debug_msg("[SGX-ENCLAVE] Memory is encrypted by CPU");
    #[cfg(feature = "use_mbedtls")]
    debug_msg("[SGX-ENCLAVE] Using TLS for secure communication");
    #[cfg(not(feature = "use_mbedtls"))]
    debug_msg("[SGX-ENCLAVE] Using TCP for communication (no TLS)");
    debug_msg("[SGX-ENCLAVE] PERSISTENT MODE - handles multiple requests");

    debug_msg("[SGX-ENCLAVE] Initializing sealed key and VM chains...");
    let init_result = sgx::ecall_initialize_sealed_key();
    debug_msg(&format!("[SGX-ENCLAVE] ecall_initialize_sealed_key returned: {} (0=existing key, 1=new key)", init_result));

    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] Failed to bind TCP: {}", e));
            return;
        }
    };

    let port = listener.local_addr().unwrap().port();
    debug_msg(&format!("[SGX-ENCLAVE] TCP server listening on port {}", port));

    println!("PORT:{}", port);
    let _ = io::stdout().flush();

    debug_msg("[SGX-ENCLAVE] Waiting for connection...");
    let (tcp_stream, addr) = match listener.accept() {
        Ok((s, a)) => {
            let _ = s.set_nodelay(true);
            debug_msg(&format!("[SGX-ENCLAVE] TCP connection from {}", a));
            (s, a)
        }
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] Accept failed: {}", e));
            return;
        }
    };

    let mut tcp_stream = tcp_stream;

    #[cfg(feature = "use_mbedtls")]
    {
        debug_msg("[SGX-ENCLAVE] Setting up TLS server...");

        let cert_pem = format!("{}\0", ENCLAVE_CERT_PEM);
        let key_pem = format!("{}\0", ENCLAVE_KEY_PEM);

        let cert = match Certificate::from_pem(cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                debug_msg(&format!("[SGX-ENCLAVE] Failed to parse certificate: {:?}", e));
                return;
            }
        };

        let key = match Pk::from_private_key(key_pem.as_bytes(), None) {
            Ok(k) => k,
            Err(e) => {
                debug_msg(&format!("[SGX-ENCLAVE] Failed to parse private key: {:?}", e));
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
            debug_msg(&format!("[SGX-ENCLAVE] Failed to set certificate: {:?}", e));
            return;
        }

        let config = Arc::new(config);

        let mut tls_ctx = Context::new(config);

        if let Err(e) = tls_ctx.establish(&mut tcp_stream, None) {
            debug_msg(&format!("[SGX-ENCLAVE] TLS handshake failed: {:?}", e));
            return;
        }

        debug_msg("[SGX-ENCLAVE] TLS connection established");
        debug_msg("[SGX-ENCLAVE] All communication is now encrypted");

        let mut request_count = 0u64;
        loop {
            request_count += 1;
            debug_msg(&format!("[SGX-ENCLAVE] Waiting for TLS request #{}...", request_count));

            match handle_single_tls_request(&mut tls_ctx) {
                Ok(should_continue) => {
                    if !should_continue {
                        debug_msg("[SGX-ENCLAVE] Received shutdown signal");
                        break;
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-ENCLAVE] TLS connection error: {}", e));
                    break;
                }
            }
        }

        debug_msg(&format!("[SGX-ENCLAVE] Handled {} TLS requests total", request_count - 1));
    }

    #[cfg(not(feature = "use_mbedtls"))]
    {
        debug_msg("[SGX-ENCLAVE] WARNING: Running without TLS encryption!");

        let mut request_count = 0u64;
        loop {
            request_count += 1;
            debug_msg(&format!("[SGX-ENCLAVE] Waiting for request #{}...", request_count));

            match handle_single_request(&mut tcp_stream) {
                Ok(should_continue) => {
                    if !should_continue {
                        debug_msg("[SGX-ENCLAVE] Received shutdown signal");
                        break;
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-ENCLAVE] Connection error: {}", e));
                    break;
                }
            }
        }

        debug_msg(&format!("[SGX-ENCLAVE] Handled {} requests total", request_count - 1));
    }

    debug_msg("[SGX-ENCLAVE] Enclave shutting down");
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

    debug_msg(&format!("[SGX-ENCLAVE] TLS: Expecting {} bytes of request data", request_len));

    const MAX_REQUEST_BYTES: usize = 256 * 1024 * 1024;
    if request_len > MAX_REQUEST_BYTES {
        debug_msg(&format!(
            "[SGX-ENCLAVE] TLS: Request too large! {} bytes > {} cap - the IMA log has outgrown \
 this limit; apply scripts/ima_policy_vpma or raise MAX_REQUEST_BYTES",
            request_len, MAX_REQUEST_BYTES
        ));
        return Err("Request too large".to_string());
    }

    let mut request_data = vec![0u8; request_len];
    if let Err(e) = ctx.read_exact(&mut request_data) {
        return Err(format!("TLS: Failed to read request: {:?}", e));
    }

    debug_msg(&format!("[SGX-ENCLAVE] TLS: Received {} bytes", request_data.len()));

    let line = match String::from_utf8(request_data) {
        Ok(s) => s,
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] TLS: Invalid UTF-8: {}", e));
            let err_response = EnclaveResponse {
                status: -50,
                message: "Invalid UTF-8 in request".to_string(),
                ima_hash: None,
                output_data: None,
            };
            send_tls_response(ctx, &err_response);
            return Ok(true);
        }
    };

    debug_msg(&format!("[SGX-ENCLAVE] TLS Request: {}", &line.chars().take(200).collect::<String>()));
    debug_msg("[SGX-ENCLAVE] About to parse JSON...");

    let request: EnclaveRequest = match serde_json::from_str(&line) {
        Ok(r) => {
            debug_msg("[SGX-ENCLAVE] JSON parsed successfully");
            r
        }
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] TLS: JSON parse error: {}", e));
            let response = EnclaveResponse {
                status: -100,
                message: format!("Failed to parse request: {}", e),
                ima_hash: None,
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
            ima_hash: None,
            output_data: None,
        };
        send_tls_response(ctx, &response);
        return Ok(false);
    }

    debug_msg(&format!("[SGX-ENCLAVE] TLS Operation: {}", request.operation));

    let response = match request.operation.as_str() {
        "verify" => handle_verify(&line),
        "get_nonce" => handle_get_nonce(),
        "compute_vm_energy" => handle_compute_vm_energy(&line),
        "compute_vm_energy_cgroup" => handle_compute_vm_energy_cgroup(&line),
        "compute_vm_energy_file" => handle_compute_vm_energy_from_file(&line),
        "compute_host_energy" => handle_compute_host_energy(&line),
        "init_sealed_key" => handle_init_sealed_key(),
        _ => EnclaveResponse {
            status: -1000,
            message: format!("Unknown operation: {}", request.operation),
            ima_hash: None,
            output_data: None,
        },
    };

    send_tls_response(ctx, &response);
    debug_msg(&format!("[SGX-ENCLAVE] TLS Operation complete, status: {}", response.status));

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

    debug_msg(&format!("[SGX-ENCLAVE] Expecting {} bytes of request data", request_len));

    if request_len > 40 * 1024 * 1024 {
        debug_msg("[SGX-ENCLAVE] Request too large!");
        return Err("Request too large".to_string());
    }

    let mut request_data = vec![0u8; request_len];
    if let Err(e) = stream.read_exact(&mut request_data) {
        return Err(format!("Failed to read request: {}", e));
    }

    debug_msg(&format!("[SGX-ENCLAVE] Received {} bytes", request_data.len()));

    let line = match String::from_utf8(request_data) {
        Ok(s) => s,
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] Invalid UTF-8: {}", e));
            let err_response = EnclaveResponse {
                status: -50,
                message: "Invalid UTF-8 in request".to_string(),
                ima_hash: None,
                output_data: None,
            };
            send_response(stream, &err_response);
            return Ok(true);
        }
    };

    debug_msg(&format!("[SGX-ENCLAVE] Request: {}", &line.chars().take(200).collect::<String>()));
    debug_msg("[SGX-ENCLAVE] About to parse JSON...");

    let request: EnclaveRequest = match serde_json::from_str(&line) {
        Ok(r) => {
            debug_msg("[SGX-ENCLAVE] JSON parsed successfully");
            r
        }
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] JSON parse error: {}", e));
            let response = EnclaveResponse {
                status: -100,
                message: format!("Failed to parse request: {}", e),
                ima_hash: None,
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
            ima_hash: None,
            output_data: None,
        };
        send_response(stream, &response);
        return Ok(false);
    }

    debug_msg(&format!("[SGX-ENCLAVE] Operation: {}", request.operation));

    let response = match request.operation.as_str() {
        "verify" => handle_verify(&line),
        "get_nonce" => handle_get_nonce(),
        "compute_vm_energy" => handle_compute_vm_energy(&line),
        "compute_vm_energy_cgroup" => handle_compute_vm_energy_cgroup(&line),
        "compute_vm_energy_file" => handle_compute_vm_energy_from_file(&line),
        "compute_host_energy" => handle_compute_host_energy(&line),
        "init_sealed_key" => handle_init_sealed_key(),
        _ => EnclaveResponse {
            status: -1000,
            message: format!("Unknown operation: {}", request.operation),
            ima_hash: None,
            output_data: None,
        },
    };

    send_response(stream, &response);
    debug_msg(&format!("[SGX-ENCLAVE] Operation complete, status: {}", response.status));

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

fn handle_verify(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct VerifyReq {
        #[allow(dead_code)]
        operation: String,
        pcr_values: String,
        ima_hash: String,
        ima_count: usize,
        ima_log: Option<String>,
        scaphandre_hash: String,
        hostname: String,
        deployment_type: String,
        immudb_addr: String,
        #[serde(default)]
        skip_ima: bool,

        #[serde(default)]
        quote_attest: String,
        #[serde(default)]
        quote_signature: String,
    }

    let request: VerifyReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse verify request: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    debug_msg("[SGX-HASH-VERIFY] Starting FULL binary verification inside SGX");
    debug_msg(&format!("[SGX-VERIFY] Hostname: {}", request.hostname));
    debug_msg(&format!("[SGX-VERIFY] Deployment: {}", request.deployment_type));
    debug_msg(&format!("[SGX-VERIFY] IMA entries: {}", request.ima_count));
    debug_msg(&format!("[SGX-VERIFY] ImmuDB address: {}", request.immudb_addr));

    let pcr_values = match hex::decode(&request.pcr_values) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Failed to decode PCR hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    if pcr_values.len() < 96 {
        debug_msg("[SGX-VERIFY] PCR values too short");
        return EnclaveResponse {
            status: -102,
            message: "PCR values too short (need 96 bytes for PCR 0,7,10)".to_string(),
            ima_hash: Some(request.ima_hash),
            output_data: None,
        };
    }

    let pcr10 = &pcr_values[64..96];
    let is_zero = pcr10.iter().all(|&b| b == 0);
    if is_zero {
        debug_msg("[SGX-VERIFY] PCR 10 is zero - IMA not active");
        return EnclaveResponse {
            status: -2,
            message: "PCR10 is zero - IMA not active".to_string(),
            ima_hash: Some(request.ima_hash),
            output_data: None,
        };
    }
    debug_msg("[SGX-VERIFY] PCR10 is non-zero (IMA active)");

    match fetch_expected_hash_from_immudb(
        "ak_pub",
        &request.hostname,
        &request.deployment_type,
        &request.immudb_addr,
        "",
    ) {
        Ok((ak_pem, _, _, _)) if !ak_pem.is_empty() => {
            let attest = hex::decode(request.quote_attest.trim()).unwrap_or_default();
            let sig = hex::decode(request.quote_signature.trim()).unwrap_or_default();
            if attest.is_empty() || sig.is_empty() {
                debug_msg("[SGX-VERIFY] AK is registered but the node sent no quote");
                return EnclaveResponse {
                    status: -122,
                    message: "an AK is registered for this node, so PCR values must be \
 accompanied by a TPM2_Quote. None was supplied."
                        .to_string(),
                    ima_hash: None,
                    output_data: None,
                };
            }
            let nonce = match ISSUED_NONCE.lock().ok().and_then(|mut n| n.take()) {
                Some(n) => n,
                None => {
                    debug_msg("[SGX-VERIFY] no nonce outstanding - call get_nonce first");
                    return EnclaveResponse {
                        status: -121,
                        message: "AK registered, so a fresh quote is required, but this enclave \
 has no outstanding nonce. Request get_nonce, then verify."
                            .to_string(),
                        ima_hash: None,
                        output_data: None,
                    };
                }
            };
            match verify_tpm_quote(&attest, &sig, &pcr_values, &nonce, &ak_pem) {
                Ok(()) => debug_msg(
                    "[SGX-VERIFY] TPM2_Quote verified - PCR values are TPM-signed, bound to \
 this enclave's nonce, and cover sha256:0,7,10",
                ),
                Err(e) => {
                    debug_msg(&format!("[SGX-VERIFY] QUOTE REJECTED: {}", e));
                    return EnclaveResponse {
                        status: -123,
                        message: format!("TPM2_Quote verification failed: {}", e),
                        ima_hash: None,
                        output_data: None,
                    };
                }
            }
        }
        Err(-8) | Ok(_) => {
            debug_msg("[SGX-VERIFY] no AK registered for this node - PCR values are \
 UNAUTHENTICATED (the node asserts them). Register one with \
 scripts/register_ak.sh to make quotes mandatory.");
        }
        Err(code) => {
            debug_msg(&format!(
                "[SGX-VERIFY] could not reach the AK registry (error {}) - refusing rather \
 than assuming no AK is registered",
                code
            ));
            return EnclaveResponse {
                status: -124,
                message: format!(
                    "could not determine whether an AK is registered for this node \
 (ImmuDB lookup failed with {}). Refusing.",
                    code
                ),
                ima_hash: None,
                output_data: None,
            };
        }
    }

    debug_msg("[SGX-VERIFY] Querying ImmuDB via TLS INSIDE SGX enclave...");
    debug_msg("[SGX-VERIFY] Host CANNOT see this query or response");

    let (expected_hash, expected_pcr0, expected_pcr7, expected_pcr10) =
        match fetch_expected_hash_from_immudb(
            "scaphandre",
            &request.hostname,
            &request.deployment_type,
            &request.immudb_addr,
            "",
        ) {
            Ok(values) => {
                debug_msg("[SGX-VERIFY] ImmuDB query successful (inside SGX)");
                values
            }
            Err(e) => {
                debug_msg(&format!("[SGX-VERIFY] Failed to query ImmuDB: error code {}", e));
                return EnclaveResponse {
                    status: -5,
                    message: format!("Failed to query ImmuDB inside SGX: error {}", e),
                    ima_hash: Some(request.ima_hash),
                    output_data: None,
                };
            }
        };

    debug_msg(&format!("[SGX-VERIFY] ImmuDB expected hash: {}", expected_hash));
    debug_msg(&format!("[SGX-VERIFY] ImmuDB expected PCR0: {}...", &expected_pcr0.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY] ImmuDB expected PCR7: {}...", &expected_pcr7.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY] ImmuDB expected PCR10: {}...", &expected_pcr10.chars().take(16).collect::<String>()));

    if request.skip_ima {
        debug_msg("[SGX-VERIFY] SKIP_IMA_VERIFY=1 - Skipping binary hash comparison (INSECURE)");
        debug_msg("[SGX-VERIFY] This bypasses IMA verification for testing only!");
        debug_msg("[SGX-VERIFY] PCR values will still be verified");
    } else {

        debug_msg("[SGX-VERIFY] Comparing hashes INSIDE SGX enclave...");
        debug_msg(&format!("[SGX-VERIFY] ImmuDB expects: {}", expected_hash));
    }

    debug_msg("[SGX-VERIFY] Verifying PCR values INSIDE SGX enclave...");

    let actual_pcr0 = hex::encode(&pcr_values[0..32]);
    let actual_pcr7 = hex::encode(&pcr_values[32..64]);
    let actual_pcr10 = hex::encode(&pcr_values[64..96]);

    let mut ima_log_reconciled = false;
    let attested: Option<sgx::AttestedImaPrefix> = match request.ima_log {
        Some(ref ima_log) => match parse_ima_log(ima_log) {
            Ok(records) => match reconcile_ima_against_pcr10(records, &actual_pcr10) {
                Ok(prefix) => {
                    debug_msg(&format!(
                        "[SGX-VERIFY] IMA log reconciles with live PCR10 - {}/{} entries attested",
                        prefix.entries_attested(), prefix.entries_total()
                    ));
                    ima_log_reconciled = true;
                    Some(prefix)
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-VERIFY] IMA LOG DOES NOT RECONCILE WITH PCR10 (code {})", e));
                    debug_msg("[SGX-VERIFY] No prefix of the shipped log replays to the hardware value -");
                    debug_msg("[SGX-VERIFY] the log is edited, truncated, or from a different boot.");
                    debug_msg("[SGX-VERIFY] Carried to the verified rule as ima_log_reconciled=false.");
                    None
                }
            },
            Err(e) => {
                debug_msg(&format!("[SGX-VERIFY] IMA log failed to parse (code {}) - refusing", e));
                None
            }
        },
        None if request.skip_ima => {
            debug_msg("[SGX-VERIFY] SKIP_IMA_VERIFY=1 and no IMA log supplied - the log/PCR10");
            debug_msg("[SGX-VERIFY] binding is DISABLED. Nothing ties this host to its TPM.");
            None
        }
        None => {
            debug_msg("[SGX-VERIFY] NO IMA LOG SUPPLIED - cannot bind anything to PCR10");
            None
        }
    };

    let scaphandre_hash = match attested.as_ref().and_then(extract_scaphandre_hash_from_ima) {
        Some(h) => {

            if !hashes_match(&h, &request.scaphandre_hash) {
                debug_msg(&format!(
                    "[SGX-VERIFY] host reported {}... but the attested IMA log measures {}... - using the LOG",
                    &request.scaphandre_hash.chars().take(12).collect::<String>(),
                    &h.chars().take(12).collect::<String>()
                ));
            }
            h
        }
        None => {
            if request.skip_ima {
                debug_msg("[SGX-VERIFY] SKIP_IMA_VERIFY set - bypassing IMA check (INSECURE)");
                debug_msg("[SGX-VERIFY] This should only be used for testing!");
                "skip_ima_verification".to_string()
            } else {
                debug_msg("[SGX-VERIFY] no scaphandre binary measurement in the attested IMA log");
                debug_msg("[SGX-VERIFY] the collector must be measured by IMA before it can be");
                debug_msg("[SGX-VERIFY] admitted; refresh the log snapshot after building");
                return EnclaveResponse {
                    status: -4,
                    message: "no scaphandre binary measurement in the attested IMA log - \
 refusing to accept a host-supplied hash in its place"
                        .to_string(),
                    ima_hash: Some(request.ima_hash),
                    output_data: None,
                };
            }
        }
    };

    debug_msg(&format!("[SGX-VERIFY] IMA measured hash: {}", scaphandre_hash));

    debug_msg(&format!("[SGX-VERIFY] Actual PCR0: {}...", &actual_pcr0.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY] Expected PCR0: {}...", &expected_pcr0.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY] Actual PCR7: {}...", &actual_pcr7.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY] Expected PCR7: {}...", &expected_pcr7.chars().take(16).collect::<String>()));

    let pcr10_nonzero = !pcr_values[64..96].iter().all(|&b| b == 0);
    let have_expected = !expected_hash.is_empty();

    let mut admitted: Option<pure::BootAdmitted> = None;

    if request.skip_ima {

        debug_msg("[SGX-VERIFY] SKIP_IMA_VERIFY=1 - binary comparison bypassed (INSECURE)");
    } else {
        match pure::admit_boot(
            actual_pcr0.as_bytes(),
            actual_pcr7.as_bytes(),
            scaphandre_hash.as_bytes(),
            expected_pcr0.as_bytes(),
            expected_pcr7.as_bytes(),
            expected_hash.as_bytes(),
            pcr10_nonzero,
            ima_log_reconciled,
            have_expected,
        ) {
            Ok(token) => {

                debug_msg("[SGX-VERIFY] ADMITTED by the verified rule (pure::admit_boot)");
                admitted = Some(token);
            }
            Err(denial) => {

                let (status, message) = match denial {
                    pure::BootDenial::Pcr10Zero =>
                        (-2, "PCR10 is zero - IMA not active".to_string()),
                    pure::BootDenial::NoBinaryHashInLog =>
                        (-4, "no scaphandre binary measurement in the attested IMA log".to_string()),
                    pure::BootDenial::ExpectedStateUnavailable =>
                        (-5, "no expected state available from ImmuDB".to_string()),
                    pure::BootDenial::BinaryHashMismatch =>
                        (-6, format!("Hash mismatch: IMA={} ImmuDB={}", scaphandre_hash, expected_hash)),
                    pure::BootDenial::Pcr0Mismatch =>
                        (-7, format!("PCR0 mismatch: actual={} expected={}", actual_pcr0, expected_pcr0)),
                    pure::BootDenial::Pcr7Mismatch =>
                        (-8, format!("PCR7 mismatch: actual={} expected={}", actual_pcr7, expected_pcr7)),
                    pure::BootDenial::ImaLogNotReconciled =>
                        (-10, "IMA log does not reconcile with PCR10".to_string()),
                };
                debug_msg(&format!("[SGX-VERIFY] DENIED by the verified rule: {}", message));
                return EnclaveResponse {
                    status,
                    message,
                    ima_hash: Some(request.ima_hash),
                    output_data: None,
                };
            }
        }
    }
    debug_msg("[SGX-VERIFY] binary hash, PCR0 and PCR7 all admitted by the verified rule");

    debug_msg(&format!(
        "[SGX-VERIFY] PCR10 (live IMA aggregate): {}... - bound to the log in STEP 4.5, not compared to a stored constant",
        &actual_pcr10.chars().take(16).collect::<String>()
    ));
    let _ = &expected_pcr10;

    if let Some(ref prefix) = attested {
        let gpu_stack = extract_gpu_stack_hashes_from_ima(prefix);
        if gpu_stack.is_empty() {
            debug_msg("[SGX-VERIFY] (no GPU-stack measurements in IMA log - IMA policy not active yet)");
        } else {
            debug_msg(&format!("[SGX-VERIFY] GPU stack measured in IMA log ({} component(s)) - verifying:", gpu_stack.len()));
            for (path, hash) in &gpu_stack {

                let base = path.rsplit('/').next().unwrap_or(path.as_str());
                let key: String = if base.starts_with("libnvidia-ml") {
                    "libnvidia-ml".to_string()
                } else {

                    match path.strip_prefix("/usr/lib/modules/").and_then(|r| r.split('/').next()) {
                        Some(kver) if !kver.is_empty() => format!("{}@{}", base, kver),
                        _ => base.to_string(),
                    }
                };
                match fetch_expected_hash_from_immudb(&key, &request.hostname, &request.deployment_type, &request.immudb_addr, "") {
                    Ok((expected, _, _, _)) if !expected.is_empty() => {
                        if hashes_match(hash, &expected) {
                            debug_msg(&format!("[SGX-VERIFY] {} matches registered hash", path));
                        } else {

                            debug_msg(&format!("[SGX-VERIFY] {} MISMATCH - measured {}... vs registered {}... (swapped driver/library?)",
                                path, &hash.chars().take(16).collect::<String>(), &expected.chars().take(16).collect::<String>()));
                            return EnclaveResponse {
                                status: -11,
                                message: format!("GPU-stack hash mismatch: {}", path),
                                ima_hash: Some(request.ima_hash),
                                output_data: None,
                            };
                        }
                    }
                    _ => debug_msg(&format!("[SGX-VERIFY] {} = {}... (not registered - log-only)",
                        path, &hash.chars().take(16).collect::<String>())),
                }
            }
        }
    }

    if let Some(ref prefix) = attested {
        let hyp = extract_hypervisor_hashes_from_ima(prefix);
        if hyp.is_empty() {
            debug_msg("[SGX-VERIFY] (no qemu/swtpm measurements in the attested log - not a hypervisor, or IMA missed them)");
        } else {
            debug_msg(&format!("[SGX-VERIFY] hypervisor stack: {} component(s) measured, verifying:", hyp.len()));
            let mut verified = 0usize;
            let mut unregistered = 0usize;
            for (key, hash) in &hyp {
                match fetch_expected_hash_from_immudb(key, &request.hostname, &request.deployment_type, &request.immudb_addr, "") {
                    Ok((expected, _, _, _)) if !expected.is_empty() => {
                        if hashes_match(hash, &expected) {
                            debug_msg(&format!("[SGX-VERIFY] {} matches its registered hash", key));
                            verified += 1;
                        } else {
                            debug_msg(&format!("[SGX-VERIFY] {} MISMATCH - measured {}... vs registered {}...",
                                key, &hash.chars().take(16).collect::<String>(), &expected.chars().take(16).collect::<String>()));
                            return EnclaveResponse {
                                status: -12,
                                message: format!(
                                    "hypervisor component '{}' does not match its registered hash - \
 refusing, because this component underpins every guest on this host",
                                    key
                                ),
                                ima_hash: Some(request.ima_hash),
                                output_data: None,
                            };
                        }
                    }
                    _ => {
                        debug_msg(&format!("[SGX-VERIFY] {} = {}... (not registered - log-only)",
                            key, &hash.chars().take(16).collect::<String>()));
                        unregistered += 1;
                    }
                }
            }
            debug_msg(&format!("[SGX-VERIFY] hypervisor stack: {} verified, {} unregistered", verified, unregistered));
        }
    }

    debug_msg("[SGX-VERIFY] FULL VERIFICATION PASSED");
    debug_msg(&format!("[SGX-VERIFY] Binary hash: {}", scaphandre_hash));
    debug_msg(&format!("[SGX-VERIFY] PCR0 (BIOS): {}...", &actual_pcr0.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY] PCR7 (SecureBoot): {}...", &actual_pcr7.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY] PCR10 (IMA): {}...", &actual_pcr10.chars().take(16).collect::<String>()));

    let status = match admitted {
        Some(token) => pure::boot_success_code(token),
        None => {
            if !request.skip_ima {

                debug_msg("[SGX-VERIFY] reached the success path without an admission token");
                return EnclaveResponse {
                    status: -6,
                    message: "internal: success path reached without a verified admission token"
                        .to_string(),
                    ima_hash: Some(request.ima_hash),
                    output_data: None,
                };
            }
            0
        }
    };

    EnclaveResponse {
        status,
        message: format!(
            "FULL VERIFICATION PASSED - hash {} verified against ImmuDB, all PCRs match ({} IMA entries)",
            &scaphandre_hash.chars().take(16).collect::<String>(),
            request.ima_count
        ),
        ima_hash: Some(request.ima_hash),
        output_data: None,
    }
}

fn handle_compute_vm_energy(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct ComputeReq {
        #[allow(dead_code)]
        operation: String,
        topo_data: String,
        proc_data: String,
        hash_data: String,

        #[serde(default)]
        tag_key: Option<[u64; 2]>,
        #[serde(default)]
        tag_epoch: u32,
        #[serde(default)]
        tag_producer: u16,
    }

    let request: ComputeReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse compute_vm_energy request: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    debug_msg("[SGX-COMPUTE] Computing VM energy inside SGX");

    let (tag_k0, tag_k1) = match request.tag_key {
        Some([a, b]) => (a, b),
        None => {
            return EnclaveResponse {
                status: -128,
                message: "RAPL readings carry keyed SipTag-32 but the request supplied no \
 tag key. An old collector, or one built without the eBPF tag \
 feature, is talking to a keyed enclave. Refusing."
                    .to_string(),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    sgx::set_rapl_tag_key(Some((tag_k0, tag_k1, request.tag_epoch, request.tag_producer)));

    let topo_bytes = match hex::decode(&request.topo_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Failed to decode topo hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    let proc_bytes = match hex::decode(&request.proc_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -103,
                message: format!("Failed to decode proc hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    let hash_bytes = match hex::decode(&request.hash_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -104,
                message: format!("Failed to decode hash hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    let mut output = vec![0u8; 65536];
    let mut out_len: usize = 0;

    debug_msg(&format!("[SGX-COMPUTE] Calling ecall_compute_vm_energy_simple with {} topo bytes, {} proc bytes, {} hash bytes",
              topo_bytes.len(), proc_bytes.len(), hash_bytes.len()));

    let result = unsafe {
        ecall_compute_vm_energy_simple(
            topo_bytes.as_ptr(),
            topo_bytes.len(),
            proc_bytes.as_ptr(),
            proc_bytes.len(),
            hash_bytes.as_ptr(),
            hash_bytes.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut out_len,
        )
    };

    debug_msg(&format!("[SGX-COMPUTE] ecall returned: result={}, out_len={}", result, out_len));

    if result == 0 {
        output.truncate(out_len);
        EnclaveResponse {
            status: 0,
            message: format!("VM energy computed successfully, {} bytes output", out_len),
            ima_hash: None,
            output_data: if out_len > 0 { Some(hex::encode(&output)) } else { None },
        }
    } else {
        EnclaveResponse {
            status: result,
            message: format!("VM energy computation failed with status {}", result),
            ima_hash: None,
            output_data: None,
        }
    }
}

fn handle_compute_vm_energy_cgroup(json: &str) -> EnclaveResponse {
    use sgx::ecall_compute_vm_energy_cgroup;

    #[derive(Deserialize)]
    struct CgroupComputeReq {
        #[allow(dead_code)]
        operation: String,
        topo_data: String,
        cgroup_data: String,
        hash_data: String,

        #[serde(default)]
        tag_key: Option<[u64; 2]>,
        #[serde(default)]
        tag_epoch: u32,
        #[serde(default)]
        tag_producer: u16,
    }

    let request: CgroupComputeReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -100,
                message: format!("Failed to parse cgroup compute request: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    let (tag_k0, tag_k1) = match request.tag_key {
        Some([a, b]) => (a, b),
        None => {
            return EnclaveResponse {
                status: -128,
                message: "RAPL readings carry keyed SipTag-32 but the cgroup request supplied \
 no tag key. Refusing."
                    .to_string(),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    sgx::set_rapl_tag_key(Some((tag_k0, tag_k1, request.tag_epoch, request.tag_producer)));

    let topo_bytes = match hex::decode(&request.topo_data) {
        Ok(b) => b,
        Err(e) => {
            return EnclaveResponse {
                status: -110,
                message: format!("Invalid topo_data hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    let cgroup_bytes = match hex::decode(&request.cgroup_data) {
        Ok(b) => b,
        Err(e) => {
            return EnclaveResponse {
                status: -111,
                message: format!("Invalid cgroup_data hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    let hash_bytes = match hex::decode(&request.hash_data) {
        Ok(b) => b,
        Err(e) => {
            return EnclaveResponse {
                status: -112,
                message: format!("Invalid hash_data hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    debug_msg(&format!("[SGX-CGROUP] Cgroup data: {} bytes (vs ~430KB for processes!)", cgroup_bytes.len()));

    let mut output = vec![0u8; 4096];
    let mut out_len: usize = 0;

    let result = unsafe {
        ecall_compute_vm_energy_cgroup(
            topo_bytes.as_ptr(),
            topo_bytes.len(),
            cgroup_bytes.as_ptr(),
            cgroup_bytes.len(),
            hash_bytes.as_ptr(),
            hash_bytes.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut out_len as *mut usize,
        )
    };

    debug_msg(&format!("[SGX-CGROUP] ecall returned: result={}, out_len={}", result, out_len));

    if result == 0 {
        output.truncate(out_len);
        EnclaveResponse {
            status: 0,
            message: format!("Cgroup VM energy computed successfully, {} bytes output", out_len),
            ima_hash: None,
            output_data: if out_len > 0 { Some(hex::encode(&output)) } else { None },
        }
    } else if result == -2 {
        EnclaveResponse {
            status: -2,
            message: "RAPL hash verification FAILED - possible tampering".to_string(),
            ima_hash: None,
            output_data: None,
        }
    } else {
        EnclaveResponse {
            status: result,
            message: format!("Cgroup VM energy computation failed with status {}", result),
            ima_hash: None,
            output_data: None,
        }
    }
}

fn handle_compute_vm_energy_from_file(json: &str) -> EnclaveResponse {
    use std::fs;

    #[derive(Deserialize)]
    struct FileReq {
        #[allow(dead_code)]
        operation: String,
        file_path: String,
    }

    let request: FileReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse file request: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    debug_msg(&format!("[SGX-COMPUTE-FILE] Reading data from: {}", request.file_path));

    let file_content = match fs::read_to_string(&request.file_path) {
        Ok(content) => content,
        Err(e) => {
            return EnclaveResponse {
                status: -110,
                message: format!("Failed to read file {}: {}", request.file_path, e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    debug_msg(&format!("[SGX-COMPUTE-FILE] Read {} bytes from file", file_content.len()));

    handle_compute_vm_energy(&file_content)
}

fn handle_compute_host_energy(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct ComputeReq {
        #[allow(dead_code)]
        operation: String,
        pkg_data: String,
        dram_data: String,
    }

    let request: ComputeReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse compute_host_energy request: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    debug_msg("[SGX-COMPUTE] Computing total host energy inside SGX");

    let pkg_bytes = match hex::decode(&request.pkg_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Failed to decode pkg hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    let dram_bytes = match hex::decode(&request.dram_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -103,
                message: format!("Failed to decode dram hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };

    let mut output = vec![0u8; 256];
    let mut out_len: usize = 0;

    let result = ecall_compute_total_host_energy(
        pkg_bytes.as_ptr(),
        pkg_bytes.len(),
        dram_bytes.as_ptr(),
        dram_bytes.len(),
        output.as_mut_ptr(),
        output.len(),
        &mut out_len,
    );

    if result == 0 && out_len > 0 {
        output.truncate(out_len);

        match String::from_utf8(output) {
            Ok(energy_str) => EnclaveResponse {
                status: 0,
                message: energy_str,
                ima_hash: None,
                output_data: None,
            },
            Err(_) => EnclaveResponse {
                status: -104,
                message: "Failed to decode output as string".to_string(),
                ima_hash: None,
                output_data: None,
            },
        }
    } else {
        EnclaveResponse {
            status: result,
            message: format!("Host energy computation failed with status {}", result),
            ima_hash: None,
            output_data: None,
        }
    }
}

fn handle_init_sealed_key() -> EnclaveResponse {
    debug_msg("[SGX-SEALED] init_sealed_key is a STUB - no key is sealed or unsealed here");
    EnclaveResponse {
        status: 0,
        message: "NOT IMPLEMENTED: sealed-key initialization is a stub; no key was sealed"
            .to_string(),
        ima_hash: None,
        output_data: None,
    }
}
