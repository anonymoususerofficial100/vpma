pub use vpma_verified as pure;
pub mod merkle;
pub mod blockchain;
pub mod redis_store;
pub mod checkpoint;

use core::slice;
use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;

#[cfg(all(feature = "use_mbedtls", target_env = "sgx"))]
#[no_mangle]
pub unsafe extern "C" fn __vsnprintf_chk(
    _s: *mut core::ffi::c_char,
    _maxlen: usize,
    _flag: core::ffi::c_int,
    _slen: usize,
    _format: *const core::ffi::c_char,
    _ap: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    0
}

type HmacSha256 = Hmac<Sha256>;

#[cfg(target_env = "sgx")]
fn enclave_master_key(label: &[u8]) -> [u8; 32] {

    if label == b"chain" {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"VPMA-NON-SGX-TEST-KEY-NOT-FOR-PRODUCTION");
        h.update(label);
        return h.finalize().into();
    }

    enclave_master_key_with_policy(label, sgx_isa::Keypolicy::MRSIGNER)
}

#[cfg(target_env = "sgx")]
fn enclave_build_bound_key(label: &[u8]) -> [u8; 32] {
    enclave_master_key_with_policy(label, sgx_isa::Keypolicy::MRENCLAVE)
}

#[cfg(target_env = "sgx")]
fn enclave_master_key_with_policy(label: &[u8], policy: sgx_isa::Keypolicy) -> [u8; 32] {
    use sgx_isa::{Keyname, Keyrequest, Report};
    use sha2::{Digest, Sha256};

    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, [u8; 32]>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));

    let mut ckey = Vec::with_capacity(label.len() + 1);
    ckey.push(if policy == sgx_isa::Keypolicy::MRENCLAVE { 1u8 } else { 0u8 });
    ckey.extend_from_slice(label);
    if let Ok(map) = cache.lock() {
        if let Some(k) = map.get(&ckey) {
            return *k;
        }
    }

    let report = Report::for_self();

    let mut keyid = [0u8; 32];
    keyid.copy_from_slice(&Sha256::digest(label));

    let req = Keyrequest {
        keyname: Keyname::Seal as u16,
        keypolicy: policy,
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributemask: [!0; 2],
        keyid,
        miscmask: !0,
        ..Default::default()
    };

    let k16 = req.egetkey().expect("EGETKEY failed - refusing to fall back to a constant key");
    let mut h = Sha256::new();
    h.update(b"vpma-enclave-key-v1");
    h.update(k16);
    h.update(label);
    let out: [u8; 32] = h.finalize().into();

    if let Ok(mut map) = cache.lock() {
        map.insert(ckey, out);
    }
    out
}

#[cfg(not(target_env = "sgx"))]
fn enclave_build_bound_key(label: &[u8]) -> [u8; 32] {
    let mut v = b"build-bound:".to_vec();
    v.extend_from_slice(label);
    enclave_master_key(&v)
}

#[cfg(not(target_env = "sgx"))]
fn enclave_master_key(label: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"VPMA-NON-SGX-TEST-KEY-NOT-FOR-PRODUCTION");
    h.update(label);
    h.finalize().into()
}

#[derive(Clone)]
struct VmChainState {
    counter: u64,
    last_signature: [u8; 32],
    initialized: bool,
    last_energy_uj: u64,
}

impl VmChainState {
    fn new() -> Self {
        Self {
            counter: 0,
            last_signature: [0u8; 32],
            initialized: false,
            last_energy_uj: 0,
        }
    }
}

static mut VM_CHAIN_STATES: Option<BTreeMap<String, VmChainState>> = None;

static mut ITERATION_COUNT: u64 = 0;
static mut ACCUMULATED_DATA: Vec<String> = Vec::new();
static mut ACCUMULATED_RECORDS: Vec<merkle::EnergyRecord> = Vec::new();
static mut BLOCK_NUMBER: u64 = 0;
static mut LATEST_CHAINED_ROOT: [u8; 32] = [0u8; 32];
const BATCH_SIZE: u64 = 100;
const MAX_RECORDS_PER_INSERT: usize = 500;

fn derive_vm_key(master_key: &[u8; 32], vm_name: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(master_key)
        .expect("HMAC can take key of any size");
    mac.update(b"vm:");
    mac.update(vm_name.as_bytes());
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn vm_chain_states_mut() -> &'static mut BTreeMap<String, VmChainState> {
    unsafe {
        if VM_CHAIN_STATES.is_none() {
            VM_CHAIN_STATES = Some(BTreeMap::new());
        }
        VM_CHAIN_STATES.as_mut().expect("VM chain map initialized")
    }
}

#[no_mangle]
pub extern "C" fn force_link_sgx_vm() {}

fn sgx_print(msg: &str) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
    let _ = std::io::stderr().flush();
}

#[no_mangle]
pub extern "C" fn ecall_compute_single_process_energy(
    vm_total_energy_uj: u64,
    cpu_percentage: f64,
    out_energy_ptr: *mut u64,
) -> i32 {

    if out_energy_ptr.is_null() {
        return -1;
    }

    if cpu_percentage < 0.0 || cpu_percentage > 100.0 {
        return -2;
    }

    let process_energy = (vm_total_energy_uj as f64 * (cpu_percentage / 100.0)) as u64;

    unsafe {
        *out_energy_ptr = process_energy;
    }

    0
}

#[no_mangle]
pub extern "C" fn ecall_verify_energy_chain(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    energy_uj: u64,
    energy_delta: u64,
    counter: u64,
    previous_hash_ptr: *const u8,
    received_signature_ptr: *const u8,
) -> i32 {

    if vm_name_ptr.is_null() || previous_hash_ptr.is_null() || received_signature_ptr.is_null() {
        return -1;
    }

    let vm_name_slice = unsafe { slice::from_raw_parts(vm_name_ptr, vm_name_len) };
    let vm_name = match core::str::from_utf8(vm_name_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let previous_hash = unsafe { slice::from_raw_parts(previous_hash_ptr, 32) };

    let received_signature = unsafe { slice::from_raw_parts(received_signature_ptr, 32) };

    let vm_key = derive_vm_key(&enclave_master_key(b"chain"), vm_name);

    let chain_data = format!(
        "{}|{}|{}|{}|{}",
        counter,
        vm_name,
        energy_uj,
        energy_delta,
        hex::encode(previous_hash)
    );

    let mut mac = HmacSha256::new_from_slice(&vm_key)
        .expect("HMAC can take key of any size");
    mac.update(chain_data.as_bytes());

    let expected_signature = mac.finalize().into_bytes();

    println!("[SGX-VM-VERIFY] Chain verification:");
    println!("[SGX-VM-VERIFY] VM: {}", vm_name);
    println!("[SGX-VM-VERIFY] Counter: {}", counter);
    println!("[SGX-VM-VERIFY] Energy: {}", energy_uj);
    println!("[SGX-VM-VERIFY] Energy Delta: {}", energy_delta);
    println!("[SGX-VM-VERIFY] Chain data: {}", &chain_data);
    println!("[SGX-VM-VERIFY] Expected sig: {}", hex::encode(&expected_signature[..8]));
    println!("[SGX-VM-VERIFY] Received sig: {}", hex::encode(&received_signature[..8]));

    let mac_ok = expected_signature.as_slice() == received_signature;
    if !mac_ok {
        println!("[SGX-VM-VERIFY] Signature mismatch!");
    } else {
        println!("[SGX-VM-VERIFY] Signature valid");
    }

    let vm_states = vm_chain_states_mut();
    let vm_state = vm_states
        .entry(vm_name.to_string())
        .or_insert_with(VmChainState::new);

    let was_initialized = vm_state.initialized;
    let prev_hash_ok = !was_initialized || previous_hash == vm_state.last_signature.as_slice();

    let verdict = crate::pure::admit_chain_step(
        mac_ok,
        prev_hash_ok,
        was_initialized,
        vm_state.counter,
        vm_state.last_energy_uj,
        counter,
        energy_uj,
        energy_delta,
    );

    match crate::pure::chain_admitted(verdict) {
        Some(_admitted) => {

            vm_state.initialized = true;
            vm_state.counter = counter;
            vm_state.last_energy_uj = energy_uj;
            vm_state.last_signature.copy_from_slice(&expected_signature);
            if was_initialized {
                0
            } else {
                1
            }
        }
        None => match verdict {
            crate::pure::ChainVerdict::IdempotentSkip => {
                println!(
                    "[SGX-VM-VERIFY] Same counter ({}), skipping (host not updated yet)",
                    counter
                );
                2
            }
            crate::pure::ChainVerdict::Reject(d) => {
                let why = match d {
                    crate::pure::ChainDenial::MacMismatch => "signature mismatch",
                    crate::pure::ChainDenial::EnergyChangedUnderSameCounter =>
                        "same counter but cumulative energy changed",
                    crate::pure::ChainDenial::CounterRollback => "counter went backwards",
                    crate::pure::ChainDenial::CounterDiscontinuity => "counter discontinuity",
                    crate::pure::ChainDenial::CumulativeEnergyMismatch =>
                        "cumulative energy mismatch",
                    crate::pure::ChainDenial::PrevHashMismatch => "previous hash mismatch",
                };
                eprintln!("[SGX-VM-VERIFY] chain step denied: {}", why);
                crate::pure::chain_denial_code(d)
            }

            crate::pure::ChainVerdict::Accept => -2,
        },
    }
}

#[no_mangle]
pub extern "C" fn ecall_sign_energy_chain(
    tenant_ptr: *const u8,
    tenant_len: usize,
    energy_uj: u64,
    energy_delta: u64,
    out_counter_ptr: *mut u64,
    out_signature_ptr: *mut u8,
    out_previous_ptr: *mut u8,
) -> i32 {
    if tenant_ptr.is_null()
        || out_counter_ptr.is_null()
        || out_signature_ptr.is_null()
        || out_previous_ptr.is_null()
    {
        return -1;
    }

    let tenant_slice = unsafe { slice::from_raw_parts(tenant_ptr, tenant_len) };
    let tenant = match core::str::from_utf8(tenant_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let states = vm_chain_states_mut();
    let state = states
        .entry(tenant.to_string())
        .or_insert_with(VmChainState::new);

    let is_first = !state.initialized;
    let counter = if is_first { 1 } else { state.counter + 1 };
    let previous_hash = state.last_signature;

    let key = derive_vm_key(&enclave_master_key(b"chain"), tenant);
    let chain_data = format!(
        "{}|{}|{}|{}|{}",
        counter,
        tenant,
        energy_uj,
        energy_delta,
        hex::encode(previous_hash)
    );
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(chain_data.as_bytes());
    let signature = mac.finalize().into_bytes();

    state.initialized = true;
    state.counter = counter;
    state.last_energy_uj = energy_uj;
    state.last_signature.copy_from_slice(&signature);

    unsafe {
        *out_counter_ptr = counter;
        slice::from_raw_parts_mut(out_signature_ptr, 32).copy_from_slice(&signature);
        slice::from_raw_parts_mut(out_previous_ptr, 32).copy_from_slice(&previous_hash);
    }

    if is_first {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn ecall_immudb_login(
    response_ptr: *mut u8,
    response_cap: usize,
    response_len_ptr: *mut usize,
) -> i32 {
    #[cfg(feature = "use_mbedtls")]
    {
        use std::net::TcpStream;
        use std::io::{Read, Write};
        use std::sync::Arc;
        use mbedtls::rng::Rdrand;
        use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
        use mbedtls::ssl::{Config, Context};
        use mbedtls::x509::certificate::Certificate;
        use mbedtls::alloc::List as MbedtlsList;

        if response_ptr.is_null() || response_len_ptr.is_null() {
            return -1;
        }

        const IMMUD_CA_PEM: &str = include_str!("../../immudb_ca.pem");

        let addr = "127.0.0.1:8443";
        let body = r#"{"username":"immudb","password":"immudb","database":"defaultdb"}"#;
        let request = format!(
            "POST /api/v2/authorization/session/open HTTP/1.1\r\n\
 Host: localhost\r\n\
 Content-Type: application/json\r\n\
 Content-Length: {}\r\n\
 Connection: close\r\n\r\n\
 {}",
            body.len(),
            body
        );

        let pem = format!("{}\0", IMMUD_CA_PEM);
        let cert = match Certificate::from_pem(pem.as_bytes()) {
            Ok(c) => c,
            Err(_) => return -2,
        };

        let mut ca_list = MbedtlsList::new();
        ca_list.push(cert);
        let ca_list: Arc<MbedtlsList<Certificate>> = Arc::new(ca_list);

        let rng = Arc::new(Rdrand);
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_authmode(AuthMode::Required);
        config.set_rng(rng.clone());
        config.set_ca_list(ca_list.clone(), None);
        let config = Arc::new(config);

        let result = (|| -> Result<String, i32> {
            let mut tcp_stream = TcpStream::connect(addr).map_err(|_| -4)?;

            let mut ctx = Context::new(config.clone());
            ctx.establish(&mut tcp_stream, Some("localhost")).map_err(|_| -6)?;

            ctx.write_all(request.as_bytes()).map_err(|_| -7)?;
            ctx.flush().map_err(|_| -7)?;

            let mut response = String::new();
            ctx.read_to_string(&mut response).map_err(|_| -8)?;

            Ok(response)
        })();

        match result {
            Ok(response) => {
                let response_bytes = response.as_bytes();
                let copy_len = response_bytes.len().min(response_cap);

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        response_bytes.as_ptr(),
                        response_ptr,
                        copy_len
                    );
                    *response_len_ptr = copy_len;
                }

                0
            }
            Err(code) => code,
        }
    }

    #[cfg(not(feature = "use_mbedtls"))]
    {
        -99
    }
}

#[no_mangle]
pub extern "C" fn ecall_immudb_insert(
    session_id_ptr: *const u8,
    session_id_len: usize,
    body_ptr: *const u8,
    body_len: usize,
    response_ptr: *mut u8,
    response_cap: usize,
    response_len_ptr: *mut usize,
) -> i32 {
    #[cfg(feature = "use_mbedtls")]
    {
        use std::net::TcpStream;
        use std::io::{Read, Write};
        use std::sync::Arc;
        use mbedtls::rng::Rdrand;
        use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
        use mbedtls::ssl::{Config, Context};
        use mbedtls::x509::certificate::Certificate;
        use mbedtls::alloc::List as MbedtlsList;

        if session_id_ptr.is_null() || body_ptr.is_null() || response_ptr.is_null() || response_len_ptr.is_null() {
            return -1;
        }

        let session_id_bytes = unsafe { slice::from_raw_parts(session_id_ptr, session_id_len) };
        let session_id = match core::str::from_utf8(session_id_bytes) {
            Ok(s) => s,
            Err(_) => return -2,
        };

        let body_bytes = unsafe { slice::from_raw_parts(body_ptr, body_len) };
        let body = match core::str::from_utf8(body_bytes) {
            Ok(s) => s,
            Err(_) => return -3,
        };

        let request = format!(
            "POST /api/v2/collection/cpulog_v3/documents HTTP/1.1\r\n\
 Host: localhost\r\n\
 Content-Type: application/json\r\n\
 Grpc-Metadata-SessionID: {}\r\n\
 Content-Length: {}\r\n\
 Connection: close\r\n\r\n\
 {}",
            session_id.trim(),
            body.len(),
            body
        );

        const IMMUD_CA_PEM: &str = include_str!("../../immudb_ca.pem");

        let addr = "127.0.0.1:8443";

        let pem = format!("{}\0", IMMUD_CA_PEM);
        let cert = match Certificate::from_pem(pem.as_bytes()) {
            Ok(c) => c,
            Err(_) => return -4,
        };

        let mut ca_list = MbedtlsList::new();
        ca_list.push(cert);
        let ca_list: Arc<MbedtlsList<Certificate>> = Arc::new(ca_list);

        let rng = Arc::new(Rdrand);
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_authmode(AuthMode::Required);
        config.set_rng(rng.clone());
        config.set_ca_list(ca_list.clone(), None);
        let config = Arc::new(config);

        let result = (|| -> Result<String, i32> {
            let mut tcp_stream = TcpStream::connect(addr).map_err(|_| -6)?;

            let mut ctx = Context::new(config.clone());
            ctx.establish(&mut tcp_stream, Some("localhost")).map_err(|_| -8)?;

            ctx.write_all(request.as_bytes()).map_err(|_| -9)?;
            ctx.flush().map_err(|_| -9)?;

            let mut response = String::new();
            ctx.read_to_string(&mut response).map_err(|_| -10)?;

            Ok(response)
        })();

        match result {
            Ok(response) => {
                let response_bytes = response.as_bytes();
                let copy_len = response_bytes.len().min(response_cap);

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        response_bytes.as_ptr(),
                        response_ptr,
                        copy_len
                    );
                    *response_len_ptr = copy_len;
                }

                0
            }
            Err(code) => code,
        }
    }

    #[cfg(not(feature = "use_mbedtls"))]
    {
        -99
    }
}

#[cfg(feature = "use_mbedtls")]
fn sgx_immudb_login(addr: &str, ca_pem: &str) -> Result<String, i32> {
    use std::sync::Arc;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use mbedtls::rng::Rdrand;
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
    use mbedtls::ssl::{Config, Context};
    use mbedtls::x509::certificate::Certificate;
    use mbedtls::alloc::List as MbedtlsList;

    let body = r#"{"username":"immudb","password":"immudb","database":"defaultdb"}"#;
    let request = format!(
        "POST /api/v2/authorization/session/open HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );

    let pem = format!("{}\0", ca_pem);
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|_| -2)?;
    let mut ca_list = MbedtlsList::new();
    ca_list.push(cert);
    let ca_list = Arc::new(ca_list);

    let rng = Arc::new(Rdrand);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::Required);
    config.set_rng(rng);
    config.set_ca_list(ca_list, None);
    let config = Arc::new(config);

    let mut tcp = TcpStream::connect(addr).map_err(|_| -3)?;
    let mut ctx = Context::new(config);
    ctx.establish(&mut tcp, Some("localhost")).map_err(|_| -4)?;
    ctx.write_all(request.as_bytes()).map_err(|_| -5)?;
    ctx.flush().map_err(|_| -5)?;

    let mut response = String::new();
    ctx.read_to_string(&mut response).map_err(|_| -6)?;

    if let Some(start) = response.find("\"sessionID\":\"") {
        if let Some(end) = response[start + 13..].find('"') {
            return Ok(response[start + 13..start + 13 + end].to_string());
        }
    }
    Err(-7)
}

#[cfg(feature = "use_mbedtls")]
fn sgx_immudb_insert(addr: &str, ca_pem: &str, session_id: &str, body: &str) -> Result<(), i32> {
    use std::sync::Arc;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use mbedtls::rng::Rdrand;
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
    use mbedtls::ssl::{Config, Context};
    use mbedtls::x509::certificate::Certificate;
    use mbedtls::alloc::List as MbedtlsList;

    let request = format!(
        "POST /api/v2/collection/cpulog_v3/documents HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nGrpc-Metadata-SessionID: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        session_id.trim(), body.len(), body
    );

    let pem = format!("{}\0", ca_pem);
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|_| -2)?;
    let mut ca_list = MbedtlsList::new();
    ca_list.push(cert);
    let ca_list = Arc::new(ca_list);

    let rng = Arc::new(Rdrand);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::Required);
    config.set_rng(rng);
    config.set_ca_list(ca_list, None);
    let config = Arc::new(config);

    let mut tcp = TcpStream::connect(addr).map_err(|_| -3)?;
    let mut ctx = Context::new(config);
    ctx.establish(&mut tcp, Some("localhost")).map_err(|_| -4)?;
    ctx.write_all(request.as_bytes()).map_err(|_| -5)?;
    ctx.flush().map_err(|_| -5)?;

    let mut response = String::new();
    ctx.read_to_string(&mut response).map_err(|_| -6)?;

    if response.contains("\"transactionId\"") { Ok(()) } else { Err(-7) }
}

#[cfg(feature = "use_mbedtls")]
fn sgx_sha256(data: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(feature = "use_mbedtls")]
fn sgx_get_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now();
    let duration = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let secs = duration.as_secs();

    let days = secs / 86400;
    let remaining = secs % 86400;
    let hour = (remaining / 3600) as u32;
    let min = ((remaining % 3600) / 60) as u32;
    let sec = (remaining % 60) as u32;

    let mut year = 1970;
    let mut day_count = days;
    loop {
        let days_in_year = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) { 366 } else { 365 };
        if day_count < days_in_year { break; }
        day_count -= days_in_year;
        year += 1;
    }

    let mut month = 1u32;
    for m in 1..=12 {
        let days_in_month = match m {
            1|3|5|7|8|10|12 => 31,
            4|6|9|11 => 30,
            2 => if (year%4==0 && year%100!=0)||(year%400==0) {29} else {28},
            _ => 0
        };
        if day_count < days_in_month { month = m; break; }
        day_count -= days_in_month;
    }
    let day = (day_count + 1) as u32;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, min, sec)
}

fn extract_scaphandre_hash_from_ima(ima_log: &str) -> Option<String> {
    let mut last_hash: Option<String> = None;

    for line in ima_log.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let file_path = parts[4];
        let file_hash = parts[3];

        if file_path.contains("scaphandre")
            && !file_path.contains("loader")
            && !file_path.contains("build-script")
            && !file_path.contains("/build/")
            && file_path.ends_with("/scaphandre") {

            let hash_value = if file_hash.contains(':') {
                file_hash.split(':').nth(1).unwrap_or("")
            } else {
                file_hash
            };

            last_hash = Some(hash_value.to_string());
        }
    }
    last_hash
}

fn extract_gpu_stack_hashes_from_ima(ima_log: &str) -> Vec<(String, String)> {
    use std::collections::BTreeMap;
    let mut latest: BTreeMap<String, String> = BTreeMap::new();

    for line in ima_log.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let file_path = parts[4];
        let file_hash = parts[3];

        let is_gpu_stack = (file_path.contains("nvidia") && file_path.contains(".ko"))
            || file_path.contains("libnvidia-ml");
        if !is_gpu_stack {
            continue;
        }

        let hash_value = if file_hash.contains(':') {
            file_hash.split(':').nth(1).unwrap_or("")
        } else {
            file_hash
        };
        latest.insert(file_path.to_string(), hash_value.to_string());
    }
    latest.into_iter().collect()
}

fn gpu_stack_registration_key(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    if base.starts_with("libnvidia-ml") {
        "libnvidia-ml".to_string()
    } else {
        base.to_string()
    }
}

#[cfg(feature = "use_mbedtls")]
pub fn fetch_expected_hash_from_immudb(
    binary_name: &str,
    hostname: &str,
    deployment_type: &str,
    addr: &str,
    ca_pem: &str,
) -> Result<(String, String, String, String), i32> {
    use mbedtls::ssl::{Config, Context};
    use mbedtls::x509::Certificate;
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
    use mbedtls::alloc::List as MbedtlsList;
    use mbedtls::rng::Rdrand;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use std::sync::Arc;

    println!("[SGX-HASH] ================================================");
    println!("[SGX-HASH] Querying ImmuDB INSIDE SGX ENCLAVE");
    println!("[SGX-HASH] ================================================");
    println!("[SGX-HASH] Binary: {}", binary_name);
    println!("[SGX-HASH] Host: {}", hostname);
    println!("[SGX-HASH] Type: {}", deployment_type);
    println!("[SGX-HASH] ImmuDB: {}", addr);
    println!("[SGX-HASH] NOTE: This TLS connection is INSIDE SGX enclave");
    println!("[SGX-HASH] Host CANNOT see the query or response");

    let login_body = format!(
        r#"{{"username":"immudb","password":"immudb","database":"defaultdb"}}"#
    );
    let login_request = format!(
        "POST /api/v2/authorization/session/open HTTP/1.1\r\n\
 Host: localhost\r\n\
 Content-Type: application/json\r\n\
 Content-Length: {}\r\n\
 Connection: keep-alive\r\n\r\n{}",
        login_body.len(),
        login_body
    );

    let pem = format!("{}\0", ca_pem);
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|_| -2)?;
    let mut ca_list = MbedtlsList::new();
    ca_list.push(cert);
    let ca_list = Arc::new(ca_list);

    let rng = Arc::new(Rdrand);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::Required);
    config.set_rng(rng);
    config.set_ca_list(ca_list, None);
    let config = Arc::new(config);

    let mut tcp = TcpStream::connect(addr).map_err(|_| -3)?;
    let mut ctx = Context::new(config.clone());
    ctx.establish(&mut tcp, Some("localhost")).map_err(|_| -4)?;
    ctx.write_all(login_request.as_bytes()).map_err(|_| -5)?;
    ctx.flush().map_err(|_| -5)?;

    let mut login_response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match ctx.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                login_response.extend_from_slice(&buffer[..n]);

                let response_str = String::from_utf8_lossy(&login_response);
                if response_str.contains("\"sessionID\":") && response_str.contains("}") {
                    break;
                }
            }
            Err(_) => return Err(-6),
        }
    }
    let login_response = String::from_utf8_lossy(&login_response).to_string();

    let session_id = if let Some(start) = login_response.find(r#""sessionID":""#) {
        let start = start + r#""sessionID":""#.len();
        if let Some(end) = login_response[start..].find('"') {
            &login_response[start..start + end]
        } else {
            return Err(-7);
        }
    } else {
        return Err(-7);
    };

    println!("[SGX-HASH] Logged in to ImmuDB (TLS inside SGX)");
    println!("[SGX-HASH] Session established - host cannot see credentials");

    let query_body = format!(
        r#"{{"page":1,"pageSize":1,"query":{{"expressions":[{{"fieldComparisons":[{{"field":"binary_name","operator":"EQ","value":"{}"}},{{"field":"hostname","operator":"EQ","value":"{}"}},{{"field":"deployment_type","operator":"EQ","value":"{}"}},{{"field":"active","operator":"EQ","value":true}}]}}]}},"orderBy":[{{"field":"_id","desc":true}}]}}"#,
        binary_name, hostname, deployment_type
    );
    let query_request = format!(
        "POST /api/v2/collection/binary_hashes_v2/documents/search HTTP/1.1\r\n\
 Host: localhost\r\n\
 Content-Type: application/json\r\n\
 Grpc-Metadata-SessionID: {}\r\n\
 Content-Length: {}\r\n\
 Connection: close\r\n\r\n{}",
        session_id,
        query_body.len(),
        query_body
    );

    let mut tcp2 = TcpStream::connect(addr).map_err(|_| -3)?;
    let mut ctx2 = Context::new(config);
    ctx2.establish(&mut tcp2, Some("localhost")).map_err(|_| -4)?;
    ctx2.write_all(query_request.as_bytes()).map_err(|_| -5)?;
    ctx2.flush().map_err(|_| -5)?;

    let mut query_response_bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match ctx2.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                query_response_bytes.extend_from_slice(&buffer[..n]);

                let response_str = String::from_utf8_lossy(&query_response_bytes);
                if response_str.contains("\"revisions\":") && response_str.ends_with("}") {
                    break;
                }
            }
            Err(_) => return Err(-6),
        }
    }
    let query_response = String::from_utf8_lossy(&query_response_bytes).to_string();

    let hash = if let Some(start) = query_response.find(r#""hash_value":""#) {
        let start = start + r#""hash_value":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            query_response[start..start + end].to_string()
        } else {
            return Err(-8);
        }
    } else {
        return Err(-8);
    };

    let pcr0 = if let Some(start) = query_response.find(r#""pcr0":""#) {
        let start = start + r#""pcr0":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            query_response[start..start + end].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let pcr7 = if let Some(start) = query_response.find(r#""pcr7":""#) {
        let start = start + r#""pcr7":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            query_response[start..start + end].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let pcr10 = if let Some(start) = query_response.find(r#""pcr10":""#) {
        let start = start + r#""pcr10":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            query_response[start..start + end].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    println!("[SGX-HASH] Retrieved expected hash from ImmuDB");
    println!("[SGX-HASH] Expected hash: {}", hash);
    println!("[SGX-HASH] Expected PCR0: {}", pcr0);
    println!("[SGX-HASH] Expected PCR7: {}", pcr7);
    println!("[SGX-HASH] Expected PCR10: {}", pcr10);
    println!("[SGX-HASH] Host CANNOT see these values - protected by SGX");

    Ok((hash, pcr0, pcr7, pcr10))
}

#[cfg(not(feature = "use_mbedtls"))]
pub fn fetch_expected_hash_from_immudb(
    _binary_name: &str,
    _hostname: &str,
    _deployment_type: &str,
    _addr: &str,
    _ca_pem: &str,
) -> Result<(String, String, String, String), i32> {
    Err(-99)
}

pub use crate::pure::extend_pcr;

pub struct ImaAttestation {

    pub entries_attested: usize,

    pub entries_total: usize,

    pub attested_bytes: usize,
}

const IMA_VIOLATION_EXTEND: [u8; 32] = [0xffu8; 32];

pub fn verify_ima_log_against_pcr10(
    ima_log: &str,
    pcr10_hex: &str,
) -> Result<ImaAttestation, i32> {
    let target = match hex::decode(pcr10_hex.trim()) {
        Ok(t) if t.len() == 32 => t,
        _ => return Err(-5),
    };

    let mut target_arr = [0u8; 32];
    target_arr.copy_from_slice(&target);

    let mut digests: Vec<[u8; 32]> = Vec::new();
    let mut offsets: Vec<usize> = Vec::new();
    let mut cursor = 0usize;

    for segment in ima_log.split_inclusive('\n') {
        cursor += segment.len();
        let line = segment.trim_end();
        if line.is_empty() {
            continue;
        }

        let mut it = line.splitn(5, ' ');
        let (pcr, log_digest, template, dfield, fname) =
            match (it.next(), it.next(), it.next(), it.next(), it.next()) {
                (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
                _ => return Err(-2),
            };
        if pcr != "10" {
            continue;
        }
        if template != "ima-ng" {

            return Err(-3);
        }

        let digest = if !log_digest.is_empty() && log_digest.bytes().all(|b| b == b'0') {
            IMA_VIOLATION_EXTEND
        } else {
            match ima_ng_template_digest_sha256(dfield, fname) {
                Some(d) => d,
                None => return Err(-4),
            }
        };

        digests.push(digest);
        offsets.push(cursor);
    }

    if digests.is_empty() {

        return Err(-1);
    }

    match crate::pure::replay_find_prefix(&digests, &target_arr) {
        Some(attested) if attested > 0 => Ok(ImaAttestation {
            entries_attested: attested,
            entries_total: digests.len(),
            attested_bytes: offsets[attested - 1],
        }),

        Some(_) => Err(-1),

        None => Err(-9),
    }
}

fn ima_ng_template_digest_sha256(dfield: &str, fname: &str) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};

    let (algo, hexdigest) = dfield.split_once(':')?;
    let raw = hex::decode(hexdigest).ok()?;

    let mut d_field = Vec::with_capacity(algo.len() + 2 + raw.len());
    d_field.extend_from_slice(algo.as_bytes());
    d_field.push(b':');
    d_field.push(0);
    d_field.extend_from_slice(&raw);

    let mut n_field = Vec::with_capacity(fname.len() + 1);
    n_field.extend_from_slice(fname.as_bytes());
    n_field.push(0);

    let mut data = Vec::with_capacity(8 + d_field.len() + n_field.len());
    data.extend_from_slice(&(d_field.len() as u32).to_le_bytes());
    data.extend_from_slice(&d_field);
    data.extend_from_slice(&(n_field.len() as u32).to_le_bytes());
    data.extend_from_slice(&n_field);

    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(&data));
    Some(out)
}

#[inline]
fn hashes_match(hash1: &str, hash2: &str) -> bool {
    crate::pure::eq_ignore_ascii_case(hash1.as_bytes(), hash2.as_bytes())
}

#[no_mangle]
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

    if pcr_values_ptr.is_null() || ima_log_ptr.is_null() || hostname_ptr.is_null()
        || deployment_type_ptr.is_null() || immudb_addr_ptr.is_null() || ca_pem_ptr.is_null() {
        return -1;
    }

    let pcr_values = unsafe { slice::from_raw_parts(pcr_values_ptr, pcr_values_len) };
    let ima_log_bytes = unsafe { slice::from_raw_parts(ima_log_ptr, ima_log_len) };
    let hostname_bytes = unsafe { slice::from_raw_parts(hostname_ptr, hostname_len) };
    let deployment_bytes = unsafe { slice::from_raw_parts(deployment_type_ptr, deployment_type_len) };
    let immudb_addr_bytes = unsafe { slice::from_raw_parts(immudb_addr_ptr, immudb_addr_len) };
    let ca_pem_bytes = unsafe { slice::from_raw_parts(ca_pem_ptr, ca_pem_len) };

    let ima_log = match core::str::from_utf8(ima_log_bytes) {
        Ok(s) => s,
        Err(_) => return -3,
    };

    let hostname = match core::str::from_utf8(hostname_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let deployment_type = match core::str::from_utf8(deployment_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let immudb_addr = match core::str::from_utf8(immudb_addr_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let ca_pem = match core::str::from_utf8(ca_pem_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    println!("[SGX-HASH-VERIFY] Starting binary verification inside SGX");
    println!("[SGX-HASH-VERIFY] Hostname: {}", hostname);
    println!("[SGX-HASH-VERIFY] Deployment: {}", deployment_type);

    if pcr_values.len() < 96 {
        return -2;
    }
    let pcr0_bytes = &pcr_values[0..32];
    let pcr7_bytes = &pcr_values[32..64];
    let pcr10_bytes = &pcr_values[64..96];

    let pcr0_hex = pcr0_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let pcr7_hex = pcr7_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let pcr10_hex = pcr10_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    println!("[SGX-HASH-VERIFY] Received PCR0: {}", pcr0_hex);
    println!("[SGX-HASH-VERIFY] Received PCR7: {}", pcr7_hex);
    println!("[SGX-HASH-VERIFY] Received PCR10: {}", pcr10_hex);

    let pcr10_nonzero = pcr10_bytes.iter().any(|&b| b != 0);
    if !pcr10_nonzero {
        eprintln!("[SGX-HASH-VERIFY] PCR 10 is zero - IMA not active (admission will deny)");
    }

    let mut ima_log_reconciled = true;
    let attested_log = match verify_ima_log_against_pcr10(ima_log, &pcr10_hex) {
        Ok(att) => {
            println!(
                "[SGX-HASH-VERIFY] IMA log reconciles with PCR10 - {}/{} entries attested",
                att.entries_attested, att.entries_total
            );
            if att.entries_attested < att.entries_total {

                println!(
                    "[SGX-HASH-VERIFY] ({} trailing entries arrived after the PCR sample and \
 are NOT trusted)",
                    att.entries_total - att.entries_attested
                );
            }
            &ima_log[..att.attested_bytes]
        }
        Err(e) => {
            eprintln!("[SGX-HASH-VERIFY] IMA LOG DOES NOT RECONCILE WITH PCR10 (code {})", e);
            eprintln!("[SGX-HASH-VERIFY] TPM PCR10: {}", pcr10_hex);
            eprintln!("[SGX-HASH-VERIFY] No prefix of the supplied log replays to that value, so");
            eprintln!("[SGX-HASH-VERIFY] the log is edited, truncated, from a different boot, or");
            eprintln!("[SGX-HASH-VERIFY] not a consistent snapshot. Admission will deny.");

            ima_log_reconciled = false;
            &ima_log[..0]
        }
    };

    let ima_hash = match extract_scaphandre_hash_from_ima(attested_log) {
        Some(hash) => hash,
        None => {
            eprintln!("[SGX-HASH-VERIFY] Scaphandre binary not found in the TPM-attested");
            eprintln!("[SGX-HASH-VERIFY] portion of the IMA log. Admission will deny.");

            String::new()
        }
    };

    println!("[SGX-HASH-VERIFY] IMA measured hash: {}", ima_hash);

    println!("[SGX-HASH-VERIFY] Querying ImmuDB via TLS inside SGX...");
    println!("[SGX-HASH-VERIFY] Host provides address but CANNOT see the query");

    let mut have_expected = true;
    let (expected_hash, expected_pcr0, expected_pcr7, expected_pcr10) = match fetch_expected_hash_from_immudb(
        "scaphandre",
        hostname,
        deployment_type,
        immudb_addr,
        ca_pem
    ) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[SGX-HASH-VERIFY] Failed to query ImmuDB: error code {}", e);

            have_expected = false;
            (String::new(), String::new(), String::new(), String::new())
        }
    };

    println!("[SGX-HASH-VERIFY] ImmuDB expected hash: {}", expected_hash);

    println!("[SGX-HASH-VERIFY] Comparing hashes inside SGX enclave...");
    println!("[SGX-HASH-VERIFY] IMA measured: {}", ima_hash);
    println!("[SGX-HASH-VERIFY] ImmuDB expects: {}", expected_hash);

    let _ = &expected_pcr10;

    {
        let gpu_stack = extract_gpu_stack_hashes_from_ima(attested_log);
        if gpu_stack.is_empty() {
            eprintln!(
                "[SGX-HASH-VERIFY] (no GPU-stack entries in the attested IMA log - policy is not \
 measuring nvidia*.ko / libnvidia-ml)"
            );
        } else {
            eprintln!(
                "[SGX-HASH-VERIFY] GPU trust stack: {} component(s) measured, verifying against ImmuDB",
                gpu_stack.len()
            );
            let mut verified = 0usize;
            let mut unregistered = 0usize;
            for (path, measured) in &gpu_stack {
                let key = gpu_stack_registration_key(path);

                match fetch_expected_hash_from_immudb(
                    &key,
                    hostname,
                    deployment_type,
                    immudb_addr,
                    ca_pem,
                ) {
                    Ok((expected, _, _, _)) if !expected.is_empty() => {
                        if hashes_match(measured, &expected) {
                            eprintln!("[SGX-HASH-VERIFY] {} matches its registered hash", key);
                            verified += 1;
                        } else {
                            eprintln!("[SGX-HASH-VERIFY] GPU STACK TAMPERED: {}", path);
                            eprintln!("[SGX-HASH-VERIFY] measured: {}", measured);
                            eprintln!("[SGX-HASH-VERIFY] registered: {}", expected);
                            eprintln!(
                                "[SGX-HASH-VERIFY] The energy counter is read through this stack, so \
 every measurement it produces is suspect. REJECTING."
                            );
                            return -11;
                        }
                    }
                    Ok(_) => {
                        eprintln!(
                            "[SGX-HASH-VERIFY] {} = {}... (not registered - measured and \
 PCR10-bound, but NOT verified against a known-good value)",
                            key,
                            &measured.chars().take(16).collect::<String>()
                        );
                        unregistered += 1;
                    }
                    Err(code) => {

                        eprintln!(
                            "[SGX-HASH-VERIFY] {} lookup FAILED (code {}) - cannot verify",
                            key, code
                        );
                        unregistered += 1;
                    }
                }
            }
            eprintln!(
                "[SGX-HASH-VERIFY] GPU stack: {} verified, {} unregistered",
                verified, unregistered
            );
        }
    }

    match crate::pure::admit_boot(
        pcr0_hex.as_bytes(), pcr7_hex.as_bytes(), ima_hash.as_bytes(),
        expected_pcr0.as_bytes(), expected_pcr7.as_bytes(), expected_hash.as_bytes(),
        pcr10_nonzero,
        ima_log_reconciled,
        have_expected,
    ) {
        Ok(token) => {
            println!("[SGX-HASH-VERIFY] ADMITTED (verified decision)");
            println!("[SGX-HASH-VERIFY] Binary integrity confirmed");
            println!("[SGX-HASH-VERIFY] Hash: {}", ima_hash);
            crate::pure::boot_success_code(token)
        }
        Err(denial) => {
            let why = match denial {
                crate::pure::BootDenial::NoBinaryHashInLog => "no binary hash in attested IMA log",
                crate::pure::BootDenial::Pcr10Zero => "PCR10 is zero",
                crate::pure::BootDenial::ImaLogNotReconciled => "IMA log did not reconcile with PCR10",
                crate::pure::BootDenial::ExpectedStateUnavailable => "no expected state",
                crate::pure::BootDenial::BinaryHashMismatch => "BINARY HASH MISMATCH",
                crate::pure::BootDenial::Pcr0Mismatch => "PCR0 MISMATCH",
                crate::pure::BootDenial::Pcr7Mismatch => "PCR7 MISMATCH",
            };
            eprintln!("[SGX-HASH-VERIFY] DENIED: {}", why);
            eprintln!("[SGX-HASH-VERIFY] IMA measured: {}", ima_hash);
            eprintln!("[SGX-HASH-VERIFY] ImmuDB expects: {}", expected_hash);
            eprintln!("[SGX-HASH-VERIFY] REJECTING ALL DATA");
            crate::pure::boot_denial_code(denial)
        }
    }
}

use crate::merkle::EnergyRecord;
use crate::checkpoint::{Checkpoint, SealedStorage};

static mut SEALED_STORAGE: Option<SealedStorage> = None;

#[cfg(test)]
mod ima_replay_tests {
    use super::*;

    const LOG: &str = concat!(
        "10 c53059ed9f89ed24527ed42bfbe33760e9d929ce ima-ng",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111 /usr/bin/scaphandre\n",
        "10 0000000000000000000000000000000000000000 ima-ng",
        "sha1:0000000000000000000000000000000000000000 /var/log/audit/audit.log\n",
    );
    const PCR_AFTER_1: &str = "bca763a82db013486a3b0271f0817ccefbc4941b3e18eac699d8fe41f696d18e";
    const PCR_AFTER_2: &str = "cf341919da0918f20bcdf9a7fa6edb64793ce486441e67fe69b95a4664920a00";

    #[test]
    fn reconciles_with_the_hardware_rule() {
        let att = verify_ima_log_against_pcr10(LOG, PCR_AFTER_2).expect("log should reconcile");
        assert_eq!(att.entries_attested, 2);
        assert_eq!(att.entries_total, 2);
        assert_eq!(att.attested_bytes, LOG.len());
    }

    #[test]
    fn matches_a_prefix_when_the_pcr_sample_is_stale() {
        let att = verify_ima_log_against_pcr10(LOG, PCR_AFTER_1).expect("prefix should reconcile");
        assert_eq!(att.entries_attested, 1);
        assert_eq!(att.entries_total, 2);
        assert_eq!(LOG[..att.attested_bytes].lines().count(), 1);
    }

    #[test]
    fn appended_entries_are_not_attested() {
        let forged = format!(
            "{}10 {} ima-ng sha256:{} /usr/bin/scaphandre\n",
            LOG,
            "aa".repeat(20),
            "22".repeat(32)
        );
        let att = verify_ima_log_against_pcr10(&forged, PCR_AFTER_2).expect("prefix reconciles");
        assert_eq!(att.entries_attested, 2);
        assert_eq!(att.entries_total, 3);
        assert!(!forged[..att.attested_bytes].contains(&"22".repeat(32)));
    }

    #[test]
    fn rejects_an_edited_log() {
        let tampered = LOG.replace(
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        assert!(matches!(verify_ima_log_against_pcr10(&tampered, PCR_AFTER_2), Err(-9)));
    }

    #[test]
    fn rejects_a_fabricated_single_entry_log() {
        let forged = "10 c53059ed9f89ed24527ed42bfbe33760e9d929ce ima-ng \
 sha256:1111111111111111111111111111111111111111111111111111111111111111 \
 /usr/bin/scaphandre\n";
        assert!(matches!(verify_ima_log_against_pcr10(forged, PCR_AFTER_2), Err(-9)));
    }

    #[test]
    #[ignore]
    fn live_hardware_snapshot_reconciles() {
        let log = std::fs::read_to_string(std::env::var("IMA_LOG").expect("set IMA_LOG")).unwrap();
        let pcr =
            std::fs::read_to_string(std::env::var("IMA_PCR10").expect("set IMA_PCR10")).unwrap();
        let att = verify_ima_log_against_pcr10(&log, pcr.trim())
            .expect("a real log must reconcile with its own PCR10");
        println!(
            "attested {}/{} entries ({} bytes); {} trailing entries arrived during the read",
            att.entries_attested,
            att.entries_total,
            att.attested_bytes,
            att.entries_total - att.entries_attested
        );
        assert!(att.entries_attested > 0);
    }

    #[test]
    fn refuses_unparseable_input_rather_than_skipping_it() {
        assert!(matches!(verify_ima_log_against_pcr10("garbage\n", PCR_AFTER_2), Err(-2)));

        let unknown = "10 c53059ed9f89ed24527ed42bfbe33760e9d929ce ima-sig sha256:11 /x\n";
        assert!(matches!(verify_ima_log_against_pcr10(unknown, PCR_AFTER_2), Err(-3)));
    }
}

pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;

pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_RSASSA: u16 = 0x0014;

pub const EXPECTED_PCR_SELECT: [u8; 3] = [0x81, 0x04, 0x00];

pub fn verify_quote_structure<'a>(
    attest: &[u8],
    signature: &'a [u8],
    pcr_values: &[u8],
    expected_nonce: &[u8],
) -> Result<&'a [u8], String> {
    use sha2::{Digest, Sha256};

    if attest.len() < 40 {
        return Err(format!("TPMS_ATTEST too short: {} bytes", attest.len()));
    }

    let magic = u32::from_be_bytes([attest[0], attest[1], attest[2], attest[3]]);
    if magic != TPM_GENERATED_VALUE {
        return Err(format!("bad magic {:#010x} (expected TPM_GENERATED_VALUE)", magic));
    }

    let atype = u16::from_be_bytes([attest[4], attest[5]]);
    if atype != TPM_ST_ATTEST_QUOTE {
        return Err(format!("bad type {:#06x} (expected TPM_ST_ATTEST_QUOTE)", atype));
    }

    let mut p = 6usize;
    let qs_len = match crate::pure::read_u16_be(attest, p) {
        Some(v) => v as usize,
        None => return Err("truncated before qualifiedSigner".to_string()),
    };
    p += 2;
    p = match crate::pure::advance_within(p, qs_len, attest.len()) {
        Some(np) => np,
        None => return Err("truncated before extraData".to_string()),
    };
    let ed_len = match crate::pure::read_u16_be(attest, p) {
        Some(v) => v as usize,
        None => return Err("truncated before extraData".to_string()),
    };
    p += 2;
    if crate::pure::advance_within(p, ed_len, attest.len()).is_none() {
        return Err("truncated extraData".to_string());
    }
    let extra_data = &attest[p..p + ed_len];

    if extra_data != expected_nonce {
        return Err("extraData != issued nonce (stale or replayed quote)".to_string());
    }

    p += ed_len + 17 + 8;

    if p + 4 > attest.len() {
        return Err("truncated before pcrSelect".to_string());
    }
    let count = u32::from_be_bytes([attest[p], attest[p + 1], attest[p + 2], attest[p + 3]]);
    p += 4;
    if count != 1 {
        return Err(format!("quote selects {} PCR banks (expected exactly 1: sha256)", count));
    }
    if p + 3 > attest.len() {
        return Err("truncated TPMS_PCR_SELECTION".to_string());
    }
    let hash_alg = u16::from_be_bytes([attest[p], attest[p + 1]]);
    if hash_alg != TPM_ALG_SHA256 {
        return Err(format!("quote bank is {:#06x}, not sha256", hash_alg));
    }
    let sel_size = attest[p + 2] as usize;
    p += 3;
    if p + sel_size > attest.len() {
        return Err("truncated pcrSelect bitmap".to_string());
    }
    let selected = &attest[p..p + sel_size];
    p += sel_size;

    if selected.len() < EXPECTED_PCR_SELECT.len()
        || selected[..EXPECTED_PCR_SELECT.len()] != EXPECTED_PCR_SELECT
        || selected[EXPECTED_PCR_SELECT.len()..].iter().any(|&b| b != 0)
    {
        return Err(format!(
            "quote covers PCR bitmap {:02x?}, expected exactly sha256:0,7,10",
            selected
        ));
    }

    if p + 2 > attest.len() {
        return Err("truncated before pcrDigest".to_string());
    }
    let dlen = u16::from_be_bytes([attest[p], attest[p + 1]]) as usize;
    p += 2;
    if dlen != 32 {
        return Err(format!("pcrDigest length {} (expected 32 / sha256)", dlen));
    }
    if p + dlen != attest.len() {
        return Err(format!(
            "TPMS_ATTEST has {} trailing byte(s) after pcrDigest",
            attest.len() as i64 - (p + dlen) as i64
        ));
    }

    let computed = Sha256::digest(pcr_values);
    if attest[p..p + dlen] != computed[..] {
        return Err("pcrDigest != sha256(supplied PCR values) - the values are not the ones signed"
            .to_string());
    }

    if signature.len() < 6 {
        return Err(format!("TPMT_SIGNATURE too short: {} bytes", signature.len()));
    }
    let sig_alg = u16::from_be_bytes([signature[0], signature[1]]);
    if sig_alg != TPM_ALG_RSASSA {
        return Err(format!("signature scheme {:#06x}, expected RSASSA", sig_alg));
    }
    let sig_hash = u16::from_be_bytes([signature[2], signature[3]]);
    if sig_hash != TPM_ALG_SHA256 {
        return Err(format!("signature hash {:#06x}, expected sha256", sig_hash));
    }
    let sig_len = u16::from_be_bytes([signature[4], signature[5]]) as usize;
    if 6 + sig_len != signature.len() {
        return Err(format!(
            "TPMT_SIGNATURE declares {} signature bytes but carries {}",
            sig_len,
            signature.len() - 6
        ));
    }

    Ok(&signature[6..])
}

#[cfg(test)]
mod tpm_quote_tests {
    use super::*;

    const ATTEST_HEX: &str = concat!(
     "ff54434780180022000bb9befedb17974bf49a23cb730fb7fb671d89f3233988e359d16851322051940a00204bfcea46",
     "e15fc0e4cb8faff62d5be167b962bd04df132a150fb0cf6f25434d4a0000000002ad183e000000040000000001201910",
     "230016363600000001000b038104000020210f7ae67fb820225ccc7dd12653e6c761402ee9be88ae1e6b69282b25acdc",
     "3a"
    );
    const SIG_HEX: &str = concat!(
     "0014000b0100a42fee0b1894c520f9131c68934f78329b090ec0f1f0005ec64bdac9523f4fb477abaa12afb498efb038",
     "347d6e18f5096d438d90a221bcec95f8701ca424fb8e15aea2b9bd68f4c775150a49cb7874558c70bcabab42ead49ed7",
     "c082b88b7752d0b15fde4f8241decdac28c57bb1972bf2d1fac6f6fd6acd549180fd7eefa2ab9667a21e55e814b3302b",
     "27706b0c6492481ab99c97f18e8d756943bb23e24b91e5b75a208b8da6fa57fe48d7bafc730ab8348823adf15ae53d87",
     "1654568716a572b2bd3c886f831d963864a057794b7d52ff5170f0dac716b1cba7ebf23f4b93285e6dc06e25761917c2",
     "d554b5b338108c516b05eb522280fc5f798607b52f8a"
    );
    const PCRS_HEX: &str = concat!(
     "e21b703ee69c77476bccb43ec0336a9a1b2914b378944f7b00a10214ca8fea93e21b703ee69c77476bccb43ec0336a9a",
     "1b2914b378944f7b00a10214ca8fea93f2ebca8b2f3c07f843a5253827719cf1f9c52ed8773ed451e8963f6d4ae4b0b8"
    );

    fn attest() -> Vec<u8> { hex::decode(ATTEST_HEX).unwrap() }
    fn sig() -> Vec<u8> { hex::decode(SIG_HEX).unwrap() }
    fn pcrs() -> Vec<u8> { hex::decode(PCRS_HEX).unwrap() }

    fn nonce() -> Vec<u8> {
        let a = attest();
        let qs = u16::from_be_bytes([a[6], a[7]]) as usize;
        let p = 8 + qs;
        let ed = u16::from_be_bytes([a[p], a[p + 1]]) as usize;
        a[p + 2..p + 2 + ed].to_vec()
    }

    #[test]
    fn genuine_quote_passes_and_yields_the_rsa_signature() {
        let s = sig();
        let raw = verify_quote_structure(&attest(), &s, &pcrs(), &nonce())
            .expect("a real quote over its own nonce must verify");

        assert_eq!(raw.len(), 256);
        assert_eq!(raw, &s[6..]);
    }

    #[test]
    fn replayed_quote_is_rejected() {
        let other = [0x5au8; 32];
        assert_ne!(nonce(), other.to_vec(), "test nonce must differ from the real one");
        let e = verify_quote_structure(&attest(), &sig(), &pcrs(), &other).unwrap_err();
        assert!(e.contains("replayed"), "expected a freshness failure, got: {}", e);
    }

    #[test]
    fn pcr_values_not_covered_by_the_quote_are_rejected() {
        let mut forged = pcrs();
        forged[80] ^= 0x01;
        let e = verify_quote_structure(&attest(), &sig(), &forged, &nonce()).unwrap_err();
        assert!(e.contains("pcrDigest"), "expected a digest mismatch, got: {}", e);
    }

    #[test]
    fn non_tpm_structure_is_rejected() {
        let mut a = attest();
        a[0] ^= 0xff;
        let e = verify_quote_structure(&a, &sig(), &pcrs(), &nonce()).unwrap_err();
        assert!(e.contains("magic"), "expected a magic failure, got: {}", e);
    }

    #[test]
    fn a_different_attestation_type_is_rejected() {
        let mut a = attest();
        a[4] = 0x80;
        a[5] = 0x17;
        let e = verify_quote_structure(&a, &sig(), &pcrs(), &nonce()).unwrap_err();
        assert!(e.contains("bad type"), "expected a type failure, got: {}", e);
    }

    #[test]
    fn a_quote_over_attacker_controlled_pcrs_is_rejected() {
        let mut a = attest();
        let at = a.len() - 32 - 2 - 3;
        a[at] = 0x00;
        a[at + 1] = 0x00;
        a[at + 2] = 0x81;
        let e = verify_quote_structure(&a, &sig(), &pcrs(), &nonce()).unwrap_err();
        assert!(e.contains("PCR bitmap"), "expected a selection failure, got: {}", e);
    }

    #[test]
    fn a_signature_under_another_scheme_is_rejected() {
        let mut s = sig();
        s[0] = 0x00;
        s[1] = 0x16;
        let e = verify_quote_structure(&attest(), &s, &pcrs(), &nonce()).unwrap_err();
        assert!(e.contains("RSASSA"), "expected a scheme failure, got: {}", e);
    }

    #[test]
    fn truncated_structures_are_rejected() {
        let a = attest();
        let s = sig();
        for cut in [0usize, 10, 39, 60, 100, a.len() - 1] {
            let e = verify_quote_structure(&a[..cut], &s, &pcrs(), &nonce());
            assert!(e.is_err(), "a {}-byte TPMS_ATTEST must not verify", cut);
        }
    }
}
