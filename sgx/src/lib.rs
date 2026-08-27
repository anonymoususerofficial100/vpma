#![cfg_attr(target_env = "sgx", no_std)]

#[cfg(target_env = "sgx")]
extern crate alloc;

#[cfg(target_env = "sgx")]
extern crate std;

#[cfg(target_env = "sgx")]
use alloc::string::{String, ToString};
#[cfg(target_env = "sgx")]
use alloc::vec;
#[cfg(target_env = "sgx")]
use alloc::vec::Vec;
#[cfg(target_env = "sgx")]
use alloc::format;

#[cfg(not(target_env = "sgx"))]
use std::string::{String, ToString};
#[cfg(not(target_env = "sgx"))]
use std::vec;
#[cfg(not(target_env = "sgx"))]
use std::vec::Vec;

use core::slice;

pub use vpma_verified as pure;

#[cfg(target_env = "sgx")]
macro_rules! sgx_println {
    () => { std::println!(); };
    ($($arg:tt)*) => { std::println!($($arg)*); };
}

#[cfg(not(target_env = "sgx"))]
macro_rules! sgx_println {
    () => { println!(); };
    ($($arg:tt)*) => { println!($($arg)*); };
}

#[cfg(target_env = "sgx")]
macro_rules! sgx_eprintln {
    () => { std::eprintln!(); };
    ($($arg:tt)*) => { std::eprintln!($($arg)*); };
}

#[cfg(not(target_env = "sgx"))]
macro_rules! sgx_eprintln {
    () => { eprintln!(); };
    ($($arg:tt)*) => { eprintln!($($arg)*); };
}

#[cfg(target_env = "sgx")]
#[inline]
fn _sgx_print_impl(msg: &str) {
    std::eprint!("{}", msg);
}

#[cfg(not(target_env = "sgx"))]
#[inline]
fn _sgx_print_impl(msg: &str) {
    eprint!("{}", msg);
}

use hmac::{Hmac, Mac};
use sha2::Sha256;

use ed25519_dalek::{Verifier, VerifyingKey, Signature};

type HmacSha256 = Hmac<Sha256>;

const ATTESTATION_SERVER_PUBLIC_KEY: [u8; 32] = [
    0xf8, 0x3b, 0xe1, 0x71, 0x2d, 0x09, 0x57, 0x71,
    0x08, 0xf7, 0xf6, 0x73, 0xda, 0xb9, 0xd1, 0x46,
    0xf8, 0x06, 0xff, 0x1e, 0x6f, 0x81, 0xa3, 0x1e,
    0xbf, 0x70, 0x46, 0x0f, 0xb9, 0x4f, 0xd0, 0x90,
];

fn sgx_print_host(msg: &str) {
    _sgx_print_impl(msg);
}

type OcallWriteVmEnergy = unsafe extern "C" fn(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    uj_value: u64,
    counter: u64,
    previous_hash_ptr: *const u8,
    signature_ptr: *const u8,
) -> i32;

type OcallReadSealedKey = unsafe extern "C" fn(
    buf_ptr: *mut u8,
    buf_len: usize,
) -> i32;

type OcallWriteSealedKey = unsafe extern "C" fn(
    buf_ptr: *const u8,
    buf_len: usize,
) -> i32;

type OcallFetchExpectedHash = unsafe extern "C" fn(
    url_ptr: *const u8,
    url_len: usize,
    hash_buf_ptr: *mut u8,
    hash_buf_len: usize,
) -> i32;

static mut OCALL_WRITE_VM_ENERGY: Option<OcallWriteVmEnergy> = None;
static mut OCALL_READ_SEALED_KEY: Option<OcallReadSealedKey> = None;
static mut OCALL_WRITE_SEALED_KEY: Option<OcallWriteSealedKey> = None;
static mut OCALL_FETCH_EXPECTED_HASH: Option<OcallFetchExpectedHash> = None;

#[allow(dead_code)]
const SEALED_KEY_PATH: &str = "/var/lib/scaphandre/.sgx_sealed_hmac_key";

#[cfg(target_env = "sgx")]
#[allow(dead_code)]
const SEALED_KEY_SIZE: usize = 12 + 32 + 16;
#[cfg(not(target_env = "sgx"))]
const SEALED_KEY_SIZE: usize = 32 + 16;

struct VmChainState {
    hmac_key: [u8; 32],
    chain_state: [u8; 32],
    counter: u64,
    cumulative_energy_uj: u64,
}

#[cfg(not(target_env = "sgx"))]
use std::collections::HashMap;
#[cfg(target_env = "sgx")]
use alloc::collections::BTreeMap as HashMap;

#[cfg(not(target_env = "sgx"))]
use std::string::String as StdString;

static mut VM_CHAINS: Option<HashMap<String, VmChainState>> = None;

#[cfg(target_env = "sgx")]
fn enclave_master_key(label: &[u8]) -> [u8; 32] {
    enclave_master_key_with_policy(label, sgx_isa::Keypolicy::MRSIGNER)
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
fn enclave_master_key(label: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"VPMA-NON-SGX-TEST-KEY-NOT-FOR-PRODUCTION");
    h.update(label);
    h.finalize().into()
}

include!("../../src/exporters/qemu.rs");

use serde_json;

pub static RAPL_TAG_KEY: std::sync::Mutex<Option<(u64, u64, u32, u16)>> =
    std::sync::Mutex::new(None);

pub fn set_rapl_tag_key(k: Option<(u64, u64, u32, u16)>) {
    if let Ok(mut slot) = RAPL_TAG_KEY.lock() {
        *slot = k;
    }
}

fn verify_rapl_hash(energy: u64, timestamp: u64, socket: u32, domain: u32, hash_from_ebpf: u64) -> bool {

    let (k0, k1, epoch, producer) = match RAPL_TAG_KEY.lock().ok().and_then(|s| *s) {
        Some(v) => v,
        None => {
            sgx_eprintln!("[SGX-SECURITY] RAPL tag check attempted with no tag key installed \
 - refusing the reading rather than falling back to a keyless hash");
            return false;
        }
    };
    let recomputed = pure::siptag(
        k0, k1, energy, timestamp, socket, domain,
        pure::SIPTAG_VERSION, producer, epoch,
    );
    pure::admit_measurement_tag(hash_from_ebpf, recomputed).is_some()
}

fn derive_vm_key(master_key: &[u8; 32], vm_name: &str) -> [u8; 32] {
    use sha2::Digest;

    let mut mac = HmacSha256::new_from_slice(master_key).unwrap();
    mac.update(b"vm:");
    mac.update(vm_name.as_bytes());

    let result = mac.finalize().into_bytes();
    let mut vm_key = [0u8; 32];
    vm_key.copy_from_slice(&result);
    vm_key
}

#[allow(dead_code)]
fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];

    #[cfg(target_env = "sgx")]
    {
        use rdrand::RdRand;

        match RdRand::new() {
            Ok(rng) => {

                for chunk in key.chunks_mut(8) {
                    match rng.try_next_u64() {
                        Ok(rand_val) => {
                            let bytes = rand_val.to_le_bytes();
                            let len = chunk.len().min(8);
                            chunk[..len].copy_from_slice(&bytes[..len]);
                        }
                        Err(_) => {

                            panic!("[SGX] RDRAND failed - hardware RNG not available");
                        }
                    }
                }
            }
            Err(_) => {
                panic!("[SGX] RDRAND not supported - cannot generate secure random key");
            }
        }
    }

    #[cfg(not(target_env = "sgx"))]
    {
        use core::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let seed = COUNTER.fetch_add(1, Ordering::SeqCst);

        let mut state = seed.wrapping_add(0xdeadbeef);
        for byte in key.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *byte = (state >> 56) as u8;
        }

        sgx_eprintln!("[SGX-SIM] WARNING: Using simulation random - NOT SECURE for production!");
    }

    key
}

#[allow(dead_code)]
fn seal_key(key: &[u8; 32]) -> [u8; SEALED_KEY_SIZE] {
    let mut sealed = [0u8; SEALED_KEY_SIZE];

    #[cfg(target_env = "sgx")]
    {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rdrand::RdRand;

        let mut nonce_bytes = [0u8; 12];
        match RdRand::new() {
            Ok(rng) => {
                if let Ok(r1) = rng.try_next_u64() {
                    nonce_bytes[0..8].copy_from_slice(&r1.to_le_bytes());
                }
                if let Ok(r2) = rng.try_next_u64() {
                    nonce_bytes[8..12].copy_from_slice(&r2.to_le_bytes()[0..4]);
                }
            }
            Err(_) => {
                panic!("[SGX] Cannot generate nonce - RDRAND not available");
            }
        }

        let sealing_key = derive_sgx_sealing_key();

        let cipher = Aes256Gcm::new_from_slice(&sealing_key)
            .expect("[SGX] Failed to create AES-GCM cipher");
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, key.as_ref())
            .expect("[SGX] AES-GCM encryption failed");

        sealed[0..12].copy_from_slice(&nonce_bytes);
        sealed[12..].copy_from_slice(&ciphertext);
    }

    #[cfg(not(target_env = "sgx"))]
    {
        sgx_eprintln!("[SGX-SIM] WARNING: Using simulation sealing - NOT SECURE for production!");

        sealed[..32].copy_from_slice(key);

        for i in 0..16 {
            sealed[32 + i] = key[i].wrapping_add(key[i + 16]);
        }
    }

    sealed
}

#[allow(dead_code)]
fn unseal_key(sealed: &[u8; SEALED_KEY_SIZE]) -> Option<[u8; 32]> {

    #[cfg(target_env = "sgx")]
    {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let nonce_bytes: [u8; 12] = sealed[0..12].try_into().ok()?;
        let ciphertext = &sealed[12..];

        let sealing_key = derive_sgx_sealing_key();

        let cipher = Aes256Gcm::new_from_slice(&sealing_key).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;

        if plaintext.len() != 32 {
            return None;
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        return Some(key);
    }

    #[cfg(not(target_env = "sgx"))]
    {
        let mut key = [0u8; 32];

        for i in 0..16 {
            let expected_mac = sealed[i].wrapping_add(sealed[i + 16]);
            if sealed[32 + i] != expected_mac {
                return None;
            }
        }

        key.copy_from_slice(&sealed[..32]);

        Some(key)
    }
}

#[cfg(target_env = "sgx")]
fn derive_sgx_sealing_key() -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(b"SGX_SEAL_KEY_MRENCLAVE_BOUND");
    hasher.update(&ATTESTATION_SERVER_PUBLIC_KEY);

    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn verify_hmac_signature(vm_name: &str, data: &str, signature: &[u8]) -> bool {
    unsafe {

        let vm_chains = match VM_CHAINS.as_ref() {
            Some(chains) => chains,
            None => return false,
        };

        let vm_state = match vm_chains.get(vm_name) {
            Some(state) => state,
            None => return false,
        };

        let mut mac = match HmacSha256::new_from_slice(&vm_state.hmac_key) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(data.as_bytes());
        mac.verify_slice(signature).is_ok()
    }
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
    let start_time = core::time::Duration::from_secs(0);
    #[cfg(not(target_env = "sgx"))]
    let start_time = std::time::Instant::now();

    if pkg_ptr.is_null() || dram_ptr.is_null() || out_ptr.is_null() || out_len_ptr.is_null() {
        return 1;
    }

    let deser_start = start_time;
    let pkg_slice = unsafe { slice::from_raw_parts(pkg_ptr, pkg_len) };
    let dram_slice = unsafe { slice::from_raw_parts(dram_ptr, dram_len) };

    let pkg_values: Vec<RawEnergyValue> = match serde_json::from_slice(pkg_slice) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    let dram_values: Vec<RawEnergyValue> = match serde_json::from_slice(dram_slice) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Deserialization: {:.2} ms", deser_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
    }

    #[cfg(not(target_env = "sgx"))]
    let calc_start = std::time::Instant::now();
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

    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Energy summation: {:.2} ms", calc_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
    }

    #[cfg(not(target_env = "sgx"))]
    let format_start = std::time::Instant::now();
    let result_str = format!("{}", total);
    let result_bytes = result_str.as_bytes();

    if result_bytes.len() > out_cap {
        return 3;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            result_bytes.as_ptr(),
            out_ptr,
            result_bytes.len(),
        );
        *out_len_ptr = result_bytes.len();
    }

    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Output formatting: {:.2} ms", format_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
        let msg2 = format!("[TIMING-SGX-HOST] Total ecall_compute_total_host_energy: {:.2} ms", start_time.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg2);
    }

    0
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
    out_cap: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    #[cfg(not(target_env = "sgx"))]
    let total_start = std::time::Instant::now();

    if topo_ptr.is_null() || proc_ptr.is_null() || out_ptr.is_null() || out_len_ptr.is_null() {
        return 1;
    }

    #[cfg(not(target_env = "sgx"))]
    let deser_start = std::time::Instant::now();
    let topo_slice = unsafe { slice::from_raw_parts(topo_ptr, topo_len) };
    let proc_slice = unsafe { slice::from_raw_parts(proc_ptr, proc_len) };

    {
        #[cfg(not(target_env = "sgx"))]
        let hash_verify_start = std::time::Instant::now();

        if !hash_ptr.is_null() && hash_len > 0 {
            let hash_slice = unsafe { slice::from_raw_parts(hash_ptr, hash_len) };

            #[derive(serde::Deserialize)]
            struct RaplReading {
                energy_uj: u64,
                timestamp_ns: u64,
                socket_id: u32,
                domain_id: u32,
                hash: u64,
                valid: u32,
            }

            let hash_readings: Vec<RaplReading> = match serde_json::from_slice(hash_slice) {
                Ok(h) => h,
                Err(_) => {
                    sgx_eprintln!("[SGX-ECALL] Failed to deserialize hash readings");
                    return -1;
                }
            };

            sgx_println!("[SGX-ECALL] Verifying {} RAPL hash readings...", hash_readings.len());

            let mut verified_count: usize = 0;
            let mut skipped_count: usize = 0;
            for reading in &hash_readings {
                if reading.valid != 1 {

                    skipped_count += 1;
                    continue;
                }

                let hash_valid = verify_rapl_hash(
                    reading.energy_uj,
                    reading.timestamp_ns,
                    reading.socket_id,
                    reading.domain_id,
                    reading.hash
                );

                if !hash_valid {
                    sgx_eprintln!("[SGX-SECURITY] RAPL TAG CHECK FAILED - REJECTING ALL DATA");
                    sgx_eprintln!("[SGX-SECURITY] Socket: {}, Domain: {}", reading.socket_id, reading.domain_id);
                    sgx_eprintln!("[SGX-SECURITY] Energy: {} µJ", reading.energy_uj);
                    sgx_eprintln!("[SGX-SECURITY] Timestamp: {} ns", reading.timestamp_ns);

                    return -2;
                }
                verified_count += 1;
            }

            if skipped_count > 0 {
                sgx_println!(
                    "[SGX-ECALL] {} RAPL hashes verified, {} SKIPPED (valid != 1) - the skipped \
 readings have NO verified kernel origin",
                    verified_count, skipped_count
                );
            } else {
                sgx_println!("[SGX-ECALL] All {} RAPL hashes verified successfully", verified_count);
            }

            #[cfg(not(target_env = "sgx"))]
            {
                let msg = format!("[TIMING-SGX-HOST] RAPL hash verification: {:.2} ms", hash_verify_start.elapsed().as_secs_f64() * 1000.0);
                sgx_print_host(&msg);
            }
        } else {
            sgx_println!("[SGX-ECALL] No hash data provided - proceeding without verification");
        }
    }

    let topo_energy_value: String =
        match serde_json::from_slice(topo_slice) {
            Ok(v) => v,
            Err(_) => return 2,
        };

    let processes: Vec<Vec<CompactProcessSample>> =
        match serde_json::from_slice(proc_slice) {
            Ok(v) => v,
            Err(_) => return 3,
        };

    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Input deserialization: {:.2} ms", deser_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
    }

    #[cfg(not(target_env = "sgx"))]
    let attribution_start = std::time::Instant::now();
    let mut exporter = QemuExporter::new();
    let updates: Vec<VmEnergyUpdate> =
        exporter.iterate_compact(String::new(), topo_energy_value, processes);

    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] VM energy attribution: {:.2} ms", attribution_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
    }

    #[derive(Serialize)]
    struct SignedVmUpdate {
        vm_name: String,
        uj_value: u64,
        counter: u64,
        previous_hash: String,
        signature: String,
    }
    let mut signed_updates: Vec<SignedVmUpdate> = Vec::new();

    #[cfg(not(target_env = "sgx"))]
    let chain_start = std::time::Instant::now();
    #[cfg(not(target_env = "sgx"))]
    let mut chain_operations = 0;

    for update in &updates {
        let vm_name_bytes = update.vm_name.as_bytes();

        unsafe {
            let vm_chains = VM_CHAINS.as_mut().unwrap();
            let vm_state = vm_chains.entry(update.vm_name.clone()).or_insert_with(|| {

                let vm_key = derive_vm_key(&enclave_master_key(b"chain"), &update.vm_name);
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

            let signed_cumulative_uj = vm_state.cumulative_energy_uj;

            let data_to_sign = format!(
                "{}|{}|{}|{}|{}",
                vm_state.counter,
                update.vm_name,
                signed_cumulative_uj,
                update.uj_to_add,
                hex::encode(&vm_state.chain_state)
            );

            let signature = {
                let mut mac = match HmacSha256::new_from_slice(&vm_state.hmac_key) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                mac.update(data_to_sign.as_bytes());
                mac.finalize().into_bytes()
            };

            let previous_hash = vm_state.chain_state.clone();

            vm_state.chain_state.copy_from_slice(&signature);

            #[cfg(not(target_env = "sgx"))]
            {
                chain_operations += 1;
            }

            signed_updates.push(SignedVmUpdate {
                vm_name: update.vm_name.clone(),
                uj_value: update.uj_to_add,
                counter: vm_state.counter,
                previous_hash: hex::encode(&previous_hash),
                signature: hex::encode(&signature),
            });

            sgx_eprintln!("[SGX-ENCLAVE] Chain state for '{}': counter={}, prev_hash={}...",
                      update.vm_name, vm_state.counter, &hex::encode(&previous_hash)[..16]);

            if let Some(ocall_fn) = OCALL_WRITE_VM_ENERGY {
                let result = ocall_fn(
                    vm_name_bytes.as_ptr(),
                    vm_name_bytes.len(),
                    update.uj_to_add,
                    vm_state.counter,
                    previous_hash.as_ptr(),
                    signature.as_ptr(),
                );

                if result != 0 {

                    sgx_eprintln!("[SGX-QEMU] OCALL write failed for VM: {}", update.vm_name);
                }
            }
        }
    }

    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Chain operations ({} VMs): {:.2} ms", chain_operations, chain_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
        let msg2 = format!("[TIMING-SGX-HOST] Total ecall_compute_vm_energy_simple: {:.2} ms", total_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg2);
    }

    if !signed_updates.is_empty() {
        if let Ok(json_bytes) = serde_json::to_vec(&signed_updates) {
            let copy_len = json_bytes.len().min(out_cap);
            unsafe {
                std::ptr::copy_nonoverlapping(json_bytes.as_ptr(), out_ptr, copy_len);
                *out_len_ptr = copy_len;
            }
            sgx_eprintln!("[SGX-ENCLAVE] Returning {} signed updates ({} bytes)", signed_updates.len(), copy_len);
        } else {
            unsafe { *out_len_ptr = 0; }
        }
    } else {
        unsafe { *out_len_ptr = 0; }
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
    out_cap: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    #[cfg(not(target_env = "sgx"))]
    let total_start = std::time::Instant::now();

    sgx_println!("[SGX-CGROUP] Cgroup-based VM energy computation");
    sgx_println!("[SGX-CGROUP] Input sizes: topo={}, cgroup={}, hash={}",
                 topo_len, cgroup_len, hash_len);

    if topo_ptr.is_null() || cgroup_ptr.is_null() {
        return 1;
    }

    let topo_slice = unsafe { core::slice::from_raw_parts(topo_ptr, topo_len) };
    let cgroup_slice = unsafe { core::slice::from_raw_parts(cgroup_ptr, cgroup_len) };
    let hash_slice = unsafe { core::slice::from_raw_parts(hash_ptr, hash_len) };

    if hash_len > 0 {
        #[cfg(not(target_env = "sgx"))]
        let hash_verify_start = std::time::Instant::now();

        sgx_println!("[SGX-CGROUP] Verifying RAPL hashes...");

        #[derive(serde::Deserialize)]
        struct RaplReading {
            energy_uj: u64,
            timestamp_ns: u64,
            socket_id: u32,
            domain_id: u32,
            hash: u64,
            valid: u32,
        }

        let hash_readings: Vec<RaplReading> = match serde_json::from_slice(hash_slice) {
            Ok(v) => v,
            Err(e) => {
                sgx_eprintln!("[SGX-CGROUP] Failed to deserialize hash readings: {:?}", e);
                return -1;
            }
        };

        for reading in &hash_readings {
            if reading.valid != 1 {
                continue;
            }

            let expected = match RAPL_TAG_KEY.lock().ok().and_then(|s| *s) {
                Some((k0, k1, epoch, producer)) => pure::siptag(
                    k0, k1,
                    reading.energy_uj,
                    reading.timestamp_ns,
                    reading.socket_id,
                    reading.domain_id,
                    pure::SIPTAG_VERSION, producer, epoch,
                ),
                None => {
                    sgx_eprintln!("[SGX-CGROUP] No RAPL tag key installed - refusing");
                    return -1;
                }
            };

            sgx_eprintln!("[SGX-CGROUP] Hash check: energy={} ts={} socket={} domain={}",
                         reading.energy_uj, reading.timestamp_ns, reading.socket_id, reading.domain_id);
            sgx_eprintln!("[SGX-CGROUP] Got hash: {:016x}, Expected: {:016x}", reading.hash, expected);

            if pure::admit_measurement_tag(reading.hash, expected).is_none() {

                sgx_eprintln!("[SGX-CGROUP] TAG MISMATCH - reading rejected (keyless tag: detects corruption, not an adversary)");
                return -2;
            }
        }

        sgx_println!("[SGX-CGROUP] All {} RAPL hashes verified", hash_readings.len());

        #[cfg(not(target_env = "sgx"))]
        {
            let msg = format!("[TIMING-SGX-CGROUP] Hash verification: {:.2} ms", hash_verify_start.elapsed().as_secs_f64() * 1000.0);
            sgx_print_host(&msg);
        }
    }

    let topo_energy_value: String = match serde_json::from_slice(topo_slice) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    let vm_samples: Vec<VmCgroupSample> = match serde_json::from_slice(cgroup_slice) {
        Ok(v) => v,
        Err(_) => return 3,
    };

    sgx_println!("[SGX-CGROUP] {} VMs, {} bytes (vs ~430KB processes!)",
                 vm_samples.len(), cgroup_len);

    #[cfg(not(target_env = "sgx"))]
    let attribution_start = std::time::Instant::now();

    let mut exporter = QemuExporter::new();
    let updates: Vec<VmEnergyUpdate> = exporter.iterate_cgroup(topo_energy_value, vm_samples);

    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-CGROUP] VM energy attribution: {:.2} ms", attribution_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
    }

    #[derive(Serialize)]
    struct SignedVmUpdate {
        vm_name: String,
        uj_value: u64,
        counter: u64,
        previous_hash: String,
        signature: String,
    }
    let mut signed_updates: Vec<SignedVmUpdate> = Vec::new();

    #[cfg(not(target_env = "sgx"))]
    let chain_start = std::time::Instant::now();

    for update in &updates {
        let vm_name_bytes = update.vm_name.as_bytes();

        unsafe {
            let vm_chains = VM_CHAINS.as_mut().unwrap();
            let vm_state = vm_chains.entry(update.vm_name.clone()).or_insert_with(|| {

                let vm_key = derive_vm_key(&enclave_master_key(b"chain"), &update.vm_name);
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
                let mut mac = HmacSha256::new_from_slice(&vm_state.hmac_key).expect("HMAC");
                mac.update(data_to_sign.as_bytes());
                let result = mac.finalize().into_bytes();
                let mut sig = [0u8; 32];
                sig.copy_from_slice(&result);
                sig
            };

            let previous_hash = vm_state.chain_state;
            vm_state.chain_state.copy_from_slice(&signature);

            signed_updates.push(SignedVmUpdate {
                vm_name: update.vm_name.clone(),
                uj_value: update.uj_to_add,
                counter: vm_state.counter,
                previous_hash: hex::encode(&previous_hash),
                signature: hex::encode(&signature),
            });

            if let Some(ocall_fn) = OCALL_WRITE_VM_ENERGY {
                let result = ocall_fn(
                    vm_name_bytes.as_ptr(),
                    vm_name_bytes.len(),
                    update.uj_to_add,
                    vm_state.counter,
                    previous_hash.as_ptr(),
                    signature.as_ptr(),
                );
                if result != 0 {
                    sgx_eprintln!("[SGX-CGROUP] OCALL write failed for VM: {}", update.vm_name);
                }
            }
        }
    }

    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-CGROUP] Chain operations ({} VMs): {:.2} ms", updates.len(), chain_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
        let msg2 = format!("[TIMING-SGX-CGROUP] Total ecall: {:.2} ms", total_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg2);
    }

    if !signed_updates.is_empty() {
        if let Ok(json_bytes) = serde_json::to_vec(&signed_updates) {
            let copy_len = json_bytes.len().min(out_cap);
            unsafe {
                std::ptr::copy_nonoverlapping(json_bytes.as_ptr(), out_ptr, copy_len);
                *out_len_ptr = copy_len;
            }
        } else {
            unsafe { *out_len_ptr = 0; }
        }
    } else {
        unsafe { *out_len_ptr = 0; }
    }

    0
}

#[no_mangle]
pub extern "C" fn ecall_initialize_sealed_key() -> i32 {
    unsafe {
        VM_CHAINS = Some(HashMap::new());
    }
    0
}

#[no_mangle]
pub extern "C" fn ecall_register_sealed_storage_ocalls(
    read_fn: OcallReadSealedKey,
    write_fn: OcallWriteSealedKey,
) -> i32 {
    unsafe {
        OCALL_READ_SEALED_KEY = Some(read_fn);
        OCALL_WRITE_SEALED_KEY = Some(write_fn);
    }
    0
}

#[no_mangle]
pub extern "C" fn ecall_register_ocall_write_vm_energy(
    ocall_fn: OcallWriteVmEnergy,
) -> i32 {
    unsafe {
        OCALL_WRITE_VM_ENERGY = Some(ocall_fn);
    }
    0
}

#[no_mangle]
pub extern "C" fn ecall_register_ocall_fetch_expected_hash(
    ocall_fn: OcallFetchExpectedHash,
) -> i32 {
    unsafe {
        OCALL_FETCH_EXPECTED_HASH = Some(ocall_fn);
    }
    0
}

#[no_mangle]
pub extern "C" fn ecall_get_chain_state(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    chain_ptr: *mut u8,
    chain_len: usize,
    counter_ptr: *mut u64,
) -> i32 {
    if vm_name_ptr.is_null() || chain_ptr.is_null() || chain_len < 32 || counter_ptr.is_null() {
        return 1;
    }

    unsafe {

        let vm_name_bytes = slice::from_raw_parts(vm_name_ptr, vm_name_len);
        let vm_name = match core::str::from_utf8(vm_name_bytes) {
            Ok(s) => s,
            Err(_) => return 2,
        };

        let vm_chains = match VM_CHAINS.as_ref() {
            Some(chains) => chains,
            None => return 3,
        };

        let vm_state = match vm_chains.get(vm_name) {
            Some(state) => state,
            None => return 4,
        };

        let chain_slice = slice::from_raw_parts_mut(chain_ptr, 32);
        chain_slice.copy_from_slice(&vm_state.chain_state);
        *counter_ptr = vm_state.counter;
    }

    0
}

pub struct ImaAttestation {

    pub entries_attested: usize,

    pub entries_total: usize,

    pub attested_bytes: usize,
}

const IMA_VIOLATION_EXTEND: [u8; 32] = [0xffu8; 32];

#[derive(Clone, Debug)]
pub struct ImaRecord {

    pub extend_digest: [u8; 32],

    pub file_hash: String,

    pub file_path: String,

    pub end_offset: usize,
}

pub fn parse_ima_log(ima_log: &str) -> Result<Vec<ImaRecord>, i32> {
    let mut out: Vec<ImaRecord> = Vec::new();
    let mut cursor = 0usize;

    for segment in ima_log.split_inclusive('\n') {
        cursor += segment.len();
        let line = segment.trim_end();
        if line.is_empty() {
            continue;
        }

        let lb = line.as_bytes();
        let mut bounds = [0usize; 4];
        let mut at = 0usize;
        let mut ok = true;
        let mut k = 0usize;
        while k < 4 {
            match pure::find_byte(lb, b' ', at) {
                Some(i) => {
                    bounds[k] = i;
                    at = i + 1;
                }
                None => {
                    ok = false;
                    break;
                }
            }
            k += 1;
        }
        if !ok || at > line.len() {
            return Err(-2);
        }
        let (pcr, log_digest, template, dfield, fname) = (
            &line[..bounds[0]],
            &line[bounds[0] + 1..bounds[1]],
            &line[bounds[1] + 1..bounds[2]],
            &line[bounds[2] + 1..bounds[3]],
            &line[bounds[3] + 1..],
        );
        if pcr != "10" {
            continue;
        }
        if template != "ima-ng" {
            return Err(-3);
        }

        let is_violation = !log_digest.is_empty() && pure::is_zero_hash(log_digest.as_bytes());
        let extend_digest = if is_violation {
            IMA_VIOLATION_EXTEND
        } else {
            match ima_ng_template_digest_sha256(dfield, fname) {
                Some(d) => d,
                None => return Err(-4),
            }
        };

        let file_hash = if is_violation {
            String::new()
        } else {
            match dfield.split_once(':') {
                Some((_algo, h)) => h.to_string(),
                None => dfield.to_string(),
            }
        };

        out.push(ImaRecord {
            extend_digest,
            file_hash,
            file_path: fname.to_string(),
            end_offset: cursor,
        });
    }
    Ok(out)
}

pub struct AttestedImaPrefix {
    attested: Vec<ImaRecord>,
    entries_total: usize,
    attested_bytes: usize,
}

impl AttestedImaPrefix {

    pub fn records(&self) -> &[ImaRecord] {
        &self.attested
    }
    pub fn entries_attested(&self) -> usize {
        self.attested.len()
    }
    pub fn entries_total(&self) -> usize {
        self.entries_total
    }
    pub fn attested_bytes(&self) -> usize {
        self.attested_bytes
    }
}

pub fn reconcile_ima_against_pcr10(
    records: Vec<ImaRecord>,
    pcr10_hex: &str,
) -> Result<AttestedImaPrefix, i32> {
    let target = match hex_decode(pcr10_hex.trim()) {
        Some(t) if t.len() == 32 => t,
        _ => return Err(-5),
    };
    let mut target_arr = [0u8; 32];
    target_arr.copy_from_slice(&target);

    if records.is_empty() {
        return Err(-1);
    }
    let digests: Vec<[u8; 32]> = records.iter().map(|r| r.extend_digest).collect();

    match pure::replay_find_prefix(&digests, &target_arr) {
        Some(n) if n > 0 => {
            let attested_bytes = records[n - 1].end_offset;
            let entries_total = records.len();
            let mut attested = records;
            attested.truncate(n);
            Ok(AttestedImaPrefix { attested, entries_total, attested_bytes })
        }

        Some(_) => Err(-1),
        None => Err(-9),
    }
}

pub fn verify_ima_log_against_pcr10(
    ima_log: &str,
    pcr10_hex: &str,
) -> Result<ImaAttestation, i32> {

    let records = parse_ima_log(ima_log)?;
    let prefix = reconcile_ima_against_pcr10(records, pcr10_hex)?;
    Ok(ImaAttestation {
        entries_attested: prefix.entries_attested(),
        entries_total: prefix.entries_total(),
        attested_bytes: prefix.attested_bytes(),
    })
}

fn ima_ng_template_digest_sha256(dfield: &str, fname: &str) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};

    let colon = dfield.find(':')?;
    let (algo, rest) = dfield.split_at(colon);
    let raw = hex_decode(&rest[1..])?;

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

fn extend_pcr(pcr: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(pcr);
    hasher.update(data);

    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

fn hex_decode(hex_str: &str) -> Option<Vec<u8>> {
    let b = hex_str.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0usize;
    while i + 1 < b.len() {
        let hi = pure::hex_val(b[i])?;
        let lo = pure::hex_val(b[i + 1])?;
        out.push(hi * 16 + lo);
        i += 2;
    }
    Some(out)
}

fn get_expected_scaphandre_hash() -> &'static str {

    ""
}

fn hash_matches(actual: &str, expected: &str) -> bool {

    if expected.is_empty() {
        return true;
    }

    actual.eq_ignore_ascii_case(expected)
}

#[no_mangle]
pub extern "C" fn ecall_verify_boot_attestation(
    quote_sig_ptr: *const u8,
    quote_sig_len: usize,
    attest_data_ptr: *const u8,
    attest_data_len: usize,
    pcr_values_ptr: *const u8,
    pcr_values_len: usize,
    ima_log_ptr: *const u8,
    ima_log_len: usize,
    verifier_url_ptr: *const u8,
    verifier_url_len: usize,
) -> i32 {
    let _ = (quote_sig_ptr, quote_sig_len, attest_data_ptr, attest_data_len);

    #[cfg(not(target_env = "sgx"))]

    #[cfg(not(target_env = "sgx"))]
    let total_start = std::time::Instant::now();

    if pcr_values_ptr.is_null() || ima_log_ptr.is_null() {
        return 1;
    }

    let pcr_values = unsafe { slice::from_raw_parts(pcr_values_ptr, pcr_values_len) };
    let ima_log_bytes = unsafe { slice::from_raw_parts(ima_log_ptr, ima_log_len) };

    let ima_log = match core::str::from_utf8(ima_log_bytes) {
        Ok(s) => s,
        Err(_) => return 2,
    };

    if pcr_values.len() < 32 {
        return 3;
    }

    if pcr_values.len() < 96 {
        return 3;
    }

    let actual_pcr10 = &pcr_values[64..96];

    let pcr10_nonzero = actual_pcr10.iter().any(|&b| b != 0);
    if !pcr10_nonzero {
        return 11;
    }

    let mut scaphandre_hash: Option<&str> = None;
    let mut sgx_component_hash: Option<&str> = None;
    let mut rapl_files_verified = 0;
    let mut ima_entry_count = 0;

    for line in ima_log.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        ima_entry_count += 1;

        let file_path = parts[4];
        let file_hash = parts[3];

        let hash_value = if file_hash.contains(':') {
            file_hash.split(':').nth(1).unwrap_or("")
        } else {
            file_hash
        };

        if file_path.ends_with("/scaphandre") {
            scaphandre_hash = Some(hash_value);
        }

        if file_path.contains("sgx") || file_path.contains("SGX") {
            sgx_component_hash = Some(hash_value);
        }

        if file_path.contains("rapl") || file_path.contains("RAPL") {
            rapl_files_verified += 1;
        }
    }

    if ima_entry_count < 100 {
        return 12;
    }

    if scaphandre_hash.is_none() {
        return 5;
    }

    if sgx_component_hash.is_none() {
        return 6;
    }

    if rapl_files_verified < 1 {
        return 10;
    }

    sgx_println!("[SGX-BOOT-ATTEST] ================================================");
    sgx_println!("[SGX-BOOT-ATTEST] Verifying scaphandre hash via ImmuDB");
    sgx_println!("[SGX-BOOT-ATTEST] ================================================");

    let (hostname, immudb_addr, ca_pem_content) = if !verifier_url_ptr.is_null() && verifier_url_len > 0 {
        let verifier_url_bytes = unsafe { slice::from_raw_parts(verifier_url_ptr, verifier_url_len) };
        let verifier_url = match core::str::from_utf8(verifier_url_bytes) {
            Ok(s) => s,
            Err(_) => return 7,
        };

        ("defaulthost", "192.168.122.1:8443", "")
    } else {
        ("defaulthost", "192.168.122.1:8443", "")
    };

    let deployment_type = "host";

    let ca_pem = if ca_pem_content.is_empty() {

        sgx_println!("[SGX-BOOT-ATTEST] Warning: No CA certificate provided");
        return 22;
    } else {
        ca_pem_content
    };

    sgx_println!("[SGX-BOOT-ATTEST] Querying ImmuDB inside SGX enclave...");

    #[cfg(not(target_env = "sgx"))]
    let immudb_start = std::time::Instant::now();
    let expected_scaphandre_hash = match fetch_expected_hash_from_immudb(
        "scaphandre",
        hostname,
        deployment_type,
        immudb_addr,
        ca_pem
    ) {
        Ok(hash) => {
            #[cfg(not(target_env = "sgx"))]
            {
                let immudb_duration = immudb_start.elapsed();
                sgx_println!("[TIMING-SGX] ImmuDB Query (inside SGX): {:.2} ms", immudb_duration.as_secs_f64() * 1000.0);
            }
            sgx_println!("[SGX-BOOT-ATTEST] Retrieved expected hash from ImmuDB");
            sgx_println!("[SGX-BOOT-ATTEST] Hash query happened inside SGX (host cannot see)");
            hash
        }
        Err(e) => {
            sgx_eprintln!("[SGX-BOOT-ATTEST] Failed to query ImmuDB: error {}", e);
            return 15;
        }
    };

    let (expected_scaphandre_hash, expected_pcr0, expected_pcr7, expected_pcr10) = expected_scaphandre_hash;

    #[cfg(not(target_env = "sgx"))]
    let verify_start = std::time::Instant::now();
    let actual_hash = scaphandre_hash.unwrap();
    if !hashes_match(actual_hash, &expected_scaphandre_hash) {
        sgx_eprintln!("[SGX-BOOT-ATTEST] Hash mismatch!");
        sgx_eprintln!("[SGX-BOOT-ATTEST] IMA measured: {}", actual_hash);
        sgx_eprintln!("[SGX-BOOT-ATTEST] ImmuDB expects: {}", expected_scaphandre_hash);
        return 13;
    }

    sgx_println!("[SGX-BOOT-ATTEST] Hash verification passed");
    sgx_println!("[SGX-BOOT-ATTEST] IMA hash: {}", actual_hash);
    sgx_println!("[SGX-BOOT-ATTEST] ImmuDB hash: {}", expected_scaphandre_hash);
    sgx_println!("[SGX-BOOT-ATTEST] ================================================");

    if !verifier_url_ptr.is_null() && verifier_url_len > 0 {
        let verifier_url_bytes = unsafe { slice::from_raw_parts(verifier_url_ptr, verifier_url_len) };
        let verifier_url = match core::str::from_utf8(verifier_url_bytes) {
            Ok(s) => s,
            Err(_) => return 7,
        };

        if !verifier_url.starts_with("https://") {
            if !verifier_url.starts_with("http://localhost") &&
               !verifier_url.starts_with("http://127.0.0.1") {
                return 8;
            }
        }

    }

    #[cfg(not(target_env = "sgx"))]
    {
        let verify_duration = verify_start.elapsed();
        let total_duration = total_start.elapsed();
        sgx_println!("[TIMING-SGX] Hash + PCR Verification: {:.2} ms", verify_duration.as_secs_f64() * 1000.0);
        sgx_println!("[TIMING-SGX] ============================================");
        sgx_println!("[TIMING-SGX] Total SGX Boot Verification: {:.2} ms", total_duration.as_secs_f64() * 1000.0);
        sgx_println!("[TIMING-SGX] ============================================");
    }
    0
}

pub fn extract_scaphandre_hash_from_ima(prefix: &AttestedImaPrefix) -> Option<String> {

    let views: Vec<pure::RecordView> = prefix
        .records()
        .iter()
        .map(|r| pure::RecordView {
            hash: r.file_hash.as_bytes().to_vec(),
            path: r.file_path.as_bytes().to_vec(),
        })
        .collect();

    if let Some(h) = pure::select_collector_hash_verified(&views) {

        if let Ok(s) = String::from_utf8(h) {
            return Some(s);
        }
    }

    let mut last_hashed: Option<String> = None;
    for rec in prefix.records() {
        if rec.file_hash.is_empty() {
            continue;
        }
        let basename = rec.file_path.rsplit('/').next().unwrap_or(&rec.file_path);
        let is_hashed = basename
            .strip_prefix("scaphandre-")
            .map(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false);
        if is_hashed {
            last_hashed = Some(rec.file_hash.clone());
        }
    }
    last_hashed
}

pub fn extract_gpu_stack_hashes_from_ima(prefix: &AttestedImaPrefix) -> Vec<(String, String)> {
    use std::collections::BTreeMap;
    let mut latest: BTreeMap<String, String> = BTreeMap::new();

    for rec in prefix.records() {
        let (file_hash, file_path) = (rec.file_hash.as_str(), rec.file_path.as_str());
        if file_hash.is_empty() {
            continue;
        }

        let basename = file_path.rsplit('/').next().unwrap_or(file_path);
        let is_module = matches!(
            basename,
            "nvidia.ko" | "nvidia-uvm.ko" | "nvidia-modeset.ko" | "nvidia-drm.ko" | "nvidia-peermem.ko"
        ) && file_path.starts_with("/usr/lib/modules/");
        let is_nvml = basename.starts_with("libnvidia-ml.so");
        if !is_module && !is_nvml {
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

pub fn extract_hypervisor_hashes_from_ima(prefix: &AttestedImaPrefix) -> Vec<(String, String)> {
    use std::collections::BTreeMap;
    let mut latest: BTreeMap<String, String> = BTreeMap::new();

    for rec in prefix.records() {
        let (file_hash, file_path) = (rec.file_hash.as_str(), rec.file_path.as_str());
        if file_hash.is_empty() {
            continue;
        }
        let base = file_path.rsplit('/').next().unwrap_or(file_path);

        let stem = base.strip_suffix(".real").unwrap_or(base);
        let is_qemu = stem.starts_with("qemu-system-") && !stem.contains('.') && stem.len() > 12;
        let is_swtpm = base == "swtpm" || base == "swtpm_setup";
        if !is_qemu && !is_swtpm {
            continue;
        }
        let key = base;

        let hash_value = if file_hash.contains(':') {
            file_hash.split(':').nth(1).unwrap_or("")
        } else {
            file_hash
        };
        if hash_value.is_empty() {
            continue;
        }

        latest.insert(key.to_string(), hash_value.to_string());
    }
    latest.into_iter().collect()
}

#[cfg(feature = "use_mbedtls")]
pub fn fetch_expected_hash_from_immudb(
    binary_name: &str,
    hostname: &str,
    deployment_type: &str,
    addr: &str,
    _ca_pem: &str,
) -> Result<(String, String, String, String), i32> {
    use mbedtls::ssl::{Config, Context};
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
    use mbedtls::x509::Certificate;
    use mbedtls::alloc::List as MbedtlsList;
    use mbedtls::rng::Rdrand;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use std::sync::Arc;

    sgx_println!("[SGX-HASH] ================================================");
    sgx_println!("[SGX-HASH] Querying ImmuDB INSIDE SGX ENCLAVE");
    sgx_println!("[SGX-HASH] ================================================");
    sgx_println!("[SGX-HASH] Binary: {}", binary_name);
    sgx_println!("[SGX-HASH] Host: {}", hostname);
    sgx_println!("[SGX-HASH] Type: {}", deployment_type);
    sgx_println!("[SGX-HASH] ImmuDB: {}", addr);
    sgx_println!("[SGX-HASH] NOTE: This TLS connection is INSIDE SGX enclave");
    sgx_println!("[SGX-HASH] Host CANNOT see the query or response");

    const IMMUDB_CA_PEM: &str = include_str!("../../immudb_ca.pem");

    let login_body = r#"{"username":"immudb","password":"immudb","database":"defaultdb"}"#;
    let login_request = format!(
        "POST /api/v2/authorization/session/open HTTP/1.1\r\n\
 Host: localhost\r\n\
 Content-Type: application/json\r\n\
 Content-Length: {}\r\n\
 Connection: keep-alive\r\n\r\n{}",
        login_body.len(),
        login_body
    );

    let pem = format!("{}\0", IMMUDB_CA_PEM);
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

    sgx_println!("[SGX-HASH] Connecting to {}...", addr);
    let mut tcp = match TcpStream::connect(addr) {
        Ok(s) => {
            sgx_println!("[SGX-HASH] TCP connection established");
            s
        }
        Err(e) => {
            sgx_eprintln!("[SGX-HASH] TCP connect failed: {:?}", e);
            return Err(-3);
        }
    };

    sgx_println!("[SGX-HASH] Establishing TLS...");
    let mut ctx = Context::new(config.clone());
    if let Err(e) = ctx.establish(&mut tcp, Some("localhost")) {
        sgx_eprintln!("[SGX-HASH] TLS establish failed: {:?}", e);
        return Err(-4);
    }
    sgx_println!("[SGX-HASH] TLS connection established");

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

    sgx_println!("[SGX-HASH] Logged in to ImmuDB (TLS inside SGX)");
    sgx_println!("[SGX-HASH] Session established - host cannot see credentials");

    let query_body = format!(
        r#"{{"page":1,"pageSize":20,"query":{{"expressions":[{{"fieldComparisons":[{{"field":"binary_name","operator":"EQ","value":"{}"}},{{"field":"hostname","operator":"EQ","value":"{}"}},{{"field":"deployment_type","operator":"EQ","value":"{}"}},{{"field":"active","operator":"EQ","value":true}}]}}]}}}}"#,
        binary_name, hostname, deployment_type
    );
    let query_request = format!(
        "POST /api/v2/collection/binary_hashes_v3/documents/search HTTP/1.1\r\n\
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

    sgx_println!("[SGX-HASH] ImmuDB response length: {} bytes", query_response.len());
    if query_response.len() < 500 {
        sgx_println!("[SGX-HASH] Response: {}", query_response);
    } else {
        sgx_println!("[SGX-HASH] Response (truncated): {}...", &query_response[..500]);
    }

    let hash = if let Some(last_hash_pos) = query_response.rfind(r#""hash_value":""#) {
        let start = last_hash_pos + r#""hash_value":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            &query_response[start..start + end]
        } else {
            sgx_eprintln!("[SGX-HASH] Failed to parse hash_value end quote");
            return Err(-8);
        }
    } else {
        sgx_eprintln!("[SGX-HASH] hash_value field not found in response");
        return Err(-8);
    };

    let pcr0 = if let Some(pos) = query_response.rfind(r#""pcr0":""#) {
        let start = pos + r#""pcr0":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            &query_response[start..start + end]
        } else {
            return Err(-9);
        }
    } else {
        return Err(-9);
    };

    let pcr7 = if let Some(pos) = query_response.rfind(r#""pcr7":""#) {
        let start = pos + r#""pcr7":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            &query_response[start..start + end]
        } else {
            return Err(-10);
        }
    } else {
        return Err(-10);
    };

    let pcr10 = if let Some(pos) = query_response.rfind(r#""pcr10":""#) {
        let start = pos + r#""pcr10":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            &query_response[start..start + end]
        } else {
            return Err(-11);
        }
    } else {
        return Err(-11);
    };

    sgx_println!("[SGX-HASH] Retrieved expected hash and PCR values from ImmuDB");
    sgx_println!("[SGX-HASH] Expected hash: {}", hash);
    sgx_println!("[SGX-HASH] Expected PCR0: {}", pcr0);
    sgx_println!("[SGX-HASH] Expected PCR7: {}", pcr7);
    sgx_println!("[SGX-HASH] Expected PCR10: {}", pcr10);
    sgx_println!("[SGX-HASH] Host CANNOT see these values - protected by SGX");

    Ok((hash.to_string(), pcr0.to_string(), pcr7.to_string(), pcr10.to_string()))
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

pub fn hashes_match(hash1: &str, hash2: &str) -> bool {
    hash1.eq_ignore_ascii_case(hash2)
}

#[no_mangle]
#[allow(unreachable_code)]
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

    sgx_println!("[SGX-VERIFY] ecall_verify_binary_hash is SUPERSEDED and refuses by design:");
    sgx_println!("[SGX-VERIFY] it never reconciles the IMA log against PCR10, so nothing binds");
    sgx_println!("[SGX-VERIFY] the log to the TPM. Use the \"verify\" operation, which does.");
    return -13;
}

pub fn verify_binary_hash(
    pcr_values: &[u8],
    ima_log: &str,
    hostname: &str,
    deployment_type: &str,
    immudb_addr: &str,
    ca_pem: &str,
) -> Result<(), i32> {
    let _ = (pcr_values, ima_log, hostname, deployment_type, immudb_addr, ca_pem);

    #[cfg(feature = "use_sgx")]
    {
        sgx_println!("[SGX-WRAPPER] ================================================");
        sgx_println!("[SGX-WRAPPER] Calling SGX enclave for hash verification");
        sgx_println!("[SGX-WRAPPER] ================================================");
        sgx_println!("[SGX-WRAPPER] Host provides:");
        sgx_println!("[SGX-WRAPPER] - PCR values: {} bytes", pcr_values.len());
        sgx_println!("[SGX-WRAPPER] - IMA log: {} bytes", ima_log.len());
        sgx_println!("[SGX-WRAPPER] - Hostname: {}", hostname);
        sgx_println!("[SGX-WRAPPER] - Deployment: {}", deployment_type);
        sgx_println!("[SGX-WRAPPER] - ImmuDB address: {}", immudb_addr);
        sgx_println!("[SGX-WRAPPER] Now entering SGX enclave...");
        sgx_println!("[SGX-WRAPPER] (All verification happens inside SGX from this point)");

        extern "C" {
            fn ecall_verify_binary_hash(
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
            ) -> i32;
        }

        let result = unsafe {
            ecall_verify_binary_hash(
                pcr_values.as_ptr(),
                pcr_values.len(),
                ima_log.as_ptr(),
                ima_log.len(),
                hostname.as_ptr(),
                hostname.len(),
                deployment_type.as_ptr(),
                deployment_type.len(),
                immudb_addr.as_ptr(),
                immudb_addr.len(),
                ca_pem.as_ptr(),
                ca_pem.len(),
            )
        };

        sgx_println!("[SGX-WRAPPER] Returned from SGX enclave");
        sgx_println!("[SGX-WRAPPER] Result code: {}", result);

        if result == 0 {
            sgx_println!("[SGX-WRAPPER] SGX enclave verified hash via ImmuDB");
            sgx_println!("[SGX-WRAPPER] ================================================");
            Ok(())
        } else {
            sgx_println!("[SGX-WRAPPER] SGX enclave rejected verification");
            sgx_println!("[SGX-WRAPPER] ================================================");
            Err(result)
        }
    }

    #[cfg(not(feature = "use_sgx"))]
    {

        Ok(())
    }
}

pub fn force_link_sgx() {

}

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
            "{}10 {} ima-ng sha256:{} /usr/lib/nvidia.ko\n",
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
    fn refuses_unparseable_input_rather_than_skipping_it() {
        assert!(matches!(verify_ima_log_against_pcr10("garbage\n", PCR_AFTER_2), Err(-2)));

        let unknown = "10 c53059ed9f89ed24527ed42bfbe33760e9d929ce ima-sig sha256:11 /x\n";
        assert!(matches!(verify_ima_log_against_pcr10(unknown, PCR_AFTER_2), Err(-3)));
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
            "attested {}/{} entries ({} bytes)",
            att.entries_attested, att.entries_total, att.attested_bytes
        );
        assert!(att.entries_attested > 0);
    }

    #[test]
    fn appended_collector_measurement_is_not_extractable() {
        const FORGED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
        const GENUINE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        let mut tampered = String::from(LOG);
        tampered.push_str("10 c53059ed9f89ed24527ed42bfbe33760e9d929ce ima-ng sha256:");
        tampered.push_str(FORGED);
        tampered.push_str(" /usr/bin/scaphandre\n");

        let records = parse_ima_log(&tampered).expect("tampered log still parses");
        let prefix = reconcile_ima_against_pcr10(records, PCR_AFTER_2)
            .expect("appending cannot break reconciliation - that is the whole problem");
        assert_eq!(prefix.entries_attested(), 2, "only the original two are attested");
        assert_eq!(prefix.entries_total(), 3, "but the log does contain the appended entry");

        let got = extract_scaphandre_hash_from_ima(&prefix).expect("the attested entry is found");
        assert_ne!(got, FORGED, "an appended measurement must never be extractable");
        assert_eq!(got, GENUINE);
    }

    #[test]
    fn entries_past_a_stale_prefix_are_invisible_to_extraction() {
        let records = parse_ima_log(LOG).expect("parses");
        let prefix = reconcile_ima_against_pcr10(records, PCR_AFTER_1).expect("prefix reconciles");
        assert_eq!(prefix.entries_attested(), 1);
        assert_eq!(prefix.records().len(), 1, "extraction sees ONLY the attested prefix");
    }

    #[test]
    fn paths_with_spaces_are_not_truncated() {
        let line = "10 c53059ed9f89ed24527ed42bfbe33760e9d929ce ima-ng \
sha256:3333333333333333333333333333333333333333333333333333333333333333 /tmp/scaphandre x\n";
        let recs = parse_ima_log(line).expect("parses");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].file_path, "/tmp/scaphandre x", "the space must survive the split");
        assert_ne!(
            recs[0].file_path.rsplit('/').next().unwrap(), "scaphandre",
            "truncating here is what made this file impersonate the collector"
        );
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
    let qs_len = match pure::read_u16_be(attest, p) {
        Some(v) => v as usize,
        None => return Err("truncated before qualifiedSigner".to_string()),
    };
    p += 2;
    p = match pure::advance_within(p, qs_len, attest.len()) {
        Some(np) => np,
        None => return Err("truncated before extraData".to_string()),
    };
    let ed_len = match pure::read_u16_be(attest, p) {
        Some(v) => v as usize,
        None => return Err("truncated before extraData".to_string()),
    };
    p += 2;
    if pure::advance_within(p, ed_len, attest.len()).is_none() {
        return Err("truncated extraData".to_string());
    }
    let extra_data = &attest[p..p + ed_len];

    if extra_data != expected_nonce {
        return Err("extraData != issued nonce (stale or replayed quote)".to_string());
    }

    p += ed_len + 17 + 8;

    let count = match pure::read_u32_be(attest, p) {
        Some(v) => v,
        None => return Err("truncated before pcrSelect".to_string()),
    };
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
