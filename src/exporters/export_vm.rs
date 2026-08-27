use std::fs;
use std::io;
use std::path::Path;

use super::qemu::VmEnergyUpdate;

use hex;

use serde_json;

#[cfg(feature = "use_sgx")]
use std::sync::Once;
#[cfg(feature = "use_sgx")]
use std::slice;

#[cfg(feature = "use_sgx")]
use crate::sgx_runner::{
    ecall_register_ocall_write_vm_energy,
    ecall_register_sealed_storage_ocalls,
    ecall_register_ocall_fetch_expected_hash,
    ecall_initialize_sealed_key,
    ecall_verify_binary_hash,
};

#[cfg(feature = "use_sgx")]
unsafe extern "C" fn ocall_read_sealed_key(
    buf_ptr: *mut u8,
    buf_len: usize,
) -> i32 {
    use std::fs;

    let sealed_path = "/var/lib/scaphandre/.sgx_sealed_hmac_key";

    match fs::read(sealed_path) {
        Ok(data) => {
            if data.len() != buf_len {
                return -1;
            }

            let buf_slice = slice::from_raw_parts_mut(buf_ptr, buf_len);
            buf_slice.copy_from_slice(&data);

            data.len() as i32
        }
        Err(_) => -1,
    }
}

#[cfg(feature = "use_sgx")]
unsafe extern "C" fn ocall_write_sealed_key(
    buf_ptr: *const u8,
    buf_len: usize,
) -> i32 {
    use std::fs;
    use std::path::Path;

    let sealed_path = "/var/lib/scaphandre/.sgx_sealed_hmac_key";

    if let Some(parent) = Path::new(sealed_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let data = slice::from_raw_parts(buf_ptr, buf_len);

    match fs::write(sealed_path, data) {
        Ok(_) => {
            println!("[EXPORT-VM] Sealed key written to {}", sealed_path);
            0
        }
        Err(e) => {
            eprintln!("[EXPORT-VM] Failed to write sealed key: {}", e);
            -1
        }
    }
}

#[cfg(feature = "use_sgx")]
unsafe extern "C" fn ocall_fetch_expected_hash(
    url_ptr: *const u8,
    url_len: usize,
    hash_buf_ptr: *mut u8,
    hash_buf_len: usize,
) -> i32 {
    use std::io::Read;

    let url_bytes = slice::from_raw_parts(url_ptr, url_len);
    let url = match std::str::from_utf8(url_bytes) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[EXPORT-VM] Invalid URL encoding");
            return -1;
        }
    };

    println!("[EXPORT-VM] Fetching hash from: {}", url);

    match ureq::get(url).call() {
        Ok(response) => {
            let mut hash_data = Vec::new();
            if let Err(e) = response.into_reader().read_to_end(&mut hash_data) {
                eprintln!("[EXPORT-VM] Failed to read response: {}", e);
                return -1;
            }

            let response_str = match std::str::from_utf8(&hash_data) {
                Ok(s) => s.trim(),
                Err(_) => {
                    eprintln!("[EXPORT-VM] Response is not valid UTF-8");
                    return -1;
                }
            };

            let is_signed = response_str.contains(':');

            if is_signed {

                let parts: Vec<&str> = response_str.split(':').collect();
                if parts.len() != 2 {
                    eprintln!("[EXPORT-VM] Invalid signed response format");
                    return -1;
                }
                if parts[0].len() != 64 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
                    eprintln!("[EXPORT-VM] Invalid hash in signed response");
                    return -1;
                }
                if parts[1].len() != 128 || !parts[1].chars().all(|c| c.is_ascii_hexdigit()) {
                    eprintln!("[EXPORT-VM] Invalid signature in signed response");
                    return -1;
                }
            } else {

                if response_str.len() != 64 || !response_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    eprintln!("[EXPORT-VM] Invalid hash format: expected 64 hex chars");
                    return -1;
                }
            }

            if response_str.len() > hash_buf_len {
                eprintln!("[EXPORT-VM] Response buffer too small");
                return -1;
            }

            let buf_slice = slice::from_raw_parts_mut(hash_buf_ptr, hash_buf_len);
            buf_slice[..response_str.len()].copy_from_slice(response_str.as_bytes());

            if is_signed {
                println!("[EXPORT-VM] Fetched signed hash: {}...", &response_str[..16]);
            } else {
                println!("[EXPORT-VM] Fetched hash: {}...", &response_str[..16]);
            }
            response_str.len() as i32
        }
        Err(e) => {
            eprintln!("[EXPORT-VM] HTTP request failed: {}", e);
            -1
        }
    }
}

#[cfg(feature = "use_sgx")]
unsafe extern "C" fn ocall_write_vm_energy_impl(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    uj_value: u64,
    counter: u64,
    previous_hash_ptr: *const u8,
    signature_ptr: *const u8,
) -> i32 {

    static INIT: Once = Once::new();
    static mut VM_EXPORTER: Option<VmEnergyExporter> = None;

    INIT.call_once(|| {
        let base_path = std::env::var("VM_EXPORT_PATH")
            .unwrap_or_else(|_| "/var/lib/scaphandre".to_string());
        VM_EXPORTER = Some(VmEnergyExporter::new(base_path));
    });

    let exporter = VM_EXPORTER.as_ref().expect("VM_EXPORTER not initialized");

    let vm_name_bytes = slice::from_raw_parts(vm_name_ptr, vm_name_len);
    let vm_name = match std::str::from_utf8(vm_name_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return 1,
    };

    let previous_hash = slice::from_raw_parts(previous_hash_ptr, 32);
    let signature = slice::from_raw_parts(signature_ptr, 32);

    println!("[OCALL-EXPORT_VM] SGX requesting write: VM '{}' = {} µJ (counter: {})",
             vm_name, uj_value, counter);

    let update = VmEnergyUpdate {
        vm_name,
        uj_to_add: uj_value,
        hmac_signature: signature.to_vec(),
    };

    match exporter.write_updates_with_chain(vec![update], counter, previous_hash, signature) {
        Ok(_) => 0,
        Err(_) => 2,
    }
}

#[cfg(feature = "use_sgx")]
pub fn initialize_sgx_sealed_storage() -> Result<(), String> {
    println!("[EXPORT-VM] Initializing SGX sealed storage...");

    unsafe {

        let status = ecall_register_sealed_storage_ocalls(
            ocall_read_sealed_key,
            ocall_write_sealed_key,
        );

        if status != 0 {
            return Err(format!("Failed to register sealed storage OCALLs, status = {}", status));
        }

        println!("[EXPORT-VM] Sealed storage OCALLs registered");

        let status = ecall_initialize_sealed_key();

        match status {
            0 => {
                println!("[EXPORT-VM] Using existing sealed key");
                Ok(())
            }
            1 => {
                println!("[EXPORT-VM] Generated new key (first run)");
                Ok(())
            }
            _ => Err(format!("Failed to initialize sealed key, status = {}", status))
        }
    }
}

#[cfg(feature = "use_sgx")]
pub fn register_sgx_ocall() {
    println!("[EXPORT-VM] Registering OCALL for SGX VM energy writes");
    unsafe {
        let status = ecall_register_ocall_write_vm_energy(ocall_write_vm_energy_impl);
        if status != 0 {
            eprintln!("[EXPORT-VM] Failed to register OCALL, status = {}", status);
        } else {
            println!("[EXPORT-VM] OCALL registered successfully");
        }

        let status = ecall_register_ocall_fetch_expected_hash(ocall_fetch_expected_hash);
        if status != 0 {
            eprintln!("[EXPORT-VM] Failed to register hash fetch OCALL, status = {}", status);
        } else {
            println!("[EXPORT-VM] Hash fetch OCALL registered successfully");
        }
    }

    if let Err(e) = initialize_sgx_sealed_storage() {
        eprintln!("[EXPORT-VM] Warning: Sealed storage initialization failed: {}", e);
        eprintln!("[EXPORT-VM] Falling back to TPM key registration (less secure)");
    }
}

#[cfg(all(feature = "use_sgx", feature = "tpm_attestation"))]
pub fn verify_boot_attestation_in_sgx(
    quote: &crate::tpm_attestation::AttestationQuote,
    verifier_url: Option<&str>,
) -> Result<(), String> {
    println!("[EXPORT-VM] ================================================");
    println!("[EXPORT-VM] Verifying binary hash via ImmuDB inside SGX");
    println!("[EXPORT-VM] ================================================");

    let hostname = crate::exporters::utils::get_hostname();

    let deployment_type: String = std::env::var("DEPLOYMENT_TYPE").ok()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| s == "vm" || s == "host")
        .unwrap_or_else(|| {
            for f in ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"] {
                if let Ok(v) = std::fs::read_to_string(f) {
                    let v = v.to_lowercase();
                    if v.contains("kvm") || v.contains("qemu")
                        || v.contains("virtualbox") || v.contains("vmware")
                    {
                        return "vm".to_string();
                    }
                }
            }

            if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
                if cpuinfo.contains("hypervisor") {
                    return "vm".to_string();
                }
            }
            "host".to_string()
        });

    let immudb_addr = std::env::var("IMMUDB_ADDR")
        .unwrap_or_else(|_| "192.168.122.1:8443".to_string());

    let ca_pem_path = std::env::var("IMMUDB_CA_CERT").ok()
        .or_else(|| {

            for path in &["enclave_ca.pem", "./enclave_ca.pem", "/etc/scaphandre/ca.pem"] {
                if std::path::Path::new(path).exists() {
                    return Some(path.to_string());
                }
            }
            None
        })
        .unwrap_or_else(|| "enclave_ca.pem".to_string());

    let ca_pem = std::fs::read_to_string(&ca_pem_path)
        .map_err(|e| format!("Failed to read CA cert from {}: {}", ca_pem_path, e))?;

    println!("[EXPORT-VM] Calling SGX enclave with ImmuDB verification");
    println!("[EXPORT-VM] - Hostname: {}", hostname);
    println!("[EXPORT-VM] - Deployment: {}", deployment_type);
    println!("[EXPORT-VM] - ImmuDB: {}", immudb_addr);

    unsafe {
        let status = ecall_verify_binary_hash(
            quote.pcr_values.as_ptr(),
            quote.pcr_values.len(),
            quote.ima_log.as_ptr(),
            quote.ima_log.len(),
            hostname.as_ptr(),
            hostname.len(),
            deployment_type.as_ptr(),
            deployment_type.len(),
            immudb_addr.as_ptr(),
            immudb_addr.len(),
            ca_pem.as_ptr(),
            ca_pem.len(),
        );

        match status {
            0 => {
                println!("[EXPORT-VM] Boot attestation verified by SGX enclave via ImmuDB");
                println!("[EXPORT-VM] - TPM PCRs validated");
                println!("[EXPORT-VM] - IMA log parsed inside SGX");
                println!("[EXPORT-VM] - Binary hash queried from ImmuDB (inside SGX)");
                println!("[EXPORT-VM] - Hash comparison successful");
                println!("[EXPORT-VM] ================================================");
                Ok(())
            }
            -1 => Err("Null pointer error".to_string()),
            -2 => Err("Invalid PCR data - IMA not active".to_string()),
            -3 => Err("IMA log parse error".to_string()),
            -4 => Err("Scaphandre binary not found in IMA log".to_string()),
            -5 => Err("ImmuDB connection failed (inside SGX)".to_string()),
            -6 => Err("HASH MISMATCH - Binary has been tampered!".to_string()),
            -99 => Err("mbedtls feature not enabled in SGX".to_string()),
            13 => Err("Scaphandre binary hash mismatch - binary has been modified".to_string()),
            _ => Err(format!("Unknown error from SGX enclave, status = {}", status)),
        }
    }
}

pub struct VmEnergyExporter {
    base_path: String,
}

impl VmEnergyExporter {

    pub fn new(base_path: String) -> Self {
        println!("[EXPORT-VM] Initialized with base_path: {}", base_path);
        VmEnergyExporter { base_path }
    }

    pub fn write_updates(&self, updates: Vec<VmEnergyUpdate>) -> io::Result<()> {
        println!(
            "[EXPORT-VM] Received {} energy updates from SGX",
            updates.len()
        );

        for update in updates {
            let vm_path = format!("{}/{}/intel-rapl:0", self.base_path, update.vm_name);

            match self.add_or_create(&vm_path, update.uj_to_add) {
                Ok(_) => {
                    println!(
                        "[EXPORT-VM] VM '{}' updated with {} µJ -> {}",
                        update.vm_name, update.uj_to_add, vm_path
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[EXPORT-VM] Failed to update VM '{}': {}",
                        update.vm_name, e
                    );
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    pub fn write_updates_with_chain(
        &self,
        updates: Vec<VmEnergyUpdate>,
        counter: u64,
        previous_hash: &[u8],
        signature: &[u8],
    ) -> io::Result<()> {
        println!("[EXPORT-VM] Writing {} updates with chain metadata (counter: {})",
                 updates.len(), counter);

        for update in updates {
            let vm_path = format!("{}/{}/intel-rapl:0", self.base_path, update.vm_name);
            let is_chain_restart = counter == 1 && previous_hash.iter().all(|&b| b == 0);

            let write_result = if is_chain_restart {
                self.write_exact(&vm_path, update.uj_to_add)
            } else {
                self.add_or_create(&vm_path, update.uj_to_add)
            };

            match write_result {
                Ok(_) => {
                    println!("[EXPORT-VM] VM '{}' energy: {} µJ",
                             update.vm_name, update.uj_to_add);
                }
                Err(e) => {
                    eprintln!("[EXPORT-VM] Failed to update VM '{}': {}",
                              update.vm_name, e);
                    return Err(e);
                }
            }

            let chain_json = serde_json::json!({
                "counter": counter,
                "energy_delta": update.uj_to_add,
                "previous_hash": hex::encode(previous_hash),
                "signature": hex::encode(signature),
                "vm_name": &update.vm_name
            });
            fs::write(format!("{}/chain_metadata.json", vm_path), chain_json.to_string())?;

            println!("[EXPORT-VM] Chain metadata written for VM '{}'", update.vm_name);
        }

        Ok(())
    }

    fn add_or_create(&self, path: &str, uj_value: u64) -> io::Result<()> {
        let mut current_value = 0u64;

        if !Path::new(path).exists() {
            println!("[EXPORT-VM] Creating directory: {}", path);
            fs::create_dir_all(path)?;
        }

        let file_path = format!("{}/energy_uj", path);

        if let Ok(content) = fs::read_to_string(&file_path) {
            current_value = content.trim().parse::<u64>().unwrap_or(0);
            println!(
                "[EXPORT-VM] Current value in {}: {} µJ",
                file_path, current_value
            );
        } else {
            println!("[EXPORT-VM] Creating new file: {}", file_path);
        }

        let new_value = current_value + uj_value;

        println!(
            "[EXPORT-VM] Writing {} µJ ({} + {}) to {}",
            new_value, current_value, uj_value, file_path
        );

        fs::write(&file_path, new_value.to_string())?;

        Ok(())
    }

    fn write_exact(&self, path: &str, uj_value: u64) -> io::Result<()> {
        if !Path::new(path).exists() {
            println!("[EXPORT-VM] Creating directory: {}", path);
            fs::create_dir_all(path)?;
        }

        let file_path = format!("{}/energy_uj", path);
        fs::write(&file_path, uj_value.to_string())?;
        println!(
            "[EXPORT-VM] Chain restart detected, reset {} to {} µJ",
            file_path, uj_value
        );

        Ok(())
    }

    pub fn base_path(&self) -> &str {
        &self.base_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_create_and_update_energy_file() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_str().unwrap().to_string();

        let exporter = VmEnergyExporter::new(base_path.clone());

        let updates = vec![
            VmEnergyUpdate {
                vm_name: "test-vm".to_string(),
                uj_to_add: 1000,
            },
        ];

        exporter.write_updates(updates).unwrap();

        let energy_file = format!("{}/test-vm/intel-rapl:0/energy_uj", base_path);
        let content = fs::read_to_string(&energy_file).unwrap();
        assert_eq!(content, "1000");

        let updates2 = vec![
            VmEnergyUpdate {
                vm_name: "test-vm".to_string(),
                uj_to_add: 500,
            },
        ];

        exporter.write_updates(updates2).unwrap();
        let content2 = fs::read_to_string(&energy_file).unwrap();
        assert_eq!(content2, "1500");
    }
}
