use crate::exporters::*;
use crate::sensors::{Sensor, Topology};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

#[cfg(feature = "use_sgx_vm")]
use crate::sgx_vm_runner;

pub struct DBExporter {
    vm_name: String,
    topology: Topology,
    stop_flag: Arc<AtomicU8>,
}

impl DBExporter {
    pub fn new(sensor: &dyn Sensor) -> DBExporter {

        let vm_name = std::env::var("VM_NAME").unwrap_or_else(|_| {

            std::fs::read_to_string("/var/scaphandre/intel-rapl:0/chain_vm_name")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| {

                    hostname::get()
                        .map(|h| h.to_string_lossy().to_string())
                        .unwrap_or_else(|_| "unknown".to_string())
                })
        });
        let hostname = utils::get_hostname();

        println!("[DB-EXPORTER] Initializing VM DB exporter");
        println!("[DB-EXPORTER] Hostname: {}", hostname);
        println!("[DB-EXPORTER] VM Name for chain: {}", vm_name);
        println!("[DB-EXPORTER] Architecture: topology.refresh() -> reads VM energy files (from HOST SGX)");
        println!("[DB-EXPORTER] -> sends to REAL SGX enclave (via TCP) -> verifies chain -> calculates per-process -> exports to ImmuDB");

        let topology = sensor.get_topology()
            .expect("[DB-EXPORTER] Failed to get topology from sensor");

        println!("[DB-EXPORTER] Topology initialized (will read from /var/scaphandre)");

        DBExporter {
            vm_name,
            topology,
            stop_flag: Arc::new(AtomicU8::new(0)),
        }
    }
}

impl Exporter for DBExporter {
    fn run(&mut self) {
        use std::thread;
        use std::time::Duration;

        println!("[DB-EXPORTER] Starting VM DB exporter for '{}'", self.vm_name);
        println!("[DB-EXPORTER] Architecture: topology.refresh() -> REAL SGX enclave (TCP) -> ImmuDB");

        #[cfg(feature = "use_sgx_vm")]
        {

            sgx_vm_runner::print_sgx_vm_info();

            println!("[DB-EXPORTER] BOOT INTEGRITY VERIFICATION (SGX)");

            let (pcr_values, ima_log) = match utils::read_consistent_ima_snapshot("DB-EXPORTER") {
                Some(v) => v,
                None => return,
            };
            println!(
                "[DB-EXPORTER] Consistent snapshot: PCRs ({} bytes) + IMA log ({} bytes)",
                pcr_values.len(),
                ima_log.len()
            );

            let hostname = utils::get_hostname();
            let deployment_type = "vm";

            let immudb_addr = if std::env::var("SGX_REMOTE_HOST").is_ok() {
                "127.0.0.1:8443"
            } else {
                "192.168.122.1:8443"
            };
            println!("[DB-EXPORTER] ImmuDB address (for enclave): {}", immudb_addr);

            const CA_PEM: &str = include_str!("../../immudb_ca.pem");

            println!("[DB-EXPORTER] Sending to REAL SGX enclave for verification...");

            let sgx_verify_start = std::time::Instant::now();

            let verify_result = match sgx_vm_runner::verify_boot_in_sgx(
                &pcr_values,
                &ima_log,
                &hostname,
                deployment_type,
                immudb_addr,
                CA_PEM,
                "",
                "",
            ) {
                Ok(status) => status,
                Err(e) => {
                    eprintln!("[DB-EXPORTER] SGX enclave error: {}", e);
                    return;
                }
            };
            let sgx_verify_duration = sgx_verify_start.elapsed();
            println!("[TIMING-VM] SGX Boot Verification: {:.2} ms", sgx_verify_duration.as_secs_f64() * 1000.0);

            match verify_result {
                0 => {
                    println!("[DB-EXPORTER] BINARY INTEGRITY VERIFIED");
                }
                -6 => {
                    eprintln!("[DB-EXPORTER] HASH MISMATCH - BINARY TAMPERED");
                    eprintln!("[DB-EXPORTER] REFUSING TO EXPORT DATA");
                    return;
                }
                -7 => {
                    eprintln!("[DB-EXPORTER] PCR0 MISMATCH - BOOT TAMPERED");
                    eprintln!("[DB-EXPORTER] REFUSING TO EXPORT DATA");
                    return;
                }
                -8 => {
                    eprintln!("[DB-EXPORTER] PCR7 MISMATCH - SECURE BOOT TAMPERED");
                    eprintln!("[DB-EXPORTER] REFUSING TO EXPORT DATA");
                    return;
                }
                -9 => {
                    eprintln!("[DB-EXPORTER] PCR10 MISMATCH - IMA TAMPERED");
                    eprintln!("[DB-EXPORTER] REFUSING TO EXPORT DATA");
                    return;
                }
                code => {
                    eprintln!("[DB-EXPORTER] Verification failed: error {}", code);
                    return;
                }
            }

            println!("[DB-EXPORTER] Starting secure data export...");

            use std::time::Instant;

            let mut prev_ticks: std::collections::HashMap<u32, u64> =
                std::collections::HashMap::new();

            loop {
                let iteration_start = Instant::now();

                let stop = self.stop_flag.load(Ordering::Relaxed);
                if stop != 0 {
                    println!("[DB-EXPORTER] Stop signal received");
                    break;
                }

                println!("\n[DB-EXPORTER] === Iteration start ===");

                let topo_start = Instant::now();
                println!("[DB-EXPORTER] Calling topology.refresh()...");
                self.topology.refresh();
                let topo_duration = topo_start.elapsed();
                println!("[DB-EXPORTER] Topology refreshed (energy files read)");
                println!("[TIMING-VM] Topology refresh: {:.2} ms", topo_duration.as_secs_f64() * 1000.0);

                let metadata_start = Instant::now();
                let chain_dir = "/var/scaphandre/intel-rapl:0";

                let energy_uj = match std::fs::read_to_string(format!("{}/energy_uj", chain_dir)) {
                    Ok(content) => content.trim().parse::<u64>().unwrap_or(0),
                    Err(e) => {
                        eprintln!("[DB-EXPORTER] Failed to read energy file: {}", e);
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };

                let chain_json = match std::fs::read_to_string(format!("{}/chain_metadata.json", chain_dir)) {
                    Ok(content) => content,
                    Err(_) => {
                        eprintln!("[DB-EXPORTER] No chain metadata found");
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };

                let chain: serde_json::Value = match serde_json::from_str(&chain_json) {
                    Ok(v) => v,
                    Err(_) => {
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };

                let counter = chain["counter"].as_u64().unwrap_or(0);
                let prev_hash_hex = chain["previous_hash"].as_str().unwrap_or("");
                let signature_hex = chain["signature"].as_str().unwrap_or("");
                let energy_delta = chain["energy_delta"].as_u64().unwrap_or(0);

                let prev_hash = match hex::decode(prev_hash_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };

                let signature = match hex::decode(signature_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };

                let metadata_duration = metadata_start.elapsed();
                println!("[TIMING-VM] Chain metadata read: {:.2} ms", metadata_duration.as_secs_f64() * 1000.0);

                let proc_start = Instant::now();
                use std::fs;
                let mut processes = Vec::new();

                let mut current_ticks: std::collections::HashMap<u32, u64> =
                    std::collections::HashMap::new();
                if let Ok(entries) = fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        if let Ok(file_name) = entry.file_name().into_string() {
                            if let Ok(pid) = file_name.parse::<u32>() {
                                let stat_path = format!("/proc/{}/stat", pid);
                                if let Ok(stat_content) = fs::read_to_string(&stat_path) {
                                    let parts: Vec<&str> = stat_content.split_whitespace().collect();
                                    if parts.len() > 14 {
                                        let utime: u64 = parts[13].parse().unwrap_or(0);
                                        let stime: u64 = parts[14].parse().unwrap_or(0);
                                        let total = utime.saturating_add(stime);
                                        current_ticks.insert(pid, total);

                                        let delta = match prev_ticks.get(&pid) {
                                            Some(prev) => total.saturating_sub(*prev),
                                            None => 0,
                                        };
                                        processes.push((pid, delta));
                                    }
                                }
                            }
                        }
                    }
                }

                prev_ticks = current_ticks;

                let proc_duration = proc_start.elapsed();
                println!("[TIMING-VM] Process data collection: {:.2} ms ({} processes)",
                         proc_duration.as_secs_f64() * 1000.0, processes.len());

                println!("[DB-EXPORTER] Calling REAL SGX enclave:");
                println!("[DB-EXPORTER] VM: {}", self.vm_name);
                println!("[DB-EXPORTER] Counter: {}", counter);
                println!("[DB-EXPORTER] Energy: {} µJ", energy_uj);
                println!("[DB-EXPORTER] Energy Delta: {} µJ", energy_delta);
                println!("[DB-EXPORTER] Prev Hash: {}", &prev_hash_hex[..16.min(prev_hash_hex.len())]);
                println!("[DB-EXPORTER] Signature: {}", &signature_hex[..16.min(signature_hex.len())]);
                println!("[DB-EXPORTER] Processes: {}", processes.len());

                let prev_hash_arr: [u8; 32] = match prev_hash.try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        eprintln!("[DB-EXPORTER] Invalid previous hash length");
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };

                let signature_arr: [u8; 32] = match signature.try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        eprintln!("[DB-EXPORTER] Invalid signature length");
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };

                let sgx_start = Instant::now();
                let result = sgx_vm_runner::db_export_in_sgx(
                    &self.vm_name,
                    energy_uj,
                    counter,
                    &prev_hash_arr,
                    &signature_arr,
                    energy_delta,
                    &processes,
                    None,
                );
                let sgx_duration = sgx_start.elapsed();

                match result {
                    Ok(energy_results) => {
                        println!("[DB-EXPORTER] Iteration completed inside REAL SGX");
                        println!("[DB-EXPORTER] {} processes with energy calculated", energy_results.len());
                        println!("[TIMING-VM] SGX verification + calculation + export: {:.2} ms", sgx_duration.as_secs_f64() * 1000.0);
                    }
                    Err(status) => {
                        match status {
                            2 => println!("[DB-EXPORTER] Skipped (same counter, waiting for host)"),
                            -2 => eprintln!("[DB-EXPORTER] Chain verification failed (tampering - signature mismatch)"),
                            -3 => eprintln!("[DB-EXPORTER] Replay/rollback attack (counter mismatch)"),
                            -4 => eprintln!("[DB-EXPORTER] Fork attack (previous hash mismatch)"),
                            -200 => eprintln!("[DB-EXPORTER] SGX hardware not available"),
                            -201 => eprintln!("[DB-EXPORTER] SGX enclave binary not found"),
                            code => eprintln!("[DB-EXPORTER] Error: {}", code),
                        }
                    }
                }

                let iteration_duration = iteration_start.elapsed();
                println!("[TIMING-VM] ========================================");
                println!("[TIMING-VM] Total iteration time: {:.2} ms", iteration_duration.as_secs_f64() * 1000.0);
                println!("[TIMING-VM] ========================================");

                thread::sleep(Duration::from_secs(2));
            }
        }

        #[cfg(not(feature = "use_sgx_vm"))]
        {
            eprintln!("[DB-EXPORTER] Error: SGX feature not enabled");
        }
    }

    fn kind(&self) -> &str {
        "db-sgx"
    }
}

impl Drop for DBExporter {
    fn drop(&mut self) {

        self.stop_flag.store(1, Ordering::Relaxed);
        #[cfg(feature = "use_sgx_vm")]
        {
            sgx_vm_runner::shutdown_vm_enclave();
        }
        println!("[DB-EXPORTER] Stopping SGX exporter");
    }
}
