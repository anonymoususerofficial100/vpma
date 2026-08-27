use crate::exporters::utils;
use crate::exporters::Exporter;
use crate::sensors::Sensor;
use std::time::Duration;

#[cfg(feature = "use_sgx_vm")]
use crate::sensors::gpu_nvml::collect_gpu_raw;
#[cfg(not(feature = "use_sgx_vm"))]
use crate::sensors::gpu_nvml::collect_container_gpu;

pub struct GpuDBExporter {
    step: Duration,

    node_id: String,

    #[cfg(feature = "use_sgx_vm")]
    test_counter: u64,

    #[cfg(feature = "use_sgx_vm")]
    last_collect_at: Option<std::time::Instant>,
}

impl GpuDBExporter {

    pub fn new(_sensor: &dyn Sensor) -> GpuDBExporter {
        GpuDBExporter {

            step: Duration::from_millis(
                std::env::var("SCAPH_GPU_STEP_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(2000),
            ),
            node_id: utils::get_hostname(),
            #[cfg(feature = "use_sgx_vm")]
            test_counter: 0,
            #[cfg(feature = "use_sgx_vm")]
            last_collect_at: None,
        }
    }

    #[cfg(feature = "use_sgx_vm")]
    fn verify_boot_as_guest() -> bool {
        use crate::sgx_vm_runner;

        println!("[GPU-DB] BOOT INTEGRITY VERIFICATION (SGX, guest mode)");

        let immudb_addr = std::env::var("IMMUDB_ADDR").unwrap_or_else(|_| {
            if std::env::var("SGX_REMOTE_HOST").is_ok() {
                "127.0.0.1:8443".to_string()
            } else {
                "192.168.122.1:8443".to_string()
            }
        });
        const CA_PEM: &str = include_str!("../../immudb_ca.pem");

        let hostname = utils::get_hostname();
        println!(
            "[GPU-DB] hostname={} deployment_type=vm immudb={}",
            hostname, immudb_addr
        );

        let quoted = sgx_vm_runner::request_nonce_from_enclave().and_then(|nonce| {
            match crate::tpm_attestation::generate_signed_quote(&nonce) {
                Ok(v) => Some(v),
                Err(e) => {
                    println!("[GPU-DB] no TPM2_Quote ({}) - PCR values will be UNAUTHENTICATED", e);
                    None
                }
            }
        });

        let (pcr_values, ima_log, quote_attest, quote_sig) = match quoted {
            Some((quoted_pcrs, attest, sig)) => {
                let ima_log = match utils::read_ima_log("GPU-DB") {
                    Some(l) => l,
                    None => return false,
                };
                println!(
                    "[GPU-DB] TPM2_Quote over PCR 0/7/10 bound to the enclave's nonce, \
 then IMA log ({} bytes) read after it",
                    ima_log.len()
                );
                (quoted_pcrs, ima_log, hex::encode(attest), hex::encode(sig))
            }
            None => {
                let (pcr_values, ima_log) = match utils::read_consistent_ima_snapshot("GPU-DB") {
                    Some(v) => v,
                    None => return false,
                };
                println!(
                    "[GPU-DB] Consistent snapshot: PCR 0/7/10 ({} bytes) + IMA log ({} bytes)",
                    pcr_values.len(),
                    ima_log.len()
                );
                (pcr_values, ima_log, String::new(), String::new())
            }
        };

        let started = std::time::Instant::now();
        let status = match sgx_vm_runner::verify_boot_in_sgx(
            &pcr_values,
            &ima_log,
            &hostname,
            "vm",
            &immudb_addr,
            CA_PEM,
            &quote_attest,
            &quote_sig,
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[GPU-DB] SGX enclave error: {}", e);
                return false;
            }
        };
        println!(
            "[TIMING-VM] SGX Boot Verification: {:.2} ms",
            started.elapsed().as_secs_f64() * 1000.0
        );

        match status {
            0 => {
                println!("[GPU-DB] BOOT INTEGRITY VERIFIED");
                true
            }
            -6 => {
                eprintln!("[GPU-DB] HASH MISMATCH - BINARY TAMPERED");
                false
            }
            -7 => {
                eprintln!("[GPU-DB] PCR0 MISMATCH - BOOT TAMPERED");
                false
            }
            -8 => {
                eprintln!("[GPU-DB] PCR7 MISMATCH - SECURE BOOT TAMPERED");
                false
            }

            -9 => {
                eprintln!("[GPU-DB] IMA LOG DOES NOT RECONCILE WITH PCR10 - log not bound to the TPM");
                false
            }

            -121 => {
                eprintln!("[GPU-DB] no enclave nonce outstanding - cannot prove PCR freshness");
                false
            }
            -122 => {
                eprintln!("[GPU-DB] an AK is REGISTERED for this node but no TPM2_Quote was sent");
                eprintln!("[GPU-DB] (a node may not downgrade to unauthenticated PCRs by omitting the quote)");
                false
            }
            -123 => {
                eprintln!("[GPU-DB] TPM2_QUOTE INVALID - the PCR values are not the ones the TPM signed");
                false
            }
            -124 => {
                eprintln!("[GPU-DB] the enclave could not reach the AK registry to learn whether");
                eprintln!("[GPU-DB] this node is provisioned, and refused rather than assume it is not");
                false
            }
            code => {
                eprintln!("[GPU-DB] Verification failed: error {}", code);
                false
            }
        }
    }

    #[cfg(feature = "use_sgx_vm")]
    fn process_cycle(&mut self) {
        let cycle_start = std::time::Instant::now();

        if std::env::var("SCAPH_GPU_TEST").is_ok() {
            self.test_counter += 1;
            let mut cumulative = 1_000_000_000 + self.test_counter * 1_000_000;

            if std::env::var("SCAPH_GPU_ROLLBACK").is_ok() && self.test_counter == 4 {
                cumulative = 1_000_000_000 + 2 * 1_000_000;
                println!("[GPU-DB] SCAPH_GPU_ROLLBACK: sending DECREASED cumulative={cumulative} (enclave must reject)");
            }

            let cg_vm_libvirt =
                "0::/machine.slice/machine-qemu\\x2d1\\x2dubuntu20.scope".to_string();
            let cg_vm_systemd = "0::/machine.slice/vm-ubuntu1.scope".to_string();
            let cg_container = format!("0::/system.slice/docker-{}.scope", "a".repeat(64));
            let cg_bare = "0::/user.slice/user-1000.slice/session-3.scope".to_string();
            let mut gpus = vec![(
                0u32,
                "GPU-SYNTHETIC-TEST-0000".to_string(),
                cumulative,
                vec![
                    (101u32, 37u64, cg_vm_libvirt),
                    (102u32, 29u64, cg_vm_systemd),
                    (103u32, 20u64, cg_container),
                    (104u32, 11u64, cg_bare),
                ],
                None,
            )];
            println!(
                "[GPU-DB] SCAPH_GPU_TEST: synthetic cumulative={} uJ (enclave derives ~1 J delta); \
 owners 37/29/20/11 (sum 97, so the split leaves a remainder) = vm:ubuntu20 / vm:ubuntu1 / ctr:aaaa... / node:{}",
                cumulative, self.node_id
            );

            if std::env::var("SCAPH_GPU_DUP").is_ok() {
                let mut dup = gpus[0].clone();
                dup.1 = "GPU-SYNTHETIC-TEST-CLONE".to_string();
                gpus.push(dup);
                println!("[GPU-DB] SCAPH_GPU_DUP: sending the same gpu_index twice (enclave must reject)");
            }
            let roundtrip_ms = self.dispatch(gpus, Some(self.step.as_secs_f64()));
            let e2e_ms = cycle_start.elapsed().as_secs_f64() * 1000.0;
            println!(
                "[TIMING] iter END-TO-END={:.3} ms (collection=synthetic, enclave_roundtrip={:.3})",
                e2e_ms, roundtrip_ms
            );
            return;
        }

        let collect_start = std::time::Instant::now();

        let interval_s = self
            .last_collect_at
            .map(|t| collect_start.duration_since(t).as_secs_f64());
        self.last_collect_at = Some(collect_start);
        let collected = collect_gpu_raw();
        let collect_ms = collect_start.elapsed().as_secs_f64() * 1000.0;
        match collected {

            Ok(samples) if samples.is_empty() => {
                println!("[GPU-DB] no GPUs visible this cycle (NVML enumerated none) - not an idle-GPU condition");
            }
            Ok(samples) => {
                let n_samples = samples.len();
                let gpus: Vec<(
                    u32,
                    String,
                    u64,
                    Vec<(u32, u64, String)>,
                    Option<(u64, u64, u64)>,
                )> = samples
                    .into_iter()
                    .map(|s| {
                        let tag = s.tag.map(|t| (t.energy_uj, t.timestamp_ns, t.hash));
                        (s.gpu_index, s.gpu_uuid, s.energy_uj, s.procs, tag)
                    })
                    .collect();
                let roundtrip_ms = self.dispatch(gpus, interval_s);
                let e2e_ms = cycle_start.elapsed().as_secs_f64() * 1000.0;
                println!(
                    "[TIMING] iter END-TO-END={:.3} ms (collection={:.3} + enclave_roundtrip={:.3}; {} sample(s))",
                    e2e_ms, collect_ms, roundtrip_ms, n_samples
                );
            }
            Err(e) => println!("[GPU-DB] collection error: {e}"),
        }
    }

    #[cfg(feature = "use_sgx_vm")]
    fn dispatch(
        &self,
        gpus: Vec<(
            u32,
            String,
            u64,
            Vec<(u32, u64, String)>,
            Option<(u64, u64, u64)>,
        )>,
        interval_s: Option<f64>,
    ) -> f64 {
        let rt_start = std::time::Instant::now();
        let outcome = crate::sgx_vm_runner::gpu_db_export_in_sgx(&self.node_id, gpus);
        let roundtrip_ms = rt_start.elapsed().as_secs_f64() * 1000.0;
        match outcome {
            Ok(results) => {

                for (process_key, energy_uj) in &results {
                    let energy_j = *energy_uj as f64 / 1_000_000.0;
                    match interval_s {
                        Some(dt) if dt > 0.0 => println!(
                            "[GPU-DB] {} power={:.3} W (energy={:.3} J over {:.3} s)",
                            process_key,
                            energy_j / dt,
                            energy_j,
                            dt
                        ),
                        _ => println!(
                            "[GPU-DB] {} energy={:.3} J (first cycle - power n/a)",
                            process_key, energy_j
                        ),
                    }
                }
            }
            Err(code) => println!("[GPU-DB] enclave export failed (status={code})"),
        }
        roundtrip_ms
    }

    #[cfg(not(feature = "use_sgx_vm"))]
    fn process_cycle(&mut self) {
        match collect_container_gpu() {
            Ok(samples) if samples.is_empty() => {
                println!("[GPU-DB] no containerized GPU processes this cycle");
            }
            Ok(samples) => {
                println!("[GPU-DB] (dry-run, no enclave) {} container/GPU row(s):", samples.len());
                for s in &samples {
                    println!(
                        "[GPU-DB] gpu{} container={} cumulative_energy={} uJ util={} procs={}",
                        s.gpu_index, s.container_id, s.energy_uj, s.sm_util, s.procs
                    );
                }
            }
            Err(e) => println!("[GPU-DB] collection error: {e}"),
        }
    }
}

impl Exporter for GpuDBExporter {
    fn run(&mut self) {
        println!(
            "[GPU-DB] GPU export (node={}, max-in-enclave). Ctrl-C to stop.",
            self.node_id
        );

        #[cfg(feature = "use_sgx_vm")]
        {
            let self_attesting = std::env::var("SGX_REMOTE_HOST").is_ok() || !cfg!(feature = "use_sgx");
            if self_attesting && !Self::verify_boot_as_guest() {
                eprintln!("[GPU-DB] REFUSING TO EXPORT - boot attestation failed");
                return;
            }
        }
        loop {
            self.process_cycle();
            std::thread::sleep(self.step);
        }
    }

    fn kind(&self) -> &str {
        "gpu-db"
    }
}
