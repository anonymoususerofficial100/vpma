#![cfg_attr(feature = "cfi", feature(sanitize))]

use clap::{command, ArgAction, Parser, Subcommand};
use colored::Colorize;
use scaphandre::{exporters, sensors::Sensor};

#[cfg(target_os = "linux")]
use scaphandre::sensors::powercap_rapl;

#[cfg(all(target_os = "linux", feature = "gpu"))]
use scaphandre::sensors::gpu_nvml;

#[cfg(target_os = "windows")]
use scaphandre::sensors::msr_rapl;

#[cfg(feature = "qemu")]
use scaphandre::sensors::powercap_rapl::QemuHostExporter;

#[cfg(all(feature = "use_sgx", feature = "qemu"))]
use scaphandre::exporters::export_vm;

#[cfg(target_os = "windows")]
use windows_service::{
    service::ServiceControl,
    service::ServiceControlAccept,
    service::ServiceExitCode,
    service::ServiceState,
    service::ServiceStatus,
    service::ServiceType,
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[cfg(target_os = "windows")]
define_windows_service!(ffi_service_main, my_service_main);

#[cfg(target_os = "windows")]
#[macro_use]
extern crate windows_service;

#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use std::ffi::OsString;

#[cfg(feature = "qemu")]
#[derive(Parser, Clone)]
pub struct QemuExporterArgs {

    #[arg(long)]
    pub verifier_url: Option<String>,
}

#[derive(Parser)]
#[command(author, version)]
struct Cli {

    #[command(subcommand)]
    exporter: ExporterChoice,

    #[arg(short, action = ArgAction::Count, default_value_t = 0)]
    verbose: u8,

    #[arg(long, default_value_t = false)]
    no_header: bool,

    #[arg(long, default_value_t = false)]
    vm: bool,

    #[arg(short, long)]
    sensor: Option<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, default_value_t = powercap_rapl::DEFAULT_BUFFER_PER_DOMAIN_MAX_KBYTES)]
    sensor_buffer_per_domain_max_kb: u16,

    #[cfg(target_os = "linux")]
    #[arg(long, default_value_t = powercap_rapl::DEFAULT_BUFFER_PER_SOCKET_MAX_KBYTES)]
    sensor_buffer_per_socket_max_kb: u16,
}

#[derive(Subcommand)]
enum ExporterChoice {

    Stdout(exporters::stdout::ExporterArgs),

    #[cfg(feature = "json")]
    Json(exporters::json::ExporterArgs),

    #[cfg(feature = "prometheus")]
    Prometheus(exporters::prometheus::ExporterArgs),

    #[cfg(feature = "qemu")]
    Qemu(QemuExporterArgs),

    #[cfg(feature = "qemu")]
    SgxQemu(QemuExporterArgs),

    #[cfg(feature = "riemann")]
    Riemann(exporters::riemann::ExporterArgs),

    #[cfg(feature = "warpten")]
    Warpten(exporters::warpten::ExporterArgs),

    #[cfg(feature = "prometheuspush")]
    PrometheusPush(exporters::prometheuspush::ExporterArgs),

    #[cfg(feature = "use_sgx_vm")]
    Db,

    #[cfg(all(target_os = "linux", feature = "gpu"))]
    GpuDb,

    #[cfg(all(target_os = "linux", feature = "gpu"))]
    GpuPrint,
}

#[cfg(target_os = "windows")]
fn my_service_main(_arguments: Vec<OsString>) {
    use std::thread::JoinHandle;
    let graceful_period = 3;

    let start_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    let stop_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    let stoppending_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(graceful_period),
        process_id: None,
    };

    let thread_handle: Option<JoinHandle<()>>;
    let mut _stop = false;
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        println!("Got service control event: {:?}", control_event);
        match control_event {
            ServiceControl::Stop => {

                _stop = true;
                ServiceControlHandlerResult::NoError
            }

            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    if let Ok(system_handler) = service_control_handler::register("scaphandre", event_handler) {

        match system_handler.set_service_status(start_status.clone()) {
            Ok(status_set) => {
                println!(
                    "Starting main thread, service status has been set: {:?}",
                    status_set
                );
                thread_handle = Some(std::thread::spawn(move || {
                    parse_cli_and_run_exporter();
                }));
            }
            Err(e) => {
                panic!("Couldn't set Windows service status. Error: {:?}", e);
            }
        }
        loop {
            if _stop {

                match system_handler.set_service_status(stoppending_status.clone()) {
                    Ok(status_set) => {
                        println!("Stop status has been set for service: {:?}", status_set);
                        if let Some(thr) = thread_handle {
                            if thr.join().is_ok() {
                                match system_handler.set_service_status(stop_status.clone()) {
                                    Ok(laststatus_set) => {
                                        println!(
                                            "Scaphandre gracefully stopped: {:?}",
                                            laststatus_set
                                        );
                                    }
                                    Err(e) => {
                                        panic!(
                                            "Could'nt set Stop status on scaphandre service: {:?}",
                                            e
                                        );
                                    }
                                }
                            } else {
                                panic!("Joining the thread failed.");
                            }
                            break;
                        } else {
                            panic!("Thread handle was not initialized.");
                        }
                    }
                    Err(e) => {
                        panic!("Couldn't set Windows service status. Error: {:?}", e);
                    }
                }
            }
        }
    } else {
        panic!("Failed getting system_handle.");
    }
}

#[cfg_attr(feature = "cfi", sanitize(cfi = "off"))]
fn main() {
    #[cfg(target_os = "windows")]
    match service_dispatcher::start("Scaphandre", ffi_service_main) {
        Ok(_) => {}
        Err(e) => {
            println!("Couldn't start Windows service dispatcher. Got : {}", e);
        }
    }

    parse_cli_and_run_exporter();
}

#[cfg_attr(feature = "cfi", sanitize(cfi = "off"))]
fn parse_cli_and_run_exporter() {
    let cli = Cli::parse();
    loggerv::init_with_verbosity(cli.verbose.into()).expect("unable to initialize the logger");

    #[cfg(any(feature = "use_sgx", feature = "use_sgx_real"))]
    scaphandre::sgx_runner::print_sgx_info();

    #[cfg(all(feature = "qemu", any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
    let verifier_url = match &cli.exporter {
        ExporterChoice::Qemu(args) => args.verifier_url.as_deref(),
        ExporterChoice::SgxQemu(args) => args.verifier_url.as_deref(),
        _ => None,
    };

    #[cfg(not(all(feature = "qemu", any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))))]
    let verifier_url: Option<&str> = None;

    #[cfg(all(feature = "use_sgx", feature = "qemu"))]
    export_vm::register_sgx_ocall();

    #[cfg(feature = "tpm_attestation")]
    let tpm_key = {
        use scaphandre::tpm_attestation::TpmAttestation;

        println!("[MAIN] Starting TPM attestation (HOST MODE - strict)...");
        match TpmAttestation::new(verifier_url) {
            Ok(tpm) => {
                if tpm.is_attested() {
                    println!("[MAIN] TPM attestation successful - boot chain verified");
                    tpm.get_hmac_key().map(|k| k.to_vec())
                } else {
                    eprintln!("[MAIN] TPM attestation failed - no HMAC key available");
                    eprintln!("[MAIN] Continuing without TPM protection (degraded security)");
                    None
                }
            }
            Err(e) => {
                eprintln!("[MAIN] TPM initialization failed: {}", e);
                eprintln!("[MAIN] This may indicate:");
                eprintln!(" - System has been tampered with");
                eprintln!(" - PCR values don't match expected measurements");
                eprintln!(" - TPM sealed key is missing or corrupted");
                eprintln!("[MAIN] ABORTING - refusing to run on untrusted system");
                std::process::exit(1);
            }
        }
    };

    #[cfg(all(feature = "tpm_attestation_vm", not(feature = "tpm_attestation")))]
    let tpm_key = {
        use scaphandre::tpm_attestation::TpmAttestation;

        println!("[MAIN] Starting vTPM attestation (VM MODE - graceful)...");
        match TpmAttestation::new_vm_mode(verifier_url) {
            Ok(tpm) => {
                if tpm.is_attested() {
                    println!("[MAIN] vTPM attestation successful - VM boot chain verified");
                    tpm.get_hmac_key().map(|k| k.to_vec())
                } else {
                    println!("[MAIN] Continuing without vTPM protection (relying on host TPM)");
                    None
                }
            }
            Err(e) => {
                eprintln!("[MAIN] vTPM initialization failed: {}", e);
                eprintln!("[MAIN] Continuing without vTPM protection (relying on host TPM)");
                None
            }
        }
    };

    #[cfg(not(any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
    let tpm_key: Option<Vec<u8>> = None;

    #[cfg(all(target_os = "linux", any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
    if let Some(ref key) = tpm_key {
        println!("[MAIN] Setting HMAC key for sensor data signing");
        powercap_rapl::set_sensor_hmac_key(key);
    }

    #[cfg(all(target_os = "linux", feature = "tpm_attestation_vm", not(feature = "tpm_attestation")))]
    {
        use sha2::{Digest, Sha256};
        use hmac::{Hmac, Mac};
        let vm_name = std::env::var("VM_NAME").unwrap_or_else(|_| {
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        });
        let master: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"VPMA-NON-SGX-TEST-KEY-NOT-FOR-PRODUCTION");
            h.update(b"chain");
            h.finalize().into()
        };
        let mut mac = <Hmac<Sha256>>::new_from_slice(&master).expect("HMAC accepts any key size");
        mac.update(b"vm:");
        mac.update(vm_name.as_bytes());
        let vm_key = mac.finalize().into_bytes();
        println!("[MAIN] VM mode: signing energy chain with co-derived per-VM key (vm_name={})", vm_name);
        powercap_rapl::set_sensor_hmac_key(&vm_key);
    }

    #[cfg(all(feature = "use_sgx", target_os = "linux"))]
    {

        let exporter_attests_itself = match cli.exporter {
            #[cfg(feature = "use_sgx_vm")]
            ExporterChoice::Db => true,
            #[cfg(all(target_os = "linux", feature = "gpu"))]
            ExporterChoice::GpuDb => true,
            _ => false,
        };
        if std::env::var("SGX_REMOTE_HOST").is_ok() && exporter_attests_itself {
            println!(
                "[HASH-VERIFY] SGX_REMOTE_HOST set - guest mode: boot attestation is performed \
 by the exporter against the remote enclave (see verify_boot_in_sgx)"
            );
        } else {
            if std::env::var("SGX_REMOTE_HOST").is_ok() {
                println!(
                    "[HASH-VERIFY] SGX_REMOTE_HOST is set, but this exporter has no guest-side \
 attestation - running the host-style check instead of skipping it."
                );
            }
            verify_hash_inside_sgx();
        }
    }

    #[cfg(all(target_os = "linux", feature = "gpu"))]
    if matches!(cli.exporter, ExporterChoice::GpuDb) {
        if std::env::var("SGX_REMOTE_HOST").is_err() {
            check_iommu_state();
        } else if std::env::var("SCAPH_REQUIRE_IOMMU").as_deref() == Ok("1") {
            println!(
                "[IOMMU] SCAPH_REQUIRE_IOMMU=1 ignored in guest mode: a guest cannot observe \
 the IOMMU that confines it. Enforce this on the host."
            );
        }
    }

    #[cfg(target_os = "linux")]
    let _runtime_protectors = init_runtime_protection();

    let sensor = build_sensor(&cli);
    let mut exporter = build_exporter(cli.exporter, sensor.as_ref());
    if !cli.no_header {
        print_scaphandre_header(exporter.kind());
    }

    exporter.run();
}

#[cfg(all(feature = "use_sgx", target_os = "linux"))]

fn publish_host_attested(hostname: &str, immudb_addr: &str) {
    use std::process::Command;
    let open = Command::new("curl")
        .args([
            "-sk", &format!("https://{}/api/v2/authorization/session/open", immudb_addr),
            "-H", "Content-Type: application/json",
            "-d", r#"{"username":"immudb","password":"immudb","database":"defaultdb"}"#,
        ])
        .output();
    let sid = match open {
        Ok(o) => {
            let body = String::from_utf8_lossy(&o.stdout).to_string();
            match body.find("\"sessionID\":\"") {
                Some(i) => {
                    let rest = &body[i + 13..];
                    rest.find('"').map(|e| rest[..e].to_string()).unwrap_or_default()
                }
                None => String::new(),
            }
        }
        Err(_) => String::new(),
    };
    if sid.is_empty() {
        eprintln!("[HASH-VERIFY] could not record host attestation (no ImmuDB session) - guests requiring it will refuse");
        return;
    }

    let stamp = format!("{:x}", std::process::id());
    let doc = format!(
        r#"{{"documents":[{{"binary_name":"host_attested","hash_value":"attested-{}","hostname":"{}","deployment_type":"host","active":true,"pcr0":"","pcr7":"","pcr10":""}}]}}"#,
        stamp, hostname
    );

    for coll in ["binary_hashes_v3", "binary_hashes_v2"] {
        let _ = Command::new("curl")
            .args([
                "-sk", "-X", "POST",
                &format!("https://{}/api/v2/collection/{}/documents", immudb_addr, coll),
                "-H", "Content-Type: application/json",
                "-H", &format!("Grpc-Metadata-SessionID: {}", sid),
                "-d", &doc,
            ])
            .output();
    }
    println!("[HASH-VERIFY] host attestation recorded - guests on this host may now attest");
}

#[cfg(all(feature = "use_sgx", target_os = "linux"))]
fn verify_hash_inside_sgx() {
    use std::fs;
    use std::path::Path;

    println!("\n[HASH-VERIFY] ================================================");
    println!("[HASH-VERIFY] Starting binary hash verification");
    println!("[HASH-VERIFY] ================================================\n");

    let mut pcr_values = read_pcr_values();
    if pcr_values.len() != 96 {
        eprintln!("[HASH-VERIFY] Failed to read PCR values (expected 96 bytes, got {})", pcr_values.len());
        std::process::exit(1);
    }

    let snapshot_pcr10 = match scaphandre::exporters::utils::snapshot_pcr10() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[HASH-VERIFY] {}", e);
            std::process::exit(1);
        }
    };

    let ima_base = std::env::var("IMA_PATH").unwrap_or_else(|_| "/sys/kernel/security/ima".to_string());
    let ima_log_path = format!("{}/ascii_runtime_measurements", ima_base);
    let ima_log = match fs::read_to_string(&ima_log_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("[HASH-VERIFY] Failed to read IMA log: {}", e);
            eprintln!("[HASH-VERIFY] Path: {}", ima_log_path);
            eprintln!("[HASH-VERIFY] Note: Requires IMA enabled and root access");
            std::process::exit(1);
        }
    };

    match scaphandre::exporters::utils::splice_pcr10(&mut pcr_values, snapshot_pcr10.as_deref()) {
        Ok(true) => println!("[HASH-VERIFY] PCR10 taken from the IMA snapshot (paired with the log)"),
        Ok(false) => {}
        Err(e) => {
            eprintln!("[HASH-VERIFY] {}", e);
            std::process::exit(1);
        }
    }

    let hostname = scaphandre::exporters::utils::get_hostname();
    println!("[HASH-VERIFY] Hostname: {}", hostname);

    let deployment_type = detect_deployment_type();
    println!("[HASH-VERIFY] Deployment type: {}", deployment_type);

    let immudb_addr = std::env::var("IMMUDB_ADDR")
        .unwrap_or_else(|_| "192.168.122.1:8443".to_string());

    let ca_pem_path = std::env::var("IMMUDB_CA_CERT")
        .unwrap_or_else(|_| {

            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            format!("{}/.immudb/certs/ca.pem", home)
        });

    let ca_pem = match fs::read_to_string(&ca_pem_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("[HASH-VERIFY] Failed to read CA certificate: {}", e);
            eprintln!("[HASH-VERIFY] Path: {}", ca_pem_path);
            std::process::exit(1);
        }
    };

    println!("[HASH-VERIFY] ImmuDB address: {}", immudb_addr);
    println!("[HASH-VERIFY] CA cert: {}", ca_pem_path);

    #[cfg(feature = "use_sgx")]
    {
        use scaphandre::sgx_runner;

        sgx_runner::print_sgx_info();

        match sgx_runner::verify_in_sgx_enclave(
            &pcr_values,
            &ima_log,
            &hostname,
            &deployment_type,
            &immudb_addr,
            &ca_pem,
        ) {
            Ok(_) => {

                publish_host_attested(&hostname, &immudb_addr);
                println!("[HASH-VERIFY] Binary hash verification PASSED");
                println!("[HASH-VERIFY] Verified INSIDE REAL SGX ENCLAVE");
            }
            Err(-200) => {
                eprintln!("[HASH-VERIFY] SGX hardware not available");
                eprintln!("[HASH-VERIFY] This system REQUIRES real SGX hardware");
                std::process::exit(1);
            }
            Err(-201) => {
                eprintln!("[HASH-VERIFY] SGX enclave binary not found");
                std::process::exit(1);
            }
            Err(-202) => {
                eprintln!("[HASH-VERIFY] Failed to start SGX enclave");
                eprintln!("[HASH-VERIFY] Install: cargo install fortanix-sgx-tools");
                std::process::exit(1);
            }
            Err(-1) => {
                eprintln!("[HASH-VERIFY] Null pointer error");
                std::process::exit(1);
            }
            Err(-2) => {
                eprintln!("[HASH-VERIFY] Invalid PCR data (IMA not active)");
                std::process::exit(1);
            }
            Err(-3) => {
                eprintln!("[HASH-VERIFY] IMA log parse error");
                std::process::exit(1);
            }
            Err(-4) => {
                eprintln!("[HASH-VERIFY] Scaphandre binary not found in IMA log");
                std::process::exit(1);
            }
            Err(-5) => {
                eprintln!("[HASH-VERIFY] ImmuDB connection failed");
                std::process::exit(1);
            }
            Err(-6) => {
                eprintln!("[HASH-VERIFY] HASH MISMATCH DETECTED");
                eprintln!("[HASH-VERIFY] Binary has been TAMPERED - REFUSING TO RUN");
                std::process::exit(1);
            }
            Err(-99) => {
                eprintln!("[HASH-VERIFY] mbedtls feature not enabled");
                std::process::exit(1);
            }
            Err(code) => {
                eprintln!("[HASH-VERIFY] Unknown error code: {}", code);
                std::process::exit(1);
            }
        }
    }
}

#[cfg(all(feature = "use_sgx", target_os = "linux"))]
fn read_pcr_values() -> Vec<u8> {
    use std::fs;

    let mut pcr_values = Vec::with_capacity(96);

    for pcr in &[0, 7, 10] {
        let path = format!("/sys/class/tpm/tpm0/pcr-sha256/{}", pcr);
        match fs::read_to_string(&path) {
            Ok(hex_str) => {
                let hex_clean = hex_str.trim();
                if hex_clean.len() == 64 {
                    for i in (0..64).step_by(2) {
                        if let Ok(byte) = u8::from_str_radix(&hex_clean[i..i+2], 16) {
                            pcr_values.push(byte);
                        } else {
                            eprintln!("[HASH-VERIFY] Failed to parse PCR {} hex", pcr);
                            return vec![0u8; 96];
                        }
                    }
                } else {
                    eprintln!("[HASH-VERIFY] Invalid PCR {} length: {} (expected 64)", pcr, hex_clean.len());
                    return vec![0u8; 96];
                }
            }
            Err(e) => {
                eprintln!("[HASH-VERIFY] Failed to read PCR {}: {}", pcr, e);
                return vec![0u8; 96];
            }
        }
    }

    pcr_values
}

#[cfg(target_os = "linux")]
fn check_iommu_state() {
    use std::fs;

    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let cmdline_flag = cmdline.contains("intel_iommu=on")
        || cmdline.contains("amd_iommu=on")
        || cmdline.contains("iommu=force");
    let groups = fs::read_dir("/sys/kernel/iommu_groups")
        .map(|d| d.filter_map(|e| e.ok()).count())
        .unwrap_or(0);
    let active = groups > 0;

    let in_vm = fs::read_to_string("/sys/class/dmi/id/product_name")
        .map(|s| {
            let s = s.to_ascii_lowercase();
            s.contains("kvm") || s.contains("qemu") || s.contains("virtual") || s.contains("bochs")
        })
        .unwrap_or(false)
        || fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .map(|s| {
                let s = s.to_ascii_lowercase();
                s.contains("qemu") || s.contains("bochs") || s.contains("innotek")
            })
            .unwrap_or(false);

    if active {
        println!(
            "[IOMMU] active: {} group(s){}",
            groups,
            if cmdline_flag { "" } else { " (enabled without an explicit cmdline flag)" }
        );
    } else if in_vm {

        println!(
            "[IOMMU] not present in this guest - expected. Under passthrough the protection is the \
 HOST's IOMMU, which confines the assigned device's DMA to this VM. Verify it on the \
 host (`ls /sys/kernel/iommu_groups`), where it is attestable; it cannot be checked \
 from in here."
        );
    } else {
        let msg = format!(
            "[IOMMU] NOT active (0 groups, cmdline flag {}). PCIe passthrough is unsafe: a \
 passed-through device could DMA to arbitrary host memory. Add `intel_iommu=on \
 iommu=pt` to the kernel command line and reboot.",
            if cmdline_flag { "present" } else { "absent" }
        );
        if std::env::var("SCAPH_REQUIRE_IOMMU").as_deref() == Ok("1") {
            eprintln!("{}", msg);
            eprintln!("[IOMMU] SCAPH_REQUIRE_IOMMU=1 - refusing to start.");
            std::process::exit(1);
        }
        eprintln!("{}", msg);
        eprintln!("[IOMMU] Continuing (set SCAPH_REQUIRE_IOMMU=1 to make this fatal).");
    }
}

#[cfg(all(feature = "use_sgx", target_os = "linux"))]
fn detect_deployment_type() -> String {
    use std::fs;

    if let Ok(forced) = std::env::var("DEPLOYMENT_TYPE") {
        let forced = forced.trim().to_lowercase();
        if forced == "vm" || forced == "host" {
            println!("[HASH-VERIFY] Deployment type forced via DEPLOYMENT_TYPE env: {}", forced);
            return forced;
        }
    }

    let product_name_path = "/sys/class/dmi/id/product_name";
    if let Ok(product_name) = fs::read_to_string(product_name_path) {
        let product_lower = product_name.to_lowercase();
        if product_lower.contains("kvm") || product_lower.contains("qemu")
            || product_lower.contains("virtualbox") || product_lower.contains("vmware") {
            return "vm".to_string();
        }
    }

    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        if cpuinfo.contains("hypervisor") {
            return "vm".to_string();
        }
    }

    "host".to_string()
}

#[cfg(target_os = "linux")]
fn init_runtime_protection() -> RuntimeProtectors {
    use scaphandre::sensors::hash_verifier;

    #[cfg(feature = "with_ebpf_guard")]
    {
        println!("\n[RUNTIME-PROTECTION] ========================================");
        println!("[RUNTIME-PROTECTION] Initializing runtime integrity defenses");
        println!("[RUNTIME-PROTECTION] ========================================\n");
    }
    #[cfg(not(feature = "with_ebpf_guard"))]
    println!("[RUNTIME-PROTECTION] none compiled in (no with_ebpf_guard, hash verification off)");

    #[cfg(feature = "with_ebpf_guard")]
    let mem_protector = match scaphandre::sensors::memory_protection::protect_current_process() {
        Ok(protector) => {
            println!("[RUNTIME-PROTECTION] Memory protection active");
            println!("[RUNTIME-PROTECTION] - Blocks ptrace (anti-debugging)");
            println!("[RUNTIME-PROTECTION] - Blocks /proc/PID/mem writes");
            println!("[RUNTIME-PROTECTION] - Blocks RWX mprotect/mmap");
            Some(protector)
        }
        Err(e) => {
            eprintln!("[RUNTIME-PROTECTION] Failed to initialize memory protection: {}", e);
            eprintln!("[RUNTIME-PROTECTION] Continuing without eBPF protection");
            eprintln!("[RUNTIME-PROTECTION] Note: Requires root/CAP_BPF and kernel eBPF support");
            None
        }
    };

    let hash_verifier: Option<hash_verifier::HashVerifier> = None;

    #[cfg(feature = "with_ebpf_guard")]
    {
        println!("\n[RUNTIME-PROTECTION] ========================================");
        println!("[RUNTIME-PROTECTION] Runtime integrity protection initialized");
        println!("[RUNTIME-PROTECTION] ========================================\n");
    }

    RuntimeProtectors {
        #[cfg(feature = "with_ebpf_guard")]
        _memory_protector: mem_protector,
        _hash_verifier: hash_verifier,
    }
}

#[cfg(target_os = "linux")]
struct RuntimeProtectors {
    #[cfg(feature = "with_ebpf_guard")]
    _memory_protector: Option<scaphandre::sensors::memory_protection::MemoryProtector>,
    _hash_verifier: Option<scaphandre::sensors::hash_verifier::HashVerifier>,
}

fn build_exporter(choice: ExporterChoice, sensor: &dyn Sensor) -> Box<dyn exporters::Exporter> {
    match choice {
        ExporterChoice::Stdout(args) => {
            Box::new(exporters::stdout::StdoutExporter::new(sensor, args))
        }
        #[cfg(feature = "json")]
        ExporterChoice::Json(args) => {
            Box::new(exporters::json::JsonExporter::new(sensor, args))
        }
        #[cfg(feature = "prometheus")]
        ExporterChoice::Prometheus(args) => {
            Box::new(exporters::prometheus::PrometheusExporter::new(sensor, args))
        }

        #[cfg(feature = "qemu")]
        ExporterChoice::Qemu(args) => {
            println!("Running SGX-QEMU exporter (qemu)...");
            let mut exporter = QemuHostExporter::new(sensor);

            if let Some(ref url) = args.verifier_url {
                exporter.set_verifier_url(url.clone());
            }

            Box::new(exporter)
        }

        #[cfg(feature = "qemu")]
        ExporterChoice::SgxQemu(args) => {
            println!("Running SGX-QEMU exporter (sgx-qemu)...");
            let mut exporter = QemuHostExporter::new(sensor);

            if let Some(ref url) = args.verifier_url {
                exporter.set_verifier_url(url.clone());
            }

            Box::new(exporter)
        }

        #[cfg(feature = "riemann")]
        ExporterChoice::Riemann(args) => {
            Box::new(exporters::riemann::RiemannExporter::new(sensor, args))
        }
        #[cfg(feature = "warpten")]
        ExporterChoice::Warpten(args) => {
            Box::new(exporters::warpten::Warp10Exporter::new(sensor, args))
        }
        #[cfg(feature = "prometheuspush")]
        ExporterChoice::PrometheusPush(args) => Box::new(
            exporters::prometheuspush::PrometheusPushExporter::new(sensor, args),
        ),

        #[cfg(feature = "use_sgx_vm")]
        ExporterChoice::Db => {
            Box::new(exporters::db::DBExporter::new(sensor))
        }

        #[cfg(all(target_os = "linux", feature = "gpu"))]
        ExporterChoice::GpuDb => {
            Box::new(exporters::gpu_db::GpuDBExporter::new(sensor))
        }

        #[cfg(all(target_os = "linux", feature = "gpu"))]
        ExporterChoice::GpuPrint => {
            Box::new(exporters::gpu_print::GpuPrintExporter::new(sensor))
        }
    }

}

fn build_sensor(cli: &Cli) -> Box<dyn Sensor> {
    #[cfg(target_os = "linux")]
    let rapl_sensor = || -> Box<dyn Sensor> {
        Box::new(powercap_rapl::PowercapRAPLSensor::new(
            cli.sensor_buffer_per_socket_max_kb,
            cli.sensor_buffer_per_domain_max_kb,
            cli.vm,
        ))
    };

    #[cfg(target_os = "windows")]
    let msr_sensor_win = || -> Box<dyn Sensor> { Box::new(msr_rapl::MsrRAPLSensor::new()) };

    match cli.sensor.as_deref() {
        #[cfg(all(target_os = "linux", feature = "gpu"))]
        Some("gpu") | Some("nvml") => Box::new(gpu_nvml::GpuNvmlSensor::new()),
        Some("powercap_rapl") => {
            #[cfg(target_os = "linux")]
            {
                rapl_sensor()
            }
            #[cfg(not(target_os = "linux"))]
            panic!("Invalid sensor: Scaphandre's powercap_rapl only works on Linux")
        }
        Some("msr") => {
            #[cfg(target_os = "windows")]
            {
                msr_sensor_win()
            }
            #[cfg(not(target_os = "windows"))]
            panic!("Invalid sensor: Scaphandre's msr only works on Windows")
        }
        Some(s) => panic!("Unknown sensor type {}", s),
        None => {
            #[cfg(target_os = "linux")]
            return rapl_sensor();

            #[cfg(target_os = "windows")]
            return msr_sensor_win();

            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            compile_error!("Unsupported target OS")
        }
    }
}

fn print_scaphandre_header(exporter_name: &str) {
    let title = format!("Scaphandre {exporter_name} exporter");
    println!("{}", title.red().bold());
    println!("Sending metrics");
}

#[cfg(test)]
mod test {
    use super::*;

    const SUBCOMMANDS: &[&str] = &[
        "stdout",
        #[cfg(feature = "prometheus")]
        "prometheus",
        #[cfg(feature = "riemann")]
        "riemann",
        #[cfg(feature = "json")]
        "json",
        #[cfg(feature = "warpten")]
        "warpten",
        #[cfg(feature = "qemu")]
        "qemu",
        #[cfg(feature = "qemu")]
        "sgx-qemu",
    ];

    #[test]
    fn test_help() {
        fn assert_shows_help(args: &[&str]) {
            match Cli::try_parse_from(args) {
                Ok(_) => panic!(
                    "The CLI didn't generate a help message for {args:?}, are the inputs correct?"
                ),
                Err(e) => assert_eq!(
                    e.kind(),
                    clap::error::ErrorKind::DisplayHelp,
                    "The CLI emitted an error for {args:?}:\n{e}"
                ),
            };
        }
        assert_shows_help(&["scaphandre", "--help"]);
        for cmd in SUBCOMMANDS {
            assert_shows_help(&["scaphandre", cmd, "--help"]);
        }
    }
}
