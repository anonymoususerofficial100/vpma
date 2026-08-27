use crate::sensors::units::Unit::MicroJoule;
use crate::sensors::utils::current_system_time_since_epoch;
use crate::sensors::{CPUSocket, Domain, Record, RecordReader, Sensor, Topology};
use procfs::{modules, KernelModule};
use regex::Regex;
use std::collections::HashMap;
use std::error::Error;
use std::time::Instant;
use std::{env, fs};

use super::units::Unit;

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
use hmac::{Hmac, Mac};
#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
use sha2::Sha256;
#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
type HmacSha256 = Hmac<Sha256>;

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
static mut SENSOR_HMAC_KEY: Option<[u8; 32]> = None;

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
pub fn set_sensor_hmac_key(key: &[u8]) {
    if key.len() != 32 {
        eprintln!("[SENSOR] Invalid HMAC key length: {} (expected 32)", key.len());
        return;
    }
    unsafe {
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        SENSOR_HMAC_KEY = Some(key_array);
        println!("[SENSOR] HMAC key set for signing sensor readings");
    }
}

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
fn sign_sensor_data(data: &str) -> Vec<u8> {
    unsafe {
        if let Some(ref key) = SENSOR_HMAC_KEY {
            if let Ok(mut mac) = HmacSha256::new_from_slice(key) {
                mac.update(data.as_bytes());
                return mac.finalize().into_bytes().to_vec();
            }
        }
    }
    Vec::new()
}

use sysinfo::PidExt;

use crate::exporters::qemu::{
    QemuExporter, ProcessSample, RawEnergyValue,
};

#[cfg(feature = "qemu")]
use crate::exporters::export_vm::VmEnergyExporter;

use crate::sensors::utils::ProcessRecord;
use crate::exporters::Exporter;

#[cfg(feature = "with_ebpf_guard")]
#[repr(C)]
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct RaplReading {
    pub energy_uj: u64,
    pub timestamp_ns: u64,
    pub socket_id: u32,
    pub domain_id: u32,
    pub hash: u64,
    pub valid: u32,
}

#[cfg(feature = "with_ebpf_guard")]
impl Default for RaplReading {
    fn default() -> Self {
        RaplReading {
            energy_uj: 0,
            timestamp_ns: 0,
            socket_id: 0,
            domain_id: 0,
            hash: 0,
            valid: 0,
        }
    }
}

#[cfg(feature = "with_ebpf_guard")]
mod ebpf_guard {
    use bcc::perf_event::PerfMapBuilder;
    use bcc::{BPF, Kprobe, BccError};
    use std::ffi::c_void;
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::thread;
    use std::time::Instant;

    const DNAME_INLINE_LEN: usize = 32;
    const TASK_COMM_LEN: usize = 32;

    #[repr(C)]
    struct Event {
        pid: u32,
        uid: u32,
        pname: [u8; DNAME_INLINE_LEN],
        fname: [u8; DNAME_INLINE_LEN],
        comm: [u8; TASK_COMM_LEN],
        otype: [u8; TASK_COMM_LEN],
        is_unauthorized: i32,
        process_inode: u32,
    }

    fn decode_cstr(buf: &[u8]) -> String {
        let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..nul]).into_owned()
    }

    unsafe extern "C" fn print_event(_cpu: i32, data: *mut c_void, _size: i32) {
        let ev = &*(data as *const Event);

        let pname = decode_cstr(&ev.pname);
        let fname = decode_cstr(&ev.fname);
        let comm = decode_cstr(&ev.comm);
        let otype = decode_cstr(&ev.otype);

    }

    fn collect_scaphandre_energy_inodes(base: &str) -> io::Result<Vec<u64>> {
        let mut result = Vec::new();
        let base_path = PathBuf::from(base);

        if !base_path.exists() {
            return Ok(result);
        }

        for entry in std::fs::read_dir(&base_path)? {
            let entry = entry?;
            let vm_path = entry.path();
            let energy_path = vm_path.join("intel-rapl:0").join("energy_uj");

            if let Ok(meta) = std::fs::metadata(&energy_path) {
                result.push(meta.ino());
            }
        }

        Ok(result)
    }

    fn collect_host_rapl_inodes() -> io::Result<Vec<u64>> {
        let mut result = Vec::new();
        let powercap_path = "/sys/class/powercap";

        if let Ok(entries) = std::fs::read_dir(powercap_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                let path_str = path.to_string_lossy();

                if path_str.contains("intel-rapl") {
                    let energy_file = path.join("energy_uj");
                    if let Ok(meta) = std::fs::metadata(&energy_file) {
                        result.push(meta.ino());
                    }
                }
            }
        }

        Ok(result)
    }

    fn collect_crypto_storage_inodes() -> io::Result<Vec<u64>> {
        let mut result = Vec::new();

        let tpm_files = vec![
            "/var/lib/scaphandre/tpm/hmac_key_sealed.bin",
            "/var/lib/scaphandre/tpm/hmac_key.pub",
            "/var/lib/scaphandre/tpm/primary.ctx",
            "/var/lib/scaphandre/tpm/sealed_key.ctx",
            "/var/lib/scaphandre/tpm/pcr.policy",
        ];

        for path in tpm_files {
            if let Ok(meta) = std::fs::metadata(path) {
                result.push(meta.ino());
            }
        }

        if let Ok(meta) = std::fs::metadata("/var/lib/scaphandre/.sgx_sealed_hmac_key") {
            result.push(meta.ino());
        }

        Ok(result)
    }

    fn collect_process_info_inodes() -> io::Result<Vec<u64>> {
        let mut result = Vec::new();

        if let Ok(meta) = std::fs::metadata("/proc/stat") {
            result.push(meta.ino());
        }

        if let Ok(meta) = std::fs::metadata("/proc/cpuinfo") {
            result.push(meta.ino());
        }

        if let Ok(meta) = std::fs::metadata("/proc/self/exe") {
            result.push(meta.ino());
        }

        if let Ok(meta) = std::fs::metadata("/proc/meminfo") {
            result.push(meta.ino());
        }

        if let Ok(meta) = std::fs::metadata("/proc/diskstats") {
            result.push(meta.ino());
        }

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name() {

                    if name.to_string_lossy().chars().all(|c| c.is_numeric()) {

                        let stat_path = path.join("stat");
                        if let Ok(meta) = std::fs::metadata(&stat_path) {
                            result.push(meta.ino());
                        }

                        let io_path = path.join("io");
                        if let Ok(meta) = std::fs::metadata(&io_path) {
                            result.push(meta.ino());
                        }

                        let cmdline_path = path.join("cmdline");
                        if let Ok(meta) = std::fs::metadata(&cmdline_path) {
                            result.push(meta.ino());
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    fn insert_inodes(bpf: &mut BPF, map_name: &str, inodes: &[u64]) -> io::Result<()> {
        let mut table = bpf.table(map_name).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to open {}: {}", map_name, e),
            )
        })?;

        for ino in inodes {
            let mut key = ino.to_ne_bytes();
            let mut val = ino.to_ne_bytes();
            table.set(&mut key, &mut val).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to insert ino {} into {}: {}", ino, map_name, e),
                )
            })?;
        }

        Ok(())
    }

    fn insert_self_exec_inode(bpf: &mut BPF) -> io::Result<()> {
        let exe_path = std::fs::read_link("/proc/self/exe")?;
        let meta = std::fs::metadata(&exe_path)?;
        let ino = meta.ino();

        insert_inodes(bpf, "authorized_exec_inodes", &[ino])
    }

    fn attach_probes(bpf: &mut BPF) -> Result<(), BccError> {

        Kprobe::new()
            .handler("trace_read")
            .function("vfs_read")
            .attach(bpf)?;

        Kprobe::new()
            .handler("trace_kernel_read")
            .function("kernel_read")
            .attach(bpf)?;

        Kprobe::new()
            .handler("trace_write")
            .function("vfs_write")
            .attach(bpf)?;

        Kprobe::new()
            .handler("trace_kernel_write")
            .function("kernel_write")
            .attach(bpf)?;

        match Kprobe::new()
            .handler("trace_rename")
            .function("vfs_rename")
            .attach(bpf)
        {
            Ok(_) => println!("[EBPF-GUARD] Attached vfs_rename probe"),
            Err(e) => eprintln!("[EBPF-GUARD] Warning: Failed to attach vfs_rename: {}", e),
        }

        match Kprobe::new()
            .handler("trace_create")
            .function("security_inode_create")
            .attach(bpf)
        {
            Ok(_) => println!("[EBPF-GUARD] Attached security_inode_create probe"),
            Err(e) => eprintln!("[EBPF-GUARD] Warning: Failed to attach security_inode_create: {}", e),
        }

        match Kprobe::new()
            .handler("trace_delete")
            .function("vfs_unlink")
            .attach(bpf)
        {
            Ok(_) => println!("[EBPF-GUARD] Attached vfs_unlink probe"),
            Err(e) => eprintln!("[EBPF-GUARD] Warning: Failed to attach vfs_unlink: {}", e),
        }

        println!(
            "[EBPF-GUARD] Attached core kprobes (vfs_read/kernel_read/vfs_write/kernel_write)"
        );
        Ok(())
    }

    pub fn start_scaphandre_guard(base_path: &str) {
        let base_path = base_path.to_string();

        thread::spawn(move || {
            let guard_start = Instant::now();
            println!("[EBPF-GUARD] Starting guard for {}", base_path);

            let load_start = Instant::now();
            let code =
                include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/filemonitor_scaphandre.c"));
            let mut bpf = match BPF::new(code) {
                Ok(b) => {
                    let load_duration = load_start.elapsed();
                    println!("[TIMING-EBPF] Scaphandre Guard Program Load: {:.2} ms", load_duration.as_secs_f64() * 1000.0);
                    b
                }
                Err(e) => {
                    eprintln!("[EBPF-GUARD] Failed to load BPF: {}", e);
                    return;
                }
            };

            let mut all_sensitive_inodes = Vec::new();

            match collect_scaphandre_energy_inodes(&base_path) {
                Ok(inodes) => {
                    println!(
                        "[EBPF-GUARD] Found {} VM energy_uj inodes under {}",
                        inodes.len(),
                        base_path
                    );
                    all_sensitive_inodes.extend(inodes);
                }
                Err(e) => eprintln!(
                    "[EBPF-GUARD] Failed to collect VM energy inodes: {}",
                    e
                ),
            }

            match collect_host_rapl_inodes() {
                Ok(inodes) => {
                    println!(
                        "[EBPF-GUARD] Found {} host RAPL energy_uj inodes",
                        inodes.len()
                    );
                    all_sensitive_inodes.extend(inodes);
                }
                Err(e) => eprintln!(
                    "[EBPF-GUARD] Failed to collect host RAPL inodes: {}",
                    e
                ),
            }

            match collect_process_info_inodes() {
                Ok(inodes) => {
                    println!(
                        "[EBPF-GUARD] Found {} process info inodes",
                        inodes.len()
                    );
                    all_sensitive_inodes.extend(inodes);
                }
                Err(e) => eprintln!(
                    "[EBPF-GUARD] Failed to collect process info inodes: {}",
                    e
                ),
            }

            match collect_crypto_storage_inodes() {
                Ok(inodes) => {
                    if !inodes.is_empty() {
                        println!(
                            "[EBPF-GUARD] Found {} crypto storage inodes (TPM + SGX sealed keys)",
                            inodes.len()
                        );
                        all_sensitive_inodes.extend(inodes);
                    }
                }
                Err(e) => eprintln!(
                    "[EBPF-GUARD] Failed to collect crypto storage inodes: {}",
                    e
                ),
            }

            println!(
                "[EBPF-GUARD] Total {} sensitive inodes to monitor",
                all_sensitive_inodes.len()
            );
            if let Err(e) = insert_inodes(&mut bpf, "sensitive_inodes", &all_sensitive_inodes) {
                eprintln!(
                    "[EBPF-GUARD] Failed to insert sensitive inodes: {}",
                    e
                );
            }

            if let Err(e) = insert_self_exec_inode(&mut bpf) {
                eprintln!(
                    "[EBPF-GUARD] Failed to insert self exec inode: {}",
                    e
                );
            }

            let attach_start = Instant::now();
            if let Err(e) = attach_probes(&mut bpf) {
                eprintln!("[EBPF-GUARD] Failed to attach probes: {}", e);
                return;
            }
            let attach_duration = attach_start.elapsed();
            println!("[TIMING-EBPF] Scaphandre Guard Probe Attach: {:.2} ms", attach_duration.as_secs_f64() * 1000.0);

            let table = match bpf.table("events") {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[EBPF-GUARD] Failed to open events table: {}", e);
                    return;
                }
            };

            let mut perf_map =
                match PerfMapBuilder::new(table, || {
                    Box::new(|data: &[u8]| unsafe {
                        print_event(
                            0,
                            data.as_ptr() as *mut c_void,
                            data.len() as i32,
                        );
                    })
                })
                .build()
                {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[EBPF-GUARD] Failed to build perf map: {}", e);
                        return;
                    }
                };

            let guard_duration = guard_start.elapsed();
            println!("[TIMING-EBPF] Total Scaphandre Guard Init: {:.2} ms", guard_duration.as_secs_f64() * 1000.0);

            println!(
                "[EBPF-GUARD] Guard running. Monitoring sensitive file accesses..."
            );

            loop {
                perf_map.poll(200);
            }
        });
    }

    pub fn start_vm_energy_guard(vm_path: &str) {
        let vm_path = vm_path.to_string();

        thread::spawn(move || {
            let vm_guard_start = Instant::now();
            println!("[VM-EBPF-GUARD] Starting guard for VM energy files at {}", vm_path);

            let load_start = Instant::now();
            let code = r#"
#define DNAME_INLINE_LEN 32
#define COMM_LEN 16

#define CAT_UNKNOWN  0
#define CAT_ENERGY   1
#define CAT_STAT     2
#define CAT_CPUINFO  3
#define CAT_MEMINFO  4
#define CAT_BINARY   5

struct data_t {
    u32 pid;
    u32 uid;
    char fname[DNAME_INLINE_LEN];
    char comm[COMM_LEN];
    char otype[8];
    int  is_unauthorized;
    u32  category;
};

BPF_PERF_OUTPUT(events);

static __always_inline int detect_cat(const char *fname) {

    if (fname[0]=='e' && fname[1]=='n' && fname[2]=='e' && fname[3]=='r' &&
        fname[4]=='g' && fname[5]=='y' && fname[6]=='_' && fname[7]=='u' && fname[8]=='j')
        return CAT_ENERGY;

    if (fname[0]=='s' && fname[1]=='t' && fname[2]=='a' && fname[3]=='t')
        return CAT_STAT;

    if (fname[0]=='c' && fname[1]=='p' && fname[2]=='u' && fname[3]=='i')
        return CAT_CPUINFO;

    if (fname[0]=='m' && fname[1]=='e' && fname[2]=='m' && fname[3]=='i')
        return CAT_MEMINFO;

    if (fname[0]=='s' && fname[1]=='c' && fname[2]=='a' && fname[3]=='p')
        return CAT_BINARY;
    return CAT_UNKNOWN;
}

static __always_inline int is_scaphandre(const char *comm) {
    return (comm[0]=='s' && comm[1]=='c' && comm[2]=='a' && comm[3]=='p' &&
            comm[4]=='h' && comm[5]=='a' && comm[6]=='n' && comm[7]=='d' &&
            comm[8]=='r' && comm[9]=='e');
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->filename);

    data.category = detect_cat(data.fname);

    int flags = args->flags;
    if ((flags & 0x3) != 0 && data.category != CAT_UNKNOWN) {
        if (!is_scaphandre(data.comm)) {
            data.is_unauthorized = 1;
            data.otype[0]='O'; data.otype[1]='P'; data.otype[2]='E'; data.otype[3]='N';
            events.perf_submit(args, &data, sizeof(data));
        }
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->oldname);

    data.category = detect_cat(data.fname);

    if (data.category != CAT_UNKNOWN && !is_scaphandre(data.comm)) {
        data.is_unauthorized = 1;
        data.otype[0]='R'; data.otype[1]='E'; data.otype[2]='N'; data.otype[3]='A';
        events.perf_submit(args, &data, sizeof(data));
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->pathname);

    data.category = detect_cat(data.fname);

    if (data.category != CAT_UNKNOWN) {
        data.is_unauthorized = 1;
        data.otype[0]='D'; data.otype[1]='E'; data.otype[2]='L'; data.otype[3]='E';
        events.perf_submit(args, &data, sizeof(data));
    }

    return 0;
}
"#;
            let mut bpf = match BPF::new(code) {
                Ok(b) => {
                    let load_duration = load_start.elapsed();
                    println!("[TIMING-EBPF] VM Guard Program Load: {:.2} ms", load_duration.as_secs_f64() * 1000.0);
                    b
                }
                Err(e) => {
                    eprintln!("[VM-EBPF-GUARD] Failed to load BPF: {}", e);
                    eprintln!("[VM-EBPF-GUARD] File monitoring disabled - energy files protected on host");
                    eprintln!("[VM-EBPF-GUARD] Memory protection and hash verification remain active");
                    return;
                }
            };

            println!("[VM-EBPF-GUARD] VM file monitor loaded (using syscall tracepoints)");

            let table = match bpf.table("events") {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[VM-EBPF-GUARD] Failed to open events table: {}", e);
                    return;
                }
            };

            let mut perf_map =
                match PerfMapBuilder::new(table, || {
                    Box::new(|data: &[u8]| unsafe {
                        print_event(
                            0,
                            data.as_ptr() as *mut c_void,
                            data.len() as i32,
                        );
                    })
                })
                .build()
                {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[VM-EBPF-GUARD] Failed to build perf map: {}", e);
                        return;
                    }
                };

            let vm_guard_duration = vm_guard_start.elapsed();
            println!("[TIMING-EBPF] Total VM Guard Init: {:.2} ms", vm_guard_duration.as_secs_f64() * 1000.0);

            println!("[VM-EBPF-GUARD] Monitoring VM energy file accesses (energy_uj files)");
            println!("[VM-EBPF-GUARD] Will alert on unauthorized write attempts");

            loop {
                perf_map.poll(200);
            }
        });
    }
}

#[cfg(feature = "with_ebpf_guard")]
use self::ebpf_guard::{start_scaphandre_guard, start_vm_energy_guard};

#[cfg(feature = "with_ebpf_guard")]
mod ebpf_rapl_hash {
    use bcc::BPF;
    use std::sync::Mutex;
    use std::time::Instant;
    use lazy_static::lazy_static;
    use super::RaplReading;

    lazy_static! {
        static ref RAPL_HASH_BPF: Mutex<Option<BPF>> = Mutex::new(None);
    }

    pub fn init_rapl_hash_bpf() -> Result<(), Box<dyn std::error::Error>> {
        let init_start = Instant::now();

        let load_start = Instant::now();
        let (k0, k1) = crate::sensors::tag_key();
        let epoch = crate::sensors::tag_epoch();
        let code = include_str!("ebpf_rapl_hash.c")
            .replace("SIPTAG_K0_PLACEHOLDER", &format!("{:016x}", k0))
            .replace("SIPTAG_K1_PLACEHOLDER", &format!("{:016x}", k1))
            .replace("SIPTAG_EPOCH_PLACEHOLDER", &format!("{}", epoch));

        if code.contains("PLACEHOLDER") {
            return Err("SipTag key substitution failed in ebpf_rapl_hash.c -- \
 refusing to load an unkeyed tagger".into());
        }
        let mut bpf = BPF::new(&code)?;
        let load_duration = load_start.elapsed();
        println!("[TIMING-EBPF] RAPL Hash Program Load: {:.2} ms", load_duration.as_secs_f64() * 1000.0);

        let attach_start = Instant::now();
        bcc::Kprobe::new()
            .handler("auto_compute_hash")
            .function("hrtimer_interrupt")
            .attach(&mut bpf)?;
        let attach_duration = attach_start.elapsed();
        println!("[TIMING-EBPF] RAPL Hash Probe Attach: {:.2} ms", attach_duration.as_secs_f64() * 1000.0);

        #[cfg(feature = "with_ebpf_kernel_read")]
        {
            bcc::Kprobe::new()
                .handler("trace_rapl_read_entry")
                .function("rapl_read_data_raw")
                .attach(&mut bpf)?;
            bcc::Kretprobe::new()
                .handler("trace_rapl_read_ret")
                .function("rapl_read_data_raw")
                .attach(&mut bpf)?;
            println!("[RAPL-HASH] kernel-read capture active (kprobe on rapl_read_data_raw)");
        }

        println!("[RAPL-HASH] eBPF program loaded with auto-computation");
        println!("[RAPL-HASH] Keyed SipTag-32 (SipHash) tagging active in kernel space");

        let mut guard = RAPL_HASH_BPF.lock().unwrap();
        *guard = Some(bpf);

        let init_duration = init_start.elapsed();
        println!("[TIMING-EBPF] Total RAPL Hash Init: {:.2} ms", init_duration.as_secs_f64() * 1000.0);

        Ok(())
    }

    pub fn compute_and_store_hash(
        energy_uj: u64,
        timestamp_ns: u64,
        socket_id: u32,
        domain_id: u32,
    ) -> Result<RaplReading, Box<dyn std::error::Error>> {
        let guard = RAPL_HASH_BPF.lock().unwrap();

        if let Some(ref bpf) = *guard {
            let mut table = bpf.table("rapl_hash_map")?;

            let map_idx = socket_id * 4 + domain_id;

            let reading = RaplReading {
                energy_uj,
                timestamp_ns,
                socket_id,
                domain_id,
                hash: 0,
                valid: 0,
            };

            let mut key = map_idx.to_ne_bytes();
            let mut value = unsafe {
                std::slice::from_raw_parts_mut(
                    &reading as *const _ as *mut u8,
                    std::mem::size_of::<RaplReading>(),
                )
            };

            table.set(&mut key, &mut value)?;

            std::thread::sleep(std::time::Duration::from_micros(100));

            let value = table.get(&mut key)?;
            let computed_reading = unsafe {
                std::ptr::read(value.as_ptr() as *const RaplReading)
            };

            if computed_reading.valid == 1 {

                Ok(computed_reading)
            } else {

                let reading_with_hash = RaplReading {
                    hash: 0,
                    valid: 0,
                    ..reading
                };

                let mut value = unsafe {
                    std::slice::from_raw_parts_mut(
                        &reading_with_hash as *const _ as *mut u8,
                        std::mem::size_of::<RaplReading>(),
                    )
                };
                table.set(&mut key, &mut value)?;

                Ok(reading_with_hash)
            }
        } else {
            Err("RAPL hash BPF not initialized".into())
        }
    }

    pub fn get_reading(socket_id: u32, domain_id: u32) -> Result<RaplReading, Box<dyn std::error::Error>> {
        let guard = RAPL_HASH_BPF.lock().unwrap();

        if let Some(ref bpf) = *guard {
            let mut table = bpf.table("rapl_hash_map")?;

            let map_idx = socket_id * 4 + domain_id;
            let mut key = map_idx.to_ne_bytes();

            let value = table.get(&mut key)?;
            let reading = unsafe {
                std::ptr::read(value.as_ptr() as *const RaplReading)
            };

            if reading.valid == 1 {
                return Ok(reading);
            }
        }

        Err("Reading not found or invalid".into())
    }

    #[cfg(feature = "with_ebpf_kernel_read")]
    pub fn set_rapl_context(socket_id: u32, domain_id: u32) {
        let guard = match RAPL_HASH_BPF.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let bpf = match guard.as_ref() {
            Some(b) => b,
            None => return,
        };
        let mut table = match bpf.table("rapl_ctx_hint") {
            Ok(t) => t,
            Err(_) => return,
        };

        let tgid = std::process::id() as u64;
        let packed = ((socket_id as u64) << 32) | (domain_id as u64);
        let mut key = tgid.to_ne_bytes();
        let mut val = packed.to_ne_bytes();
        let _ = table.set(&mut key, &mut val);
    }

    fn rotl64(x: u64, b: u32) -> u64 {
        (x << b) | (x >> (64 - b))
    }

    fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
        *v0 = v0.wrapping_add(*v1);
        *v1 = rotl64(*v1, 13);
        *v1 ^= *v0;
        *v0 = rotl64(*v0, 32);

        *v2 = v2.wrapping_add(*v3);
        *v3 = rotl64(*v3, 16);
        *v3 ^= *v2;

        *v0 = v0.wrapping_add(*v3);
        *v3 = rotl64(*v3, 21);
        *v3 ^= *v0;

        *v2 = v2.wrapping_add(*v1);
        *v1 = rotl64(*v1, 17);
        *v1 ^= *v2;
        *v2 = rotl64(*v2, 32);
    }

    #[allow(dead_code)]
    fn compute_siphash24(energy: u64, timestamp: u64, socket: u32, domain: u32) -> u64 {

        const K0: u64 = 0x0706050403020100;
        const K1: u64 = 0x0f0e0d0c0b0a0908;

        let mut v0 = 0x736f6d6570736575u64 ^ K0;
        let mut v1 = 0x646f72616e646f6du64 ^ K1;
        let mut v2 = 0x6c7967656e657261u64 ^ K0;
        let mut v3 = 0x7465646279746573u64 ^ K1;

        v3 ^= energy;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= energy;

        v3 ^= timestamp;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= timestamp;

        let ids = ((socket as u64) << 32) | (domain as u64);
        v3 ^= ids;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= ids;

        v2 ^= 0xff;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);

        v0 ^ v1 ^ v2 ^ v3
    }
}

#[cfg(feature = "with_ebpf_guard")]
use self::ebpf_rapl_hash::{init_rapl_hash_bpf, compute_and_store_hash, get_reading};

impl Exporter for QemuHostExporter {
    fn kind(&self) -> &str {
        "sgx-qemu"
    }

    fn run(&mut self) {
        println!("[SGX-QEMU] Exporter run() started");

        #[cfg(feature = "with_ebpf_guard")]
        {
            start_scaphandre_guard("/var/lib/scaphandre");
        }

        loop {
            self.iterate("/var/lib/scaphandre".to_string());

            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }
}

#[cfg(feature = "use_sgx")]
use crate::sgx_runner::ecall_compute_vm_energy_simple;

#[no_mangle]
pub extern "C" fn ocall_print_host(msg_ptr: *const u8, msg_len: usize) {
    if msg_ptr.is_null() {
        return;
    }
    let msg_slice = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
    if let Ok(msg_str) = std::str::from_utf8(msg_slice) {
        println!("{}", msg_str);
    }
}

pub struct SgxQemuExporter {
    inner: QemuExporter,
    #[cfg(feature = "qemu")]
    vm_exporter: VmEnergyExporter,
    #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
    hmac_key: Option<Vec<u8>>,
}

impl SgxQemuExporter {
    pub fn new() -> Self {
        #[cfg(feature = "qemu")]
        let vm_exporter = VmEnergyExporter::new("/var/lib/scaphandre".to_string());

        SgxQemuExporter {
            inner: QemuExporter::new(),
            #[cfg(feature = "qemu")]
            vm_exporter,
            #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
            hmac_key: None,
        }
    }

    pub fn iterate(
        &mut self,
        path: String,
        topo_energy_value: String,
        processes: Vec<Vec<ProcessSample>>,
        #[cfg(feature = "with_ebpf_guard")]
        hash_readings: Vec<RaplReading>,
    ) {
        println!("[SGX-QEMU] iterate() called");
        println!(" path = {}", path);
        println!(" topo_energy_value = {}", topo_energy_value);
        println!(" process groups = {}", processes.len());

        #[cfg(feature = "with_ebpf_guard")]
        println!(" hash_readings = {}", hash_readings.len());

        #[cfg(not(feature = "use_sgx"))]
        {
            println!(
                "[SGX-QEMU] SGX feature NOT enabled -> using direct QemuExporter"
            );
            let updates = self.inner.iterate(path, topo_energy_value, processes);

            #[cfg(feature = "qemu")]
            {
                println!("[SGX-QEMU] -> Sending {} updates to export_vm", updates.len());
                if let Err(e) = self.vm_exporter.write_updates(updates) {
                    eprintln!("[SGX-QEMU] Failed to write updates: {}", e);
                }
            }

            return;
        }

        #[cfg(feature = "use_sgx")]
        {
            use serde_json;

            println!("[SGX-QEMU] Serializing topo energy...");
            let topo_json = match serde_json::to_vec(&topo_energy_value) {
                Ok(v) => v,
                Err(e) => {
                    println!(
                        "[SGX-QEMU] Failed to serialize topo energy: {}",
                        e
                    );
                    return;
                }
            };

            println!("[SGX-QEMU] Serializing process samples...");
            let proc_json = match serde_json::to_vec(&processes) {
                Ok(v) => v,
                Err(e) => {
                    println!(
                        "[SGX-QEMU] Failed to serialize process samples: {}",
                        e
                    );
                    return;
                }
            };

            #[cfg(feature = "with_ebpf_guard")]
            let hash_json = {
                println!("[SGX-QEMU] Serializing hash readings...");
                match serde_json::to_vec(&hash_readings) {
                    Ok(v) => v,
                    Err(e) => {
                        println!("[SGX-QEMU] Failed to serialize hash readings: {}", e);
                        return;
                    }
                }
            };

            #[cfg(not(feature = "with_ebpf_guard"))]
            let hash_json = vec![];

            const OUT_CAP: usize = 16 * 1024;
            let mut out_buf = vec![0u8; OUT_CAP];
            let mut out_len: usize = 0;

            println!(
                "[SGX-QEMU] Calling ECALL: topo_len = {}, proc_len = {}, hash_len = {}",
                topo_json.len(),
                proc_json.len(),
                hash_json.len()
            );

            if hash_json.is_empty() {
                println!("[SGX-QEMU] No RAPL tags collected - enclave will compute WITHOUT tag verification");
            } else {
                println!("[SGX-QEMU] Sending RAPL tags; enclave will verify them before computation");
            }
            println!("[SGX-QEMU] SGX will call OCALL (main.rs) -> export_vm for each VM");

            let status = unsafe {
                ecall_compute_vm_energy_simple(
                    topo_json.as_ptr(),
                    topo_json.len(),
                    proc_json.as_ptr(),
                    proc_json.len(),
                    hash_json.as_ptr(),
                    hash_json.len(),
                    out_buf.as_mut_ptr(),
                    OUT_CAP,
                    &mut out_len as *mut usize,
                )
            };

            println!("[SGX-QEMU] ECALL returned status = {}", status);

            if status == -2 {
                eprintln!("[SGX-QEMU] HASH VERIFICATION FAILED IN SGX!");
                eprintln!("[SGX-QEMU] RAPL data integrity compromised - possible tampering");
                eprintln!("[SGX-QEMU] Rejecting energy computation");
                return;
            }

            if status != 0 {
                println!(
                    "[SGX-QEMU] ECALL ecall_compute_vm_energy_simple failed with status {}",
                    status
                );
                return;
            }

            println!("[SGX-QEMU] ECALL completed successfully");
            if hash_json.is_empty() {
                println!("[SGX-QEMU] (no tags were supplied - nothing was verified)");
            } else {
                println!("[SGX-QEMU] Enclave accepted all supplied RAPL tags");
            }
            println!("[SGX-QEMU] VM energy files written via OCALL -> export_vm");

        }
    }
}

pub const DEFAULT_BUFFER_PER_SOCKET_MAX_KBYTES: u16 = 1;
pub const DEFAULT_BUFFER_PER_DOMAIN_MAX_KBYTES: u16 = 1;

pub struct QemuHostExporter {
    topology: Topology,
    qemu_calc: SgxQemuExporter,
    verifier_url: Option<String>,
}

impl QemuHostExporter {
    pub fn new(sensor: &dyn Sensor) -> Self {
        let topology = sensor.get_topology().unwrap();
        let qemu_calc = SgxQemuExporter::new();

        QemuHostExporter {
            topology,
            qemu_calc,
            verifier_url: None,
        }
    }

    pub fn set_verifier_url(&mut self, url: String) {
        self.verifier_url = Some(url);
    }

    pub fn iterate(&mut self, path: String) {
        use std::time::Instant;
        let iteration_start = Instant::now();

        println!("\n[QEMU-HOST] iterate() --- begin");
        println!("[QEMU-HOST] path = {}", path);

        let refresh_start = Instant::now();
        self.topology.refresh();
        let refresh_duration = refresh_start.elapsed();
        println!("[QEMU-HOST] topology refreshed");
        println!("[TIMING-QEMU] Topology Refresh: {:.2} ms", refresh_duration.as_secs_f64() * 1000.0);

        if let Some(topo_energy) = self.topology.get_records_diff_energy_microjoules() {
            println!("[QEMU-HOST] topo_energy delta = {} uJ", topo_energy.value);

            let processes = self.topology.proc_tracker.get_alive_processes();
            println!(
                "[QEMU-HOST] Found {} process groups",
                processes.len()
            );

            let sample_start = Instant::now();
            let samples = self.build_samples(&processes);
            let sample_duration = sample_start.elapsed();
            println!("[QEMU-HOST] Built {} sample groups", samples.len());
            println!("[TIMING-QEMU] Sample Building: {:.2} ms", sample_duration.as_secs_f64() * 1000.0);

            #[cfg(feature = "with_ebpf_guard")]
            let hash_readings = {
                let hash_collect_start = Instant::now();
                let mut readings = Vec::new();

                println!("[QEMU-HOST] Collecting RAPL hash readings from eBPF...");

                for (socket_idx, _socket) in self.topology.sockets.iter().enumerate() {

                    match get_reading(socket_idx as u32, 0) {
                        Ok(mut reading) => {
                            if reading.valid == 1 {
                                println!("[QEMU-HOST] Socket {} hash collected", socket_idx);

                                readings.push(reading);
                            } else {
                                println!("[QEMU-HOST] Socket {} reading invalid", socket_idx);
                            }
                        }
                        Err(e) => {
                            println!("[QEMU-HOST] Failed to get socket {} hash: {}", socket_idx, e);
                        }
                    }
                }

                let hash_duration = hash_collect_start.elapsed();
                println!("[QEMU-HOST] Collected {} hash readings total", readings.len());
                println!("[TIMING-QEMU] RAPL Hash Collection: {:.2} ms", hash_duration.as_secs_f64() * 1000.0);
                readings
            };

            println!("[QEMU-HOST] -> Calling SGX (will write directly to export_vm)");

            let sgx_start = Instant::now();
            #[cfg(feature = "with_ebpf_guard")]
            self.qemu_calc.iterate(
                path.clone(),
                topo_energy.value.clone(),
                samples,
                hash_readings
            );

            #[cfg(not(feature = "with_ebpf_guard"))]
            self.qemu_calc.iterate(
                path.clone(),
                topo_energy.value.clone(),
                samples
            );
            let sgx_duration = sgx_start.elapsed();

            println!("[QEMU-HOST] SGX computation and export completed");
            println!("[TIMING-QEMU] SGX Computation + Export: {:.2} ms", sgx_duration.as_secs_f64() * 1000.0);
        } else {
            println!(
                "[QEMU-HOST] topo_energy is None, skipping VM update"
            );
        }

        let iteration_duration = iteration_start.elapsed();
        println!("[TIMING-QEMU] Total Iteration: {:.2} ms", iteration_duration.as_secs_f64() * 1000.0);
        println!("[QEMU-HOST] iterate() --- end\n");
    }

    fn build_samples(
        &self,
        processes: &[&Vec<ProcessRecord>],
    ) -> Vec<Vec<ProcessSample>> {
        let mut result = vec![];

        for vecp in processes {
            let mut v2 = vec![];
            for p in *vecp {
                let cmdline = p
                    .process
                    .cmdline(&self.topology.proc_tracker)
                    .unwrap_or_default();
                let cpu = self
                    .topology
                    .get_process_cpu_usage_percentage(p.process.pid)
                    .map(|x| x.value.clone())
                    .unwrap_or_else(|| "0".to_string());

                v2.push(ProcessSample {
                    pid: p.process.pid.as_u32(),
                    cmdline,
                    cpu_usage_percentage: cpu,
                });
            }
            result.push(v2);
        }

        result
    }
}

pub struct PowercapRAPLSensor {
    base_path: String,
    buffer_per_socket_max_kbytes: u16,
    buffer_per_domain_max_kbytes: u16,
    virtual_machine: bool,
}

impl PowercapRAPLSensor {

    pub fn new(
        buffer_per_socket_max_kbytes: u16,
        buffer_per_domain_max_kbytes: u16,
        virtual_machine: bool,
    ) -> PowercapRAPLSensor {
        let mut powercap_path = env::var("POWERCAP_PATH").unwrap_or_else(|_| String::from("/sys/class/powercap"));
        println!("[SENSOR] PowercapRAPLSensor::new() - base_path = {}", powercap_path);
        if virtual_machine {
            powercap_path = String::from("/var/scaphandre");
            if let Ok(val) = env::var("SCAPHANDRE_POWERCAP_PATH") {
                powercap_path = val;
            }

            info!("Powercap_rapl path is: {}", powercap_path);

            #[cfg(feature = "with_ebpf_guard")]
            {
                println!("[VM-MODE] Starting eBPF guard for VM energy files");
                start_vm_energy_guard(&powercap_path);
            }

            #[cfg(feature = "use_sgx_vm")]
            {
                println!("[VM-SGX] Initializing SGX enclave for per-process energy calculation");
                if let Err(e) = init_vm_sgx_enclave() {
                    warn!("[VM-SGX] Failed to initialize SGX enclave: {}", e);
                    warn!("[VM-SGX] Falling back to non-SGX per-process calculation");
                } else {
                    println!("[VM-SGX] SGX enclave ready for trusted process energy computation");
                }
            }
        }

        #[cfg(feature = "with_ebpf_guard")]
        {
            if let Err(e) = ebpf_rapl_hash::init_rapl_hash_bpf() {
                warn!("Failed to initialize eBPF RAPL hash program: {}", e);
                warn!("Hash verification will be disabled");
            } else {
                info!("eBPF RAPL hash program initialized");
            }
        }

        PowercapRAPLSensor {
            base_path: powercap_path,
            buffer_per_socket_max_kbytes,
            buffer_per_domain_max_kbytes,
            virtual_machine,
        }
    }

    pub fn get_vm_energy_with_chain(&self) -> Result<(u64, u64, Vec<u8>, Vec<u8>, u64), Box<dyn Error>> {
        if !self.virtual_machine {
            return Err("Not in VM mode".into());
        }

        let chain_dir = format!("{}/intel-rapl:0", self.base_path);

        let energy_uj = fs::read_to_string(format!("{}/energy_uj", chain_dir))?
            .trim()
            .parse::<u64>()?;

        let counter = fs::read_to_string(format!("{}/chain_counter", chain_dir))?
            .trim()
            .parse::<u64>()?;

        let prev_hash_hex = fs::read_to_string(format!("{}/chain_previous_hash", chain_dir))?
            .trim()
            .to_string();
        let prev_hash = hex::decode(prev_hash_hex)?;

        let signature_hex = fs::read_to_string(format!("{}/chain_signature", chain_dir))?
            .trim()
            .to_string();
        let signature = hex::decode(signature_hex)?;

        let energy_delta = fs::read_to_string(format!("{}/chain_energy_delta", chain_dir))?
            .trim()
            .parse::<u64>()?;

        Ok((energy_uj, counter, prev_hash, signature, energy_delta))
    }

    pub fn check_module() -> Result<String, String> {
        let modules = modules().unwrap();
        let rapl_modules = modules
            .iter()
            .filter(|(_, v)| {
                v.name == "intel_rapl"
                    || v.name == "intel_rapl_msr"
                    || v.name == "intel_rapl_common"
            })
            .collect::<HashMap<&String, &KernelModule>>();

        if !rapl_modules.is_empty() {
            Ok(String::from(
                "intel_rapl or intel_rapl_msr+intel_rapl_common modules found.",
            ))
        } else {
            Err(String::from(
                "None of intel_rapl, intel_rapl_common or intel_rapl_msr kernel modules found.",
            ))
        }
    }
}

impl RecordReader for Topology {
    fn read_record(&self) -> Result<Record, Box<dyn Error>> {

        if let Some(psys_record) = self.get_rapl_psys_energy_microjoules() {
            debug!("Using PSYS metric");
            Ok(psys_record)
        } else {
            debug!("Summing socket PKG and DRAM metrics to get host metric");

            let mut pkg_values: Vec<RawEnergyValue> = Vec::new();
            let mut dram_values: Vec<RawEnergyValue> = Vec::new();

            println!("[TOPO] Summing per-socket energy metrics...");

            for s in &self.sockets {

                if let Ok(r) = s.read_record() {
                    println!("[TOPO] socket energy value = {}", r.value);
                    pkg_values.push(RawEnergyValue {
                        value: r.value,
                        hmac_signature: Vec::new(),
                    });
                }

                for d in &s.domains {
                    if d.name == "dram" {
                        if let Ok(dr) = d.read_record() {
                            println!("[TOPO] DRAM domain value = {}", dr.value);
                            dram_values.push(RawEnergyValue {
                                value: dr.value,
                                hmac_signature: Vec::new(),
                            });
                        }
                    }
                }
            }

            #[cfg(feature = "use_sgx")]
            let total_str = {
                use crate::sgx_runner::ecall_compute_total_host_energy;

                let pkg_json = serde_json::to_vec(&pkg_values).unwrap();
                let dram_json = serde_json::to_vec(&dram_values).unwrap();

                let mut out_buf = vec![0u8; 256];
                let mut out_len: usize = 0;

                let status = unsafe {
                    ecall_compute_total_host_energy(
                        pkg_json.as_ptr(),
                        pkg_json.len(),
                        dram_json.as_ptr(),
                        dram_json.len(),
                        out_buf.as_mut_ptr(),
                        out_buf.len(),
                        &mut out_len as *mut usize,
                    )
                };

                if status == 0 {
                    let result = String::from_utf8_lossy(&out_buf[..out_len]).to_string();
                    println!("[SGX-HOST] Total energy computed in SGX enclave: {}", result);
                    result
                } else {
                    warn!("[SGX-HOST] SGX summation failed (status {}), falling back to userspace", status);
                    crate::exporters::qemu::compute_total_host_energy(&pkg_values, &dram_values)
                }
            };

            #[cfg(not(feature = "use_sgx"))]
            let total_str = crate::exporters::qemu::compute_total_host_energy(
                &pkg_values,
                &dram_values,
            );

            println!(
                "[TOPO] Total host energy (string) = {}",
                total_str
            );

            Ok(Record::new(
                current_system_time_since_epoch(),
                total_str,
                Unit::MicroJoule,
            ))
        }
    }
}

impl RecordReader for CPUSocket {
    fn read_record(&self) -> Result<Record, Box<dyn Error>> {

        #[cfg(feature = "gpu")]
        if let Some(gpu_index) = self
            .sensor_data
            .get(crate::sensors::gpu_nvml::GPU_INDEX_KEY)
        {
            return crate::sensors::gpu_nvml::read_gpu_energy_record(gpu_index);
        }
        let source_file = self.sensor_data.get("source_file").unwrap();

        #[cfg(feature = "with_ebpf_kernel_read")]
        {

            let socket_id: u32 = self.id as u32;
            ebpf_rapl_hash::set_rapl_context(socket_id, 0);
        }

        match fs::read_to_string(source_file) {
            Ok(result) => {

                let timestamp_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                let energy_uj: u64 = result.trim().parse().unwrap_or(0);

                let socket_id: u32 = self.id as u32;

                #[cfg(all(feature = "with_ebpf_guard", not(feature = "with_ebpf_kernel_read")))]
                let hash_result = compute_and_store_hash(energy_uj, timestamp_ns, socket_id, 0);
                #[cfg(all(feature = "with_ebpf_guard", feature = "with_ebpf_kernel_read"))]
                let _ = (energy_uj, timestamp_ns, socket_id);

                #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
                {
                    let signature = sign_sensor_data(&result);
                    Ok(Record::new_with_signature(
                        current_system_time_since_epoch(),
                        result,
                        MicroJoule,
                        signature,
                    ))
                }
                #[cfg(not(any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
                Ok(Record::new(
                    current_system_time_since_epoch(),
                    result,
                    MicroJoule,
                ))
            }
            Err(error) => Err(Box::new(error)),
        }
    }
}

impl RecordReader for Domain {
    fn read_record(&self) -> Result<Record, Box<dyn Error>> {
        let source_file = self.sensor_data.get("source_file").unwrap();
        match fs::read_to_string(source_file) {
            Ok(result) => {

                let timestamp_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                let energy_uj: u64 = result.trim().parse().unwrap_or(0);

                let socket_id: u32 = 0;
                let domain_id: u32 = if self.name == "dram" { 1 } else if self.name == "core" { 2 } else { 3 };

                #[cfg(all(feature = "with_ebpf_guard", not(feature = "with_ebpf_kernel_read")))]
                let hash_result = compute_and_store_hash(energy_uj, timestamp_ns, socket_id, domain_id);
                #[cfg(all(feature = "with_ebpf_guard", feature = "with_ebpf_kernel_read"))]
                let _ = (energy_uj, timestamp_ns, socket_id, domain_id);

                #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
                {

                    let signature = sign_sensor_data(&result);
                    Ok(Record::new_with_signature(
                        current_system_time_since_epoch(),
                        result,
                        MicroJoule,
                        signature,
                    ))
                }
                #[cfg(not(any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
                Ok(Record {
                    timestamp: current_system_time_since_epoch(),
                    unit: MicroJoule,
                    value: result,
                })
            }
            Err(error) => Err(Box::new(error)),
        }
    }
}

impl Sensor for PowercapRAPLSensor {

    fn generate_topology(&self) -> Result<Topology, Box<dyn Error>> {
        let modules_state = PowercapRAPLSensor::check_module();
        if modules_state.is_err() && !self.virtual_machine {
            warn!("Couldn't find intel_rapl modules.");
        }
        let mut topo = Topology::new(HashMap::new());
        let re_socket = Regex::new(r"^.*/intel-rapl:\d+$").unwrap();
        let re_domain = Regex::new(r"^.*/intel-rapl:\d+:\d+$").unwrap();
        let re_socket_mmio = Regex::new(r"^.*/intel-rapl-mmio:\d+$").unwrap();
        let re_domain_mmio = Regex::new(r"^.*/intel-rapl-mmio:\d+:\d+$").unwrap();
        let mut re_domain_matched = false;
        for folder in fs::read_dir(&self.base_path).unwrap() {
            let folder_name = String::from(
                folder.unwrap().path().to_str().unwrap(),
            );
            info!("working on {folder_name}");

            if re_domain.is_match(&folder_name) {
                re_domain_matched = true;

                let mut splitted = folder_name.split(':');
                let _ = splitted.next();
                let socket_id =
                    String::from(splitted.next().unwrap()).parse().unwrap();
                let domain_id =
                    String::from(splitted.next().unwrap()).parse().unwrap();
                let mut sensor_data_for_socket = HashMap::new();
                sensor_data_for_socket.insert(
                    String::from("source_file"),
                    format!(
                        "{}/intel-rapl:{}/energy_uj",
                        self.base_path, socket_id
                    ),
                );
                topo.safe_add_socket(
                    socket_id,
                    vec![],
                    vec![],
                    format!(
                        "{}/intel-rapl:{}/energy_uj",
                        self.base_path, socket_id
                    ),
                    self.buffer_per_socket_max_kbytes,
                    sensor_data_for_socket,
                );
                let mut sensor_data_for_domain = HashMap::new();
                sensor_data_for_domain.insert(
                    String::from("source_file"),
                    format!(
                        "{}/intel-rapl:{}:{}/energy_uj",
                        self.base_path, socket_id, domain_id
                    ),
                );
                if let Ok(domain_name) =
                    &fs::read_to_string(format!("{folder_name}/name"))
                {
                    topo.safe_add_domain_to_socket(
                        socket_id,
                        domain_id,
                        domain_name.trim(),
                        &format!(
                            "{}/intel-rapl:{}:{}/energy_uj",
                            self.base_path, socket_id, domain_id
                        ),
                        self.buffer_per_domain_max_kbytes,
                        sensor_data_for_domain,
                    );
                }
            } else if re_socket_mmio.is_match(&folder_name) {
                info!("matched {folder_name}");
                let mut splitted = folder_name.split(':');
                let _ = splitted.next();
                let socket_id: u16 =
                    String::from(splitted.next().unwrap()).parse().unwrap();
                for s in topo.get_sockets() {
                    if socket_id == s.id {
                        s.sensor_data.insert(
                            String::from("mmio"),
                            format!(
                                "{}/intel-rapl-mmio:{}/energy_uj",
                                self.base_path, socket_id
                            ),
                        );
                    }
                }
            } else if re_domain_mmio.is_match(&folder_name) {
                debug!("matched {folder_name}");
                let mut splitted = folder_name.split(':');
                let _ = splitted.next();
                let socket_id: u16 =
                    String::from(splitted.next().unwrap()).parse().unwrap();
                for s in topo.get_sockets() {
                    if socket_id == s.id {
                        let mmio_file = format!("{}/energy_uj", folder_name);
                        for d in s.get_domains() {
                            let name_in_folder = fs::read_to_string(
                                format!("{folder_name}/name"),
                            )
                            .unwrap();

                            if d.name.trim() == name_in_folder.trim() {
                                d.sensor_data.insert(
                                    String::from("mmio"),
                                    mmio_file.clone(),
                                );
                            }
                        }
                    }
                }
            }
        }
        if !re_domain_matched {
            warn!(
                "Couldn't find domain folders from powercap. Fallback on socket folders."
            );
            warn!(
                "Scaphandre will not be able to provide per-domain data."
            );
            let mut found = false;
            for folder in fs::read_dir(&self.base_path).unwrap() {
                let folder_name = String::from(
                    folder.unwrap().path().to_str().unwrap(),
                );
                if let Ok(domain_name) =
                    &fs::read_to_string(format!("{folder_name}/name"))
                {
                    if domain_name != "psys" && re_socket.is_match(&folder_name)
                    {
                        let mut splitted = folder_name.split(':');
                        let _ = splitted.next();
                        let socket_id = String::from(
                            splitted.next().unwrap(),
                        )
                        .parse()
                        .unwrap();
                        let mut sensor_data_for_socket = HashMap::new();
                        sensor_data_for_socket.insert(
                            String::from("source_file"),
                            format!(
                                "{}/intel-rapl:{}/energy_uj",
                                self.base_path, socket_id
                            ),
                        );
                        topo.safe_add_socket(
                            socket_id,
                            vec![],
                            vec![],
                            format!(
                                "{}/intel-rapl:{}/energy_uj",
                                self.base_path, socket_id
                            ),
                            self.buffer_per_socket_max_kbytes,
                            sensor_data_for_socket,
                        );
                        found = true;
                    }
                } else {
                    warn!("Couldn't read RAPL folder name : {folder_name}");
                }
            }
            if !found {
                warn!(
                    "Could'nt find any RAPL PKG domain (nor psys)."
                );
            }
        }
        for folder in fs::read_dir(&self.base_path).unwrap() {
            let folder_name = String::from(
                folder.unwrap().path().to_str().unwrap(),
            );
            match &fs::read_to_string(format!("{folder_name}/name")) {
                Ok(domain_name) => {
                    let domain_name_trimed = domain_name.trim();
                    if domain_name_trimed == "psys" {
                        debug!("Found PSYS domain RAPL folder.");
                        topo._sensor_data
                            .insert(String::from("psys"), folder_name);
                    }
                }
                Err(e) => {
                    debug!("Got error while reading {folder_name}: {e}");
                }
            }
        }

        if self.virtual_machine && topo.get_sockets().is_empty() {
            info!("[VM-MODE] No RAPL sockets found, creating virtual socket for VM");
            let mut sensor_data = HashMap::new();
            sensor_data.insert(
                String::from("source_file"),
                format!("{}/energy_uj", self.base_path),
            );
            topo.safe_add_socket(
                0,
                vec![],
                vec![],
                format!("{}/energy_uj", self.base_path),
                self.buffer_per_socket_max_kbytes,
                sensor_data,
            );
        }

        topo.add_cpu_cores();
        Ok(topo)
    }

    fn get_topology(&self) -> Box<Option<Topology>> {
        let topology = self.generate_topology().ok();
        if topology.is_none() {
            panic!("Couldn't generate the topology !");
        }
        Box::new(topology)
    }
}

#[cfg(feature = "use_sgx_vm")]
mod vm_sgx {
    use std::sync::Mutex;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref VM_SGX_INITIALIZED: Mutex<bool> = Mutex::new(false);
    }

    pub fn init_vm_sgx_enclave() -> Result<(), Box<dyn std::error::Error>> {
        let mut initialized = VM_SGX_INITIALIZED.lock().unwrap();

        if *initialized {
            return Ok(());
        }

        println!("[VM-SGX] Initializing SGX enclave for VM per-process energy calculation");
        println!("[VM-SGX] Enclave will provide trusted execution for process attribution");

        *initialized = true;

        println!("[VM-SGX] Enclave initialized and ready");
        Ok(())
    }

    pub fn is_sgx_initialized() -> bool {
        *VM_SGX_INITIALIZED.lock().unwrap()
    }
}

#[cfg(feature = "use_sgx_vm")]
pub use self::vm_sgx::{init_vm_sgx_enclave, is_sgx_initialized};

#[cfg(feature = "use_sgx_vm")]
extern "C" {

    fn ecall_compute_single_process_energy(
        vm_total_energy_uj: u64,
        cpu_percentage: f64,
        out_energy_ptr: *mut u64,
    ) -> i32;
}

#[cfg(feature = "use_sgx_vm")]
#[allow(dead_code)]
fn verify_energy_chain_deprecated(source_file: &str) -> Result<(), Box<dyn Error>> {
    use std::path::Path;
    use std::sync::Mutex;

    static LAST_VERIFIED_COUNTER: Mutex<Option<u64>> = Mutex::new(None);

    let chain_dir = Path::new(source_file).parent().unwrap();

    let counter_str = fs::read_to_string(chain_dir.join("chain_counter"))?;
    let counter: u64 = counter_str.trim().parse()?;

    {
        let mut last_counter = LAST_VERIFIED_COUNTER.lock().unwrap();
        if let Some(last) = *last_counter {
            if counter == last {

                return Ok(());
            }
        }
    }

    let prev_hash_hex = fs::read_to_string(chain_dir.join("chain_previous_hash"))?;
    let prev_hash = hex::decode(prev_hash_hex.trim())?;

    let signature_hex = fs::read_to_string(chain_dir.join("chain_signature"))?;
    let signature = hex::decode(signature_hex.trim())?;

    let energy_delta_str = fs::read_to_string(chain_dir.join("chain_energy_delta"))?;
    let energy_value: u64 = energy_delta_str.trim().parse()?;

    let vm_name = "ubuntu20";

    extern "C" {
        fn ecall_verify_energy_chain(
            vm_name_ptr: *const u8,
            vm_name_len: usize,
            energy_uj: u64,
            energy_delta: u64,
            counter: u64,
            previous_hash_ptr: *const u8,
            received_signature_ptr: *const u8,
        ) -> i32;
    }

    let result = unsafe {
        ecall_verify_energy_chain(
            vm_name.as_ptr(),
            vm_name.len(),
            energy_value,
            energy_value,
            counter,
            prev_hash.as_ptr(),
            signature.as_ptr(),
        )
    };

    let verification_result = match result {
        0 => {
            println!("[VM-SGX] Chain continuity verified: counter={}, energy={}µJ", counter, energy_value);
            Ok(())
        }
        1 => {
            println!("[VM-SGX] Chain initialized: counter={}, energy={}µJ (first verification)", counter, energy_value);
            Ok(())
        }
        -2 => {
            Err(format!("[VM-SGX-SECURITY] TAMPERING DETECTED: Signature mismatch (counter: {})", counter).into())
        }
        -3 => {
            Err(format!("[VM-SGX-SECURITY] REPLAY/ROLLBACK ATTACK: Counter discontinuity (counter: {})", counter).into())
        }
        -4 => {
            Err(format!("[VM-SGX-SECURITY] FORK ATTACK: Previous hash mismatch (counter: {})", counter).into())
        }
        _ => {
            Err(format!("[VM-SGX-SECURITY] Chain verification FAILED (code: {}, counter: {})", result, counter).into())
        }
    };

    if verification_result.is_ok() {
        let mut last_counter = LAST_VERIFIED_COUNTER.lock().unwrap();
        *last_counter = Some(counter);
    }

    verification_result
}

#[cfg(feature = "use_sgx_vm")]
#[allow(dead_code)]
fn _force_link_sgx_vm_crate() {

    extern "C" {
        fn force_link_sgx_vm();
    }
    unsafe {
        force_link_sgx_vm();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::type_name;

    fn type_of<T>(_: T) -> &'static str {
        type_name::<T>()
    }
    #[test]
    fn get_topology_returns_topology_type() {
        let sensor = PowercapRAPLSensor::new(1, 1, false);
        let topology = sensor.get_topology();
        assert_eq!(
            "alloc::boxed::Box<core::option::Option<scaphandre::sensors::Topology>>",
            type_of(topology)
        )
    }
}
