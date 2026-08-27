use crate::sensors::units::Unit;
use crate::sensors::utils::current_system_time_since_epoch;
use crate::sensors::{Record, Sensor, Topology};
use std::collections::HashMap;
use std::error::Error;

use nvml_wrapper::error::NvmlError;
use nvml_wrapper::Nvml;
use std::sync::OnceLock;

static NVML: OnceLock<Nvml> = OnceLock::new();

fn nvml() -> Result<&'static Nvml, NvmlError> {
    if let Some(handle) = NVML.get() {
        return Ok(handle);
    }
    let handle = Nvml::init()?;

    let _ = NVML.set(handle);
    Ok(NVML.get().expect("NVML handle set above"))
}

pub const GPU_INDEX_KEY: &str = "gpu_index";

pub struct GpuNvmlSensor;

impl Default for GpuNvmlSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl GpuNvmlSensor {
    pub fn new() -> Self {
        Self
    }
}

pub fn read_gpu_energy_record(gpu_index: &str) -> Result<Record, Box<dyn Error>> {
    let idx: u32 = gpu_index.parse()?;
    let device = nvml()?.device_by_index(idx)?;

    let energy_mj: u64 = match device.total_energy_consumption() {
        Ok(v) => v,
        Err(e) => {
            if matches!(e, NvmlError::NotSupported) {
                warn!("[GPU] gpu{idx}: total energy counter no longer supported");
            }
            return Err(e.into());
        }
    };

    let energy_uj: u64 = energy_mj.saturating_mul(1000);
    debug!("[GPU] gpu{idx} energy = {energy_uj} uJ");
    Ok(Record::new(
        current_system_time_since_epoch(),
        energy_uj.to_string(),
        Unit::MicroJoule,
    ))
}

impl Sensor for GpuNvmlSensor {
    fn generate_topology(&self) -> Result<Topology, Box<dyn Error>> {
        let nvml = nvml()?;
        let count = nvml.device_count()?;
        let mut topology = Topology::new(HashMap::new());
        for i in 0..count {
            let device = nvml.device_by_index(i)?;

            match device.total_energy_consumption() {
                Ok(_) => {}
                Err(NvmlError::NotSupported) => {
                    warn!("[GPU] gpu{i}: total energy counter not supported, skipping");
                    continue;
                }
                Err(e) => {
                    warn!("[GPU] gpu{i}: energy counter probe failed ({e}), skipping");
                    continue;
                }
            }
            let uuid = device.uuid().unwrap_or_else(|_| format!("gpu-{i}"));
            let mut sensor_data = HashMap::new();
            sensor_data.insert(String::from(GPU_INDEX_KEY), i.to_string());
            sensor_data.insert(String::from("gpu_uuid"), uuid);
            sensor_data.insert(String::from("id"), i.to_string());

            topology.safe_add_socket(
                i as u16,
                vec![],
                vec![],
                String::from(""),
                1,
                sensor_data,
            );
        }
        Ok(topology)
    }

    fn get_topology(&self) -> Box<Option<Topology>> {
        Box::new(self.generate_topology().ok())
    }
}

pub struct ContainerGpuSample {

    pub container_id: String,
    pub gpu_index: u32,
    pub gpu_uuid: String,

    pub energy_uj: u64,

    pub sm_util: u32,

    pub procs: u32,
}

pub fn container_of_pid(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    content.lines().find_map(extract_container_id)
}

fn extract_container_id(cgroup_line: &str) -> Option<String> {

    let path = cgroup_line.rsplit(':').next().unwrap_or(cgroup_line);
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
    None
}

pub fn collect_container_gpu() -> Result<Vec<ContainerGpuSample>, Box<dyn Error>> {
    let nvml = nvml()?;
    let count = nvml.device_count()?;
    let mut out = Vec::new();
    for i in 0..count {
        let device = nvml.device_by_index(i)?;
        let energy_uj = device
            .total_energy_consumption()
            .map(|mj| mj.saturating_mul(1000))
            .unwrap_or(0);
        let uuid = device.uuid().unwrap_or_else(|_| format!("gpu-{i}"));

        let samples = device.process_utilization_stats(None::<u64>).unwrap_or_default();

        let mut agg: HashMap<String, (u32, u32)> = HashMap::new();
        for s in samples {
            if let Some(cid) = container_of_pid(s.pid) {
                let e = agg.entry(cid).or_insert((0, 0));
                e.0 += s.sm_util;
                e.1 += 1;
            }
        }
        for (container_id, (sm_util, procs)) in agg {
            out.push(ContainerGpuSample {
                container_id,
                gpu_index: i,
                gpu_uuid: uuid.clone(),
                energy_uj,
                sm_util,
                procs,
            });
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug)]
pub struct GpuTag {
    pub energy_uj: u64,
    pub timestamp_ns: u64,
    pub hash: u64,
}

pub struct GpuRawSample {
    pub gpu_index: u32,

    pub gpu_uuid: String,
    pub energy_uj: u64,
    pub procs: Vec<(u32, u64, String)>,

    pub tag: Option<GpuTag>,
}

pub fn collect_gpu_raw() -> Result<Vec<GpuRawSample>, Box<dyn Error>> {
    let nvml = nvml()?;
    let count = nvml.device_count()?;
    let mut out = Vec::new();
    for i in 0..count {
        let device = nvml.device_by_index(i)?;

        #[cfg(feature = "with_gpu_ebpf")]
        ebpf_gpu::set_gpu_context(i);
        let energy_uj = device
            .total_energy_consumption()
            .map(|mj| mj.saturating_mul(1000))
            .unwrap_or(0);

        #[cfg(feature = "with_gpu_ebpf")]
        let tag = ebpf_gpu::get_gpu_tag(i);
        #[cfg(not(feature = "with_gpu_ebpf"))]
        let tag = None;
        let samples = device.process_utilization_stats(None::<u64>).unwrap_or_default();
        let mut procs = Vec::new();
        for s in samples {

            if let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{}/cgroup", s.pid)) {
                procs.push((s.pid, s.sm_util as u64, cgroup));
            }
        }

        out.push(GpuRawSample {
            gpu_index: i,
            gpu_uuid: device.uuid().unwrap_or_else(|_| format!("gpu-{i}")),
            energy_uj,
            procs,
            tag,
        });
    }
    Ok(out)
}

#[cfg(feature = "with_gpu_ebpf")]
mod ebpf_gpu {
    use bcc::{BPF, Kprobe, Uprobe, Uretprobe};
    use lazy_static::lazy_static;
    use std::sync::Mutex;

    lazy_static! {
        static ref GPU_BPF: Mutex<Option<BPF>> = Mutex::new(None);
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct GpuReading {
        energy_uj: u64,
        timestamp_ns: u64,
        gpu_index: u32,
        domain_id: u32,
        hash: u64,
        valid: u8,
        _pad: [u8; 7],
    }

    const LIBNVML_PATHS: &[&str] = &[
        "/lib/x86_64-linux-gnu/libnvidia-ml.so.1",
        "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1",
        "/usr/lib/libnvidia-ml.so.1",
    ];

    fn libnvml_path() -> Option<&'static str> {
        LIBNVML_PATHS
            .iter()
            .copied()
            .find(|p| std::path::Path::new(p).exists())
    }

    fn init() -> Result<(), Box<dyn std::error::Error>> {
        let mut guard = GPU_BPF.lock().map_err(|_| "GPU_BPF lock poisoned")?;
        if guard.is_some() {
            return Ok(());
        }

        let (k0, k1) = super::tag_key();
        let epoch = super::tag_epoch();
        let code = include_str!("ebpf_gpu_tag.c")
            .replace("SIPTAG_K0_PLACEHOLDER", &format!("{:016x}", k0))
            .replace("SIPTAG_K1_PLACEHOLDER", &format!("{:016x}", k1))
            .replace("SIPTAG_EPOCH_PLACEHOLDER", &format!("{}", epoch));

        if code.contains("PLACEHOLDER") {
            return Err("SipTag key substitution failed -- refusing to load an unkeyed tagger".into());
        }
        let mut bpf = BPF::new(&code)?;
        let lib = libnvml_path().ok_or("libnvidia-ml.so not found")?;

        Uprobe::new()
            .handler("trace_nvml_energy_entry")
            .binary(lib)
            .symbol("nvmlDeviceGetTotalEnergyConsumption")
            .attach(&mut bpf)?;
        Uretprobe::new()
            .handler("trace_nvml_energy_ret")
            .binary(lib)
            .symbol("nvmlDeviceGetTotalEnergyConsumption")
            .attach(&mut bpf)?;

        match Kprobe::new()
            .handler("trace_nvidia_ioctl")
            .function("nvidia_unlocked_ioctl")
            .attach(&mut bpf)
        {
            Ok(_) => println!("[GPU-EBPF] access monitor attached (nvidia_unlocked_ioctl)"),
            Err(e) => eprintln!("[GPU-EBPF] access monitor attach failed (non-fatal): {}", e),
        }
        println!("[GPU-EBPF] integrity tag active (uretprobe on nvmlDeviceGetTotalEnergyConsumption)");
        *guard = Some(bpf);
        Ok(())
    }

    pub fn set_gpu_context(gpu_index: u32) {
        if let Err(e) = init() {

            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| eprintln!("[GPU-EBPF] disabled (could not load eBPF): {}", e));
            return;
        }
        let guard = match GPU_BPF.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let bpf = match guard.as_ref() {
            Some(b) => b,
            None => return,
        };
        let mut table = match bpf.table("gpu_ctx_hint") {
            Ok(t) => t,
            Err(_) => return,
        };
        let tgid = std::process::id() as u64;
        let mut key = tgid.to_ne_bytes();
        let mut val = gpu_index.to_ne_bytes();
        let _ = table.set(&mut key, &mut val);
    }

    pub fn get_gpu_tag(gpu_index: u32) -> Option<super::GpuTag> {
        let guard = GPU_BPF.lock().ok()?;
        let bpf = guard.as_ref()?;
        let mut table = bpf.table("gpu_hash_map").ok()?;
        let mut key = gpu_index.to_ne_bytes();
        let value = table.get(&mut key).ok()?;
        if value.len() < std::mem::size_of::<GpuReading>() {
            return None;
        }
        let r = unsafe { std::ptr::read_unaligned(value.as_ptr() as *const GpuReading) };
        if r.valid != 1 {
            return None;
        }
        Some(super::GpuTag {
            energy_uj: r.energy_uj,
            timestamp_ns: r.timestamp_ns,
            hash: r.hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::extract_container_id;

    #[test]
    fn docker_systemd_scope() {
        let line = "0::/system.slice/docker-abc123def4567890abc123def4567890abc123def4567890abc123def456789.scope";
        assert_eq!(extract_container_id(line).as_deref(), Some("abc123def456"));
    }

    #[test]
    fn docker_cgroupfs() {
        let line = "0::/docker/abc123def4567890abc123def4567890abc123def4567890abc123def456789";
        assert_eq!(extract_container_id(line).as_deref(), Some("abc123def456"));
    }

    #[test]
    fn kubepods_cri_containerd() {
        let line = "0::/kubepods.slice/kubepods-besteffort.slice/pod1/cri-containerd-abc123def4567890abc123def4567890abc123def4567890abc123def456789.scope";
        assert_eq!(extract_container_id(line).as_deref(), Some("abc123def456"));
    }

    #[test]
    fn bare_user_session_is_none() {
        let line = "0::/user.slice/user-5836386.slice/session-5.scope";
        assert_eq!(extract_container_id(line), None);
    }
}

pub use crate::sensors::{tag_epoch, tag_key};
