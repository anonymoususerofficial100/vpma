use serde::{Serialize, Deserialize};

#[cfg(target_env = "sgx")]
use alloc::collections::BTreeMap;
#[cfg(not(target_env = "sgx"))]
use std::collections::HashMap as BTreeMap;

#[derive(Debug, Clone)]
struct PrevCpuSample {
    cpu_usage_ns: u64,
    timestamp_ns: u64,
}

static mut PREV_CPU_SAMPLES: Option<BTreeMap<String, PrevCpuSample>> = None;

fn ensure_cpu_samples_init() {
    unsafe {
        if PREV_CPU_SAMPLES.is_none() {
            PREV_CPU_SAMPLES = Some(BTreeMap::new());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEnergyValue {
    pub value: String,

    #[serde(default)]
    pub hmac_signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSample {
    pub pid: u32,
    pub cmdline: Vec<String>,
    pub cpu_usage_percentage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactProcessSample {
    pub pid: u32,

    pub cmdline: Vec<String>,
    pub cpu_usage_percentage: String,
}

impl ProcessSample {

    pub fn to_compact(&self) -> CompactProcessSample {
        let compact_cmdline: Vec<String> = self.cmdline.iter()
            .filter(|arg| {

                arg.contains("qemu-system") ||
                arg.starts_with("guest=") ||
                arg == &"-name" ||

                (arg.len() < 64 && !arg.starts_with("-") && !arg.starts_with("/") && !arg.contains("="))
            })
            .map(|s| {

                if s.len() > 64 {
                    s[..64].to_string()
                } else {
                    s.clone()
                }
            })
            .take(10)
            .collect();

        CompactProcessSample {
            pid: self.pid,
            cmdline: compact_cmdline,
            cpu_usage_percentage: self.cpu_usage_percentage.clone(),
        }
    }
}

pub fn compactify_processes(processes: &[Vec<ProcessSample>]) -> Vec<Vec<CompactProcessSample>> {
    processes.iter()
        .map(|group| {
            group.iter()
                .map(|p| p.to_compact())
                .collect()
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmEnergyUpdate {
    pub vm_name: String,
    pub uj_to_add: u64,
    #[serde(default)]
    pub hmac_signature: Vec<u8>,
}

pub fn compute_total_host_energy(
    pkg_values: &[RawEnergyValue],
    dram_values: &[RawEnergyValue],
) -> String {
    let mut total: i128 = 0;

    for r in pkg_values {
        if let Ok(v) = r.value.trim().parse::<i128>() {
            total += v;
        }
    }

    for r in dram_values {
        if let Ok(v) = r.value.trim().parse::<i128>() {
            total += v;
        }
    }

    total.to_string()
}

pub struct QemuExporter {}

impl QemuExporter {
    pub fn new() -> QemuExporter {
        QemuExporter {}
    }

    pub fn iterate(
        &mut self,
        _path: String,
        topo_energy_value: String,
        processes: Vec<Vec<ProcessSample>>,
    ) -> Vec<VmEnergyUpdate> {
        let topo_energy = topo_energy_value.parse::<f64>().unwrap_or(0.0);

        let qemu_proc_groups = Self::filter_qemu_vm_processes(&processes);

        let mut updates = vec![];

        for proc_group in qemu_proc_groups {
            if let Some(first_proc) = proc_group.first() {
                let vm_name = Self::get_vm_name_from_cmdline(&first_proc.cmdline);
                if vm_name.is_empty() {
                    continue;
                }

                let cpu_percent =
                    first_proc.cpu_usage_percentage.parse::<f64>().unwrap_or(0.0);

                let uj_to_add = cpu_percent * topo_energy / 100.0;

                updates.push(VmEnergyUpdate {
                    vm_name,
                    uj_to_add: uj_to_add.max(0.0) as u64,
                    hmac_signature: Vec::new(),
                });
            }
        }

        updates
    }

    pub fn iterate_compact(
        &mut self,
        _path: String,
        topo_energy_value: String,
        processes: Vec<Vec<CompactProcessSample>>,
    ) -> Vec<VmEnergyUpdate> {
        let topo_energy = topo_energy_value.parse::<f64>().unwrap_or(0.0);

        let qemu_proc_groups = Self::filter_qemu_vm_processes_compact(&processes);

        let mut updates = vec![];

        for proc_group in qemu_proc_groups {
            if let Some(first_proc) = proc_group.first() {
                let vm_name = Self::get_vm_name_from_cmdline(&first_proc.cmdline);
                if vm_name.is_empty() {
                    continue;
                }

                let cpu_percent =
                    first_proc.cpu_usage_percentage.parse::<f64>().unwrap_or(0.0);

                let uj_to_add = cpu_percent * topo_energy / 100.0;

                updates.push(VmEnergyUpdate {
                    vm_name,
                    uj_to_add: uj_to_add.max(0.0) as u64,
                    hmac_signature: Vec::new(),
                });
            }
        }

        updates
    }

    pub fn get_vm_name_from_cmdline(cmdline: &[String]) -> String {
        for e in cmdline {
            if e.starts_with("guest=") {
                let mut parts = e.split('=');
                parts.next();
                return parts.next().unwrap().split(',').next().unwrap().to_string();
            }
        }
        String::new()
    }

    pub fn filter_qemu_vm_processes(
        processes: &[Vec<ProcessSample>],
    ) -> Vec<Vec<ProcessSample>> {
        let mut out = vec![];

        for g in processes {
            if let Some(f) = g.first() {
                if f.cmdline.iter().any(|a| a.contains("qemu-system")) {
                    out.push(g.clone());
                }
            }
        }

        out
    }

    pub fn filter_qemu_vm_processes_compact(
        processes: &[Vec<CompactProcessSample>],
    ) -> Vec<Vec<CompactProcessSample>> {
        let mut out = vec![];

        for g in processes {
            if let Some(f) = g.first() {
                if f.cmdline.iter().any(|a| a.contains("qemu-system")) {
                    out.push(g.clone());
                }
            }
        }

        out
    }

    pub fn kind(&self) -> &str {
        "qemu"
    }

    pub fn iterate_cgroup(
        &mut self,
        topo_energy_value: String,
        vm_samples: Vec<VmCgroupSample>,
    ) -> Vec<VmEnergyUpdate> {
        ensure_cpu_samples_init();

        let topo_energy = topo_energy_value.parse::<f64>().unwrap_or(0.0);
        let mut updates = Vec::new();

        for sample in vm_samples {

            let cpu_percent = unsafe {
                let samples = PREV_CPU_SAMPLES.as_mut().unwrap();

                if let Some(prev) = samples.get(&sample.vm_name) {

                    let elapsed_ns = sample.timestamp_ns.saturating_sub(prev.timestamp_ns) as f64;
                    let delta_ns = sample.cpu_usage_ns.saturating_sub(prev.cpu_usage_ns) as f64;

                    const MAX_AGE_NS: f64 = 10.0 * 1_000_000_000.0;

                    if elapsed_ns > 0.0 && elapsed_ns <= MAX_AGE_NS {

                        (delta_ns / elapsed_ns * 100.0).min(100.0 * 128.0)
                    } else {
                        0.0
                    }
                } else {
                    0.0
                }
            };

            unsafe {
                let samples = PREV_CPU_SAMPLES.as_mut().unwrap();
                samples.insert(sample.vm_name.clone(), PrevCpuSample {
                    cpu_usage_ns: sample.cpu_usage_ns,
                    timestamp_ns: sample.timestamp_ns,
                });
            }

            let uj_to_add = cpu_percent * topo_energy / 100.0;

            updates.push(VmEnergyUpdate {
                vm_name: sample.vm_name,
                uj_to_add: uj_to_add.max(0.0) as u64,
                hmac_signature: Vec::new(),
            });
        }

        updates
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmCgroupSample {

    pub vm_name: String,

    pub cpu_usage_ns: u64,

    pub timestamp_ns: u64,
}
