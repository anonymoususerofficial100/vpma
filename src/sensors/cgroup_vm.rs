use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const CPU_SAMPLE_MAX_AGE_SECS: f64 = 10.0;

const CGROUP_PATHS: &[&str] = &[
    "/sys/fs/cgroup/cpu,cpuacct/machine.slice",
    "/sys/fs/cgroup/cpu/machine.slice",
    "/sys/fs/cgroup/cpuacct/machine.slice",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmCgroupSample {

    pub vm_name: String,

    pub cpu_usage_ns: u64,

    pub timestamp_ns: u64,
}

#[derive(Debug, Clone)]
struct PreviousSample {
    cpu_usage_ns: u64,
    timestamp: Instant,
}

pub struct VmCgroupReader {

    cgroup_base: PathBuf,

    previous_samples: HashMap<String, PreviousSample>,

    init_time: Instant,
}

impl VmCgroupReader {

    pub fn new() -> Option<Self> {

        for base in CGROUP_PATHS {
            let path = Path::new(base);
            if path.exists() && path.is_dir() {
                println!("[CGROUP] Found VM cgroup base: {}", base);
                return Some(Self {
                    cgroup_base: path.to_path_buf(),
                    previous_samples: HashMap::new(),
                    init_time: Instant::now(),
                });
            }
        }

        eprintln!("[CGROUP] No VM cgroup base found. VMs may not be running.");
        None
    }

    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            cgroup_base: path.as_ref().to_path_buf(),
            previous_samples: HashMap::new(),
            init_time: Instant::now(),
        }
    }

    pub fn read_vm_cpu_samples(&mut self) -> Vec<VmCgroupSample> {
        let mut samples = Vec::new();
        let now = Instant::now();
        let timestamp_ns = now.duration_since(self.init_time).as_nanos() as u64;

        let entries = match fs::read_dir(&self.cgroup_base) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[CGROUP] Failed to read cgroup directory: {}", e);
                return samples;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = match entry.file_name().to_str() {
                Some(n) => n.to_string(),
                None => continue,
            };

            if !name.starts_with("machine-qemu") || !name.ends_with(".scope") {
                continue;
            }

            let vm_name = match Self::extract_vm_name(&name) {
                Some(n) => n,
                None => continue,
            };

            let emulator_path = path.join("emulator");
            let cpu_usage_ns = match Self::read_cpuacct_usage(&emulator_path) {
                Some(v) => v,
                None => {

                    match Self::read_cpuacct_usage(&path) {
                        Some(v) => v,
                        None => continue,
                    }
                }
            };

            samples.push(VmCgroupSample {
                vm_name,
                cpu_usage_ns,
                timestamp_ns,
            });
        }

        println!("[CGROUP] Read {} VM cgroup samples ({} bytes)",
            samples.len(),
            samples.len() * std::mem::size_of::<VmCgroupSample>());

        samples
    }

    pub fn read_vm_cpu_percentages(&mut self) -> Vec<VmCpuPercentage> {
        let raw_samples = self.read_vm_cpu_samples();
        let now = Instant::now();
        let mut results = Vec::new();

        for sample in raw_samples {
            let (cpu_percent, debug_info) = if let Some(prev) = self.previous_samples.get(&sample.vm_name) {

                let elapsed = now.duration_since(prev.timestamp);
                let elapsed_ns = elapsed.as_nanos() as f64;

                let delta_ns = sample.cpu_usage_ns.saturating_sub(prev.cpu_usage_ns) as f64;
                let debug = format!("prev={} curr={} delta={:.0} elapsed={:.0}ns",
                    prev.cpu_usage_ns, sample.cpu_usage_ns, delta_ns, elapsed_ns);

                if elapsed_ns > 0.0 && elapsed.as_secs_f64() <= CPU_SAMPLE_MAX_AGE_SECS {

                    let pct = (delta_ns / elapsed_ns * 100.0).min(100.0 * num_cpus());
                    (pct, debug)
                } else {
                    (0.0, format!("{} (stale)", debug))
                }
            } else {
                (0.0, format!("first_sample curr={}", sample.cpu_usage_ns))
            };

            println!("[CGROUP] VM '{}': cpu_percent={:.2}% ({})",
                     sample.vm_name, cpu_percent, debug_info);

            self.previous_samples.insert(
                sample.vm_name.clone(),
                PreviousSample {
                    cpu_usage_ns: sample.cpu_usage_ns,
                    timestamp: now,
                },
            );

            results.push(VmCpuPercentage {
                vm_name: sample.vm_name,
                cpu_percent,
                timestamp_ns: sample.timestamp_ns,
            });
        }

        results
    }

    fn extract_vm_name(cgroup_name: &str) -> Option<String> {

        let decoded = cgroup_name
            .replace("\\x2d", "-")
            .replace("\\x2d", "-");

        let without_scope = decoded.strip_suffix(".scope")?;
        let without_prefix = without_scope.strip_prefix("machine-qemu-")?;

        let parts: Vec<&str> = without_prefix.splitn(2, '-').collect();
        if parts.len() >= 2 {
            Some(parts[1].to_string())
        } else {

            Some(without_prefix.to_string())
        }
    }

    fn read_cpuacct_usage(cgroup_path: &Path) -> Option<u64> {
        let usage_path = cgroup_path.join("cpuacct.usage");
        match fs::read_to_string(&usage_path) {
            Ok(content) => content.trim().parse().ok(),
            Err(_) => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmCpuPercentage {

    pub vm_name: String,

    pub cpu_percent: f64,

    pub timestamp_ns: u64,
}

fn num_cpus() -> f64 {
    std::thread::available_parallelism()
        .map(|p| p.get() as f64)
        .unwrap_or(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_vm_name() {
        assert_eq!(
            VmCgroupReader::extract_vm_name("machine-qemu\\x2d1\\x2dubuntu20.scope"),
            Some("ubuntu20".to_string())
        );
        assert_eq!(
            VmCgroupReader::extract_vm_name("machine-qemu-2-fedora33.scope"),
            Some("fedora33".to_string())
        );
    }
}
