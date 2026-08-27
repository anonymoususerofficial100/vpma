use crate::exporters::utils;
use crate::exporters::Exporter;
use crate::sensors::gpu_nvml::collect_gpu_raw;
use crate::sensors::Sensor;
use std::collections::HashMap;
use std::time::Duration;

const MAX_UJ_PER_CYCLE: u64 = 400 * 10 * 1_000_000;

pub struct GpuPrintExporter {
    step: Duration,
    node_id: String,

    baselines: HashMap<String, u64>,
    last_collect_at: Option<std::time::Instant>,
}

impl GpuPrintExporter {
    pub fn new(_sensor: &dyn Sensor) -> GpuPrintExporter {
        GpuPrintExporter {
            step: Duration::from_millis(
                std::env::var("SCAPH_GPU_STEP_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(2000),
            ),
            node_id: utils::get_hostname(),
            baselines: HashMap::new(),
            last_collect_at: None,
        }
    }

    fn extract_vm_name(content: &str) -> Option<String> {
        let mut found: Option<String> = None;
        for line in content.lines() {
            let path = line.rsplit(':').next().unwrap_or(line);
            let segs: Vec<&str> = path.split('/').collect();
            for (i, seg) in segs.iter().enumerate() {
                if i == 0 || segs[i - 1] != "machine.slice" {
                    continue;
                }
                let decoded = seg.replace("\\x2d", "-");
                let without_scope = match decoded.strip_suffix(".scope") {
                    Some(s) => s,
                    None => continue,
                };
                let name = if let Some(rest) = without_scope.strip_prefix("machine-qemu-") {
                    rest.splitn(2, '-').nth(1).unwrap_or(rest).to_string()
                } else if let Some(rest) = without_scope.strip_prefix("vm-") {
                    rest.to_string()
                } else {
                    continue;
                };

                if !vpma_verified::is_valid_tenant_label(name.as_bytes()) {
                    continue;
                }
                found = Some(name);
            }
        }
        found
    }

    fn extract_container_id(content: &str) -> Option<String> {
        for line in content.lines() {
            let path = line.rsplit(':').next().unwrap_or(line);
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
        }
        None
    }

    fn resolve_owner(cgroup: &str, node_id: &str) -> String {
        if let Some(vm) = Self::extract_vm_name(cgroup) {
            return format!("vm:{}", vm);
        }
        if let Some(ctr) = Self::extract_container_id(cgroup) {
            return format!("ctr:{}", ctr);
        }
        format!("node:{}", node_id)
    }

    fn process_cycle(&mut self) {
        let cycle_start = std::time::Instant::now();

        let collect_start = std::time::Instant::now();
        let interval_s = self
            .last_collect_at
            .map(|t| collect_start.duration_since(t).as_secs_f64());
        self.last_collect_at = Some(collect_start);
        let collected = collect_gpu_raw();
        let collect_ms = collect_start.elapsed().as_secs_f64() * 1000.0;

        let samples = match collected {
            Ok(s) if s.is_empty() => {
                println!("[GPU-PRINT] no GPUs visible this cycle (NVML enumerated none)");
                return;
            }
            Ok(s) => s,
            Err(e) => {
                println!("[GPU-PRINT] collection error: {e}");
                return;
            }
        };
        let n_samples = samples.len();

        let attr_start = std::time::Instant::now();
        let mut node_delta: u64 = 0;
        let mut rows: Vec<(String, u64)> = Vec::new();

        for gpu in samples {

            let uuid_tag: String = gpu
                .gpu_uuid
                .trim_start_matches("GPU-")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(8)
                .collect();

            let previous = self.baselines.get(&gpu.gpu_uuid).copied();
            let delta = match previous {
                Some(last) if gpu.energy_uj > last => gpu.energy_uj - last,
                Some(_) => 0,
                None => 0,
            };
            let baseline = previous.map_or(gpu.energy_uj, |last| last.max(gpu.energy_uj));
            self.baselines.insert(gpu.gpu_uuid.clone(), baseline);

            node_delta = node_delta.saturating_add(delta);
            if delta == 0 {
                continue;
            }
            let bracketed = delta <= MAX_UJ_PER_CYCLE;

            let mut buckets: Vec<(String, u64)> = Vec::new();
            if bracketed {
                for p in &gpu.procs {
                    if p.1 == 0 {
                        continue;
                    }
                    let util = p.1.min(100);
                    let owner = Self::resolve_owner(&p.2, &self.node_id);
                    buckets.push((
                        format!("pid:{}@{}@gpu{}:{}", p.0, owner, gpu.gpu_index, uuid_tag),
                        util,
                    ));
                }
            }

            let mut total_util: u64 = buckets.iter().map(|(_, u)| *u).sum();
            if total_util == 0 {
                let kind = if bracketed { "idle" } else { "unattributed" };
                buckets.push((
                    format!("pid:0@{}@gpu{}:{}", kind, gpu.gpu_index, uuid_tag),
                    1,
                ));
                total_util = 1;
            }
            let _ = total_util;

            let weights: Vec<u64> = buckets.iter().map(|(_, u)| *u).collect();
            let shares = match vpma_verified::attribute_by_weight(delta, &weights) {
                Some(s) => s,
                None => continue,
            };
            debug_assert_eq!(shares.iter().sum::<u64>(), delta);

            for (i, (label, _)) in buckets.into_iter().enumerate() {
                if shares[i] == 0 {
                    continue;
                }
                rows.push((label, shares[i]));
            }
        }
        let attr_ms = attr_start.elapsed().as_secs_f64() * 1000.0;

        for (label, uj) in &rows {
            let joules = *uj as f64 / 1_000_000.0;
            match interval_s {
                Some(s) if s > 0.0 => println!(
                    "[GPU-PRINT] {} energy={:.6} J power={:.3} W",
                    label,
                    joules,
                    joules / s
                ),
                _ => println!("[GPU-PRINT] {} energy={:.6} J", label, joules),
            }
        }
        let sum: u64 = rows.iter().map(|(_, e)| *e).sum();
        println!(
            "[GPU-PRINT] cycle node_delta={} uJ, {} record(s), conservation {}",
            node_delta,
            rows.len(),
            if sum == node_delta { "OK" } else { "VIOLATED" }
        );

        let e2e_ms = cycle_start.elapsed().as_secs_f64() * 1000.0;

        println!(
            "[TIMING] iter END-TO-END={:.3} ms (collection={:.3} + attribution={:.3}; {} sample(s))",
            e2e_ms, collect_ms, attr_ms, n_samples
        );
    }
}

impl Exporter for GpuPrintExporter {
    fn run(&mut self) {
        println!("[GPU-PRINT] INSECURE GPU export (node={}).", self.node_id);
        println!("[GPU-PRINT] no SGX, no TPM, no IMA, no eBPF, no CFI, no chain/Merkle, no Redis/ImmuDB.");
        println!("[GPU-PRINT] energy collection + per-process attribution only; results are printed.");
        println!("[GPU-PRINT] nothing here is attested or signed - the output is only as trustworthy as this host.");
        loop {
            self.process_cycle();
            std::thread::sleep(self.step);
        }
    }

    fn kind(&self) -> &str {
        "gpu-print"
    }
}
