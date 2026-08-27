#[cfg(target_os = "windows")]
pub mod msr_rapl;
#[cfg(target_os = "windows")]
use msr_rapl::get_msr_value;
#[cfg(target_os = "linux")]
pub mod powercap_rapl;
#[cfg(all(target_os = "linux", feature = "gpu"))]
pub mod gpu_nvml;

pub mod units;
pub mod utils;

static TAG_KEY: std::sync::OnceLock<(u64, u64, u32)> = std::sync::OnceLock::new();

fn tag_key_triple() -> (u64, u64, u32) {
    *TAG_KEY.get_or_init(|| {
        use std::io::Read;
        let mut b = [0u8; 20];

        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut b))
            .expect("/dev/urandom unreadable -- refusing to run with a guessable tag key");
        let k0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(b[8..16].try_into().unwrap());

        let epoch = u32::from_le_bytes(b[16..20].try_into().unwrap());
        (k0, k1, epoch)
    })
}

pub fn tag_key() -> (u64, u64) { let (a, b, _) = tag_key_triple(); (a, b) }

pub fn tag_epoch() -> u32 { tag_key_triple().2 }

#[cfg(target_os = "linux")]
pub mod cgroup_vm;

#[cfg(target_os = "linux")]

#[cfg(feature = "with_ebpf_guard")]
pub mod memory_protection;
#[cfg(target_os = "linux")]
pub mod hash_verifier;
#[cfg(target_os = "linux")]
use procfs::{CpuInfo, CpuTime, KernelStats};
use std::{collections::HashMap, error::Error, fmt, fs, mem::size_of_val, str, time::Duration};
#[allow(unused_imports)]

use sysinfo::{CpuExt, Pid, System, SystemExt};
use sysinfo::{DiskExt, DiskType};
use utils::{current_system_time_since_epoch, IProcess, ProcessTracker};

pub trait Sensor {
    fn get_topology(&self) -> Box<Option<Topology>>;
    fn generate_topology(&self) -> Result<Topology, Box<dyn Error>>;
}

pub trait RecordGenerator {
    fn refresh_record(&mut self);
    fn get_records_passive(&self) -> Vec<Record>;
    fn clean_old_records(&mut self);
}

pub trait RecordReader {
    fn read_record(&self) -> Result<Record, Box<dyn Error>>;
}

#[derive(Debug, Clone)]
pub struct Topology {

    pub sockets: Vec<CPUSocket>,

    pub proc_tracker: ProcessTracker,

    pub stat_buffer: Vec<CPUStat>,

    pub record_buffer: Vec<Record>,

    pub buffer_max_kbytes: u16,

    pub domains_names: Option<Vec<String>>,

    pub _sensor_data: HashMap<String, String>,
}

impl RecordGenerator for Topology {

    fn refresh_record(&mut self) {
        match self.read_record() {
            Ok(record) => {
                self.record_buffer.push(record);
            }
            Err(e) => {
                warn!(
                    "Could'nt read record from {}, error was : {:?}",
                    self._sensor_data
                        .get("source_file")
                        .unwrap_or(&String::from("SRCFILENOTKNOWN")),
                    e
                );
            }
        }

        if !self.record_buffer.is_empty() {
            self.clean_old_records();
        }
    }

    fn clean_old_records(&mut self) {
        let record_ptr = &self.record_buffer[0];
        let record_size = size_of_val(record_ptr);
        let curr_size = record_size * self.record_buffer.len();
        trace!(
            "topology: current size of record buffer: {} max size: {}",
            curr_size,
            self.buffer_max_kbytes * 1000
        );
        if curr_size as u16 > self.buffer_max_kbytes * 1000 {
            let size_diff = curr_size - (self.buffer_max_kbytes * 1000) as usize;
            trace!(
                "topology: size_diff: {} record size: {}",
                size_diff,
                record_size
            );
            if size_diff > record_size {
                let nb_records_to_delete = size_diff as f32 / record_size as f32;
                for _ in 1..nb_records_to_delete as u32 {
                    if !self.record_buffer.is_empty() {
                        let res = self.record_buffer.remove(0);
                        debug!("Cleaning record buffer on Topology, removing: {:?}", res);
                    }
                }
            }
        }
    }

    fn get_records_passive(&self) -> Vec<Record> {
        let mut result = vec![];
        for r in &self.record_buffer {
            result.push(Record::new(
                r.timestamp,
                r.value.clone(),
                units::Unit::MicroJoule,
            ));
        }
        result
    }
}

impl Default for Topology {
    fn default() -> Self {
        {
            Self::new(HashMap::new())
        }
    }
}

impl Topology {

    pub fn new(sensor_data: HashMap<String, String>) -> Topology {
        Topology {
            sockets: vec![],
            proc_tracker: ProcessTracker::new(5),
            stat_buffer: vec![],
            record_buffer: vec![],
            buffer_max_kbytes: 1,
            domains_names: None,
            _sensor_data: sensor_data,
        }
    }

    pub fn generate_cpu_cores() -> Option<Vec<CPUCore>> {
        let mut cores = vec![];

        let sysinfo_system = System::new_all();
        let sysinfo_cores = sysinfo_system.cpus();
        warn!("Sysinfo sees {}", sysinfo_cores.len());
        #[cfg(target_os = "linux")]
        let cpuinfo = CpuInfo::new().unwrap();
        for (id, c) in (0_u16..).zip(sysinfo_cores.iter()) {
            let mut info = HashMap::<String, String>::new();
            #[cfg(target_os = "linux")]
            {
                for (k, v) in cpuinfo.get_info(id as usize).unwrap().iter() {
                    info.insert(String::from(*k), String::from(*v));
                }
            }
            info.insert(String::from("frequency"), c.frequency().to_string());
            info.insert(String::from("name"), c.name().to_string());
            info.insert(String::from("vendor_id"), c.vendor_id().to_string());
            info.insert(String::from("brand"), c.brand().to_string());
            cores.push(CPUCore::new(id, info));
        }
        Some(cores)
    }

    pub fn safe_add_socket(
        &mut self,
        socket_id: u16,
        domains: Vec<Domain>,
        attributes: Vec<Vec<HashMap<String, String>>>,
        counter_uj_path: String,
        buffer_max_kbytes: u16,
        sensor_data: HashMap<String, String>,
    ) -> Option<CPUSocket> {
        if !self.sockets.iter().any(|s| s.id == socket_id) {
            let socket = CPUSocket::new(
                socket_id,
                domains,
                attributes,
                counter_uj_path,
                buffer_max_kbytes,
                sensor_data,
            );
            let res = socket.clone();
            self.sockets.push(socket);
            Some(res)
        } else {
            None
        }
    }

    pub fn safe_insert_socket(&mut self, socket: CPUSocket) {
        if !self.sockets.iter().any(|s| s.id == socket.id) {
            self.sockets.push(socket);
        }
    }

    pub fn get_proc_tracker(&self) -> &ProcessTracker {
        &self.proc_tracker
    }

    pub fn get_sockets(&mut self) -> &mut Vec<CPUSocket> {
        &mut self.sockets
    }

    pub fn get_sockets_passive(&self) -> &Vec<CPUSocket> {
        &self.sockets
    }

    fn build_domains_names(&mut self) {
        let mut names: HashMap<String, ()> = HashMap::new();
        for s in self.sockets.iter() {
            for d in s.get_domains_passive() {
                names.insert(d.name.clone(), ());
            }
        }
        let mut domain_names = names.keys().cloned().collect::<Vec<String>>();
        domain_names.sort();
        self.domains_names = Some(domain_names);
    }

    pub fn set_domains_names(&mut self, names: Vec<String>) {
        self.domains_names = Some(names);
    }

    pub fn safe_add_domain_to_socket(
        &mut self,
        socket_id: u16,
        domain_id: u16,
        name: &str,
        uj_counter: &str,
        buffer_max_kbytes: u16,
        sensor_data: HashMap<String, String>,
    ) {
        let iterator = self.sockets.iter_mut();
        for socket in iterator {
            if socket.id == socket_id {
                socket.safe_add_domain(Domain::new(
                    domain_id,
                    String::from(name),
                    String::from(uj_counter),
                    buffer_max_kbytes,
                    sensor_data.clone(),
                ));
            }
        }
        self.build_domains_names();
    }

    #[cfg(target_os = "linux")]
    pub fn add_cpu_cores(&mut self) {
        if let Some(mut cores) = Topology::generate_cpu_cores() {
            while let Some(c) = cores.pop() {
                let socket_id = &c
                    .attributes
                    .get("physical id")
                    .unwrap()
                    .parse::<u16>()
                    .unwrap();
                let socket_match = self.sockets.iter_mut().find(|x| &x.id == socket_id);

                let socket = match socket_match {
                    Some(x) => x,
                    None =>self.sockets.first_mut().expect("Trick: if you are running on a vm, do not forget to use --vm parameter invoking scaphandre at the command line")
                };

                if socket_id == &socket.id {
                    socket.add_cpu_core(c);
                } else {
                    socket.add_cpu_core(c);
                    warn!("coud't not match core to socket - mapping to first socket instead - if you are not using --vm there is something wrong")
                }
            }

        } else {
            panic!("Couldn't retrieve any CPU Core from the topology. (generate_cpu_cores)");
        }
    }

    pub fn refresh(&mut self) {
        let sockets = &mut self.sockets;
        for s in sockets {

            s.refresh_record();
            s.refresh_stats();
            let domains = s.get_domains();
            for d in domains {
                d.refresh_record();
            }

        }
        self.proc_tracker.refresh();
        self.refresh_procs();
        self.refresh_record();
        self.refresh_stats();
    }

    fn refresh_procs(&mut self) {
        {
            let pt = &mut self.proc_tracker;
            pt.sysinfo.refresh_processes();
            let current_procs = pt
                .sysinfo
                .processes()
                .values()
                .map(IProcess::new)
                .collect::<Vec<_>>();
            for p in current_procs {
                match pt.add_process_record(p) {
                    Ok(_) => {}
                    Err(msg) => {
                        panic!("Failed to track process !\nGot: {}", msg)
                    }
                }
            }
        }
    }

    pub fn refresh_stats(&mut self) {
        if let Some(stats) = self.read_stats() {
            self.stat_buffer.insert(0, stats);
            if !self.stat_buffer.is_empty() {
                self.clean_old_stats();
            }
        } else {
            debug!("read_stats() is None");
        }
    }

    fn clean_old_stats(&mut self) {
        let stat_ptr = &self.stat_buffer[0];
        let size_of_stat = size_of_val(stat_ptr);
        let curr_size = size_of_stat * self.stat_buffer.len();
        trace!("current_size of stats in topo: {}", curr_size);
        if curr_size > (self.buffer_max_kbytes * 1000) as usize {
            let size_diff = curr_size - (self.buffer_max_kbytes * 1000) as usize;
            if size_diff > size_of_stat {
                let nb_stats_to_delete = size_diff as f32 / size_of_stat as f32;
                trace!(
                    "nb_stats_to_delete: {} size_diff: {} size of: {}",
                    nb_stats_to_delete,
                    size_diff,
                    size_of_stat
                );
                for _ in 1..nb_stats_to_delete as u32 {
                    if !self.stat_buffer.is_empty() {
                        let res = self.stat_buffer.pop();
                        debug!("Cleaning topology stat buffer, removing: {:?}", res);
                    }
                }
            }
        }
    }

    pub fn get_records_diff(&self) -> Option<Record> {
        let len = self.record_buffer.len();
        if len > 2 {
            let last = self.record_buffer.last().unwrap();
            let previous = self.record_buffer.get(len - 2).unwrap();
            let last_value = last.value.parse::<u64>().unwrap();
            let previous_value = previous.value.parse::<u64>().unwrap();
            if previous_value <= last_value {
                let diff = last_value - previous_value;
                return Some(Record::new(last.timestamp, diff.to_string(), last.unit));
            }
        }
        None
    }

    pub fn get_records_diff_power_microwatts(&self) -> Option<Record> {
        if self.record_buffer.len() > 1 {
            let last_record = self.record_buffer.last().unwrap();
            let previous_record = self
                .record_buffer
                .get(self.record_buffer.len() - 2)
                .unwrap();
            match previous_record.value.trim().parse::<u128>() {
                Ok(previous_microjoules) => match last_record.value.trim().parse::<u128>() {
                    Ok(last_microjoules) => {
                        if previous_microjoules > last_microjoules {
                            return None;
                        }
                        let microjoules = last_microjoules - previous_microjoules;
                        let time_diff = last_record.timestamp.as_secs_f64()
                            - previous_record.timestamp.as_secs_f64();
                        let microwatts = microjoules as f64 / time_diff;
                        return Some(Record::new(
                            last_record.timestamp,
                            (microwatts as u64).to_string(),
                            units::Unit::MicroWatt,
                        ));
                    }
                    Err(e) => {
                        warn!(
                            "Could'nt get previous_microjoules - value : '{}' - error : {:?}",
                            previous_record.value, e
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        "Couldn't parse previous_microjoules - value : '{}' - error : {:?}",
                        previous_record.value.trim(),
                        e
                    );
                }
            }
        }
        None
    }

    pub fn get_records_diff_energy_microjoules(&self) -> Option<Record> {
        if self.record_buffer.len() > 1 {
            let last_record = self.record_buffer.last().unwrap();
            let previous_record = self
                .record_buffer
                .get(self.record_buffer.len() - 2)
                .unwrap();
            if let (Ok(last_microjoules), Ok(previous_microjoules)) = (
                last_record.value.trim().parse::<u64>(),
                previous_record.value.trim().parse::<u64>(),
            ) {
                if previous_microjoules > last_microjoules {
                    return None;
                }
                let microjoules = last_microjoules - previous_microjoules;
                return Some(Record::new(
                    last_record.timestamp,
                    microjoules.to_string(),
                    units::Unit::MicroJoule,
                ));
            }
        }
        None
    }

    pub fn get_last_interval_seconds(&self) -> Option<f64> {
        if self.record_buffer.len() > 1 {
            let last_record = self.record_buffer.last().unwrap();
            let previous_record = self
                .record_buffer
                .get(self.record_buffer.len() - 2)
                .unwrap();
            let dt =
                last_record.timestamp.as_secs_f64() - previous_record.timestamp.as_secs_f64();
            if dt > 0.0 {
                return Some(dt);
            }
        }
        None
    }

    pub fn get_stats_diff(&self) -> Option<CPUStat> {
        if self.stat_buffer.len() > 1 {
            let last = &self.stat_buffer[0];
            let previous = &self.stat_buffer[1];
            let mut iowait = None;
            let mut irq = None;
            let mut softirq = None;
            let mut steal = None;
            let mut guest = None;
            let mut guest_nice = None;
            if last.iowait.is_some() && previous.iowait.is_some() {
                iowait = Some(last.iowait.unwrap() - previous.iowait.unwrap());
            }
            if last.irq.is_some() && previous.irq.is_some() {
                irq = Some(last.irq.unwrap() - previous.irq.unwrap());
            }
            if last.softirq.is_some() && previous.softirq.is_some() {
                softirq = Some(last.softirq.unwrap() - previous.softirq.unwrap());
            }
            if last.steal.is_some() && previous.steal.is_some() {
                steal = Some(last.steal.unwrap() - previous.steal.unwrap());
            }
            if last.guest.is_some() && previous.guest.is_some() {
                guest = Some(last.guest.unwrap() - previous.guest.unwrap());
            }
            if last.guest_nice.is_some() && previous.guest_nice.is_some() {
                guest_nice = Some(last.guest_nice.unwrap() - previous.guest_nice.unwrap());
            }
            return Some(CPUStat {
                user: last.user - previous.user,
                nice: last.nice - previous.nice,
                system: last.system - previous.system,
                idle: last.idle - previous.idle,
                iowait,
                irq,
                softirq,
                steal,
                guest,
                guest_nice,
            });
        }
        None
    }

    pub fn read_stats(&self) -> Option<CPUStat> {
        #[cfg(target_os = "linux")]
        {
            let kernelstats_or_not = KernelStats::new();
            if let Ok(res_cputime) = kernelstats_or_not {
                return Some(CPUStat {
                    user: res_cputime.total.user,
                    guest: res_cputime.total.guest,
                    guest_nice: res_cputime.total.guest_nice,
                    idle: res_cputime.total.idle,
                    iowait: res_cputime.total.iowait,
                    irq: res_cputime.total.irq,
                    nice: res_cputime.total.nice,
                    softirq: res_cputime.total.softirq,
                    steal: res_cputime.total.steal,
                    system: res_cputime.total.system,
                });
            }
        }
        None
    }

    pub fn read_nb_process_total_count(&self) -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(result) = KernelStats::new() {
                return Some(result.processes);
            }
        }
        None
    }

    pub fn read_nb_process_running_current(&self) -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(result) = KernelStats::new() {
                if let Some(procs_running) = result.procs_running {
                    return Some(procs_running);
                }
            }
        }
        None
    }

    pub fn read_nb_process_blocked_current(&self) -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(result) = KernelStats::new() {
                if let Some(procs_blocked) = result.procs_blocked {
                    return Some(procs_blocked);
                }
            }
        }
        None
    }

    pub fn read_nb_context_switches_total_count(&self) -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(result) = KernelStats::new() {
                return Some(result.ctxt);
            }
        }
        None
    }

    pub fn get_cpu_frequency(&self) -> Record {
        Record::new(
            current_system_time_since_epoch(),
            self.proc_tracker.get_cpu_frequency().to_string(),
            units::Unit::MegaHertz,
        )
    }

    pub fn get_load_avg(&self) -> Option<Vec<Record>> {
        let load = self.get_proc_tracker().sysinfo.load_average();
        let timestamp = current_system_time_since_epoch();
        Some(vec![
            Record::new(timestamp, load.one.to_string(), units::Unit::Numeric),
            Record::new(timestamp, load.five.to_string(), units::Unit::Numeric),
            Record::new(timestamp, load.five.to_string(), units::Unit::Numeric),
        ])
    }

    pub fn get_disks(&self) -> HashMap<String, (String, HashMap<String, String>, Record)> {
        let timestamp = current_system_time_since_epoch();
        let mut res = HashMap::new();
        for d in self.proc_tracker.sysinfo.disks() {
            let mut attributes = HashMap::new();
            if let Ok(file_system) = str::from_utf8(d.file_system()) {
                attributes.insert(String::from("disk_file_system"), String::from(file_system));
            }
            if let Some(mount_point) = d.mount_point().to_str() {
                attributes.insert(String::from("disk_mount_point"), String::from(mount_point));
            }
            match d.type_() {
                DiskType::SSD => {
                    attributes.insert(String::from("disk_type"), String::from("SSD"));
                }
                DiskType::HDD => {
                    attributes.insert(String::from("disk_type"), String::from("HDD"));
                }
                DiskType::Unknown(_) => {
                    attributes.insert(String::from("disk_type"), String::from("Unknown"));
                }
            }
            attributes.insert(
                String::from("disk_is_removable"),
                d.is_removable().to_string(),
            );
            if let Some(disk_name) = d.name().to_str() {
                attributes.insert(String::from("disk_name"), String::from(disk_name));
            }
            res.insert(
                String::from("scaph_host_disk_total_bytes"),
                (
                    String::from("Total disk size, in bytes."),
                    attributes.clone(),
                    Record::new(timestamp, d.total_space().to_string(), units::Unit::Bytes),
                ),
            );
            res.insert(
                String::from("scaph_host_disk_available_bytes"),
                (
                    String::from("Available disk space, in bytes."),
                    attributes.clone(),
                    Record::new(
                        timestamp,
                        d.available_space().to_string(),
                        units::Unit::Bytes,
                    ),
                ),
            );
        }
        res
    }

    pub fn get_total_memory_bytes(&self) -> Record {
        Record {
            timestamp: current_system_time_since_epoch(),
            value: self.proc_tracker.sysinfo.total_memory().to_string(),
            unit: units::Unit::Bytes,
            #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
            signature: Vec::new(),
        }
    }

    pub fn get_available_memory_bytes(&self) -> Record {
        Record {
            timestamp: current_system_time_since_epoch(),
            value: self.proc_tracker.sysinfo.available_memory().to_string(),
            unit: units::Unit::Bytes,
            #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
            signature: Vec::new(),
        }
    }

    pub fn get_free_memory_bytes(&self) -> Record {
        Record {
            timestamp: current_system_time_since_epoch(),
            value: self.proc_tracker.sysinfo.free_memory().to_string(),
            unit: units::Unit::Bytes,
            #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
            signature: Vec::new(),
        }
    }

    pub fn get_total_swap_bytes(&self) -> Record {
        Record {
            timestamp: current_system_time_since_epoch(),
            value: self.proc_tracker.sysinfo.total_swap().to_string(),
            unit: units::Unit::Bytes,
            #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
            signature: Vec::new(),
        }
    }

    pub fn get_free_swap_bytes(&self) -> Record {
        Record {
            timestamp: current_system_time_since_epoch(),
            value: self.proc_tracker.sysinfo.free_swap().to_string(),
            unit: units::Unit::Bytes,
            #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
            signature: Vec::new(),
        }
    }

    pub fn get_process_power_consumption_microwatts(&self, pid: Pid) -> Option<Record> {
        if let Some(record) = self.get_proc_tracker().get_process_last_record(pid) {
            let process_cpu_percentage = self.get_process_cpu_usage_percentage(pid).unwrap();
            let topo_conso = self.get_records_diff_power_microwatts();
            if let Some(conso) = &topo_conso {
                let conso_f64 = conso.value.parse::<f64>().unwrap();

                #[cfg(feature = "use_sgx_vm")]
                {
                    use crate::sensors::powercap_rapl::is_sgx_initialized;

                    if is_sgx_initialized() {

                        let cpu_pct = process_cpu_percentage.value.parse::<f64>().unwrap();
                        let mut sgx_result: u64 = 0;

                        extern "C" {
                            fn ecall_compute_single_process_energy(
                                vm_total_energy_uj: u64,
                                cpu_percentage: f64,
                                out_energy_ptr: *mut u64,
                            ) -> i32;
                        }

                        let status = unsafe {
                            ecall_compute_single_process_energy(
                                conso_f64 as u64,
                                cpu_pct,
                                &mut sgx_result as *mut u64,
                            )
                        };

                        if status == 0 {
                            trace!("[VM-SGX] Process {} energy computed in SGX enclave: {} µW", pid, sgx_result);
                            return Some(Record::new(
                                record.timestamp,
                                sgx_result.to_string(),
                                units::Unit::MicroWatt,
                            ));
                        } else {
                            warn!("[VM-SGX] ECALL failed with status {}, falling back to userspace calculation", status);
                        }
                    }
                }

                let result =
                    (conso_f64 * process_cpu_percentage.value.parse::<f64>().unwrap()) / 100.0_f64;
                return Some(Record::new(
                    record.timestamp,
                    result.to_string(),
                    units::Unit::MicroWatt,
                ));
            }
        } else {
            trace!("Couldn't find records for PID: {}", pid);
        }
        None
    }

    pub fn get_all_per_process(&self, pid: Pid) -> Option<HashMap<String, (String, Record)>> {
        let mut res = HashMap::new();
        if let Some(record) = self.get_proc_tracker().get_process_last_record(pid) {
            let process_cpu_percentage =
                record.process.cpu_usage_percentage / self.proc_tracker.nb_cores as f32;
            res.insert(
                String::from("scaph_process_cpu_usage_percentage"),
                (String::from("CPU time consumed by the process, as a percentage of the capacity of all the CPU Cores"),
                Record::new(
                    record.timestamp,
                    process_cpu_percentage.to_string(),
                    units::Unit::Percentage,
                    )
                )
            );
            res.insert(
                String::from("scaph_process_memory_virtual_bytes"),
                (
                    String::from("Virtual RAM usage by the process, in bytes"),
                    Record::new(
                        record.timestamp,
                        record.process.virtual_memory.to_string(),
                        units::Unit::Percentage,
                    ),
                ),
            );
            res.insert(
                String::from("scaph_process_memory_bytes"),
                (
                    String::from("Physical RAM usage by the process, in bytes"),
                    Record::new(
                        record.timestamp,
                        record.process.memory.to_string(),
                        units::Unit::Bytes,
                    ),
                ),
            );
            res.insert(
                String::from("scaph_process_disk_write_bytes"),
                (
                    String::from("Data written on disk by the process, in bytes"),
                    Record::new(
                        record.timestamp,
                        record.process.disk_written.to_string(),
                        units::Unit::Bytes,
                    ),
                ),
            );
            res.insert(
                String::from("scaph_process_disk_read_bytes"),
                (
                    String::from("Data read on disk by the process, in bytes"),
                    Record::new(
                        record.timestamp,
                        record.process.disk_read.to_string(),
                        units::Unit::Bytes,
                    ),
                ),
            );
            res.insert(
                String::from("scaph_process_disk_total_write_bytes"),
                (
                    String::from("Total data written on disk by the process, in bytes"),
                    Record::new(
                        record.timestamp,
                        record.process.total_disk_written.to_string(),
                        units::Unit::Bytes,
                    ),
                ),
            );
            res.insert(
                String::from("scaph_process_disk_total_read_bytes"),
                (
                    String::from("Total data read on disk by the process, in bytes"),
                    Record::new(
                        record.timestamp,
                        record.process.total_disk_read.to_string(),
                        units::Unit::Bytes,
                    ),
                ),
            );
            let topo_conso = self.get_records_diff_power_microwatts();
            if let Some(conso) = &topo_conso {
                let conso_f64 = conso.value.parse::<f64>().unwrap();
                let result = (conso_f64 * process_cpu_percentage as f64) / 100.0_f64;
                res.insert(
                    String::from("scaph_process_power_consumption_microwatts"),
                    (
                        String::from("Total data read on disk by the process, in bytes"),
                        Record::new(record.timestamp, result.to_string(), units::Unit::MicroWatt),
                    ),
                );
            }
        }
        Some(res)
    }

    pub fn get_process_cpu_usage_percentage(&self, pid: Pid) -> Option<Record> {
        if let Some(record) = self.get_proc_tracker().get_process_last_record(pid) {
            return Some(Record::new(
                record.timestamp,
                (record.process.cpu_usage_percentage / self.proc_tracker.nb_cores as f32)
                    .to_string(),
                units::Unit::Percentage,
            ));
        }
        None
    }

    pub fn get_process_memory_virtual_bytes(&self, pid: Pid) -> Option<Record> {
        if let Some(record) = self.get_proc_tracker().get_process_last_record(pid) {
            return Some(Record::new(
                record.timestamp,
                record.process.virtual_memory.to_string(),
                units::Unit::Bytes,
            ));
        }
        None
    }

    pub fn get_process_memory_bytes(&self, pid: Pid) -> Option<Record> {
        if let Some(record) = self.get_proc_tracker().get_process_last_record(pid) {
            return Some(Record::new(
                record.timestamp,
                record.process.memory.to_string(),
                units::Unit::Bytes,
            ));
        }
        None
    }

    pub fn get_process_disk_written_bytes(&self, pid: Pid) -> Option<Record> {
        if let Some(record) = self.get_proc_tracker().get_process_last_record(pid) {
            return Some(Record::new(
                record.timestamp,
                record.process.disk_written.to_string(),
                units::Unit::Bytes,
            ));
        }
        None
    }

    pub fn get_process_disk_read_bytes(&self, pid: Pid) -> Option<Record> {
        if let Some(record) = self.get_proc_tracker().get_process_last_record(pid) {
            return Some(Record::new(
                record.timestamp,
                record.process.disk_read.to_string(),
                units::Unit::Bytes,
            ));
        }
        None
    }
    pub fn get_process_disk_total_read_bytes(&self, pid: Pid) -> Option<Record> {
        if let Some(record) = self.get_proc_tracker().get_process_last_record(pid) {
            return Some(Record::new(
                record.timestamp,
                record.process.total_disk_read.to_string(),
                units::Unit::Bytes,
            ));
        }
        None
    }

    pub fn get_process_disk_total_write_bytes(&self, pid: Pid) -> Option<Record> {
        if let Some(record) = self.get_proc_tracker().get_process_last_record(pid) {
            return Some(Record::new(
                record.timestamp,
                record.process.total_disk_written.to_string(),
                units::Unit::Bytes,
            ));
        }
        None
    }

    #[cfg(target_os = "linux")]
    pub fn get_rapl_psys_energy_microjoules(&self) -> Option<Record> {
        if let Some(psys) = self._sensor_data.get("psys") {
            match &fs::read_to_string(format!("{psys}/energy_uj")) {
                Ok(val) => {
                    debug!("Read PSYS from {psys}/energy_uj: {}", val.to_string());
                    return Some(Record::new(
                        current_system_time_since_epoch(),
                        val.to_string(),
                        units::Unit::MicroJoule,
                    ));
                }
                Err(e) => {
                    warn!("PSYS Error: {:?}", e);
                }
            }
        } else {
            debug!("Asked for PSYS but there is no psys entry in sensor_data.");
        }
        None
    }

    #[cfg(target_os = "windows")]
    pub unsafe fn get_rapl_psys_energy_microjoules(&self) -> Option<Record> {
        let msr_addr = msr_rapl::MSR_PLATFORM_ENERGY_STATUS;
        match get_msr_value(0, msr_addr.into(), &self._sensor_data) {
            Ok(res) => {
                return Some(Record::new(
                    current_system_time_since_epoch(),
                    res.value.to_string(),
                    units::Unit::MicroJoule,
                ))
            }
            Err(e) => {
                debug!("get_msr_value returned error : {}", e);
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct CPUSocket {

    pub id: u16,

    pub domains: Vec<Domain>,

    pub attributes: Vec<Vec<HashMap<String, String>>>,

    pub counter_uj_path: String,

    pub record_buffer: Vec<Record>,

    pub buffer_max_kbytes: u16,

    pub cpu_cores: Vec<CPUCore>,

    pub stat_buffer: Vec<CPUStat>,

    #[allow(dead_code)]
    pub sensor_data: HashMap<String, String>,
}

impl RecordGenerator for CPUSocket {

    fn refresh_record(&mut self) {
        match self.read_record() {
            Ok(record) => {
                self.record_buffer.push(record);
            }
            Err(e) => {
                warn!(
                    "Could'nt read record from {}, error was: {:?}",
                    self.sensor_data
                        .get("source_file")
                        .unwrap_or(&String::from("SRCFILENOTKNOWN")),
                    e
                );
            }
        }

        if !self.record_buffer.is_empty() {
            self.clean_old_records();
        }
    }

    fn clean_old_records(&mut self) {
        let record_ptr = &self.record_buffer[0];
        let curr_size = size_of_val(record_ptr) * self.record_buffer.len();
        trace!(
            "socket rebord buffer current size: {} max_bytes: {}",
            curr_size,
            self.buffer_max_kbytes * 1000
        );
        if curr_size > (self.buffer_max_kbytes * 1000) as usize {
            let size_diff = curr_size - (self.buffer_max_kbytes * 1000) as usize;
            trace!(
                "socket record size_diff: {} sizeof: {}",
                size_diff,
                size_of_val(record_ptr)
            );
            if size_diff > size_of_val(record_ptr) {
                let nb_records_to_delete = size_diff as f32 / size_of_val(record_ptr) as f32;
                for _ in 1..nb_records_to_delete as u32 {
                    if !self.record_buffer.is_empty() {
                        let res = self.record_buffer.remove(0);
                        debug!(
                            "Cleaning socket id {} records buffer, removing: {}",
                            self.id, res
                        );
                    }
                }
            }
        }
    }

    fn get_records_passive(&self) -> Vec<Record> {
        let mut result = vec![];
        for r in &self.record_buffer {
            result.push(Record::new(
                r.timestamp,
                r.value.clone(),
                units::Unit::MicroJoule,
            ));
        }
        result
    }
}

impl CPUSocket {

    fn new(
        id: u16,
        domains: Vec<Domain>,
        attributes: Vec<Vec<HashMap<String, String>>>,
        counter_uj_path: String,
        buffer_max_kbytes: u16,
        sensor_data: HashMap<String, String>,
    ) -> CPUSocket {
        CPUSocket {
            id,
            domains,
            attributes,
            counter_uj_path,
            record_buffer: vec![],
            buffer_max_kbytes,
            cpu_cores: vec![],
            stat_buffer: vec![],
            sensor_data,
        }
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id
    }

    fn safe_add_domain(&mut self, domain: Domain) {
        if !self.domains.iter().any(|d| d.id == domain.id) {
            self.domains.push(domain);
        }
    }

    pub fn get_domains(&mut self) -> &mut Vec<Domain> {
        &mut self.domains
    }

    pub fn get_domains_passive(&self) -> &Vec<Domain> {
        &self.domains
    }

    pub fn get_cores(&mut self) -> &mut Vec<CPUCore> {
        &mut self.cpu_cores
    }

    pub fn get_cores_passive(&self) -> &Vec<CPUCore> {
        &self.cpu_cores
    }

    pub fn add_cpu_core(&mut self, core: CPUCore) {
        self.cpu_cores.push(core);
    }

    pub fn refresh_stats(&mut self) {
        if !self.stat_buffer.is_empty() {
            self.clean_old_stats();
        }
        self.stat_buffer.insert(0, self.read_stats().unwrap());
    }

    fn clean_old_stats(&mut self) {
        let stat_ptr = &self.stat_buffer[0];
        let size_of_stat = size_of_val(stat_ptr);
        let curr_size = size_of_stat * self.stat_buffer.len();
        trace!("current_size of stats in socket {}: {}", self.id, curr_size);
        trace!(
            "estimated max nb of socket stats: {}",
            self.buffer_max_kbytes as f32 * 1000.0 / size_of_stat as f32
        );
        if curr_size > (self.buffer_max_kbytes * 1000) as usize {
            let size_diff = curr_size - (self.buffer_max_kbytes * 1000) as usize;
            trace!(
                "socket {} size_diff: {} size of: {}",
                self.id,
                size_diff,
                size_of_stat
            );
            if size_diff > size_of_stat {
                let nb_stats_to_delete = size_diff as f32 / size_of_stat as f32;
                trace!(
                    "socket {} nb_stats_to_delete: {} size_diff: {} size of: {}",
                    self.id,
                    nb_stats_to_delete,
                    size_diff,
                    size_of_stat
                );
                trace!("nb stats to delete: {}", nb_stats_to_delete as u32);
                for _ in 1..nb_stats_to_delete as u32 {
                    if !self.stat_buffer.is_empty() {
                        let res = self.stat_buffer.pop();
                        debug!(
                            "Cleaning stat buffer of socket {}, removing: {:?}",
                            self.id, res
                        );
                    }
                }
            }
        }
    }

    pub fn read_stats(&self) -> Option<CPUStat> {
        let mut stats = CPUStat {
            user: 0,
            nice: 0,
            system: 0,
            idle: 0,
            iowait: Some(0),
            irq: Some(0),
            softirq: Some(0),
            guest: Some(0),
            guest_nice: Some(0),
            steal: Some(0),
        };
        for c in &self.cpu_cores {
            if let Some(c_stats) = c.read_stats() {
                stats.user += c_stats.user;
                stats.nice += c_stats.nice;
                stats.system += c_stats.system;
                stats.idle += c_stats.idle;
                stats.iowait =
                    Some(stats.iowait.unwrap_or_default() + c_stats.iowait.unwrap_or_default());
                stats.irq = Some(stats.irq.unwrap_or_default() + c_stats.irq.unwrap_or_default());
                stats.softirq =
                    Some(stats.softirq.unwrap_or_default() + c_stats.softirq.unwrap_or_default());
            }
        }
        Some(stats)
    }

    pub fn get_stats_diff(&mut self) -> Option<CPUStat> {
        if self.stat_buffer.len() > 1 {
            let last = &self.stat_buffer[0];
            let previous = &self.stat_buffer[1];
            let mut iowait = None;
            let mut irq = None;
            let mut softirq = None;
            let mut steal = None;
            let mut guest = None;
            let mut guest_nice = None;
            if last.iowait.is_some() && previous.iowait.is_some() {
                iowait = Some(last.iowait.unwrap() - previous.iowait.unwrap());
            }
            if last.irq.is_some() && previous.irq.is_some() {
                irq = Some(last.irq.unwrap() - previous.irq.unwrap());
            }
            if last.softirq.is_some() && previous.softirq.is_some() {
                softirq = Some(last.softirq.unwrap() - previous.softirq.unwrap());
            }
            if last.steal.is_some() && previous.steal.is_some() {
                steal = Some(last.steal.unwrap() - previous.steal.unwrap());
            }
            if last.guest.is_some() && previous.guest.is_some() {
                guest = Some(last.guest.unwrap() - previous.guest.unwrap());
            }
            if last.guest_nice.is_some() && previous.guest_nice.is_some() {
                guest_nice = Some(last.guest_nice.unwrap() - previous.guest_nice.unwrap());
            }
            return Some(CPUStat {
                user: last.user - previous.user,
                nice: last.nice - previous.nice,
                system: last.system - previous.system,
                idle: last.idle - previous.idle,
                iowait,
                irq,
                softirq,
                steal,
                guest,
                guest_nice,
            });
        }
        None
    }

    pub fn get_records_diff_power_microwatts(&self) -> Option<Record> {
        if self.record_buffer.len() > 1 {
            let last_record = self.record_buffer.last().unwrap();
            let previous_record = self
                .record_buffer
                .get(self.record_buffer.len() - 2)
                .unwrap();
            debug!(
                "socket : last_record value: {} previous_record value: {}",
                &last_record.value, &previous_record.value
            );
            let last_rec_val = last_record.value.trim();
            debug!("socket : l1187 : trying to parse {} as u64", last_rec_val);
            let prev_rec_val = previous_record.value.trim();
            debug!("socket : l1189 : trying to parse {} as u64", prev_rec_val);
            if let (Ok(last_microjoules), Ok(previous_microjoules)) =
                (last_rec_val.parse::<u64>(), prev_rec_val.parse::<u64>())
            {

                if last_microjoules < previous_microjoules {
                    debug!(
                        "socket: counter wrapped: previous_microjoules ({}) > last_microjoules ({})",
                        previous_microjoules, last_microjoules
                    );
                    return None;
                }
                let microjoules = last_microjoules - previous_microjoules;
                let time_diff =
                    last_record.timestamp.as_secs_f64() - previous_record.timestamp.as_secs_f64();
                let microwatts = microjoules as f64 / time_diff;
                debug!("socket : l1067: microwatts: {}", microwatts);
                return Some(Record::new(
                    last_record.timestamp,
                    (microwatts as u64).to_string(),
                    units::Unit::MicroWatt,
                ));
            }
        } else {
            warn!("Not enough records for socket");
        }
        None
    }

    pub fn get_rapl_mmio_energy_microjoules(&self) -> Option<Record> {
        if let Some(mmio) = self.sensor_data.get("mmio") {
            match &fs::read_to_string(mmio) {
                Ok(val) => {
                    return Some(Record::new(
                        current_system_time_since_epoch(),
                        val.to_string(),
                        units::Unit::MicroJoule,
                    ));
                }
                Err(e) => {
                    debug!("MMIO Error: {:?}", e)
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct CPUCore {
    pub id: u16,
    pub attributes: HashMap<String, String>,
}

impl CPUCore {

    pub fn new(id: u16, attributes: HashMap<String, String>) -> CPUCore {
        CPUCore { id, attributes }
    }

    fn read_stats(&self) -> Option<CPUStat> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(mut kernelstats) = KernelStats::new() {
                return Some(CPUStat::from_procfs_cputime(
                    kernelstats.cpu_time.remove(self.id as usize),
                ));
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct Domain {

    pub id: u16,

    pub name: String,

    pub counter_uj_path: String,

    pub record_buffer: Vec<Record>,

    pub buffer_max_kbytes: u16,

    #[allow(dead_code)]
    sensor_data: HashMap<String, String>,
}
impl RecordGenerator for Domain {

    fn refresh_record(&mut self) {
        match self.read_record() {
            Ok(record) => {
                self.record_buffer.push(record);
            }
            Err(e) => {
                warn!(
                    "Could'nt read record from {}. Error was : {:?}.",
                    self.sensor_data
                        .get("source_file")
                        .unwrap_or(&String::from("SRCFILENOTKNOWN")),
                    e
                );
            }
        }

        if !self.record_buffer.is_empty() {
            self.clean_old_records();
        }
    }

    fn clean_old_records(&mut self) {
        let record_ptr = &self.record_buffer[0];
        let curr_size = size_of_val(record_ptr) * self.record_buffer.len();
        if curr_size > (self.buffer_max_kbytes * 1000) as usize {
            let size_diff = curr_size - (self.buffer_max_kbytes * 1000) as usize;
            if size_diff > size_of_val(&self.record_buffer[0]) {
                let nb_records_to_delete =
                    size_diff as f32 / size_of_val(&self.record_buffer[0]) as f32;
                for _ in 1..nb_records_to_delete as u32 {
                    if !self.record_buffer.is_empty() {
                        self.record_buffer.remove(0);
                    }
                }
            }
        }
    }

    fn get_records_passive(&self) -> Vec<Record> {
        let mut result = vec![];
        for r in &self.record_buffer {
            result.push(Record::new(
                r.timestamp,
                r.value.clone(),
                units::Unit::MicroJoule,
            ));
        }
        result
    }
}
impl Domain {

    fn new(
        id: u16,
        name: String,
        counter_uj_path: String,
        buffer_max_kbytes: u16,
        sensor_data: HashMap<String, String>,
    ) -> Domain {
        Domain {
            id,
            name,
            counter_uj_path,
            record_buffer: vec![],
            buffer_max_kbytes,
            sensor_data,
        }
    }

    pub fn get_records_diff_power_microwatts(&self) -> Option<Record> {
        if self.record_buffer.len() > 1 {
            let last_record = self.record_buffer.last().unwrap();
            let previous_record = self
                .record_buffer
                .get(self.record_buffer.len() - 2)
                .unwrap();
            if let (Ok(last_microjoules), Ok(previous_microjoules)) = (
                last_record.value.trim().parse::<u64>(),
                previous_record.value.trim().parse::<u64>(),
            ) {
                if previous_microjoules > last_microjoules {
                    return None;
                }
                let microjoules = last_microjoules - previous_microjoules;
                let time_diff =
                    last_record.timestamp.as_secs_f64() - previous_record.timestamp.as_secs_f64();
                let microwatts = microjoules as f64 / time_diff;
                return Some(Record::new(
                    last_record.timestamp,
                    (microwatts as u64).to_string(),
                    units::Unit::MicroWatt,
                ));
            }
        }
        None
    }

    pub fn get_rapl_mmio_energy_microjoules(&self) -> Option<Record> {
        if let Some(mmio) = self.sensor_data.get("mmio") {
            match &fs::read_to_string(mmio) {
                Ok(val) => {
                    return Some(Record::new(
                        current_system_time_since_epoch(),
                        val.to_string(),
                        units::Unit::MicroJoule,
                    ));
                }
                Err(e) => {
                    debug!("MMIO Error in get microjoules: {:?}", e);
                }
            }
        }
        None
    }
}
impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Domain: {}", self.name)
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub timestamp: Duration,
    pub value: String,
    pub unit: units::Unit,

    #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
    pub signature: Vec<u8>,
}

impl Record {

    pub fn new(timestamp: Duration, value: String, unit: units::Unit) -> Record {
        Record {
            timestamp,
            value,
            unit,
            #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
            signature: Vec::new(),
        }
    }

    #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
    pub fn new_with_signature(timestamp: Duration, value: String, unit: units::Unit, signature: Vec<u8>) -> Record {
        Record {
            timestamp,
            value,
            unit,
            signature,
        }
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "recorded {} {} at {:?}",
            self.value.trim(),
            self.unit,
            self.timestamp
        )
    }
}

#[derive(Debug)]
pub struct CPUStat {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    irq: Option<u64>,
    iowait: Option<u64>,
    softirq: Option<u64>,
    steal: Option<u64>,
    guest: Option<u64>,
    guest_nice: Option<u64>,
}

impl CPUStat {
    #[cfg(target_os = "linux")]
    pub fn from_procfs_cputime(cpu_time: CpuTime) -> CPUStat {
        CPUStat {
            user: cpu_time.user,
            nice: cpu_time.nice,
            system: cpu_time.system,
            idle: cpu_time.idle,
            irq: cpu_time.irq,
            iowait: cpu_time.iowait,
            softirq: cpu_time.softirq,
            steal: cpu_time.steal,
            guest: cpu_time.guest,
            guest_nice: cpu_time.guest_nice,
        }
    }

    pub fn total_time_jiffies(&self) -> u64 {
        let user = self.user;
        let nice = self.nice;
        let system = self.system;
        let idle = self.idle;
        let irq = self.irq.unwrap_or_default();
        let iowait = self.iowait.unwrap_or_default();
        let softirq = self.softirq.unwrap_or_default();
        let steal = self.steal.unwrap_or_default();
        let guest_nice = self.guest_nice.unwrap_or_default();
        let guest = self.guest.unwrap_or_default();

        trace!(
            "CPUStat contains user {} nice {} system {} idle: {} irq {} softirq {} iowait {} steal {} guest_nice {} guest {}",
            user, nice, system, idle, irq, softirq, iowait, steal, guest_nice, guest
        );
        user + nice + system + guest_nice + guest
    }
}

impl Clone for CPUStat {

    fn clone(&self) -> CPUStat {
        CPUStat {
            user: self.user,
            guest: self.guest,
            guest_nice: self.guest_nice,
            idle: self.idle,
            iowait: self.iowait,
            irq: self.irq,
            nice: self.nice,
            softirq: self.softirq,
            steal: self.steal,
            system: self.system,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn get_proc_cpuinfo() {
        let cores = Topology::generate_cpu_cores().unwrap();
        println!(
            "cores: {} attributes in core 0: {}",
            cores.len(),
            cores[0].attributes.len()
        );
        for c in &cores {
            println!("{:?}", c.attributes);
        }
        assert_eq!(!cores.is_empty(), true);
        for c in &cores {
            assert_eq!(c.attributes.len() > 3, true);
        }
    }

    #[test]
    fn read_topology_stats() {
        #[cfg(target_os = "linux")]
        let sensor = powercap_rapl::PowercapRAPLSensor::new(8, 8, false);
        #[cfg(not(target_os = "linux"))]
        let sensor = msr_rapl::MsrRAPLSensor::new();
        let topo = (*sensor.get_topology()).unwrap();
        println!("{:?}", topo.read_stats());
    }

    #[test]
    fn read_core_stats() {
        #[cfg(target_os = "linux")]
        let sensor = powercap_rapl::PowercapRAPLSensor::new(8, 8, false);
        #[cfg(not(target_os = "linux"))]
        let sensor = msr_rapl::MsrRAPLSensor::new();
        let mut topo = (*sensor.get_topology()).unwrap();
        for s in topo.get_sockets() {
            for c in s.get_cores() {
                println!("{:?}", c.read_stats());
            }
        }
    }

    #[test]
    fn read_socket_stats() {
        #[cfg(target_os = "linux")]
        let sensor = powercap_rapl::PowercapRAPLSensor::new(8, 8, false);
        #[cfg(not(target_os = "linux"))]
        let sensor = msr_rapl::MsrRAPLSensor::new();
        let mut topo = (*sensor.get_topology()).unwrap();
        for s in topo.get_sockets() {
            println!("{:?}", s.read_stats());
        }
    }
}
