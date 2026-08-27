use clap::crate_version;
use std::collections::HashMap;
use std::fmt::Write;
#[cfg(feature = "containers")]
use {
    docker_sync::Docker,
    k8s_sync::{errors::KubernetesError, kubernetes::Kubernetes},
};

pub const DEFAULT_IP_ADDRESS: &str = "::";

pub fn filter_cmdline(cmdline: &str) -> String {
    cmdline.replace('\"', "\\\"").replace('\n', "")
}

pub fn format_prometheus_metric(
    key: &str,
    value: &str,
    labels: Option<&HashMap<String, String>>,
) -> String {
    let mut result = key.to_string();
    if let Some(labels) = labels {
        result.push('{');
        for (k, v) in labels.iter() {
            let _ = write!(
                result,
                "{}=\"{}\",",
                k,
                v.replace('\"', "_").replace('\\', "")
 );
 }
 result.remove(result.len() - 1);
 result.push('}');
 }
 let _ = writeln!(result, " {value}");
 result
}

pub fn filter_qemu_cmdline(cmdline: &str) -> Option<String> {
 if cmdline.contains("qemu-system") && cmdline.contains("guest=") {
 let vmname: Vec<Vec<&str>> = cmdline
 .split("guest=")
 .map(|x| x.split(',').collect())
 .collect();

 match (vmname[1].len(), vmname[1][0].is_empty()) {
 (1, _) => return None,
 (_, true) => return None,
 (_, false) => return Some(String::from(vmname[1][0])),
 }
 }
 None
}

pub fn get_scaphandre_version() -> String {
 let mut version_parts = crate_version!().split('.');
 let major_version = version_parts.next().unwrap();
 let patch_version = version_parts.next().unwrap();
 let minor_version = version_parts.next().unwrap();
 format!("{major_version}.{patch_version}{minor_version}")
}

pub fn get_hostname() -> String {

 if let Ok(vm_name) = std::env::var("VM_NAME") {
 return vm_name;
 }

 String::from(
 hostname::get()
 .expect("Fail to get system hostname")
 .to_str()
 .unwrap(),
 )
}

#[cfg(test)]
mod tests {
 use super::*;
 #[test]
 fn test_filter_qemu_cmdline_ok() {
 let cmdline = "file=/var/lib/libvirt/qemu/domain-1-fedora33/master-key.aes-object-Sguest=fedora33,debug-threads=on-name/usr/bin/qemu-system-x86_64";
 assert_eq!(filter_qemu_cmdline(cmdline), Some("fedora33".to_string()));
 }

 #[test]
 fn test_filter_qemu_cmdline_ko_not_qemu() {
 let cmdline = "file=/var/lib/libvirt/qemu/domain-1-fedora33/master-key.aes-object-Sguest=fedora33,debug-threads=on-name/usr/bin/bidule";
 assert_eq!(filter_qemu_cmdline(cmdline), None);
 }

 #[test]
 fn test_filter_qemu_cmdline_ko_no_guest_token() {
 let cmdline = "file=/var/lib/libvirt/qemu/domain-1-fedora33/master-key.aes-object-Sfuest=fedora33,debug-threads=on-name/usr/bin/qemu-system-x86_64";
 assert_eq!(filter_qemu_cmdline(cmdline), None);
 }

 #[test]
 fn test_filter_qemu_cmdline_ko_no_comma_separator() {
 let cmdline = "file=/var/lib/libvirt/qemu/domain-1-fedora33/master-key.aes-object-Sguest=fedora33#debug-threads=on-name/usr/bin/qemu-system-x86_64";
 assert_eq!(filter_qemu_cmdline(cmdline), None);
 }

 #[test]
 fn test_filter_qemu_cmdline_ko_empty_guest01() {
 let cmdline = "file=/var/lib/libvirt/qemu/domain-1-fedora33/master-key.aes-object-Sguest=,,debug-threads=on-name/usr/bin/qemu-system-x86_64";
 assert_eq!(filter_qemu_cmdline(cmdline), None);
 }

 #[test]
 fn test_filter_qemu_cmdline_ko_empty_guest02() {
 let cmdline = "qemu-system-x86_64,file=/var/lib/libvirt/qemu/domain-1-fedora33/master-key.aes-object-Sguest=";
 assert_eq!(filter_qemu_cmdline(cmdline), None);
 }
}

#[cfg(feature = "containers")]
pub fn get_docker_client() -> Result<Docker, std::io::Error> {
 let docker = match Docker::connect() {
 Ok(docker) => docker,
 Err(err) => return Err(err),
 };
 Ok(docker)
}

#[cfg(feature = "containers")]
pub fn get_kubernetes_client() -> Result<Kubernetes, KubernetesError> {
 match Kubernetes::connect(
 Some(String::from("/root/.kube/config")),
 None,
 None,
 None,
 true,
 ) {
 Ok(kubernetes) => Ok(kubernetes),
 Err(err) => {
 eprintln!("Got Kubernetes error: {err} | {err:?}");
 Err(err)
 }
 }
}

#[test]

fn test_filter_cmdline_with_carriage_return() {
 let cmdline = "bash-csleep infinity;\n> echo plop";
 assert_eq!(
 filter_cmdline(cmdline),
 String::from("bash-csleep infinity;> echo plop")
 );
}

fn is_live_securityfs(dir: &str) -> bool {
 const SECURITYFS: &str = "/sys/kernel/security";
 std::fs::canonicalize(dir)
 .map(|p| p.starts_with(SECURITYFS))
 .unwrap_or_else(|_| dir.trim_end_matches('/').starts_with(SECURITYFS))
}

pub fn snapshot_pcr10() -> Result<Option<Vec<u8>>, String> {
 let base = match std::env::var("IMA_PATH") {
 Ok(b) => b,
 Err(_) => return Ok(None),
 };
 let dir = base.trim_end_matches('/');
 if is_live_securityfs(dir) {
 return Ok(None);
 }
 let pcr10_file = format!("{}/pcr10", dir);
 let raw = std::fs::read_to_string(&pcr10_file).map_err(|e| {
 format!(
 "IMA_PATH={} is a snapshot directory but has no paired PCR10 at {} ({}). A live PCR10 \
             read is always newer than a snapshot, so the enclave could not reconcile them. Refresh \
             the pair with: sudo scripts/ima_snapshot.sh {}",
 base, pcr10_file, e, base
 )
 })?;
 let hexstr = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
 let bytes = hex::decode(hexstr).map_err(|e| format!("{} is not valid hex: {}", pcr10_file, e))?;
 if bytes.len() != 32 {
 return Err(format!(
 "{} holds {} bytes; expected a 32-byte sha256 PCR10",
 pcr10_file,
 bytes.len()
 ));
 }
 Ok(Some(bytes))
}

pub fn splice_pcr10(pcr_values: &mut [u8], pcr10: Option<&[u8]>) -> Result<bool, String> {
 let bytes = match pcr10 {
 Some(b) => b,
 None => return Ok(false),
 };
 if pcr_values.len() < 96 {
 return Err(format!(
 "PCR blob is {} bytes; expected at least 96 ([PCR0|PCR7|PCR10])",
 pcr_values.len()
 ));
 }
 pcr_values[64..96].copy_from_slice(bytes);
 Ok(true)
}

pub fn platform_pcr_pair() -> (u8, u8) {
 match std::env::var("VPMA_PLATFORM_PCRS") {
 Ok(spec) => {
 let parts: Vec<&str> = spec.split(',').map(|s| s.trim()).collect();
 if parts.len() == 2 {
 if let (Ok(a), Ok(b)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
 if a < 24 && b < 24 {
 return (a, b);
 }
 }
 }
 eprintln!(
 "[PCR] VPMA_PLATFORM_PCRS={:?} is not \"a,b\" with two PCR indices < 24 - \
 falling back to (0,7)",
                spec
            );
            (0, 7)
        }
        Err(_) => (0, 7),
    }
}

pub fn read_consistent_ima_snapshot(tag: &str) -> Option<(Vec<u8>, String)> {
    let (pcr_a, pcr_b) = platform_pcr_pair();
    let read_pcr = |pcr: u8| -> Option<String> {
        let path = format!("/sys/class/tpm/tpm0/pcr-sha256/{}", pcr);
        match std::fs::read_to_string(&path) {
            Ok(c) => Some(c.trim().strip_prefix("0x").unwrap_or(c.trim()).to_string()),
            Err(e) => {
                eprintln!("[{}] Failed to read PCR{}: {} ({})", tag, pcr, e, path);
                None
            }
        }
    };
    let ima_dir = std::env::var("IMA_PATH").ok();
    let ima_path = ima_dir
        .as_ref()
        .map(|p| format!("{}/ascii_runtime_measurements", p.trim_end_matches('/')))
        .unwrap_or_else(|| "/sys/kernel/security/ima/ascii_runtime_measurements".to_string());

    if let Some(dir) = ima_dir.as_ref() {
        let pcr10_file = format!("{}/pcr10", dir.trim_end_matches('/'));
        if let Ok(raw) = std::fs::read_to_string(&pcr10_file) {
            let pcr10_hex = raw.trim().strip_prefix("0x").unwrap_or(raw.trim()).to_string();
            let ima_log = match std::fs::read_to_string(&ima_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[{}] Failed to read IMA log {}: {}", tag, ima_path, e);
                    return None;
                }
            };
            let mut pcr_values = Vec::with_capacity(96);
            for (label, hexstr) in [
                (format!("PCR{}", pcr_a), read_pcr(pcr_a)?),
                (format!("PCR{}", pcr_b), read_pcr(pcr_b)?),
                ("PCR10".to_string(), pcr10_hex),
            ] {
                match hex::decode(&hexstr) {
                    Ok(bytes) => pcr_values.extend_from_slice(&bytes),
                    Err(e) => {
                        eprintln!("[{}] Invalid {} hex: {}", tag, label, e);
                        return None;
                    }
                }
            }
            println!(
                "[{}] Using snapshot-paired PCR10 from {} (log is a root-made snapshot)",
                tag, pcr10_file
            );
            return Some((pcr_values, ima_log));
        }
    }

    const ATTEMPTS: usize = 5;
    for attempt in 1..=ATTEMPTS {
        let pcr10_before = read_pcr(10)?;
        let ima_log = match std::fs::read_to_string(&ima_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[{}] Failed to read IMA log {}: {}", tag, ima_path, e);
                return None;
            }
        };
        let pcr10_after = read_pcr(10)?;
        if pcr10_before != pcr10_after {
            eprintln!(
                "[{}] IMA snapshot raced (PCR10 moved during the read), retry {}/{}",
                tag, attempt, ATTEMPTS
            );
            continue;
        }
        let mut pcr_values = Vec::with_capacity(96);
        for (label, hexstr) in [
            (format!("PCR{}", pcr_a), read_pcr(pcr_a)?),
            (format!("PCR{}", pcr_b), read_pcr(pcr_b)?),
            ("PCR10".to_string(), pcr10_after),
        ] {
            match hex::decode(&hexstr) {
                Ok(bytes) => pcr_values.extend_from_slice(&bytes),
                Err(e) => {
                    eprintln!("[{}] Invalid {} hex: {}", tag, label, e);
                    return None;
                }
            }
        }
        return Some((pcr_values, ima_log));
    }
    eprintln!(
        "[{}] No consistent PCR10/IMA snapshot after {} attempts - the node is \
 measuring files continuously. Refusing (the enclave would reject it anyway).",
        tag, ATTEMPTS
    );
    None
}

pub fn read_ima_log(tag: &str) -> Option<String> {
    let ima_path = std::env::var("IMA_PATH")
        .ok()
        .map(|p| format!("{}/ascii_runtime_measurements", p.trim_end_matches('/')))
        .unwrap_or_else(|| "/sys/kernel/security/ima/ascii_runtime_measurements".to_string());
    match std::fs::read_to_string(&ima_path) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("[{}] Failed to read IMA log {}: {}", tag, ima_path, e);
            None
        }
    }
}

pub fn log_enclave_identity(kind: &str, path: &str) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    let (kind, path) = (kind.to_string(), path.to_string());
    ONCE.call_once(move || {
        let meta = std::fs::metadata(&path);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let age = meta
            .as_ref()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|d| format!("{:.1} days old", d.as_secs_f64() / 86_400.0))
            .unwrap_or_else(|| "unknown age".to_string());
        let digest = std::fs::read(&path)
            .map(|bytes| {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(&bytes))
            })
            .unwrap_or_else(|_| "unreadable".to_string());
        println!("[SGX-IMAGE] {} enclave: {}", kind, path);
        println!(
            "[SGX-IMAGE] sha256={} ({} bytes, {})",
            &digest[..digest.len().min(32)],
            size,
            age
        );
    });
}
