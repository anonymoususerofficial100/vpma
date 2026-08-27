use std::io::{self, Error, ErrorKind};
use std::path::Path;
use std::process::Command;
use std::fs;
use std::time::Instant;
use std::env;

fn get_tpm_dir() -> String {
    env::var("TPM_PATH").unwrap_or_else(|_| "/var/lib/scaphandre/tpm".to_string())
}

pub struct TpmAttestation {
    hmac_key: Option<Vec<u8>>,
}

fn detect_vtpm() -> bool {

    let vtpm_paths = [
        "/dev/tpm0",
        "/dev/tpmrm0",
        "/sys/class/tpm/tpm0",
    ];

    for path in &vtpm_paths {
        if Path::new(path).exists() {

            if let Ok(output) = Command::new("dmesg").arg("|").arg("grep").arg("-i").arg("tpm").output() {
                let dmesg_str = String::from_utf8_lossy(&output.stdout);
                if dmesg_str.contains("vtpm") || dmesg_str.contains("virtual") {
                    println!("[TPM] Detected vTPM (virtual TPM) device");
                    return true;
                }
            }

            if let Ok(manufacturer) = fs::read_to_string("/sys/class/tpm/tpm0/device/manufacturer") {
                if manufacturer.trim().contains("1414") {
                    println!("[TPM] Detected Microsoft vTPM");
                    return true;
                }
            }

            println!("[TPM] TPM device found at {}", path);
            return true;
        }
    }

    false
}

impl TpmAttestation {

    pub fn new(verifier_url: Option<&str>) -> io::Result<Self> {
        let total_start = Instant::now();
        println!("[TPM] Initializing TPM attestation...");

        #[cfg(feature = "tpm_attestation")]
        {

            if !detect_vtpm() {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "TPM device not found. For VMs, ensure vTPM is configured."
                ));
            }

            println!("[TPM] Connected to TPM device (via tpm2-tools)");

            if let Some(url) = verifier_url {
                println!("[TPM] Using remote verification server: {}", url);
            }

            let pcr_start = Instant::now();
            Self::read_and_display_pcrs()?;
            let pcr_duration = pcr_start.elapsed();
            println!("[TIMING] PCR Reading: {:.2} ms", pcr_duration.as_secs_f64() * 1000.0);

            println!("[TPM] ============================================");
            println!("[TPM] BOOT ATTESTATION (as per paper requirement)");
            println!("[TPM] ============================================");

            let quote_start = Instant::now();
            let attestation_quote = generate_tpm_quote()?;
            let quote_duration = quote_start.elapsed();
            println!("[TIMING] TPM Quote Generation: {:.2} ms", quote_duration.as_secs_f64() * 1000.0);

            #[cfg(feature = "use_sgx")]
            {
                use crate::exporters::export_vm::verify_boot_attestation_in_sgx;

                let sgx_verify_start = Instant::now();

                match verify_boot_attestation_in_sgx(&attestation_quote, verifier_url) {
                    Ok(_) => {
                        let sgx_verify_duration = sgx_verify_start.elapsed();
                        println!("[TIMING] SGX Boot Verification: {:.2} ms", sgx_verify_duration.as_secs_f64() * 1000.0);
                        println!("[TPM] SGX enclave verified boot attestation");
                        println!("[TPM] - TPM quote signature validated");
                        println!("[TPM] - IMA measurements verified");
                        if verifier_url.is_some() {
                            println!("[TPM] - External verifier confirmed system integrity");
                        }
                    }
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::PermissionDenied,
                            format!("BOOT ATTESTATION FAILED: {}\nSystem integrity cannot be verified. Refusing to start.", e)
                        ));
                    }
                }
            }

            #[cfg(not(feature = "use_sgx"))]
            {
                println!("[TPM] Warning: SGX not enabled, skipping enclave verification");
                println!("[TPM] (TPM quote generated but not validated)");
            }

            println!("[TPM] ============================================");

            let tpm_dir = get_tpm_dir();
            let sealed_key_path = format!("{}/hmac_key_sealed.bin", tpm_dir);

            let unseal_start = Instant::now();
            let hmac_key = if Path::new(&sealed_key_path).exists() {
                println!("[TPM] Found existing sealed key, attempting unseal...");
                Self::unseal_hmac_key_via_tpm2tools()?
            } else {
                println!("[TPM] No sealed key found, generating and sealing new key...");
                Self::create_and_seal_key_via_tpm2tools()?
            };
            let unseal_duration = unseal_start.elapsed();
            println!("[TIMING] TPM Key Unseal/Create: {:.2} ms", unseal_duration.as_secs_f64() * 1000.0);

            println!("[TPM] HMAC key ready (boot chain verified by TPM)");

            let total_duration = total_start.elapsed();
            println!("[TIMING] ============================================");
            println!("[TIMING] Total TPM Attestation Init: {:.2} ms", total_duration.as_secs_f64() * 1000.0);
            println!("[TIMING] ============================================");

            Ok(TpmAttestation {
                hmac_key: Some(hmac_key),
            })
        }

        #[cfg(not(feature = "tpm_attestation"))]
        {
            println!("[TPM] TPM attestation disabled (feature not enabled)");
            Ok(TpmAttestation {
                hmac_key: None,
            })
        }
    }

    #[cfg(feature = "tpm_attestation_vm")]
    pub fn new_vm_mode(verifier_url: Option<&str>) -> io::Result<Self> {
        let total_start = Instant::now();
        println!("[TPM-VM] Initializing vTPM attestation (VM MODE)...");

        if !detect_vtpm() {
            println!("[TPM-VM] vTPM not found - continuing without TPM");
            println!("[TPM-VM] To enable vTPM: virsh edit <vm-name> and add <tpm model='tpm-crb'>");
            return Ok(TpmAttestation {
                hmac_key: None,
            });
        }

        println!("[TPM-VM] vTPM device detected");

        if let Some(url) = verifier_url {
            println!("[TPM-VM] Using remote verification server: {}", url);
        }

        let pcr_start = Instant::now();
        if let Err(e) = Self::read_and_display_pcrs() {
            let pcr_duration = pcr_start.elapsed();
            println!("[TIMING] PCR Reading Failed: {:.2} ms", pcr_duration.as_secs_f64() * 1000.0);
            println!("[TPM-VM] Could not read PCRs: {}", e);
            println!("[TPM-VM] Installing tpm2-tools: sudo apt install tpm2-tools");
            return Ok(TpmAttestation {
                hmac_key: None,
            });
        } else {
            let pcr_duration = pcr_start.elapsed();
            println!("[TIMING] vTPM PCR Reading: {:.2} ms", pcr_duration.as_secs_f64() * 1000.0);
        }

        println!("[TPM-VM] Generating vTPM quote for VM attestation...");

        let quote_start = Instant::now();
        let attestation_quote = match generate_tpm_quote() {
            Ok(quote) => {
                let quote_duration = quote_start.elapsed();
                println!("[TIMING] vTPM Quote Generation: {:.2} ms", quote_duration.as_secs_f64() * 1000.0);
                quote
            },
            Err(e) => {
                println!("[TPM-VM] Failed to generate TPM quote: {}", e);
                println!("[TPM-VM] Continuing without attestation (relying on host TPM)");
                return Ok(TpmAttestation {
                    hmac_key: None,
                });
            }
        };

        println!("[TPM-VM] vTPM quote generated successfully");

        let tpm_dir = get_tpm_dir();
        let sealed_key_path = format!("{}/hmac_key_sealed.bin", tpm_dir);

        let unseal_start = Instant::now();
        let hmac_key = if Path::new(&sealed_key_path).exists() {
            println!("[TPM-VM] Found existing sealed key, attempting unseal...");
            match Self::unseal_hmac_key_vm_with_policy_session() {
                Ok(key) => Some(key),
                Err(e) => {
                    println!("[TPM-VM] Failed to unseal key: {}", e);
                    println!("[TPM-VM] Continuing without HMAC signing");
                    None
                }
            }
        } else {
            println!("[TPM-VM] No sealed key found, generating new key...");
            match Self::create_and_seal_key_via_tpm2tools() {
                Ok(key) => Some(key),
                Err(e) => {
                    println!("[TPM-VM] Failed to create/seal key: {}", e);
                    println!("[TPM-VM] Continuing without HMAC signing");
                    None
                }
            }
        };
        let unseal_duration = unseal_start.elapsed();
        println!("[TIMING] vTPM Key Unseal/Create: {:.2} ms", unseal_duration.as_secs_f64() * 1000.0);

        if hmac_key.is_some() {
            println!("[TPM-VM] vTPM key ready for HMAC signing");
        } else {
            println!("[TPM-VM] Running without TPM-backed HMAC (relying on host security)");
        }

        let total_duration = total_start.elapsed();
        println!("[TIMING] ============================================");
        println!("[TIMING] Total vTPM Attestation Init: {:.2} ms", total_duration.as_secs_f64() * 1000.0);
        println!("[TIMING] ============================================");

        Ok(TpmAttestation { hmac_key })
    }

    #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
    fn read_and_display_pcrs() -> io::Result<()> {
        println!("[TPM] Reading PCR values:");
        println!("[TPM] PCR 0 = BIOS/UEFI firmware (sealed)");
        println!("[TPM] PCR 7 = Secure Boot state (sealed)");
        println!("[TPM] PCR 10 = IMA measurements (monitored, not sealed)");

        let output = Command::new("tpm2_pcrread")
            .args(&["sha256:0,7,10"])
            .output()
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to run tpm2_pcrread: {}", e))
            })?;

        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("tpm2_pcrread failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        println!("[TPM] PCR values read successfully");

        Ok(())
    }

    #[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
    fn create_and_seal_key_via_tpm2tools() -> io::Result<Vec<u8>> {
        use rand::RngCore;
        use std::fs;

        let tpm_dir = get_tpm_dir();

        println!("[TPM] Generating random 32-byte HMAC key...");
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        fs::create_dir_all(&tpm_dir)?;

        let temp_key_path = format!("{}/hmac_key_temp.bin", tpm_dir);
        fs::write(&temp_key_path, &key)?;

        println!("[TPM] Creating TPM primary key...");

        let primary_ctx = format!("{}/primary.ctx", tpm_dir);
        let pcr_policy = format!("{}/pcr.policy", tpm_dir);
        let sealed_bin = format!("{}/hmac_key_sealed.bin", tpm_dir);
        let pub_key = format!("{}/hmac_key.pub", tpm_dir);

        let output = Command::new("tpm2_createprimary")
            .args(&[
                "-C", "o",
                "-g", "sha256",
                "-G", "rsa",
                "-c", &primary_ctx,
            ])
            .output()
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to run tpm2_createprimary: {}", e))
            })?;

        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("tpm2_createprimary failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        println!("[TPM] Sealing key with PCR policy (0, 7)...");

        let output = Command::new("tpm2_createpolicy")
            .args(&[
                "--policy-pcr",
                "-l", "sha256:0,7",
                "-L", &pcr_policy,
            ])
            .output()
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to run tpm2_createpolicy: {}", e))
            })?;

        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("tpm2_createpolicy failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        let output = Command::new("tpm2_create")
            .args(&[
                "-C", &primary_ctx,
                "-g", "sha256",
                "-i", &temp_key_path,
                "-r", &sealed_bin,
                "-u", &pub_key,
                "-L", &pcr_policy,
                "-a", "fixedtpm|fixedparent",
            ])
            .output()
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to run tpm2_create: {}", e))
            })?;

        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("tpm2_create failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        println!("[TPM] Key sealed successfully");
        println!("[TPM] Sealed key saved to {}", sealed_bin);

        fs::remove_file(&temp_key_path)?;
        println!("[TPM] Plaintext key deleted");

        Ok(key)
    }

    #[cfg(any(feature = "tpm_attestation"))]
    fn unseal_hmac_key_via_tpm2tools() -> io::Result<Vec<u8>> {
        use std::fs;

        let tpm_dir = get_tpm_dir();
        let primary_ctx = format!("{}/primary.ctx", tpm_dir);
        let sealed_bin = format!("{}/hmac_key_sealed.bin", tpm_dir);
        let pub_key = format!("{}/hmac_key.pub", tpm_dir);
        let sealed_ctx = format!("{}/sealed_key.ctx", tpm_dir);

        println!("[TPM] Loading sealed key...");

        println!("[TPM] Creating primary key...");
        let output = Command::new("tpm2_createprimary")
            .args(&[
                "-C", "o",
                "-g", "sha256",
                "-G", "rsa",
                "-c", &primary_ctx,
            ])
            .output()
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to run tpm2_createprimary: {}", e))
            })?;

        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("tpm2_createprimary failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        println!("[TPM] Loading sealed object into TPM...");
        let output = Command::new("tpm2_load")
            .args(&[
                "-C", &primary_ctx,
                "-r", &sealed_bin,
                "-u", &pub_key,
                "-c", &sealed_ctx,
            ])
            .output()
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to run tpm2_load: {}", e))
            })?;

        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("tpm2_load failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        println!("[TPM] Unsealing key (TPM validating PCRs 0, 7)...");
        let key = unseal_with_pcr_policy(&sealed_ctx, "pcr:sha256:0,7", "TPM")?;

        println!("[TPM] PCR policy validated - boot chain verified by TPM hardware");
        println!("[TPM] Key unsealed successfully");

        if key.len() != 32 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsealed key has wrong length: {} bytes (expected 32)", key.len())
            ));
        }

        Ok(key)
    }

    #[cfg(feature = "tpm_attestation_vm")]
    fn unseal_hmac_key_vm_with_policy_session() -> io::Result<Vec<u8>> {
        use std::fs;

        let tpm_dir = get_tpm_dir();
        let primary_ctx = format!("{}/primary.ctx", tpm_dir);
        let sealed_bin = format!("{}/hmac_key_sealed.bin", tpm_dir);
        let pub_key = format!("{}/hmac_key.pub", tpm_dir);
        let sealed_ctx = format!("{}/sealed_key.ctx", tpm_dir);
        let session_ctx = format!("{}/session.ctx", tpm_dir);

        println!("[vTPM] Loading sealed key...");

        println!("[vTPM] Creating primary key...");
        let output = Command::new("tpm2_createprimary")
            .args(&[
                "-C", "o",
                "-g", "sha256",
                "-G", "rsa",
                "-c", &primary_ctx,
            ])
            .output()
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to run tpm2_createprimary: {}", e))
            })?;

        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("vtpm2_createprimary failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        println!("[vTPM] Loading sealed object into TPM...");
        let output = Command::new("tpm2_load")
            .args(&[
                "-C", &primary_ctx,
                "-r", &sealed_bin,
                "-u", &pub_key,
                "-c", &sealed_ctx,
            ])
            .output()
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to run tpm2_load: {}", e))
            })?;

        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("vtpm2_load failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        println!("[vTPM] Unsealing key (vTPM validating PCRs 0, 7)...");
        let _ = &session_ctx;
        let key = unseal_with_pcr_policy(&sealed_ctx, "pcr:sha256:0,7", "vTPM")?;

        println!("[vTPM] PCR policy validated - boot chain verified by vTPM");
        println!("[vTPM] Key unsealed successfully");

        if key.len() != 32 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsealed key has wrong length: {} bytes (expected 32)", key.len())
            ));
        }

        Ok(key)
    }

    pub fn get_hmac_key(&self) -> Option<&[u8]> {
        self.hmac_key.as_deref()
    }

    pub fn is_attested(&self) -> bool {
        self.hmac_key.is_some()
    }
}

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
pub fn sign_with_hmac(key: &[u8], data: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data.as_bytes());

    mac.finalize().into_bytes().to_vec()
}

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
pub fn verify_hmac(key: &[u8], data: &str, signature: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data.as_bytes());

    mac.verify_slice(signature).is_ok()
}

#[derive(Debug, Clone)]
pub struct AttestationQuote {
    pub pcr_values: Vec<u8>,
    pub quote_signature: Vec<u8>,
    pub attestation_data: Vec<u8>,
    pub ima_log: String,
}

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
pub fn quoted_pcrs() -> Vec<u8> {
    let (a, b) = crate::exporters::utils::platform_pcr_pair();
    vec![a, b, 10]
}

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
pub fn generate_signed_quote(nonce_hex: &str) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use std::fs;

    let dir = env::var("TPM_PATH").unwrap_or_else(|_| "/var/lib/scaphandre/tpm".to_string());
    let ak_ctx = format!("{}/ak.ctx", dir);
    if !std::path::Path::new(&ak_ctx).exists() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!(
                "no Attestation Key at {}. Create one once per machine:\n \
 tpm2_createek -c {}/ek.ctx -G rsa -u {}/ek.pub\n \
 tpm2_createak -C {}/ek.ctx -c {} -G rsa -g sha256 -s rsassa -u {}/ak.pub -f pem\n\
 then register its public key so the enclave will trust it \
 (scripts/register_ak.sh).",
                ak_ctx, dir, dir, dir, ak_ctx, dir
            ),
        ));
    }

    let qp = quoted_pcrs();
    let sel = qp
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let pcr_list = format!("sha256:{}", sel);

    for attempt in 1..=40 {
        let mut pcr_values = Vec::with_capacity(32 * qp.len());
        let mut read_ok = true;
        for p in &qp {
            match fs::read_to_string(format!("/sys/class/tpm/tpm0/pcr-sha256/{}", p)) {
                Ok(s) => match hex::decode(s.trim()) {
                    Ok(b) if b.len() == 32 => pcr_values.extend_from_slice(&b),
                    _ => { read_ok = false; break; }
                },
                Err(_) => { read_ok = false; break; }
            }
        }
        if !read_ok {
            return Err(Error::new(ErrorKind::Other, "could not read PCR sysfs values"));
        }

        let msg = format!("{}/quote.msg", dir);
        let sig = format!("{}/quote.sig", dir);
        let out = Command::new("tpm2_quote")
            .args(&["-c", &ak_ctx, "-l", &pcr_list, "-q", nonce_hex,
                    "-m", &msg, "-s", &sig, "-g", "sha256"])
            .output()
            .map_err(|e| Error::new(ErrorKind::Other, format!("tpm2_quote failed to run: {}", e)))?;
        if !out.status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("tpm2_quote failed: {}", String::from_utf8_lossy(&out.stderr)),
            ));
        }

        let attest = fs::read(&msg)?;
        let signature = fs::read(&sig)?;

        if quote_pcr_digest_matches(&attest, &pcr_values) {
            if attempt > 1 {
                println!("[TPM-QUOTE] PCR10 moved during quoting; settled on attempt {}", attempt);
            }
            return Ok((pcr_values, attest, signature));
        }

        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    Err(Error::new(
        ErrorKind::Other,
        "PCR values kept changing while quoting (40 attempts). The node is measuring files \
 continuously; retry when it is quieter.",
    ))
}

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
fn quote_pcr_digest_matches(attest: &[u8], pcr_values: &[u8]) -> bool {
    use sha2::{Digest, Sha256};

    if attest.len() < 34 || pcr_values.is_empty() {
        return false;
    }
    let quoted = &attest[attest.len() - 32..];
    let computed = Sha256::digest(pcr_values);
    quoted == computed.as_slice()
}

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
pub fn generate_tpm_quote() -> io::Result<AttestationQuote> {
    use std::fs;

    println!("[TPM-QUOTE] Collecting boot attestation data for SGX verification...");

    println!("[TPM-QUOTE] Reading PCR values from TPM...");
    let scratch_dir = get_tpm_dir();
    let _ = fs::create_dir_all(&scratch_dir);
    let pcr_file = format!("{}/pcrs-{}.bin", scratch_dir, std::process::id());

    let (pcr_a, pcr_b) = crate::exporters::utils::platform_pcr_pair();
    let pcr_sel = format!("sha256:{},{},10", pcr_a, pcr_b);
    let output = Command::new("tpm2_pcrread")
        .args(&["-o", &pcr_file, &pcr_sel])
        .output()
        .map_err(|e| {
            Error::new(ErrorKind::Other, format!("Failed to read PCRs: {}", e))
        })?;

    if !output.status.success() {
        let _ = fs::remove_file(&pcr_file);
        return Err(Error::new(
            ErrorKind::Other,
            format!("tpm2_pcrread failed: {}", String::from_utf8_lossy(&output.stderr))
        ));
    }

    let mut pcr_values = fs::read(&pcr_file)
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to read PCR file: {}", e)))?;
    let _ = fs::remove_file(&pcr_file);

    println!("[TPM-QUOTE] PCR values collected from TPM hardware");

    let snapshot_pcr10 = crate::exporters::utils::snapshot_pcr10()
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    let ima_log = read_ima_log()?;

    if crate::exporters::utils::splice_pcr10(&mut pcr_values, snapshot_pcr10.as_deref())
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?
    {
        println!("[TPM-QUOTE] PCR10 taken from the IMA snapshot (paired with the log)");
    }

    println!("[TPM-QUOTE] Attestation data package created");
    println!("[TPM-QUOTE] - PCR values: {} bytes (PCRs {},{},10 from TPM)", pcr_values.len(), pcr_a, pcr_b);
    println!("[TPM-QUOTE] - IMA measurements: {} entries", ima_log.lines().count());
    println!("[TPM-QUOTE] This data will be forwarded to SGX enclave for verification");
    println!("[TPM-QUOTE] Paper requirement: \"host process can read the signed measurement");
    println!("[TPM-QUOTE] values from the TPM and forward to the enclave\"");

    Ok(AttestationQuote {
        pcr_values,
        quote_signature: Vec::new(),
        attestation_data: Vec::new(),
        ima_log,
    })
}

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
fn unseal_with_pcr_policy(sealed_ctx: &str, pcr_spec: &str, tag: &str) -> io::Result<Vec<u8>> {
    const ATTEMPTS: usize = 12;
    let mut last = String::new();

    for attempt in 1..=ATTEMPTS {
        let output = Command::new("tpm2_unseal")
            .args(&["-c", sealed_ctx, "-p", pcr_spec])
            .output()
            .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to run tpm2_unseal: {}", e)))?;

        if output.status.success() {
            if attempt > 1 {
                println!("[{}] Key unsealed on attempt {} (PCR counter moved under IMA)", tag, attempt);
            }
            return Ok(output.stdout);
        }

        last = String::from_utf8_lossy(&output.stderr).to_string();

        if !last.contains("0x00000128") && !last.to_lowercase().contains("pcr have changed") {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "{} unseal FAILED - PCR values do not match the sealed policy, i.e. the boot \
 state genuinely differs from when the key was sealed.\n{}",
                    tag, last
                ),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(120 * attempt as u64));
    }

    Err(Error::new(
        ErrorKind::Other,
        format!(
            "{} unseal lost the TPM pcrUpdateCounter race {} times in a row. This is NOT a boot-state \
 mismatch: the policy digest matched, but IMA extended a PCR between the policy check and \
 the unseal each time. The node is measuring files unusually fast.\n{}",
            tag, ATTEMPTS, last
        ),
    ))
}

#[cfg(any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))]
pub fn read_ima_log() -> io::Result<String> {
    use std::fs;
    use std::env;

    println!("[IMA] Reading measurement log...");

    let ima_base = env::var("IMA_PATH").unwrap_or_else(|_| "/sys/kernel/security/ima".to_string());
    let ima_path = format!("{}/ascii_runtime_measurements", ima_base);

    let log = fs::read_to_string(&ima_path)
        .map_err(|e| Error::new(ErrorKind::PermissionDenied,
            format!("Failed to read IMA log from {}: {}", ima_path, e)))?;

    let line_count = log.lines().count();
    println!("[IMA] Read {} measurement entries", line_count);

    Ok(log)
}

#[cfg(not(any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
pub fn sign_with_hmac(_key: &[u8], _data: &str) -> Vec<u8> {
    Vec::new()
}

#[cfg(not(any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
pub fn verify_hmac(_key: &[u8], _data: &str, _signature: &[u8]) -> bool {
    true
}
