use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct HashVerifier {
    binary_path: String,
    expected_hash: String,
    running: Arc<Mutex<bool>>,
}

impl HashVerifier {

    pub fn new<P: AsRef<Path>>(binary_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = binary_path.as_ref().to_str()
            .ok_or("Invalid path")?
            .to_string();

        let initial_hash = Self::compute_file_hash(&path)?;

        Ok(HashVerifier {
            binary_path: path,
            expected_hash: initial_hash.clone(),
            running: Arc::new(Mutex::new(false)),
        })
    }

    fn compute_file_hash(path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn start_periodic_verification(&self, interval_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut running = self.running.lock().unwrap();
        if *running {
            return Ok(());
        }
        *running = true;
        drop(running);

        let binary_path = self.binary_path.clone();
        let expected_hash = self.expected_hash.clone();
        let running_flag = Arc::clone(&self.running);

        thread::spawn(move || {
            Self::verification_loop(binary_path, expected_hash, running_flag, interval_secs);
        });

        println!(
            "[HASH-VERIFIER] Started periodic verification (every {}s) for {}",
            interval_secs, self.binary_path
        );
        println!("[HASH-VERIFIER] Expected hash: {}", self.expected_hash);

        Ok(())
    }

    fn verification_loop(
        binary_path: String,
        expected_hash: String,
        running: Arc<Mutex<bool>>,
        interval_secs: u64,
    ) {
        let mut check_count = 0u64;

        loop {

            {
                let running_guard = running.lock().unwrap();
                if !*running_guard {
                    break;
                }
            }

            thread::sleep(Duration::from_secs(interval_secs));

            match Self::compute_file_hash(&binary_path) {
                Ok(current_hash) => {
                    check_count += 1;

                    if current_hash == expected_hash {
                        println!(
                            "[HASH-VERIFIER] Verification #{}: Binary integrity OK ({})",
                            check_count, binary_path
                        );
                    } else {
                        eprintln!(
                            "[HASH-VERIFIER] CRITICAL: Binary has been MODIFIED!"
                        );
                        eprintln!("[HASH-VERIFIER] Binary: {}", binary_path);
                        eprintln!("[HASH-VERIFIER] Expected: {}", expected_hash);
                        eprintln!("[HASH-VERIFIER] Current: {}", current_hash);
                        eprintln!("[HASH-VERIFIER] Action: TERMINATING for security");

                        std::process::exit(101);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[HASH-VERIFIER] Error computing hash for {}: {}",
                        binary_path, e
                    );
                    eprintln!("[HASH-VERIFIER] This could indicate tampering - terminating");
                    std::process::exit(102);
                }
            }
        }

        println!("[HASH-VERIFIER] Stopped verification loop");
    }

    pub fn verify_now(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let current_hash = Self::compute_file_hash(&self.binary_path)?;

        if current_hash == self.expected_hash {
            println!("[HASH-VERIFIER] Immediate verification: Binary integrity OK");
            Ok(true)
        } else {
            eprintln!("[HASH-VERIFIER] Immediate verification: Binary has been MODIFIED!");
            eprintln!("[HASH-VERIFIER] Expected: {}", self.expected_hash);
            eprintln!("[HASH-VERIFIER] Current: {}", current_hash);
            Ok(false)
        }
    }

    pub fn update_expected_hash(&mut self, new_hash: String) {
        println!(
            "[HASH-VERIFIER] Updated expected hash from {} to {}",
            self.expected_hash, new_hash
        );
        self.expected_hash = new_hash;
    }

    pub fn stop(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
        println!("[HASH-VERIFIER] Stopped periodic verification");
    }
}

impl Drop for HashVerifier {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn protect_current_binary(interval_secs: u64) -> Result<HashVerifier, Box<dyn std::error::Error>> {

    let current_exe = std::env::current_exe()?;
    let exe_path = current_exe.to_str()
        .ok_or("Cannot convert exe path to string")?;

    let verifier = HashVerifier::new(exe_path)?;

    verifier.start_periodic_verification(interval_secs)?;

    Ok(verifier)
}
