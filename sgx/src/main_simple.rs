use std::io::{self, BufRead, Write};
use serde::{Deserialize, Serialize};

use sgx::ecall_verify_binary_hash;

fn debug_msg(msg: &str) {
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
    let _ = std::io::stderr().flush();
}

#[derive(Deserialize)]
struct VerifyRequest {
    pcr_values: String,
    ima_log: String,
    hostname: String,
    deployment_type: String,
    immudb_addr: String,
    ca_pem: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    status: i32,
    message: String,
}

fn main() {
    debug_msg("[SGX] Starting simple test enclave...");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    debug_msg("[SGX] Reading stdin...");

    let mut line = String::new();
    match stdin.lock().read_line(&mut line) {
        Ok(0) => {
            debug_msg("[SGX] No input received");
            return;
        }
        Ok(n) => {
            debug_msg(&format!("[SGX] Read {} bytes", n));
        }
        Err(e) => {
            debug_msg(&format!("[SGX] Read error: {}", e));
            return;
        }
    }

    debug_msg("[SGX] Parsing JSON...");

    let request: VerifyRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            debug_msg(&format!("[SGX] Parse error: {}", e));
            let response = VerifyResponse {
                status: -100,
                message: format!("Parse error: {}", e),
            };
            let _ = writeln!(stdout, "{}", serde_json::to_string(&response).unwrap());
            return;
        }
    };

    debug_msg(&format!("[SGX] Request hostname: {}", request.hostname));

    let response = VerifyResponse {
        status: 0,
        message: format!("Received request for host: {}", request.hostname),
    };

    let _ = writeln!(stdout, "{}", serde_json::to_string(&response).unwrap());
    debug_msg("[SGX] Done!");
}
