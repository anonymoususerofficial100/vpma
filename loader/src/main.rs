#!/usr/bin/env rust

use clap::Parser;
use std::process::Command;
use std::env;
use std::path::Path;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

fn main() {
    let args = Args::parse();

    println!("[LOADER] Scaphandre Bootstrap Loader v{}", env!("CARGO_PKG_VERSION"));
    println!("[LOADER] This binary is measured by IMA with a stable hash");

    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("scaphandre")))
        .unwrap_or_default();
    let exe_dir_str = exe_dir.to_str().unwrap_or("");

    let possible_paths = [
        "/usr/bin/scaphandre-main",
        "/usr/local/bin/scaphandre-main",
        "./target/release/scaphandre",
        "../target/release/scaphandre",
        exe_dir_str,
    ];

    let scaphandre_main = possible_paths
        .iter()
        .find(|path| !path.is_empty() && Path::new(path).exists())
        .unwrap_or_else(|| {
            eprintln!("[LOADER] Error: scaphandre-main binary not found!");
            eprintln!("[LOADER] Searched locations:");
            for path in &possible_paths {
                if !path.is_empty() {
                    eprintln!("[LOADER] - {}", path);
                }
            }
            eprintln!();
            eprintln!("[LOADER] Please install scaphandre-main to /usr/bin/scaphandre-main");
            eprintln!("[LOADER] or run from the build directory");
            std::process::exit(1);
        });

    println!("[LOADER] Found scaphandre-main: {}", scaphandre_main);
    println!("[LOADER] Launching with args: {:?}", args.args);
    println!();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(scaphandre_main)
            .args(&args.args)
            .exec();

        eprintln!("[LOADER] Failed to execute scaphandre-main: {}", err);
        std::process::exit(1);
    }

    #[cfg(not(unix))]
    {

        let status = Command::new(scaphandre_main)
            .args(&args.args)
            .status()
            .unwrap_or_else(|e| {
                eprintln!("[LOADER] Failed to execute scaphandre-main: {}", e);
                std::process::exit(1);
            });

        std::process::exit(status.code().unwrap_or(1));
    }
}
