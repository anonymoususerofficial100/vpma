use std::env;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();

    if target.contains("fortanix") || target.contains("sgx") {

        cc::Build::new()
            .file("src/vsnprintf_shim.c")
            .flag("-fno-stack-protector")
            .flag("-fPIC")
            .compile("vsnprintf_shim");

        println!("cargo:rerun-if-changed=src/vsnprintf_shim.c");
    }
}
