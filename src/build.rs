fn main() {

    println!("cargo:rustc-link-search=native=sgx/target/x86_64-fortanix-unknown-sgx/release");
    println!("cargo:rustc-link-lib=static=sgx");

    println!("cargo:rustc-link-lib=dylib=unwind");
}
