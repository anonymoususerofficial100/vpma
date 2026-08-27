use std::io::{self, Write};

fn main() {

    let _ = io::stdout().write_all(b"TEST_OUTPUT_STDOUT\n");
    let _ = io::stdout().flush();

    let _ = io::stderr().write_all(b"TEST_OUTPUT_STDERR\n");
    let _ = io::stderr().flush();

    println!("PRINTLN_TEST");
    eprintln!("EPRINTLN_TEST");
}
