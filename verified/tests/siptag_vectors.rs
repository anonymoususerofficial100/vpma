use std::fs;

fn parse(line: &str) -> Option<([u64; 9], u64)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') { return None; }
    let (lhs, rhs) = line.split_once("=>")?;
    let f: Vec<u64> = lhs.split_whitespace().map(|t| t.parse().unwrap()).collect();
    assert_eq!(f.len(), 9, "malformed row: {line}");
    Some(([f[0],f[1],f[2],f[3],f[4],f[5],f[6],f[7],f[8]], rhs.trim().parse().unwrap()))
}

#[test]
fn rust_matches_the_siptag_golden_table() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/siptag_vectors.txt");
    let text = fs::read_to_string(path).expect("siptag_vectors.txt missing");
    let mut n = 0;
    for line in text.lines() {
        let Some((f, want)) = parse(line) else { continue };
        let got = vpma_verified::siptag(
            f[0], f[1], f[2], f[3], f[4] as u32, f[5] as u32,
            f[6] as u16, f[7] as u16, f[8] as u32,
        );
        assert_eq!(got, want, "\n  siptag{f:?}\n  got  {got}\n  want {want}");
        n += 1;
    }
    assert!(n >= 5, "expected at least 5 vectors, parsed {n}");
    eprintln!("{n} siptag vectors matched");
}

#[test]
fn row_one_is_official_siphash_vector_32() {

    let got = vpma_verified::siptag(
        0x0706050403020100, 0x0f0e0d0c0b0a0908,
        0x0706050403020100, 0x0f0e0d0c0b0a0908,
        0x13121110, 0x17161514, 0x1918, 0x1b1a, 0x1f1e1d1c,
    );
    assert_eq!(got, 0x7127512f72f27cce, "packing or primitive drifted");
}

#[test]
fn the_key_actually_matters() {
    let a = vpma_verified::siptag(1, 2, 1000, 2000, 0, 0, 1, 2, 1);
    let b = vpma_verified::siptag(1, 3, 1000, 2000, 0, 0, 1, 2, 1);
    let c = vpma_verified::siptag(0, 2, 1000, 2000, 0, 0, 1, 2, 1);
    assert_ne!(a, b, "k1 not mixed in");
    assert_ne!(a, c, "k0 not mixed in");
}

#[test]
fn producer_classes_are_separated() {
    let seeded = vpma_verified::siptag(9, 9, 1000, 2000, 3, 0, 1,
        vpma_verified::SIPTAG_PRODUCER_RAPL_SEEDED, 1);
    let kernel = vpma_verified::siptag(9, 9, 1000, 2000, 3, 0, 1,
        vpma_verified::SIPTAG_PRODUCER_RAPL_KERNEL, 1);
    let gpu = vpma_verified::siptag(9, 9, 1000, 2000, 3, 0, 1,
        vpma_verified::SIPTAG_PRODUCER_GPU_NVML, 1);
    assert_ne!(seeded, kernel, "the two RAPL producers collide");
    assert_ne!(seeded, gpu, "RAPL and GPU collide");
    assert_ne!(kernel, gpu, "RAPL-kernel and GPU collide");
}
