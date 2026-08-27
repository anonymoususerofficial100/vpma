use std::slice;

unsafe fn emit(src: &[u8], out: *mut u8, out_cap: usize) -> isize {
    if out.is_null() || src.len() > out_cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(src.as_ptr(), out, src.len());
    src.len() as isize
}

#[no_mangle]
pub unsafe extern "C" fn vpma_encode_record(
    pid: u32,
    cpu_bits: u64,
    energy_bits: u64,
    power_bits: u64,
    vm_name: *const u8,
    vm_name_len: usize,
    timestamp: *const u8,
    timestamp_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    if vm_name.is_null() || timestamp.is_null() {
        return -1;
    }
    let vm = slice::from_raw_parts(vm_name, vm_name_len);
    let ts = slice::from_raw_parts(timestamp, timestamp_len);
    let v = vpma_verified::encode_record_fields(pid, cpu_bits, energy_bits, power_bits, vm, ts);
    emit(&v, out, out_cap)
}

#[no_mangle]
pub unsafe extern "C" fn vpma_encode_leaf(
    record: *const u8,
    record_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    if record.is_null() {
        return -1;
    }
    let v = vpma_verified::encode_leaf(slice::from_raw_parts(record, record_len));
    emit(&v, out, out_cap)
}

#[no_mangle]
pub unsafe extern "C" fn vpma_encode_internal(
    left: *const u8,
    right: *const u8,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    if left.is_null() || right.is_null() {
        return -1;
    }
    let v = vpma_verified::encode_internal(
        slice::from_raw_parts(left, 32),
        slice::from_raw_parts(right, 32),
    );
    emit(&v, out, out_cap)
}

#[no_mangle]
pub unsafe extern "C" fn vpma_encode_root(
    leaf_count: u64,
    subtree: *const u8,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    if subtree.is_null() {
        return -1;
    }
    let v = vpma_verified::encode_root(leaf_count, slice::from_raw_parts(subtree, 32));
    emit(&v, out, out_cap)
}

#[no_mangle]
pub unsafe extern "C" fn vpma_encode_chained_root(
    prev: *const u8,
    merkle: *const u8,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    if prev.is_null() || merkle.is_null() {
        return -1;
    }
    let v = vpma_verified::encode_chained_root(
        slice::from_raw_parts(prev, 32),
        slice::from_raw_parts(merkle, 32),
    );
    emit(&v, out, out_cap)
}

#[no_mangle]
pub extern "C" fn vpma_domain_leaf() -> u8 { vpma_verified::DOMAIN_LEAF }
#[no_mangle]
pub extern "C" fn vpma_domain_internal() -> u8 { vpma_verified::DOMAIN_INTERNAL }
#[no_mangle]
pub extern "C" fn vpma_domain_root() -> u8 { vpma_verified::DOMAIN_ROOT }
#[no_mangle]
pub extern "C" fn vpma_domain_chain() -> u8 { vpma_verified::DOMAIN_CHAIN }
#[no_mangle]
pub extern "C" fn vpma_record_format_version() -> u8 { vpma_verified::RECORD_FORMAT_V2 }

#[no_mangle]
pub unsafe extern "C" fn vpma_merkle_root(
    leaves: *const u8,
    n: usize,
    out: *mut u8,
) -> isize {
    if leaves.is_null() || out.is_null() {
        return -1;
    }
    let flat = slice::from_raw_parts(leaves, n.saturating_mul(32));
    let mut v: Vec<[u8; 32]> = Vec::with_capacity(n);
    for i in 0..n {
        let mut a = [0u8; 32];
        a.copy_from_slice(&flat[i * 32..(i + 1) * 32]);
        v.push(a);
    }
    match sgx_vm::merkle::compute_root_from_leaves(&v) {
        Some(root) => emit(&root, out, 32),
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn vpma_sha256(data: *const u8, len: usize, out: *mut u8) -> isize {
    if data.is_null() || out.is_null() {
        return -1;
    }
    let d = sgx_vm::merkle::sha256(slice::from_raw_parts(data, len));
    emit(&d, out, 32)
}
