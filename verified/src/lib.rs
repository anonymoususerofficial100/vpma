#![no_std]
#![allow(unused_imports)]

extern crate alloc;

use alloc::vec::Vec;
use vstd::prelude::*;
use vstd::slice::slice_subrange;

use vstd::seq_lib::{assert_seqs_equal, assert_seqs_equal_internal};

verus! {

pub const DOMAIN_LEAF: u8 = 0x00;
pub const DOMAIN_INTERNAL: u8 = 0x01;
pub const DOMAIN_ROOT: u8 = 0x02;
pub const DOMAIN_CHAIN: u8 = 0x03;

pub const RECORD_FORMAT_V2: u8 = 0x02;

pub const MAX_TENANT_LABEL: usize = 64;

pub open spec fn spec_u32_le(v: u32) -> Seq<u8> {
    seq![
        (v & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        ((v >> 16) & 0xff) as u8,
        ((v >> 24) & 0xff) as u8,
    ]
}

pub open spec fn spec_u64_le(v: u64) -> Seq<u8> {
    seq![
        (v & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        ((v >> 16) & 0xff) as u8,
        ((v >> 24) & 0xff) as u8,
        ((v >> 32) & 0xff) as u8,
        ((v >> 40) & 0xff) as u8,
        ((v >> 48) & 0xff) as u8,
        ((v >> 56) & 0xff) as u8,
    ]
}

pub proof fn lemma_u32_le_injective(a: u32, b: u32)
    requires spec_u32_le(a) == spec_u32_le(b)
    ensures a == b
{
    assert(spec_u32_le(a)[0] == spec_u32_le(b)[0]);
    assert(spec_u32_le(a)[1] == spec_u32_le(b)[1]);
    assert(spec_u32_le(a)[2] == spec_u32_le(b)[2]);
    assert(spec_u32_le(a)[3] == spec_u32_le(b)[3]);
    assert(
        (a & 0xff) as u8 == (b & 0xff) as u8
        && ((a >> 8) & 0xff) as u8 == ((b >> 8) & 0xff) as u8
        && ((a >> 16) & 0xff) as u8 == ((b >> 16) & 0xff) as u8
        && ((a >> 24) & 0xff) as u8 == ((b >> 24) & 0xff) as u8
        ==> a == b
    ) by (bit_vector);
}

pub proof fn lemma_u64_le_injective(a: u64, b: u64)
    requires spec_u64_le(a) == spec_u64_le(b)
    ensures a == b
{
    assert(spec_u64_le(a)[0] == spec_u64_le(b)[0]);
    assert(spec_u64_le(a)[1] == spec_u64_le(b)[1]);
    assert(spec_u64_le(a)[2] == spec_u64_le(b)[2]);
    assert(spec_u64_le(a)[3] == spec_u64_le(b)[3]);
    assert(spec_u64_le(a)[4] == spec_u64_le(b)[4]);
    assert(spec_u64_le(a)[5] == spec_u64_le(b)[5]);
    assert(spec_u64_le(a)[6] == spec_u64_le(b)[6]);
    assert(spec_u64_le(a)[7] == spec_u64_le(b)[7]);
    assert(
        (a & 0xff) as u8 == (b & 0xff) as u8
        && ((a >> 8) & 0xff) as u8 == ((b >> 8) & 0xff) as u8
        && ((a >> 16) & 0xff) as u8 == ((b >> 16) & 0xff) as u8
        && ((a >> 24) & 0xff) as u8 == ((b >> 24) & 0xff) as u8
        && ((a >> 32) & 0xff) as u8 == ((b >> 32) & 0xff) as u8
        && ((a >> 40) & 0xff) as u8 == ((b >> 40) & 0xff) as u8
        && ((a >> 48) & 0xff) as u8 == ((b >> 48) & 0xff) as u8
        && ((a >> 56) & 0xff) as u8 == ((b >> 56) & 0xff) as u8
        ==> a == b
    ) by (bit_vector);
}

pub proof fn lemma_concat_split(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>, d: Seq<u8>)
    requires
        a + b == c + d,
        a.len() == c.len(),
    ensures
        a == c,
        b == d,
{

    let ab = a + b;
    let cd = c + d;
    assert(ab.len() == a.len() + b.len());
    assert(cd.len() == c.len() + d.len());
    assert(b.len() == d.len());

    assert_seqs_equal!(a == c, i => {
        assert(ab[i] == a[i]);
        assert(cd[i] == c[i]);
    });
    assert_seqs_equal!(b == d, i => {
        assert(ab[a.len() + i] == b[i]);
        assert(cd[c.len() + i] == d[i]);
    });
}

pub fn push_u32_le(out: &mut Vec<u8>, v: u32)
    ensures final(out)@ == old(out)@ + spec_u32_le(v)
{

    let ghost before = out@;
    out.push((v & 0xff) as u8);
    out.push(((v >> 8) & 0xff) as u8);
    out.push(((v >> 16) & 0xff) as u8);
    out.push(((v >> 24) & 0xff) as u8);
    proof { assert_seqs_equal!(out@ == before + spec_u32_le(v)); }
}

pub fn push_u64_le(out: &mut Vec<u8>, v: u64)
    ensures final(out)@ == old(out)@ + spec_u64_le(v)
{
    let ghost before = out@;
    out.push((v & 0xff) as u8);
    out.push(((v >> 8) & 0xff) as u8);
    out.push(((v >> 16) & 0xff) as u8);
    out.push(((v >> 24) & 0xff) as u8);
    out.push(((v >> 32) & 0xff) as u8);
    out.push(((v >> 40) & 0xff) as u8);
    out.push(((v >> 48) & 0xff) as u8);
    out.push(((v >> 56) & 0xff) as u8);
    proof { assert_seqs_equal!(out@ == before + spec_u64_le(v)); }
}

pub fn push_len_prefixed(out: &mut Vec<u8>, field: &[u8])
    requires field@.len() < 0x1_0000_0000
    ensures final(out)@ == old(out)@ + spec_u32_le(field@.len() as u32) + field@
{
    push_u32_le(out, field.len() as u32);
    let ghost after_len = out@;
    let mut i: usize = 0;
    while i < field.len()
        invariant
            0 <= i <= field@.len(),
            out@ == after_len + field@.subrange(0, i as int),
        decreases field@.len() - i
    {
        out.push(field[i]);
        assert(field@.subrange(0, i + 1) =~= field@.subrange(0, i as int).push(field@[i as int]));
        i = i + 1;
    }
    assert(field@.subrange(0, field@.len() as int) =~= field@);
}

pub open spec fn spec_safe_label_byte(b: u8) -> bool {
    ||| (b >= 0x30 && b <= 0x39)
    ||| (b >= 0x41 && b <= 0x5A)
    ||| (b >= 0x61 && b <= 0x7A)
    ||| b == 0x2E
    ||| b == 0x5F
    ||| b == 0x2D
}

pub open spec fn spec_valid_tenant_label(s: Seq<u8>) -> bool {
    &&& s.len() > 0
    &&& s.len() <= MAX_TENANT_LABEL
    &&& forall|i: int| 0 <= i < s.len() ==> spec_safe_label_byte(#[trigger] s[i])
}

pub fn is_safe_label_byte(b: u8) -> (r: bool)
    ensures r == spec_safe_label_byte(b)
{
    (b >= 0x30 && b <= 0x39)
        || (b >= 0x41 && b <= 0x5A)
        || (b >= 0x61 && b <= 0x7A)
        || b == 0x2E
        || b == 0x5F
        || b == 0x2D
}

pub fn is_valid_tenant_label(s: &[u8]) -> (r: bool)
    ensures r == spec_valid_tenant_label(s@)
{
    if s.len() == 0 || s.len() > MAX_TENANT_LABEL {
        return false;
    }
    let mut i: usize = 0;
    while i < s.len()
        invariant
            0 <= i <= s@.len(),
            forall|j: int| 0 <= j < i ==> spec_safe_label_byte(#[trigger] s@[j]),
        decreases s@.len() - i
    {
        if !is_safe_label_byte(s[i]) {
            assert(!spec_safe_label_byte(s@[i as int]));
            return false;
        }
        i = i + 1;
    }
    true
}

pub proof fn theorem_valid_label_is_safe(s: Seq<u8>)
    requires spec_valid_tenant_label(s)
    ensures forall|i: int| 0 <= i < s.len() ==>
        s[i] != 0x7C
        && s[i] != 0x3A
        && s[i] != 0x40
        && s[i] != 0x0A
{
    assert forall|i: int| 0 <= i < s.len() implies
        s[i] != 0x7C && s[i] != 0x3A && s[i] != 0x40 && s[i] != 0x0A
    by {
        assert(spec_safe_label_byte(s[i]));
    }
}

pub open spec fn spec_encode_record(
    pid: u32, cpu_bits: u64, energy_bits: u64, power_bits: u64,
    vm_name: Seq<u8>, timestamp: Seq<u8>,
) -> Seq<u8> {
    seq![RECORD_FORMAT_V2]
        + spec_u32_le(pid)
        + spec_u64_le(cpu_bits)
        + spec_u64_le(energy_bits)
        + spec_u64_le(power_bits)
        + spec_u32_le(vm_name.len() as u32) + vm_name
        + spec_u32_le(timestamp.len() as u32) + timestamp
}

pub fn encode_record_fields(
    pid: u32,
    cpu_bits: u64,
    energy_bits: u64,
    power_bits: u64,
    vm_name: &[u8],
    timestamp: &[u8],
) -> (out: Vec<u8>)
    requires
        vm_name@.len() < 0x1_0000_0000,
        timestamp@.len() < 0x1_0000_0000,
    ensures
        out@ == spec_encode_record(pid, cpu_bits, energy_bits, power_bits, vm_name@, timestamp@),
{
    let mut out: Vec<u8> = Vec::new();
    out.push(RECORD_FORMAT_V2);
    push_u32_le(&mut out, pid);
    push_u64_le(&mut out, cpu_bits);
    push_u64_le(&mut out, energy_bits);
    push_u64_le(&mut out, power_bits);
    push_len_prefixed(&mut out, vm_name);
    push_len_prefixed(&mut out, timestamp);
    proof {
        assert_seqs_equal!(out@ ==
            spec_encode_record(pid, cpu_bits, energy_bits, power_bits, vm_name@, timestamp@));
    }
    out
}

pub proof fn lemma_len_prefixed_split(x: Seq<u8>, xs: Seq<u8>, y: Seq<u8>, ys: Seq<u8>)
    requires
        x.len() < 0x1_0000_0000,
        y.len() < 0x1_0000_0000,
        spec_u32_le(x.len() as u32) + x + xs == spec_u32_le(y.len() as u32) + y + ys,
    ensures
        x == y,
        xs == ys,
{

    assert(spec_u32_le(x.len() as u32) + x + xs
        =~= spec_u32_le(x.len() as u32) + (x + xs));
    assert(spec_u32_le(y.len() as u32) + y + ys
        =~= spec_u32_le(y.len() as u32) + (y + ys));

    lemma_concat_split(
        spec_u32_le(x.len() as u32), x + xs,
        spec_u32_le(y.len() as u32), y + ys,
    );
    lemma_u32_le_injective(x.len() as u32, y.len() as u32);
    lemma_concat_split(x, xs, y, ys);
}

pub proof fn theorem_record_encoding_injective(
    pid1: u32, c1: u64, e1: u64, p1: u64, vm1: Seq<u8>, ts1: Seq<u8>,
    pid2: u32, c2: u64, e2: u64, p2: u64, vm2: Seq<u8>, ts2: Seq<u8>,
)
    requires
        vm1.len() < 0x1_0000_0000, ts1.len() < 0x1_0000_0000,
        vm2.len() < 0x1_0000_0000, ts2.len() < 0x1_0000_0000,
        spec_encode_record(pid1, c1, e1, p1, vm1, ts1)
            == spec_encode_record(pid2, c2, e2, p2, vm2, ts2),
    ensures
        pid1 == pid2, c1 == c2, e1 == e2, p1 == p2, vm1 == vm2, ts1 == ts2,
{
    let tail1 = spec_u32_le(pid1) + spec_u64_le(c1) + spec_u64_le(e1) + spec_u64_le(p1)
        + spec_u32_le(vm1.len() as u32) + vm1 + spec_u32_le(ts1.len() as u32) + ts1;
    let tail2 = spec_u32_le(pid2) + spec_u64_le(c2) + spec_u64_le(e2) + spec_u64_le(p2)
        + spec_u32_le(vm2.len() as u32) + vm2 + spec_u32_le(ts2.len() as u32) + ts2;

    assert(spec_encode_record(pid1, c1, e1, p1, vm1, ts1)
        =~= seq![RECORD_FORMAT_V2] + tail1);
    assert(spec_encode_record(pid2, c2, e2, p2, vm2, ts2)
        =~= seq![RECORD_FORMAT_V2] + tail2);
    lemma_concat_split(seq![RECORD_FORMAT_V2], tail1, seq![RECORD_FORMAT_V2], tail2);

    let r1 = spec_u64_le(c1) + spec_u64_le(e1) + spec_u64_le(p1)
        + spec_u32_le(vm1.len() as u32) + vm1 + spec_u32_le(ts1.len() as u32) + ts1;
    let r2 = spec_u64_le(c2) + spec_u64_le(e2) + spec_u64_le(p2)
        + spec_u32_le(vm2.len() as u32) + vm2 + spec_u32_le(ts2.len() as u32) + ts2;
    assert(tail1 =~= spec_u32_le(pid1) + r1);
    assert(tail2 =~= spec_u32_le(pid2) + r2);
    lemma_concat_split(spec_u32_le(pid1), r1, spec_u32_le(pid2), r2);
    lemma_u32_le_injective(pid1, pid2);

    let r3 = spec_u64_le(e1) + spec_u64_le(p1)
        + spec_u32_le(vm1.len() as u32) + vm1 + spec_u32_le(ts1.len() as u32) + ts1;
    let r4 = spec_u64_le(e2) + spec_u64_le(p2)
        + spec_u32_le(vm2.len() as u32) + vm2 + spec_u32_le(ts2.len() as u32) + ts2;
    assert(r1 =~= spec_u64_le(c1) + r3);
    assert(r2 =~= spec_u64_le(c2) + r4);
    lemma_concat_split(spec_u64_le(c1), r3, spec_u64_le(c2), r4);
    lemma_u64_le_injective(c1, c2);

    let r5 = spec_u64_le(p1) + spec_u32_le(vm1.len() as u32) + vm1
        + spec_u32_le(ts1.len() as u32) + ts1;
    let r6 = spec_u64_le(p2) + spec_u32_le(vm2.len() as u32) + vm2
        + spec_u32_le(ts2.len() as u32) + ts2;
    assert(r3 =~= spec_u64_le(e1) + r5);
    assert(r4 =~= spec_u64_le(e2) + r6);
    lemma_concat_split(spec_u64_le(e1), r5, spec_u64_le(e2), r6);
    lemma_u64_le_injective(e1, e2);

    let r7 = spec_u32_le(vm1.len() as u32) + vm1 + spec_u32_le(ts1.len() as u32) + ts1;
    let r8 = spec_u32_le(vm2.len() as u32) + vm2 + spec_u32_le(ts2.len() as u32) + ts2;
    assert(r5 =~= spec_u64_le(p1) + r7);
    assert(r6 =~= spec_u64_le(p2) + r8);
    lemma_concat_split(spec_u64_le(p1), r7, spec_u64_le(p2), r8);
    lemma_u64_le_injective(p1, p2);

    assert(r7 =~= spec_u32_le(vm1.len() as u32) + vm1
        + (spec_u32_le(ts1.len() as u32) + ts1));
    assert(r8 =~= spec_u32_le(vm2.len() as u32) + vm2
        + (spec_u32_le(ts2.len() as u32) + ts2));
    lemma_len_prefixed_split(
        vm1, spec_u32_le(ts1.len() as u32) + ts1,
        vm2, spec_u32_le(ts2.len() as u32) + ts2,
    );
    assert(spec_u32_le(ts1.len() as u32) + ts1
        =~= spec_u32_le(ts1.len() as u32) + ts1 + Seq::<u8>::empty());
    assert(spec_u32_le(ts2.len() as u32) + ts2
        =~= spec_u32_le(ts2.len() as u32) + ts2 + Seq::<u8>::empty());
    lemma_len_prefixed_split(ts1, Seq::empty(), ts2, Seq::empty());
}

pub open spec fn spec_encode_leaf(record_bytes: Seq<u8>) -> Seq<u8> {
    seq![DOMAIN_LEAF] + record_bytes
}

pub open spec fn spec_encode_internal(left: Seq<u8>, right: Seq<u8>) -> Seq<u8> {
    seq![DOMAIN_INTERNAL] + left + right
}

pub open spec fn spec_encode_root(leaf_count: u64, subtree_root: Seq<u8>) -> Seq<u8> {
    seq![DOMAIN_ROOT] + spec_u64_le(leaf_count) + subtree_root
}

pub open spec fn spec_encode_chained_root(prev: Seq<u8>, merkle: Seq<u8>) -> Seq<u8> {
    seq![DOMAIN_CHAIN] + prev + merkle
}

pub fn encode_leaf(record_bytes: &[u8]) -> (out: Vec<u8>)
    ensures out@ == spec_encode_leaf(record_bytes@)
{
    let mut out: Vec<u8> = Vec::new();
    out.push(DOMAIN_LEAF);
    let mut i: usize = 0;
    while i < record_bytes.len()
        invariant
            0 <= i <= record_bytes@.len(),
            out@ == seq![DOMAIN_LEAF] + record_bytes@.subrange(0, i as int),
        decreases record_bytes@.len() - i
    {
        out.push(record_bytes[i]);
        i = i + 1;
    }
    assert(record_bytes@.subrange(0, record_bytes@.len() as int) =~= record_bytes@);
    out
}

pub fn encode_internal(left: &[u8], right: &[u8]) -> (out: Vec<u8>)
    ensures out@ == spec_encode_internal(left@, right@)
{
    let mut out: Vec<u8> = Vec::new();
    out.push(DOMAIN_INTERNAL);
    let mut i: usize = 0;
    while i < left.len()
        invariant
            0 <= i <= left@.len(),
            out@ == seq![DOMAIN_INTERNAL] + left@.subrange(0, i as int),
        decreases left@.len() - i
    {
        out.push(left[i]);
        i = i + 1;
    }
    assert(left@.subrange(0, left@.len() as int) =~= left@);
    let ghost after_left = out@;
    let mut j: usize = 0;
    while j < right.len()
        invariant
            0 <= j <= right@.len(),
            out@ == after_left + right@.subrange(0, j as int),
        decreases right@.len() - j
    {
        out.push(right[j]);
        j = j + 1;
    }
    assert(right@.subrange(0, right@.len() as int) =~= right@);
    proof { assert_seqs_equal!(out@ == spec_encode_internal(left@, right@)); }
    out
}

pub fn encode_root(leaf_count: u64, subtree_root: &[u8]) -> (out: Vec<u8>)
    ensures out@ == spec_encode_root(leaf_count, subtree_root@)
{
    let mut out: Vec<u8> = Vec::new();
    out.push(DOMAIN_ROOT);
    push_u64_le(&mut out, leaf_count);
    let ghost prefix = out@;
    let mut i: usize = 0;
    while i < subtree_root.len()
        invariant
            0 <= i <= subtree_root@.len(),
            out@ == prefix + subtree_root@.subrange(0, i as int),
        decreases subtree_root@.len() - i
    {
        out.push(subtree_root[i]);
        i = i + 1;
    }
    assert(subtree_root@.subrange(0, subtree_root@.len() as int) =~= subtree_root@);
    proof { assert_seqs_equal!(out@ == spec_encode_root(leaf_count, subtree_root@)); }
    out
}

pub fn encode_chained_root(prev: &[u8], merkle: &[u8]) -> (out: Vec<u8>)
    ensures out@ == spec_encode_chained_root(prev@, merkle@)
{
    let mut out: Vec<u8> = Vec::new();
    out.push(DOMAIN_CHAIN);
    let mut i: usize = 0;
    while i < prev.len()
        invariant
            0 <= i <= prev@.len(),
            out@ == seq![DOMAIN_CHAIN] + prev@.subrange(0, i as int),
        decreases prev@.len() - i
    {
        out.push(prev[i]);
        i = i + 1;
    }
    assert(prev@.subrange(0, prev@.len() as int) =~= prev@);
    let ghost after_prev = out@;
    let mut j: usize = 0;
    while j < merkle.len()
        invariant
            0 <= j <= merkle@.len(),
            out@ == after_prev + merkle@.subrange(0, j as int),
        decreases merkle@.len() - j
    {
        out.push(merkle[j]);
        j = j + 1;
    }
    assert(merkle@.subrange(0, merkle@.len() as int) =~= merkle@);
    proof { assert_seqs_equal!(out@ == spec_encode_chained_root(prev@, merkle@)); }
    out
}

pub proof fn theorem_domains_pairwise_disjoint(
    rec: Seq<u8>, l: Seq<u8>, r: Seq<u8>, n: u64, sub: Seq<u8>, p: Seq<u8>, m: Seq<u8>,
)
    ensures
        spec_encode_leaf(rec) != spec_encode_internal(l, r),
        spec_encode_leaf(rec) != spec_encode_root(n, sub),
        spec_encode_leaf(rec) != spec_encode_chained_root(p, m),
        spec_encode_internal(l, r) != spec_encode_root(n, sub),
        spec_encode_internal(l, r) != spec_encode_chained_root(p, m),
        spec_encode_root(n, sub) != spec_encode_chained_root(p, m),
{
    assert(spec_encode_leaf(rec)[0] == DOMAIN_LEAF);
    assert(spec_encode_internal(l, r)[0] == DOMAIN_INTERNAL);
    assert(spec_encode_root(n, sub)[0] == DOMAIN_ROOT);
    assert(spec_encode_chained_root(p, m)[0] == DOMAIN_CHAIN);
}

pub proof fn theorem_root_binds_leaf_count(n1: u64, n2: u64, sub: Seq<u8>)
    requires n1 != n2
    ensures spec_encode_root(n1, sub) != spec_encode_root(n2, sub)
{
    if spec_encode_root(n1, sub) == spec_encode_root(n2, sub) {
        assert(spec_encode_root(n1, sub) =~= seq![DOMAIN_ROOT] + (spec_u64_le(n1) + sub));
        assert(spec_encode_root(n2, sub) =~= seq![DOMAIN_ROOT] + (spec_u64_le(n2) + sub));
        lemma_concat_split(
            seq![DOMAIN_ROOT], spec_u64_le(n1) + sub,
            seq![DOMAIN_ROOT], spec_u64_le(n2) + sub,
        );
        lemma_concat_split(spec_u64_le(n1), sub, spec_u64_le(n2), sub);
        lemma_u64_le_injective(n1, n2);
        assert(false);
    }
}

pub open spec fn spec_encode_checkpoint_msg(
    tenant: Seq<u8>, block_number: u64, chained_root: Seq<u8>,
) -> Seq<u8> {
    seq![0x63u8, 0x68, 0x65, 0x63, 0x6B, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2D, 0x76, 0x31, 0x7C]
        + tenant + seq![0x7Cu8] + spec_u64_le(block_number) + chained_root
}

pub fn encode_checkpoint_msg(
    tenant: &[u8],
    block_number: u64,
    chained_root: &[u8],
) -> (out: Vec<u8>)
    ensures out@ == spec_encode_checkpoint_msg(tenant@, block_number, chained_root@)
{
    let mut out: Vec<u8> = Vec::new();

    out.push(0x63); out.push(0x68); out.push(0x65); out.push(0x63);
    out.push(0x6B); out.push(0x70); out.push(0x6F); out.push(0x69);
    out.push(0x6E); out.push(0x74); out.push(0x2D); out.push(0x76);
    out.push(0x31); out.push(0x7C);

    let ghost after_tag = out@;
    let mut i: usize = 0;
    while i < tenant.len()
        invariant
            0 <= i <= tenant@.len(),
            out@ == after_tag + tenant@.subrange(0, i as int),
        decreases tenant@.len() - i
    {
        out.push(tenant[i]);
        i = i + 1;
    }
    assert(tenant@.subrange(0, tenant@.len() as int) =~= tenant@);

    out.push(0x7C);
    push_u64_le(&mut out, block_number);

    let ghost before_root = out@;
    let mut j: usize = 0;
    while j < chained_root.len()
        invariant
            0 <= j <= chained_root@.len(),
            out@ == before_root + chained_root@.subrange(0, j as int),
        decreases chained_root@.len() - j
    {
        out.push(chained_root[j]);
        j = j + 1;
    }
    assert(chained_root@.subrange(0, chained_root@.len() as int) =~= chained_root@);
    proof { assert_seqs_equal!(out@ == spec_encode_checkpoint_msg(tenant@, block_number, chained_root@)); }
    out
}

pub open spec fn spec_ascii_lower(b: u8) -> u8 {
    if b >= 0x41 && b <= 0x5A { (b + 32) as u8 } else { b }
}

pub fn ascii_lower(b: u8) -> (r: u8)
    ensures r == spec_ascii_lower(b)
{
    if b >= 0x41 && b <= 0x5A { b + 32 } else { b }
}

pub fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> (r: bool)
    ensures r == (a@.len() == b@.len()
        && forall|i: int| 0 <= i < a@.len()
            ==> spec_ascii_lower(#[trigger] a@[i]) == spec_ascii_lower(b@[i]))
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            0 <= i <= a@.len(),
            a@.len() == b@.len(),
            forall|j: int| 0 <= j < i
                ==> spec_ascii_lower(#[trigger] a@[j]) == spec_ascii_lower(b@[j]),
        decreases a@.len() - i
    {
        if ascii_lower(a[i]) != ascii_lower(b[i]) {
            return false;
        }
        i = i + 1;
    }
    true
}

pub open spec fn spec_hex_eq(a: Seq<u8>, b: Seq<u8>) -> bool {
    &&& a.len() == b.len()
    &&& forall|i: int| 0 <= i < a.len()
            ==> spec_ascii_lower(#[trigger] a[i]) == spec_ascii_lower(b[i])
}

pub open spec fn spec_hex_val(c: u8) -> Option<u8> {
    if c >= 0x30 && c <= 0x39 { Some((c - 0x30) as u8) }
    else if c >= 0x61 && c <= 0x66 { Some((c - 0x61 + 10) as u8) }
    else if c >= 0x41 && c <= 0x46 { Some((c - 0x41 + 10) as u8) }
    else { None }
}

pub fn hex_val(c: u8) -> (r: Option<u8>)
    ensures
        r == spec_hex_val(c),

        r is Some ==> r->Some_0 < 16,
{
    if c >= 0x30 && c <= 0x39 { Some(c - 0x30) }
    else if c >= 0x61 && c <= 0x66 { Some(c - 0x61 + 10) }
    else if c >= 0x41 && c <= 0x46 { Some(c - 0x41 + 10) }
    else { None }
}

pub open spec fn spec_all_hex(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> #[trigger] spec_hex_val(s[i]) is Some
}

pub fn hex_decode_32(s: &[u8]) -> (r: Option<[u8; 32]>)
    ensures r is Some <==> (s@.len() == 64 && spec_all_hex(s@))
{
    if s.len() != 64 {
        return None;
    }
    let mut out: [u8; 32] = [0u8; 32];
    let mut i: usize = 0;
    while i < 32
        invariant
            0 <= i <= 32,
            s@.len() == 64,
            forall|j: int| 0 <= j < 2 * i ==> #[trigger] spec_hex_val(s@[j]) is Some,
        decreases 32 - i
    {
        let hi = hex_val(s[2 * i]);
        let lo = hex_val(s[2 * i + 1]);
        match (hi, lo) {
            (Some(h), Some(l)) => {
                assert(h < 16 && l < 16);
                out[i] = h * 16 + l;
            }
            _ => {
                return None;
            }
        }
        i = i + 1;
    }
    Some(out)
}

pub fn parse_u64_dec(s: &[u8]) -> (r: Option<u64>)
    ensures r is Some ==> s@.len() > 0
{
    if s.len() == 0 || s.len() > 20 {
        return None;
    }
    let mut acc: u64 = 0;
    let mut i: usize = 0;
    while i < s.len()
        invariant
            0 <= i <= s@.len(),
        decreases s@.len() - i
    {
        let c = s[i];
        if c < 0x30 || c > 0x39 {
            return None;
        }
        let d: u64 = (c - 0x30) as u64;

        if acc > (0xFFFF_FFFF_FFFF_FFFFu64 - d) / 10 {
            return None;
        }
        acc = acc * 10 + d;
        i = i + 1;
    }
    Some(acc)
}

pub struct BootAdmitted { _seal: u8 }

pub struct ChainAdmitted { _seal: u8 }

pub struct TagAdmitted { _seal: u8 }

#[derive(PartialEq, Eq, Structural, Clone, Copy)]
pub enum BootDenial {
    NoBinaryHashInLog,
    Pcr10Zero,
    ImaLogNotReconciled,
    ExpectedStateUnavailable,
    BinaryHashMismatch,
    Pcr0Mismatch,
    Pcr7Mismatch,
}

pub open spec fn spec_boot_admissible(
    pcr0: Seq<u8>, pcr7: Seq<u8>, bin: Seq<u8>,
    exp_pcr0: Seq<u8>, exp_pcr7: Seq<u8>, exp_bin: Seq<u8>,
    pcr10_nonzero: bool, ima_log_reconciled: bool, have_expected: bool,
) -> bool {
    &&& bin.len() > 0
    &&& pcr10_nonzero
    &&& ima_log_reconciled
    &&& have_expected
    &&& spec_hex_eq(bin, exp_bin)
    &&& (exp_pcr0.len() == 0 || spec_hex_eq(pcr0, exp_pcr0))
    &&& (exp_pcr7.len() == 0 || spec_hex_eq(pcr7, exp_pcr7))
}

pub fn admit_boot(
    pcr0: &[u8], pcr7: &[u8], bin: &[u8],
    exp_pcr0: &[u8], exp_pcr7: &[u8], exp_bin: &[u8],
    pcr10_nonzero: bool, ima_log_reconciled: bool, have_expected: bool,
) -> (r: Result<BootAdmitted, BootDenial>)
    ensures
        r is Ok <==> spec_boot_admissible(
            pcr0@, pcr7@, bin@, exp_pcr0@, exp_pcr7@, exp_bin@,
            pcr10_nonzero, ima_log_reconciled, have_expected),
{

    if !pcr10_nonzero {
        return Err(BootDenial::Pcr10Zero);
    }
    if !ima_log_reconciled {
        return Err(BootDenial::ImaLogNotReconciled);
    }
    if !have_expected {
        return Err(BootDenial::ExpectedStateUnavailable);
    }
    if bin.len() == 0 {
        return Err(BootDenial::NoBinaryHashInLog);
    }

    if !eq_ignore_ascii_case(bin, exp_bin) {
        return Err(BootDenial::BinaryHashMismatch);
    }
    if exp_pcr0.len() != 0 && !eq_ignore_ascii_case(pcr0, exp_pcr0) {
        return Err(BootDenial::Pcr0Mismatch);
    }
    if exp_pcr7.len() != 0 && !eq_ignore_ascii_case(pcr7, exp_pcr7) {
        return Err(BootDenial::Pcr7Mismatch);
    }
    Ok(BootAdmitted { _seal: 0 })
}

pub fn boot_success_code(_t: BootAdmitted) -> (r: i32)
    ensures r == 0
{
    0
}

pub fn boot_denial_code(d: BootDenial) -> (r: i32)
    ensures r < 0
{
    match d {
        BootDenial::NoBinaryHashInLog => -4,
        BootDenial::Pcr10Zero => -2,
        BootDenial::ImaLogNotReconciled => -9,
        BootDenial::ExpectedStateUnavailable => -5,
        BootDenial::BinaryHashMismatch => -6,
        BootDenial::Pcr0Mismatch => -7,
        BootDenial::Pcr7Mismatch => -8,
    }
}

#[derive(PartialEq, Eq, Structural, Clone, Copy)]
pub enum ChainDenial {
    MacMismatch,
    EnergyChangedUnderSameCounter,
    CounterRollback,
    CounterDiscontinuity,
    CumulativeEnergyMismatch,
    PrevHashMismatch,
}

#[derive(PartialEq, Eq, Structural, Clone, Copy)]
pub enum ChainVerdict {

    Accept,

    IdempotentSkip,
    Reject(ChainDenial),
}

pub open spec fn spec_sat_add(a: u64, b: u64) -> int {
    if a as int + b as int > u64::MAX as int { u64::MAX as int } else { a as int + b as int }
}

pub open spec fn spec_chain_step_acceptable(
    mac_ok: bool, prev_hash_ok: bool, initialized: bool,
    stored_counter: u64, stored_energy: u64,
    incoming_counter: u64, incoming_energy: u64, incoming_delta: u64,
) -> bool {
    &&& mac_ok
    &&& (initialized ==> {
            &&& incoming_counter == stored_counter + 1
            &&& incoming_energy as int == spec_sat_add(stored_energy, incoming_delta)
            &&& prev_hash_ok
        })
}

pub fn admit_chain_step(
    mac_ok: bool,
    prev_hash_ok: bool,
    initialized: bool,
    stored_counter: u64,
    stored_energy: u64,
    incoming_counter: u64,
    incoming_energy: u64,
    incoming_delta: u64,
) -> (r: ChainVerdict)
    ensures
        (r == ChainVerdict::Accept) <==> spec_chain_step_acceptable(
            mac_ok, prev_hash_ok, initialized, stored_counter, stored_energy,
            incoming_counter, incoming_energy, incoming_delta),
        (r == ChainVerdict::IdempotentSkip) ==>
            mac_ok && initialized && incoming_counter == stored_counter
            && incoming_energy == stored_energy,
{
    if !mac_ok {
        return ChainVerdict::Reject(ChainDenial::MacMismatch);
    }
    if !initialized {
        return ChainVerdict::Accept;
    }
    if incoming_counter == stored_counter {
        if incoming_energy != stored_energy {
            return ChainVerdict::Reject(ChainDenial::EnergyChangedUnderSameCounter);
        }
        return ChainVerdict::IdempotentSkip;
    }
    if incoming_counter < stored_counter {
        return ChainVerdict::Reject(ChainDenial::CounterRollback);
    }
    if incoming_counter != stored_counter + 1 {
        return ChainVerdict::Reject(ChainDenial::CounterDiscontinuity);
    }
    let expected_energy: u64 = if stored_energy > u64::MAX - incoming_delta {
        u64::MAX
    } else {
        stored_energy + incoming_delta
    };
    if incoming_energy != expected_energy {
        return ChainVerdict::Reject(ChainDenial::CumulativeEnergyMismatch);
    }
    if !prev_hash_ok {
        return ChainVerdict::Reject(ChainDenial::PrevHashMismatch);
    }
    ChainVerdict::Accept
}

pub fn chain_denial_code(d: ChainDenial) -> (r: i32)
    ensures r < 0
{
    match d {
        ChainDenial::MacMismatch => -2,
        ChainDenial::EnergyChangedUnderSameCounter => -2,
        ChainDenial::CumulativeEnergyMismatch => -2,
        ChainDenial::CounterRollback => -3,
        ChainDenial::CounterDiscontinuity => -3,
        ChainDenial::PrevHashMismatch => -4,
    }
}

pub fn chain_admitted(v: ChainVerdict) -> (r: Option<ChainAdmitted>)
    ensures r is Some <==> v == ChainVerdict::Accept
{
    match v {
        ChainVerdict::Accept => Some(ChainAdmitted { _seal: 0 }),
        _ => None,
    }
}

pub struct ParsedAnchor {
    pub block_number: u64,
    pub root: [u8; 32],
    pub sig: [u8; 32],
}

pub open spec fn spec_anchor_tag() -> Seq<u8> {
    seq![0x63u8, 0x68, 0x65, 0x63, 0x6B, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2D, 0x76, 0x31]
}

#[verifier::rlimit(60)]
pub fn parse_checkpoint_line(line: &[u8], tenant: &[u8]) -> (r: Option<ParsedAnchor>)
    ensures
        r is Some ==> line@.len() >= spec_anchor_tag().len() + tenant@.len() + 4,
{

    let mut seps: [usize; 4] = [0, 0, 0, 0];
    let mut nsep: usize = 0;
    let mut i: usize = 0;
    while i < line.len()
        invariant
            0 <= i <= line@.len(),
            nsep <= 4,
        decreases line@.len() - i
    {
        if line[i] == 0x7C {
            if nsep >= 4 {
                return None;
            }
            seps[nsep] = i;
            nsep = nsep + 1;
        }
        i = i + 1;
    }
    if nsep != 4 {
        return None;
    }

    let s0 = seps[0];
    let s1 = seps[1];
    let s2 = seps[2];
    let s3 = seps[3];

    if !(s0 < s1 && s1 < s2 && s2 < s3 && s3 < line.len()) {
        return None;
    }

    let f_tag = slice_subrange(line, 0, s0);
    let f_tenant = slice_subrange(line, s0 + 1, s1);
    let f_block = slice_subrange(line, s1 + 1, s2);
    let f_root = slice_subrange(line, s2 + 1, s3);
    let f_sig = slice_subrange(line, s3 + 1, line.len());

    if !slices_eq(f_tag, anchor_tag_bytes()) {
        return None;
    }

    if !slices_eq(f_tenant, tenant) {
        return None;
    }

    let block_number = match parse_u64_dec(f_block) {
        Some(b) => b,
        None => return None,
    };
    let root = match hex_decode_32(f_root) {
        Some(rt) => rt,
        None => return None,
    };
    let sig = match hex_decode_32(f_sig) {
        Some(sg) => sg,
        None => return None,
    };

    Some(ParsedAnchor { block_number, root, sig })
}

pub fn anchor_tag_bytes() -> (r: &'static [u8])
    ensures r@ == spec_anchor_tag()
{
    &[0x63u8, 0x68, 0x65, 0x63, 0x6B, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2D, 0x76, 0x31]
}

pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> (r: bool)
    ensures r == (a@ == b@)
{
    let mut diff: u8 = 0;
    let mut i: usize = 0;
    while i < 32
        invariant
            0 <= i <= 32,
            (diff == 0) <==> (forall|j: int| 0 <= j < i ==> a@[j] == b@[j]),
        decreases 32 - i
    {
        let x = a[i];
        let y = b[i];
        let d0 = diff;

        proof {
            assert(((d0 | (x ^ y)) == 0) <==> (d0 == 0 && x == y)) by (bit_vector);
        }
        diff = d0 | (x ^ y);
        i = i + 1;
    }
    proof {
        assert(a@ =~= b@ <==> (forall|j: int| 0 <= j < 32 ==> a@[j] == b@[j]));
    }
    diff == 0
}

pub uninterp spec fn spec_extend(pcr: Seq<u8>, digest: Seq<u8>) -> Seq<u8>;

#[verifier::external_body]
pub fn extend_pcr(pcr: &[u8; 32], digest: &[u8; 32]) -> (r: [u8; 32])
    ensures r@ == spec_extend(pcr@, digest@)
{
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pcr);
    hasher.update(digest);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub open spec fn spec_zero32() -> Seq<u8> {
    Seq::new(32, |_i: int| 0u8)
}

pub open spec fn spec_replay(digests: Seq<Seq<u8>>, n: nat) -> Seq<u8>
    decreases n
{
    if n == 0 {
        spec_zero32()
    } else {
        spec_extend(spec_replay(digests, (n - 1) as nat), digests[(n - 1) as int])
    }
}

pub open spec fn digest_seq(digests: Seq<[u8; 32]>) -> Seq<Seq<u8>> {
    digests.map_values(|d: [u8; 32]| d@)
}

pub fn replay_find_prefix(digests: &[[u8; 32]], target: &[u8; 32]) -> (r: Option<usize>)
    ensures
        match r {
            Some(n) => {
                &&& n <= digests@.len()
                &&& spec_replay(digest_seq(digests@), n as nat) == target@
                &&& forall|k: nat| k < n
                        ==> #[trigger] spec_replay(digest_seq(digests@), k) != target@
            }
            None => forall|k: nat| k <= digests@.len()
                        ==> #[trigger] spec_replay(digest_seq(digests@), k) != target@,
        }
{
    let mut pcr: [u8; 32] = [0u8; 32];

    proof { assert(spec_replay(digest_seq(digests@), 0nat) =~= spec_zero32()); }
    if ct_eq_32(&pcr, target) {
        return Some(0);
    }

    proof {
        assert(pcr@ =~= spec_zero32());
        assert(spec_replay(digest_seq(digests@), 0nat) != target@);
    }

    let mut i: usize = 0;
    while i < digests.len()
        invariant
            0 <= i <= digests@.len(),
            digest_seq(digests@).len() == digests@.len(),
            pcr@ == spec_replay(digest_seq(digests@), i as nat),
            forall|k: nat| k <= i
                ==> #[trigger] spec_replay(digest_seq(digests@), k) != target@,
        decreases digests@.len() - i
    {
        proof { assert(digest_seq(digests@)[i as int] =~= digests@[i as int]@); }
        pcr = extend_pcr(&pcr, &digests[i]);
        i = i + 1;

        proof {
            assert(spec_replay(digest_seq(digests@), i as nat)
                =~= spec_extend(spec_replay(digest_seq(digests@), (i - 1) as nat),
                                digest_seq(digests@)[(i - 1) as int]));
        }
        if ct_eq_32(&pcr, target) {
            return Some(i);
        }
    }
    None
}

pub uninterp spec fn spec_hash_pair(l: Seq<u8>, r: Seq<u8>) -> Seq<u8>;

pub proof fn lemma_digest_seq_len(s: Seq<[u8; 32]>)
    ensures digest_seq(s).len() == s.len()
{
    assert(digest_seq(s) =~= s.map_values(|d: [u8; 32]| d@));
}

pub proof fn lemma_digest_seq_index(s: Seq<[u8; 32]>, i: int)
    requires 0 <= i < s.len()
    ensures digest_seq(s)[i] == s[i]@
{
    lemma_digest_seq_len(s);
    assert(digest_seq(s)[i] == s.map_values(|d: [u8; 32]| d@)[i]);
}

#[verifier::external_body]
pub fn hash_pair_bytes(l: &[u8; 32], r: &[u8; 32]) -> (res: [u8; 32])
    ensures res@ == spec_hash_pair(l@, r@)
{
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&encode_internal(l, r));
    let out = hasher.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

pub open spec fn spec_fold_level(level: Seq<Seq<u8>>) -> Seq<Seq<u8>>
    decreases level.len()
{
    if level.len() < 2 {
        level
    } else {
        seq![spec_hash_pair(level[0], level[1])]
            + spec_fold_level(level.skip(2))
    }
}

pub proof fn lemma_fold_level_len(level: Seq<Seq<u8>>)
    ensures spec_fold_level(level).len() == (level.len() + 1) / 2
    decreases level.len()
{
    if level.len() >= 2 {
        lemma_fold_level_len(level.skip(2));
    }
}

pub open spec fn spec_fold_to_root(level: Seq<Seq<u8>>) -> Seq<u8>
    decreases level.len()
    via spec_fold_to_root_decreases
{
    if level.len() == 0 {
        spec_zero32()
    } else if level.len() == 1 {
        level[0]
    } else {
        spec_fold_to_root(spec_fold_level(level))
    }
}

#[via_fn]
proof fn spec_fold_to_root_decreases(level: Seq<Seq<u8>>) {
    if level.len() >= 2 {
        lemma_fold_level_len(level);
    }
}

#[verifier::rlimit(300)]
pub fn fold_to_root(leaves: &Vec<[u8; 32]>) -> (r: [u8; 32])
    requires leaves@.len() > 0
    ensures r@ == spec_fold_to_root(digest_seq(leaves@))
{
    let mut cur: Vec<[u8; 32]> = Vec::new();
    let mut c: usize = 0;
    while c < leaves.len()
        invariant
            0 <= c <= leaves@.len(),
            cur@.len() == c,
            forall|j: int| 0 <= j < c ==> #[trigger] cur@[j] == leaves@[j],
        decreases leaves@.len() - c
    {
        cur.push(leaves[c]);
        c = c + 1;
    }
    proof { assert(cur@ =~= leaves@); }

    while cur.len() > 1
        invariant
            cur@.len() > 0,
            spec_fold_to_root(digest_seq(cur@)) == spec_fold_to_root(digest_seq(leaves@)),
        decreases cur@.len()
    {
        let ghost before = digest_seq(cur@);
        let mut next: Vec<[u8; 32]> = Vec::new();
        let mut i: usize = 0;
        proof {

            assert(before.skip(0) =~= before);
            assert(digest_seq(next@) =~= Seq::<Seq<u8>>::empty());
            assert(digest_seq(next@) + spec_fold_level(before.skip(0))
                =~= spec_fold_level(before));
        }
        while i + 1 < cur.len()
            invariant
                0 <= i <= cur@.len(),
                i % 2 == 0,
                next@.len() == i / 2,

                before == digest_seq(cur@),
                before.len() == cur@.len(),
                digest_seq(next@) + spec_fold_level(before.skip(i as int))
                    == spec_fold_level(before),
            decreases cur@.len() - i
        {
            let ghost n_before = next@;
            let h = hash_pair_bytes(&cur[i], &cur[i + 1]);
            next.push(h);
            proof {

                lemma_digest_seq_len(cur@);
                lemma_digest_seq_index(cur@, i as int);
                lemma_digest_seq_index(cur@, i as int + 1);
                assert(before.skip(i as int).len() == before.len() - i);
                assert(before.skip(i as int).len() >= 2);
                assert(before.skip(i as int)[0] == before[0 + i as int]);
                assert(before.skip(i as int)[1] == before[1 + i as int]);
                assert(before.skip(i as int).skip(2) =~= before.skip(i as int + 2));
                assert(spec_fold_level(before.skip(i as int))
                    =~= seq![h@] + spec_fold_level(before.skip(i as int + 2)));
                assert(digest_seq(next@) =~= digest_seq(n_before).push(h@));
                assert(digest_seq(n_before) + spec_fold_level(before.skip(i as int))
                    =~= digest_seq(next@) + spec_fold_level(before.skip(i as int + 2)));
            }
            i = i + 2;
        }
        if i < cur.len() {
            next.push(cur[i]);
        }
        proof {
            lemma_fold_level_len(before);
            assert(digest_seq(next@) =~= spec_fold_level(before));
        }
        cur = next;
    }
    cur[0]
}

pub fn admit_measurement_tag(claimed: u64, recomputed: u64) -> (r: Option<TagAdmitted>)
    ensures r is Some <==> claimed == recomputed
{
    if claimed == recomputed {
        Some(TagAdmitted { _seal: 0 })
    } else {
        None
    }
}

pub const TAG_PRODUCER_GPU: u32 = 0x8000;

pub const SIPTAG_IV0: u64 = 0x736f6d6570736575;
pub const SIPTAG_IV1: u64 = 0x646f72616e646f6d;
pub const SIPTAG_IV2: u64 = 0x6c7967656e657261;
pub const SIPTAG_IV3: u64 = 0x7465646279746573;

pub const SIPTAG_LEN_BLOCK: u64 = 0x2000000000000000;

pub const SIPTAG_VERSION: u16 = 1;

pub const SIPTAG_PRODUCER_RAPL_SEEDED: u16 = 1;
pub const SIPTAG_PRODUCER_RAPL_KERNEL: u16 = 2;
pub const SIPTAG_PRODUCER_GPU_NVML:    u16 = 3;

pub open spec fn spec_sipround(v0: u64, v1: u64, v2: u64, v3: u64) -> (u64, u64, u64, u64) {
    let a0 = v0.wrapping_add(v1);
    let b1 = ((v1 << 13u64) | (v1 >> 51u64)) ^ a0;
    let a0r = (a0 << 32u64) | (a0 >> 32u64);
    let a2 = v2.wrapping_add(v3);
    let b3 = ((v3 << 16u64) | (v3 >> 48u64)) ^ a2;
    let c0 = a0r.wrapping_add(b3);
    let d3 = ((b3 << 21u64) | (b3 >> 43u64)) ^ c0;
    let c2 = a2.wrapping_add(b1);
    let d1 = ((b1 << 17u64) | (b1 >> 47u64)) ^ c2;
    let c2r = (c2 << 32u64) | (c2 >> 32u64);
    (c0, d1, c2r, d3)
}

pub fn sipround(v0: u64, v1: u64, v2: u64, v3: u64) -> (r: (u64, u64, u64, u64))
    ensures r == spec_sipround(v0, v1, v2, v3)
{
    let a0 = v0.wrapping_add(v1);
    let b1 = ((v1 << 13u64) | (v1 >> 51u64)) ^ a0;
    let a0r = (a0 << 32u64) | (a0 >> 32u64);
    let a2 = v2.wrapping_add(v3);
    let b3 = ((v3 << 16u64) | (v3 >> 48u64)) ^ a2;
    let c0 = a0r.wrapping_add(b3);
    let d3 = ((b3 << 21u64) | (b3 >> 43u64)) ^ c0;
    let c2 = a2.wrapping_add(b1);
    let d1 = ((b1 << 17u64) | (b1 >> 47u64)) ^ c2;
    let c2r = (c2 << 32u64) | (c2 >> 32u64);
    (c0, d1, c2r, d3)
}

pub open spec fn spec_siptag_words(
    energy_uj: u64, timestamp_ns: u64, unit_id: u32, domain_id: u32,
    version: u16, producer: u16, key_epoch: u32,
) -> (u64, u64, u64, u64) {
    (energy_uj,
     timestamp_ns,
     (unit_id as u64) | ((domain_id as u64) << 32u64),
     (version as u64) | ((producer as u64) << 16u64) | ((key_epoch as u64) << 32u64))
}

pub open spec fn spec_siptag(
    k0: u64, k1: u64,
    energy_uj: u64, timestamp_ns: u64, unit_id: u32, domain_id: u32,
    version: u16, producer: u16, key_epoch: u32,
) -> u64 {
    let (m0, m1, m2, m3) = spec_siptag_words(
        energy_uj, timestamp_ns, unit_id, domain_id, version, producer, key_epoch);
    let s0 = spec_absorb(SIPTAG_IV0 ^ k0, SIPTAG_IV1 ^ k1, SIPTAG_IV2 ^ k0, SIPTAG_IV3 ^ k1, m0);
    let s1 = spec_absorb(s0.0, s0.1, s0.2, s0.3, m1);
    let s2 = spec_absorb(s1.0, s1.1, s1.2, s1.3, m2);
    let s3 = spec_absorb(s2.0, s2.1, s2.2, s2.3, m3);
    let s4 = spec_absorb(s3.0, s3.1, s3.2, s3.3, SIPTAG_LEN_BLOCK);
    let f0 = spec_sipround(s4.0, s4.1, s4.2 ^ 0xffu64, s4.3);
    let f1 = spec_sipround(f0.0, f0.1, f0.2, f0.3);
    let f2 = spec_sipround(f1.0, f1.1, f1.2, f1.3);
    let f3 = spec_sipround(f2.0, f2.1, f2.2, f2.3);
    f3.0 ^ f3.1 ^ f3.2 ^ f3.3
}

pub open spec fn spec_absorb(v0: u64, v1: u64, v2: u64, v3: u64, m: u64) -> (u64, u64, u64, u64) {
    let a = spec_sipround(v0, v1, v2, v3 ^ m);
    let b = spec_sipround(a.0, a.1, a.2, a.3);
    (b.0 ^ m, b.1, b.2, b.3)
}

pub fn absorb(v0: u64, v1: u64, v2: u64, v3: u64, m: u64) -> (r: (u64, u64, u64, u64))
    ensures r == spec_absorb(v0, v1, v2, v3, m)
{
    let a = sipround(v0, v1, v2, v3 ^ m);
    let b = sipround(a.0, a.1, a.2, a.3);
    (b.0 ^ m, b.1, b.2, b.3)
}

pub fn siptag(
    k0: u64, k1: u64,
    energy_uj: u64, timestamp_ns: u64, unit_id: u32, domain_id: u32,
    version: u16, producer: u16, key_epoch: u32,
) -> (r: u64)
    ensures r == spec_siptag(k0, k1, energy_uj, timestamp_ns, unit_id, domain_id,
                             version, producer, key_epoch)
{
    let m0 = energy_uj;
    let m1 = timestamp_ns;
    let m2 = (unit_id as u64) | ((domain_id as u64) << 32u64);
    let m3 = (version as u64) | ((producer as u64) << 16u64) | ((key_epoch as u64) << 32u64);

    let s0 = absorb(SIPTAG_IV0 ^ k0, SIPTAG_IV1 ^ k1, SIPTAG_IV2 ^ k0, SIPTAG_IV3 ^ k1, m0);
    let s1 = absorb(s0.0, s0.1, s0.2, s0.3, m1);
    let s2 = absorb(s1.0, s1.1, s1.2, s1.3, m2);
    let s3 = absorb(s2.0, s2.1, s2.2, s2.3, m3);
    let s4 = absorb(s3.0, s3.1, s3.2, s3.3, SIPTAG_LEN_BLOCK);

    let f0 = sipround(s4.0, s4.1, s4.2 ^ 0xffu64, s4.3);
    let f1 = sipround(f0.0, f0.1, f0.2, f0.3);
    let f2 = sipround(f1.0, f1.1, f1.2, f1.3);
    let f3 = sipround(f2.0, f2.1, f2.2, f2.3);
    f3.0 ^ f3.1 ^ f3.2 ^ f3.3
}

pub fn slices_eq(a: &[u8], b: &[u8]) -> (r: bool)
    ensures r == (a@ == b@)
{
    if a.len() != b.len() {
        assert(a@.len() != b@.len());
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            0 <= i <= a@.len(),
            a@.len() == b@.len(),
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a@.len() - i
    {
        if a[i] != b[i] {
            assert(a@[i as int] != b@[i as int]);
            return false;
        }
        i = i + 1;
    }
    assert(a@ =~= b@);
    true
}

#[derive(PartialEq, Eq, Structural)]
pub enum RefusalReason {

    AnchorStorageMismatch,

    MissingAnchor,

    MissingBlocks,
}

#[derive(PartialEq, Eq, Structural)]
pub enum ResumeDecision {

    Fresh,

    Resume { block_number: u64 },

    Refuse { reason: RefusalReason },
}

pub fn decide_resume(
    have_anchor: bool,
    anchor_block: u64,
    have_stored: bool,
    stored_block: u64,
    roots_equal: bool,
) -> (r: ResumeDecision)
    ensures

        (r is Resume) ==> have_anchor && have_stored
            && anchor_block == stored_block && roots_equal,
        (r is Resume) ==> r->Resume_block_number == anchor_block,

        (r is Fresh) ==> !have_anchor && !have_stored,

        (r is Refuse) ==> have_anchor || have_stored,
{
    if have_anchor && have_stored {
        if anchor_block != stored_block || !roots_equal {
            ResumeDecision::Refuse { reason: RefusalReason::AnchorStorageMismatch }
        } else {
            ResumeDecision::Resume { block_number: anchor_block }
        }
    } else if have_stored {
        ResumeDecision::Refuse { reason: RefusalReason::MissingAnchor }
    } else if have_anchor {
        ResumeDecision::Refuse { reason: RefusalReason::MissingBlocks }
    } else {
        ResumeDecision::Fresh
    }
}

pub open spec fn sum_u64(s: Seq<u64>) -> int
    decreases s.len()
{
    if s.len() == 0 { 0int } else { s[0] as int + sum_u64(s.drop_first()) }
}

pub proof fn lemma_elem_le_sum(s: Seq<u64>, i: int)
    requires 0 <= i < s.len()
    ensures s[i] as int <= sum_u64(s)
    decreases s.len()
{
    if i == 0 {
        lemma_sum_nonneg(s.drop_first());
    } else {
        lemma_elem_le_sum(s.drop_first(), i - 1);
        assert(s.drop_first()[i - 1] == s[i]);
    }
}

pub proof fn lemma_sum_nonneg(s: Seq<u64>)
    ensures sum_u64(s) >= 0
    decreases s.len()
{
    if s.len() != 0 {
        lemma_sum_nonneg(s.drop_first());
    }
}

pub proof fn lemma_sum_push(s: Seq<u64>, v: u64)
    ensures sum_u64(s.push(v)) == sum_u64(s) + v as int
    decreases s.len()
{
    if s.len() == 0 {
        assert(s.push(v).len() == 1);
        assert(s.push(v).len() != 0);
        assert(s.push(v)[0] == v);
        assert(sum_u64(Seq::<u64>::empty()) == 0);
        assert(s.push(v).drop_first() =~= Seq::<u64>::empty());
    } else {
        lemma_sum_push(s.drop_first(), v);

        assert(s.push(v)[0] == s[0]);
        assert(s.push(v).drop_first() =~= s.drop_first().push(v));
    }
}

pub proof fn lemma_sum_update_u64(s: Seq<u64>, i: int, v: u64)
    requires 0 <= i < s.len()
    ensures sum_u64(s.update(i, v)) == sum_u64(s) - s[i] as int + v as int
    decreases s.len()
{
    if i == 0 {
        assert(s.update(0, v)[0] == v);
        assert(s.update(0, v).drop_first() =~= s.drop_first());
    } else {
        lemma_sum_update_u64(s.drop_first(), i - 1, v);
        assert(s.update(i, v)[0] == s[0]);
        assert(s.update(i, v).drop_first() =~= s.drop_first().update(i - 1, v));
    }
}

pub proof fn lemma_prefix_sum_le(s: Seq<u64>, m: int)
    requires 0 <= m <= s.len()
    ensures sum_u64(s.subrange(0, m)) <= sum_u64(s)
    decreases s.len()
{
    if s.len() == 0 {
        assert(s.subrange(0, m) =~= s);
    } else if m == 0 {
        assert(s.subrange(0, 0) =~= Seq::<u64>::empty());
        lemma_sum_nonneg(s);
    } else {
        lemma_prefix_sum_le(s.drop_first(), m - 1);
        assert(s.subrange(0, m).drop_first() =~= s.drop_first().subrange(0, m - 1));
        assert(s.subrange(0, m)[0] == s[0]);
    }
}

pub proof fn lemma_prefix_floors_le_total(
    total: u64, weights: Seq<u64>, tw: int, shares: Seq<u64>, m: int,
)
    requires
        tw > 0,
        tw == sum_u64(weights),
        shares.len() == weights.len(),
        0 <= m <= shares.len(),
        forall|j: int| 0 <= j < shares.len() ==>
            #[trigger] shares[j] as int == spec_floor_share(total, weights[j], tw),
    ensures
        0 <= sum_u64(shares.subrange(0, m)) <= total as int,
{
    let ws = weights.subrange(0, m);
    let ss = shares.subrange(0, m);
    assert forall|j: int| 0 <= j < ss.len()
        implies #[trigger] ss[j] as int == spec_floor_share(total, ws[j], tw) by {
        assert(ss[j] == shares[j]);
        assert(ws[j] == weights[j]);
    }
    lemma_sum_floors_partial_eq(total, ws, tw, ss);
    lemma_sum_floors_scaled(total, ws, tw);
    lemma_prefix_sum_le(weights, m);
    lemma_sum_nonneg(ss);

    assert(total as int * sum_u64(ws) <= total as int * tw) by (nonlinear_arith)
        requires sum_u64(ws) <= tw, total as int >= 0;
    lemma_cancel_mul_le(spec_sum_floors(total, ws, tw), total as int, tw);
}

pub proof fn lemma_sum_bounded(s: Seq<u64>, bound: u64)
    requires forall|i: int| 0 <= i < s.len() ==> #[trigger] s[i] <= bound
    ensures sum_u64(s) <= s.len() * bound as int
    decreases s.len()
{
    if s.len() != 0 {

        assert forall|i: int| 0 <= i < s.drop_first().len()
            implies #[trigger] s.drop_first()[i] <= bound
        by {
            assert(s.drop_first()[i] == s[i + 1]);
        }
        lemma_sum_bounded(s.drop_first(), bound);
        assert(s.len() * bound as int
            == (s.len() - 1) * bound as int + bound as int) by (nonlinear_arith);
    }
}

pub open spec fn spec_floor_share(total: u64, w: u64, tw: int) -> int {
    (total as int * w as int) / tw
}

pub open spec fn spec_sum_floors(total: u64, ws: Seq<u64>, tw: int) -> int
    decreases ws.len()
{
    if ws.len() == 0 {
        0int
    } else {
        spec_floor_share(total, ws[0], tw) + spec_sum_floors(total, ws.drop_first(), tw)
    }
}

pub proof fn lemma_floor_scaled(total: u64, w: u64, tw: int)
    requires tw > 0
    ensures spec_floor_share(total, w, tw) * tw <= total as int * w as int
{
    let a = total as int * w as int;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(a, tw);
    vstd::arithmetic::div_mod::lemma_mod_bound(a, tw);

    assert(tw * (a / tw) <= a);
    assert((a / tw) * tw == tw * (a / tw)) by (nonlinear_arith);
}

pub proof fn lemma_floor_nonneg(total: u64, w: u64, tw: int)
    requires tw > 0
    ensures spec_floor_share(total, w, tw) >= 0
{
    assert(total as int * w as int >= 0) by (nonlinear_arith);
    vstd::arithmetic::div_mod::lemma_div_pos_is_pos(total as int * w as int, tw);
}

pub proof fn lemma_sum_floors_scaled(total: u64, ws: Seq<u64>, tw: int)
    requires tw > 0
    ensures
        spec_sum_floors(total, ws, tw) * tw <= total as int * sum_u64(ws),
        spec_sum_floors(total, ws, tw) >= 0,
    decreases ws.len()
{
    if ws.len() == 0 {
        assert(spec_sum_floors(total, ws, tw) == 0);
        assert(sum_u64(ws) == 0);
    } else {
        let head = spec_floor_share(total, ws[0], tw);
        let rest = ws.drop_first();

        lemma_floor_scaled(total, ws[0], tw);
        lemma_floor_nonneg(total, ws[0], tw);
        lemma_sum_floors_scaled(total, rest, tw);

        assert((head + spec_sum_floors(total, rest, tw)) * tw
            == head * tw + spec_sum_floors(total, rest, tw) * tw) by (nonlinear_arith);

        assert(total as int * ws[0] as int + total as int * sum_u64(rest)
            == total as int * (ws[0] as int + sum_u64(rest))) by (nonlinear_arith);
        assert(sum_u64(ws) == ws[0] as int + sum_u64(rest));
    }
}

pub proof fn lemma_cancel_mul_le(x: int, y: int, c: int)
    requires c > 0, x * c <= y * c
    ensures x <= y
{
    assert(x <= y) by (nonlinear_arith)
        requires c > 0, x * c <= y * c;
}

pub proof fn lemma_floors_bounded(total: u64, weights: Seq<u64>, total_weight: int, partial: Seq<u64>)
    requires
        total_weight > 0,
        total_weight == sum_u64(weights),
        partial.len() == weights.len(),
        forall|i: int| 0 <= i < partial.len() ==>
            #[trigger] partial[i] as int == spec_floor_share(total, weights[i], total_weight),
    ensures
        0 <= sum_u64(partial) <= total as int,
{
    lemma_sum_floors_partial_eq(total, weights, total_weight, partial);
    lemma_sum_floors_scaled(total, weights, total_weight);

    assert(spec_sum_floors(total, weights, total_weight) * total_weight
        <= total as int * total_weight);
    lemma_cancel_mul_le(
        spec_sum_floors(total, weights, total_weight),
        total as int,
        total_weight,
    );
}

pub proof fn lemma_sum_floors_partial_eq(
    total: u64, weights: Seq<u64>, tw: int, partial: Seq<u64>,
)
    requires
        tw > 0,
        partial.len() == weights.len(),
        forall|i: int| 0 <= i < partial.len() ==>
            #[trigger] partial[i] as int == spec_floor_share(total, weights[i], tw),
    ensures
        sum_u64(partial) == spec_sum_floors(total, weights, tw),
    decreases weights.len()
{
    if weights.len() == 0 {
    } else {
        lemma_sum_floors_partial_eq(total, weights.drop_first(), tw, partial.drop_first());
    }
}

pub fn attribute_by_weight(total: u64, weights: &[u64]) -> (r: Option<Vec<u64>>)
    requires

        weights@.len() < 0x1_0000_0000,
    ensures
        match r {
            Some(shares) => shares@.len() == weights@.len() && sum_u64(shares@) == total as int,
            None => weights@.len() == 0 || sum_u64(weights@) == 0,
        }
{
    if weights.len() == 0 {
        return None;
    }

    let mut total_weight: u128 = 0;
    let mut i: usize = 0;
    while i < weights.len()
        invariant
            0 <= i <= weights@.len(),
            weights@.len() < 0x1_0000_0000,

            total_weight as int == sum_u64(weights@.subrange(0, i as int)),

            total_weight <= 0x1_0000_0000_0000_0000_0000_0000u128,
        decreases weights@.len() - i
    {
        proof {
            let pre = weights@.subrange(0, i as int);
            let post = weights@.subrange(0, i + 1);
            assert(post =~= pre.push(weights@[i as int]));
            lemma_sum_push(pre, weights@[i as int]);

            lemma_sum_bounded(post, 0xFFFF_FFFF_FFFF_FFFFu64);

            assert(post.len() * (0xFFFF_FFFF_FFFF_FFFFu64 as int)
                    <= 0x1_0000_0000_0000_0000_0000_0000int)
                by (nonlinear_arith)
                requires post.len() <= 0x1_0000_0000int;
        }
        total_weight = total_weight + weights[i] as u128;
        i = i + 1;
    }
    assert(weights@.subrange(0, weights@.len() as int) =~= weights@);

    if total_weight == 0 {
        return None;
    }

    let mut shares: Vec<u64> = Vec::new();
    let mut k: usize = 0;
    while k < weights.len()
        invariant
            0 <= k <= weights@.len(),
            shares@.len() == k,
            total_weight > 0,
            total_weight as int == sum_u64(weights@),

            forall|j: int| 0 <= j < k ==> #[trigger] shares@[j] as int
                == spec_floor_share(total, weights@[j], total_weight as int),
        decreases weights@.len() - k
    {

        let w: u64 = weights[k];
        proof {
            assert(w == weights@[k as int]);

            lemma_elem_le_sum(weights@, k as int);
            assert(w as int <= total_weight as int);

            assert(total as u128 * w as u128
                    <= 0xFFFF_FFFF_FFFF_FFFFu128 * 0xFFFF_FFFF_FFFF_FFFFu128)
                by (nonlinear_arith)
                requires
                    total as u128 <= 0xFFFF_FFFF_FFFF_FFFFu128,
                    w as u128 <= 0xFFFF_FFFF_FFFF_FFFFu128;
        }
        let share128: u128 = (total as u128 * w as u128) / total_weight;
        proof {

            assert(share128 as int
                == (total as int * w as int) / (total_weight as int));
            assert((total as int * w as int) / (total_weight as int) <= total as int)
                by (nonlinear_arith)
                requires
                    total_weight as int > 0,
                    w as int <= total_weight as int,
                    total as int >= 0;
        }
        let share = share128 as u64;
        shares.push(share);
        k = k + 1;
    }

    let mut assigned: u64 = 0;
    let mut m: usize = 0;
    while m < shares.len()
        invariant
            0 <= m <= shares@.len(),
            shares@.len() == weights@.len(),
            total_weight > 0,
            total_weight as int == sum_u64(weights@),
            forall|j: int| 0 <= j < shares@.len() ==> #[trigger] shares@[j] as int
                == spec_floor_share(total, weights@[j], total_weight as int),
            assigned as int == sum_u64(shares@.subrange(0, m as int)),

            assigned <= total,
        decreases shares@.len() - m
    {
        proof {
            lemma_prefix_floors_le_total(
                total, weights@, total_weight as int, shares@, m + 1);
            assert(shares@.subrange(0, m + 1) =~= shares@.subrange(0, m as int)
                .push(shares@[m as int]));
            lemma_sum_push(shares@.subrange(0, m as int), shares@[m as int]);
        }
        assigned = assigned + shares[m];
        m = m + 1;
    }
    assert(shares@.subrange(0, shares@.len() as int) =~= shares@);

    proof { lemma_floors_bounded(total, weights@, total_weight as int, shares@); }
    let remainder: u64 = total - assigned;

    if remainder > 0 {

        let mut heaviest: usize = 0;
        let mut n: usize = 1;
        while n < weights.len()
            invariant
                0 <= heaviest < weights@.len(),
                1 <= n <= weights@.len(),
            decreases weights@.len() - n
        {
            if weights[n] >= weights[heaviest] {
                heaviest = n;
            }
            n = n + 1;
        }
        proof {

            lemma_elem_le_sum(shares@, heaviest as int);
            assert(shares@[heaviest as int] as int <= sum_u64(shares@));
            assert(sum_u64(shares@) == assigned as int);
        }
        let old_share = shares[heaviest];
        let new_share: u64 = old_share + remainder;
        let ghost before = shares@;
        shares.set(heaviest, new_share);
        proof {
            lemma_sum_update_u64(before, heaviest as int, new_share);
            assert(shares@ =~= before.update(heaviest as int, new_share));

        }
    }

    Some(shares)
}

pub open spec fn spec_is_zero_hash(s: Seq<u8>) -> bool {
    &&& s.len() > 0
    &&& forall|i: int| 0 <= i < s.len() ==> #[trigger] s[i] == '0' as u8
}

pub fn is_zero_hash(s: &[u8]) -> (r: bool)
    ensures r == spec_is_zero_hash(s@)
{
    if s.len() == 0 {
        return false;
    }
    let mut i: usize = 0;
    while i < s.len()
        invariant
            0 <= i <= s@.len(),
            s@.len() > 0,
            forall|j: int| 0 <= j < i ==> #[trigger] s@[j] == '0' as u8,
        decreases s@.len() - i
    {
        if s[i] != '0' as u8 {
            assert(s@[i as int] != '0' as u8);
            return false;
        }
        i = i + 1;
    }
    true
}

#[derive(PartialEq, Eq, Structural, Clone, Copy)]
pub enum CollectorHash {

    Exact,

    Hashed,

    Absent,
}

pub open spec fn spec_collector_choice(have_exact: bool, have_hashed: bool) -> CollectorHash {
    if have_exact {
        CollectorHash::Exact
    } else if have_hashed {
        CollectorHash::Hashed
    } else {
        CollectorHash::Absent
    }
}

pub fn choose_collector_hash(have_exact: bool, have_hashed: bool) -> (r: CollectorHash)
    ensures
        r == spec_collector_choice(have_exact, have_hashed),
        r == CollectorHash::Hashed ==> !have_exact,
        r == CollectorHash::Absent ==> (!have_exact && !have_hashed),
        r == CollectorHash::Exact ==> have_exact,
{
    if have_exact {
        CollectorHash::Exact
    } else if have_hashed {
        CollectorHash::Hashed
    } else {
        CollectorHash::Absent
    }
}

pub open spec fn spec_in_bounds(len: nat, off: nat, n: nat) -> bool {
    off + n <= len
}

pub fn read_u16_be(buf: &[u8], off: usize) -> (r: Option<u16>)
    ensures
        r is Some <==> spec_in_bounds(buf@.len() as nat, off as nat, 2),
{
    if off > buf.len() || buf.len() - off < 2 {
        return None;
    }
    let hi = buf[off] as u16;
    let lo = buf[off + 1] as u16;
    Some(hi * 256 + lo)
}

pub fn read_u32_be(buf: &[u8], off: usize) -> (r: Option<u32>)
    ensures
        r is Some <==> spec_in_bounds(buf@.len() as nat, off as nat, 4),
{
    if off > buf.len() || buf.len() - off < 4 {
        return None;
    }
    let b0 = buf[off] as u32;
    let b1 = buf[off + 1] as u32;
    let b2 = buf[off + 2] as u32;
    let b3 = buf[off + 3] as u32;
    Some(b0 * 16777216 + b1 * 65536 + b2 * 256 + b3)
}

pub fn advance_within(off: usize, by: usize, len: usize) -> (r: Option<usize>)
    ensures
        r is Some <==> (off + by <= len),
        r is Some ==> r->Some_0 == off + by,
{
    if off > len || len - off < by {
        return None;
    }
    Some(off + by)
}

pub fn find_byte(hay: &[u8], needle: u8, from: usize) -> (r: Option<usize>)
    requires from <= hay@.len(),
    ensures
        match r {
            Some(i) => {
                &&& from <= i < hay@.len()
                &&& hay@[i as int] == needle
                &&& forall|j: int| from <= j < i ==> #[trigger] hay@[j] != needle
            }
            None => forall|j: int| from <= j < hay@.len() ==> #[trigger] hay@[j] != needle,
        }
{
    let mut i: usize = from;
    while i < hay.len()
        invariant
            from <= i <= hay@.len(),
            forall|j: int| from <= j < i ==> #[trigger] hay@[j] != needle,
        decreases hay@.len() - i
    {
        if hay[i] == needle {
            return Some(i);
        }
        i = i + 1;
    }
    None
}

pub open spec fn spec_is_hex_of_len(s: Seq<u8>, n: nat) -> bool {
    &&& s.len() == n
    &&& spec_all_hex(s)
}

pub fn is_hex_of_len(s: &[u8], n: usize) -> (r: bool)
    ensures r == spec_is_hex_of_len(s@, n as nat)
{
    if s.len() != n {
        return false;
    }
    let mut i: usize = 0;
    while i < s.len()
        invariant
            0 <= i <= s@.len(),
            s@.len() == n,
            forall|j: int| 0 <= j < i ==> #[trigger] spec_hex_val(s@[j]) is Some,
        decreases s@.len() - i
    {
        if hex_val(s[i]).is_none() {
            assert(spec_hex_val(s@[i as int]) is None);
            return false;
        }
        i = i + 1;
    }
    true
}

pub struct RecordView {
    pub hash: Vec<u8>,
    pub path: Vec<u8>,
}

pub open spec fn spec_name_is(path: Seq<u8>, name: Seq<u8>) -> bool {
    ||| path =~= name
    ||| (path.len() > name.len()
         && path.subrange(path.len() - name.len(), path.len() as int) =~= name
         && path[path.len() - name.len() - 1] == '/' as u8)
}

pub fn name_is(path: &[u8], name: &[u8]) -> (r: bool)
    ensures r == spec_name_is(path@, name@)
{
    if path.len() == name.len() {
        return slices_eq(path, name);
    }
    if path.len() <= name.len() {
        return false;
    }

    let plen: usize = path.len();
    let nlen: usize = name.len();
    let start = plen - nlen;

    if path[start - 1] != 0x2F {
        return false;
    }
    let mut i: usize = 0;
    while i < nlen
        invariant
            0 <= i <= nlen,
            plen == path@.len(),
            nlen == name@.len(),
            plen > nlen,
            start == plen - nlen,
            start + i <= plen,
            forall|j: int| 0 <= j < i ==> #[trigger] path@[start + j] == name@[j],
        decreases nlen - i
    {
        if path[start + i] != name[i] {
            assert(path@[start + i as int] != name@[i as int]);
            return false;
        }
        i = i + 1;
    }

    proof {
        assert_seqs_equal!(path@.subrange(start as int, path@.len() as int) == name@, k => {
            assert(path@[start + k] == name@[k]);
        });
    }
    true
}

pub open spec fn spec_collector_name() -> Seq<u8> {

    seq![0x73u8, 0x63, 0x61, 0x70, 0x68, 0x61, 0x6E, 0x64, 0x72, 0x65]
}

pub open spec fn spec_is_collector_record(r: RecordView) -> bool {
    &&& spec_name_is(r.path@, spec_collector_name())
    &&& !spec_is_zero_hash(r.hash@)
    &&& r.hash@.len() > 0
}

pub fn select_collector_hash_verified(records: &Vec<RecordView>) -> (r: Option<Vec<u8>>)
    ensures
        match r {
            Some(h) => exists|i: int|
                0 <= i < records@.len()
                && #[trigger] spec_is_collector_record(records@[i])
                && records@[i].hash@ =~= h@,
            None => forall|i: int|
                0 <= i < records@.len() ==> !(#[trigger] spec_is_collector_record(records@[i])),
        }
{
    let mut found: Option<Vec<u8>> = None;
    let mut i: usize = 0;
    while i < records.len()
        invariant
            0 <= i <= records@.len(),
            match found {
                Some(ref h) => exists|k: int|
                    0 <= k < i && #[trigger] spec_is_collector_record(records@[k])
                    && records@[k].hash@ =~= h@,
                None => forall|k: int|
                    0 <= k < i ==> !(#[trigger] spec_is_collector_record(records@[k])),
            },
        decreases records@.len() - i
    {
        let rec = &records[i];
        let is_collector = name_is(rec.path.as_slice(), &[
            0x73u8, 0x63, 0x61, 0x70, 0x68, 0x61, 0x6E, 0x64, 0x72, 0x65,
        ]) && rec.hash.len() > 0 && !is_zero_hash(rec.hash.as_slice());
        if is_collector {
            let mut copy: Vec<u8> = Vec::new();
            let mut j: usize = 0;
            while j < rec.hash.len()
                invariant
                    0 <= j <= rec.hash@.len(),
                    copy@ =~= rec.hash@.subrange(0, j as int),
                decreases rec.hash@.len() - j
            {
                copy.push(rec.hash[j]);
                j = j + 1;
            }
            assert(copy@ =~= rec.hash@);
            assert(spec_is_collector_record(records@[i as int]));
            found = Some(copy);
        }
        i = i + 1;
    }
    found
}

}
