use sha2::{Sha256, Digest};

pub use vpma_verified::{
    DOMAIN_LEAF, DOMAIN_INTERNAL, DOMAIN_ROOT, RECORD_FORMAT_V2,
    encode_record_fields, encode_leaf, encode_internal, encode_root,
};

#[derive(Clone, Debug)]
pub struct EnergyRecord {
    pub pid: u32,
    pub cpu_time: f64,
    pub energy_joules: f64,
    pub power_watts: f64,
    pub vm_name: String,
    pub timestamp: String,
}

impl EnergyRecord {

    pub fn new(
        pid: u32,
        cpu_time: f64,
        energy_joules: f64,
        power_watts: f64,
        vm_name: String,
        timestamp: String,
    ) -> Self {
        Self {
            pid,
            cpu_time,
            energy_joules,
            power_watts,
            vm_name,
            timestamp,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encode_record_fields(
            self.pid,
            self.cpu_time.to_bits(),
            self.energy_joules.to_bits(),
            self.power_watts.to_bits(),
            self.vm_name.as_bytes(),
            self.timestamp.as_bytes(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct MerkleNode {

    pub level: u32,

    pub position: u32,

    pub hash: [u8; 32],

    pub left_child: Option<[u8; 32]>,

    pub right_child: Option<[u8; 32]>,
}

pub struct MerkleTree {

    pub root: Option<[u8; 32]>,

    pub leaf_hashes: Vec<[u8; 32]>,

    pub leaf_count: usize,

    pub internal_nodes: Vec<MerkleNode>,

    pub height: usize,
}

impl MerkleTree {

    pub fn build(records: &[EnergyRecord]) -> Self {
        if records.is_empty() {
            return Self {
                root: None,
                leaf_hashes: Vec::new(),
                leaf_count: 0,
                internal_nodes: Vec::new(),
                height: 0,
            };
        }

        let leaf_hashes: Vec<[u8; 32]> = records
            .iter()
            .map(|record| hash_leaf(&record.to_bytes()))
            .collect();

        let leaf_count = leaf_hashes.len();
        let mut internal_nodes = Vec::new();

        for (pos, hash) in leaf_hashes.iter().enumerate() {
            internal_nodes.push(MerkleNode {
                level: 0,
                position: pos as u32,
                hash: *hash,
                left_child: None,
                right_child: None,
            });
        }

        let mut current_level = leaf_hashes.clone();
        let mut level_num: u32 = 0;

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            level_num += 1;

            let mut i = 0usize;
            let mut pos = 0u32;
            while i + 1 < current_level.len() {
                let left = current_level[i];
                let right = current_level[i + 1];
                let parent_hash = hash_pair(&left, &right);
                next_level.push(parent_hash);

                internal_nodes.push(MerkleNode {
                    level: level_num,
                    position: pos,
                    hash: parent_hash,
                    left_child: Some(left),
                    right_child: Some(right),
                });

                i += 2;
                pos += 1;
            }

            if i < current_level.len() {
                next_level.push(current_level[i]);
            }

            current_level = next_level;
        }

        let root = commit_root(leaf_count, &crate::pure::fold_to_root(&leaf_hashes));

        Self {
            root: Some(root),
            leaf_hashes,
            leaf_count,
            internal_nodes,
            height: (level_num + 1) as usize,
        }
    }

    pub fn get_nodes_at_level(&self, level: u32) -> Vec<&MerkleNode> {
        self.internal_nodes.iter()
            .filter(|n| n.level == level)
            .collect()
    }

    pub fn get_node(&self, level: u32, position: u32) -> Option<&MerkleNode> {
        self.internal_nodes.iter()
            .find(|n| n.level == level && n.position == position)
    }

    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.root
    }

    pub fn root_hash_hex(&self) -> String {
        match self.root {
            Some(hash) => hex::encode(hash),
            None => "0".repeat(64),
        }
    }

    pub fn verify_record(&self, record: &EnergyRecord, leaf_index: usize) -> bool {
        if leaf_index >= self.leaf_hashes.len() {
            return false;
        }

        let computed_hash = hash_leaf(&record.to_bytes());
        computed_hash == self.leaf_hashes[leaf_index]
    }

    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }

        let mut proof_hashes = Vec::new();
        let mut proof_directions = Vec::new();

        let mut current_index = leaf_index;
        let mut current_level = self.leaf_hashes.clone();

        while current_level.len() > 1 {

            let is_promoted_odd =
                current_level.len() % 2 == 1 && current_index == current_level.len() - 1;

            if !is_promoted_odd {
                let sibling_index = if current_index % 2 == 0 {
                    current_index + 1
                } else {
                    current_index - 1
                };
                proof_hashes.push(current_level[sibling_index]);
                proof_directions.push(current_index % 2 == 1);
            }

            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            let mut i = 0usize;
            while i + 1 < current_level.len() {
                next_level.push(hash_pair(&current_level[i], &current_level[i + 1]));
                i += 2;
            }
            if i < current_level.len() {
                next_level.push(current_level[i]);
            }

            current_level = next_level;
            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_hash: self.leaf_hashes[leaf_index],
            proof_hashes,
            proof_directions,
            leaf_index,
            leaf_count: self.leaf_count,
        })
    }
}

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub leaf_hash: [u8; 32],
    pub proof_hashes: Vec<[u8; 32]>,
    pub proof_directions: Vec<bool>,
    pub leaf_index: usize,

    pub leaf_count: usize,
}

impl MerkleProof {

    pub fn verify(&self, root_hash: &[u8; 32]) -> bool {
        let mut current_hash = self.leaf_hash;

        for (sibling_hash, is_left) in self.proof_hashes.iter().zip(self.proof_directions.iter()) {
            if *is_left {
                current_hash = hash_pair(sibling_hash, &current_hash);
            } else {
                current_hash = hash_pair(&current_hash, sibling_hash);
            }
        }

        commit_root(self.leaf_count, &current_hash) == *root_hash
    }

    pub fn to_json(&self) -> String {
        format!(
            r#"{{"leaf_hash":"{}","proof_hashes":[{}],"directions":[{}],"leaf_index":{},"leaf_count":{}}}"#,
            hex::encode(self.leaf_hash),
            self.proof_hashes.iter().map(|h| format!("\"{}\"", hex::encode(h))).collect::<Vec<_>>().join(","),
            self.proof_directions.iter().map(|d| if *d { "true" } else { "false" }).collect::<Vec<_>>().join(","),
            self.leaf_index,
            self.leaf_count
        )
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

pub fn hash_leaf(record_bytes: &[u8]) -> [u8; 32] {
    sha256(&encode_leaf(record_bytes))
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&encode_internal(left, right))
}

pub fn commit_root(leaf_count: usize, subtree_root: &[u8; 32]) -> [u8; 32] {
    sha256(&encode_root(leaf_count as u64, subtree_root))
}

pub fn hash_record(record: &EnergyRecord) -> String {
    hex::encode(hash_leaf(&record.to_bytes()))
}

pub fn compute_root_from_leaves(leaf_hashes: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaf_hashes.is_empty() {
        return None;
    }

    let leaf_count = leaf_hashes.len();

    let subtree = crate::pure::fold_to_root(&leaf_hashes.to_vec());

    Some(commit_root(leaf_count, &subtree))
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const MAX_FIELD: usize = 3;

    fn any_field() -> Vec<u8> {
        let len: usize = kani::any();
        kani::assume(len <= MAX_FIELD);
        let bytes: [u8; MAX_FIELD] = kani::any();
        bytes[..len].to_vec()
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_record_encoding_is_injective() {
        let pid_a: u32 = kani::any();
        let pid_b: u32 = kani::any();
        let energy_a: u64 = kani::any();
        let energy_b: u64 = kani::any();
        let vm_a = any_field();
        let vm_b = any_field();
        let ts_a = any_field();
        let ts_b = any_field();

        kani::assume(pid_a != pid_b || energy_a != energy_b || vm_a != vm_b || ts_a != ts_b);

        let enc_a = encode_record_fields(pid_a, 0, energy_a, 0, &vm_a, &ts_a);
        let enc_b = encode_record_fields(pid_b, 0, energy_b, 0, &vm_b, &ts_b);

        assert!(enc_a != enc_b, "distinct records must not share an encoding");
    }

    #[kani::proof]
    fn kani_leaf_never_collides_with_internal() {
        let left: [u8; 32] = kani::any();
        let right: [u8; 32] = kani::any();

        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&left);
        raw[32..].copy_from_slice(&right);

        assert!(encode_leaf(&raw)[..] != encode_internal(&left, &right)[..]);
    }

    #[kani::proof]
    fn kani_root_binds_leaf_count() {
        let n1: u64 = kani::any();
        let n2: u64 = kani::any();
        kani::assume(n1 != n2);

        let subtree: [u8; 32] = kani::any();

        assert!(encode_root(n1, &subtree) != encode_root(n2, &subtree));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_tree_build_is_total() {
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 4);

        let mut leaves: Vec<[u8; 32]> = Vec::new();
        let mut i = 0;
        while i < n {
            leaves.push(kani::any());
            i += 1;
        }

        let root = compute_root_from_leaves(&leaves);
        assert!(root.is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(pid: u32) -> EnergyRecord {
        EnergyRecord::new(
            pid,
            pid as f64 * 0.1,
            pid as f64 * 0.001,
            pid as f64 * 0.5,
            "test_vm".to_string(),
            format!("2026-02-06T10:00:{:02}Z", pid % 60),
        )
    }

    #[test]
    fn test_merkle_tree_single_record() {
        let records = vec![make_record(1)];
        let tree = MerkleTree::build(&records);

        assert!(tree.root.is_some());
        assert_eq!(tree.leaf_count, 1);
        assert!(tree.verify_record(&records[0], 0));
    }

    #[test]
    fn test_merkle_tree_multiple_records() {
        let records: Vec<EnergyRecord> = (1..=4).map(make_record).collect();
        let tree = MerkleTree::build(&records);

        assert!(tree.root.is_some());
        assert_eq!(tree.leaf_count, 4);

        for (i, record) in records.iter().enumerate() {
            assert!(tree.verify_record(record, i));
        }
    }

    #[test]
    fn test_merkle_proof() {
        let records: Vec<EnergyRecord> = (1..=4).map(make_record).collect();
        let tree = MerkleTree::build(&records);
        let root_hash = tree.root_hash().unwrap();

        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(&root_hash), "Proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_tamper_detection() {
        let records: Vec<EnergyRecord> = (1..=4).map(make_record).collect();
        let tree = MerkleTree::build(&records);

        let tampered = make_record(999);
        assert!(!tree.verify_record(&tampered, 0));
    }

    #[test]
    fn test_compute_root_from_leaves() {
        let records: Vec<EnergyRecord> = (1..=4).map(make_record).collect();
        let tree = MerkleTree::build(&records);

        let recomputed = compute_root_from_leaves(&tree.leaf_hashes).unwrap();
        assert_eq!(tree.root_hash().unwrap(), recomputed);
    }

    #[test]
    fn test_odd_leaf_padding_is_not_ambiguous() {
        let r1 = make_record(1);
        let r2 = make_record(2);
        let r3 = make_record(3);

        let three = vec![r1.clone(), r2.clone(), r3.clone()];
        let four = vec![r1, r2, r3.clone(), r3];

        let root_three = MerkleTree::build(&three).root_hash().unwrap();
        let root_four = MerkleTree::build(&four).root_hash().unwrap();

        assert_ne!(
            root_three, root_four,
            "a 3-leaf tree must not share a root with a 4-leaf tree"
        );
    }

    #[test]
    fn test_to_bytes_resists_delimiter_injection() {
        let a = EnergyRecord::new(1, 1.0, 2.0, 3.0, "vm|evil".to_string(), "ts".to_string());
        let b = EnergyRecord::new(1, 1.0, 2.0, 3.0, "vm".to_string(), "evil|ts".to_string());

        assert_ne!(
            a.to_bytes(),
            b.to_bytes(),
            "distinct records must not share a serialization"
        );
        assert_ne!(hash_leaf(&a.to_bytes()), hash_leaf(&b.to_bytes()));
    }

    #[test]
    fn test_to_bytes_binds_full_float_precision() {
        let a = EnergyRecord::new(1, 0.0, 1.000_000_001, 0.0, "vm".to_string(), "ts".to_string());
        let b = EnergyRecord::new(1, 0.0, 1.000_000_002, 0.0, "vm".to_string(), "ts".to_string());

        assert_ne!(
            a.to_bytes(),
            b.to_bytes(),
            "energy values differing below 1e-6 must still hash differently"
        );
    }

    #[test]
    fn test_leaf_and_internal_domains_are_disjoint() {
        let left = [0xAAu8; 32];
        let right = [0xBBu8; 32];

        let mut as_leaf_bytes = [0u8; 64];
        as_leaf_bytes[..32].copy_from_slice(&left);
        as_leaf_bytes[32..].copy_from_slice(&right);

        assert_ne!(
            hash_leaf(&as_leaf_bytes),
            hash_pair(&left, &right),
            "a leaf must never collide with an internal node over the same bytes"
        );
    }

    #[test]
    fn test_root_commits_to_leaf_count() {
        let subtree = [0x42u8; 32];
        assert_ne!(commit_root(3, &subtree), commit_root(4, &subtree));
    }
}
