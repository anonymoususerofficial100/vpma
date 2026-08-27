use crate::merkle::{sha256, hash_pair, EnergyRecord, MerkleTree, MerkleNode};

#[derive(Clone, Debug)]
pub struct Block {

    pub block_number: u64,

    pub vm_name: String,

    pub merkle_root: [u8; 32],

    pub prev_chained_root: [u8; 32],

    pub chained_root: [u8; 32],

    pub record_count: u32,

    pub timestamp: String,

    pub records: Vec<EnergyRecord>,

    pub leaf_hashes: Vec<[u8; 32]>,

    pub internal_nodes: Vec<MerkleNode>,

    pub tree_height: usize,
}

impl Block {

    pub fn new(
        block_number: u64,
        vm_name: String,
        prev_chained_root: [u8; 32],
        records: Vec<EnergyRecord>,
        timestamp: String,
    ) -> Self {

        let tree = MerkleTree::build(&records);
        let merkle_root = tree.root_hash().unwrap_or([0u8; 32]);
        let leaf_hashes = tree.leaf_hashes.clone();
        let internal_nodes = tree.internal_nodes.clone();
        let tree_height = tree.height;
        let record_count = records.len() as u32;

        let chained_root = compute_chained_root(&prev_chained_root, &merkle_root);

        Self {
            block_number,
            vm_name,
            merkle_root,
            prev_chained_root,
            chained_root,
            record_count,
            timestamp,
            records,
            leaf_hashes,
            internal_nodes,
            tree_height,
        }
    }

    pub fn genesis(vm_name: String, records: Vec<EnergyRecord>, timestamp: String) -> Self {
        Self::new(0, vm_name, [0u8; 32], records, timestamp)
    }

    pub fn merkle_root_hex(&self) -> String {
        hex::encode(self.merkle_root)
    }

    pub fn prev_chained_root_hex(&self) -> String {
        hex::encode(self.prev_chained_root)
    }

    pub fn chained_root_hex(&self) -> String {
        hex::encode(self.chained_root)
    }

    pub fn verify(&self) -> BlockVerifyResult {

        let tree = MerkleTree::build(&self.records);
        let computed_merkle_root = tree.root_hash().unwrap_or([0u8; 32]);

        if computed_merkle_root != self.merkle_root {
            return BlockVerifyResult::MerkleRootMismatch {
                stored: hex::encode(self.merkle_root),
                computed: hex::encode(computed_merkle_root),
            };
        }

        let computed_chained = compute_chained_root(&self.prev_chained_root, &self.merkle_root);
        if computed_chained != self.chained_root {
            return BlockVerifyResult::ChainedRootMismatch {
                stored: hex::encode(self.chained_root),
                computed: hex::encode(computed_chained),
            };
        }

        if self.records.len() as u32 != self.record_count {
            return BlockVerifyResult::RecordCountMismatch {
                stored: self.record_count,
                actual: self.records.len() as u32,
            };
        }

        BlockVerifyResult::Valid
    }

    pub fn verify_chain_link(&self, prev_block: &Block) -> bool {
        self.prev_chained_root == prev_block.chained_root
    }
}

#[derive(Debug, Clone)]
pub enum BlockVerifyResult {
    Valid,
    MerkleRootMismatch { stored: String, computed: String },
    ChainedRootMismatch { stored: String, computed: String },
    RecordCountMismatch { stored: u32, actual: u32 },
}

impl BlockVerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, BlockVerifyResult::Valid)
    }
}

pub struct Blockchain {

    pub vm_name: String,

    pub current_block_number: u64,

    pub latest_chained_root: [u8; 32],

    accumulated_records: Vec<EnergyRecord>,

    batch_size: usize,
}

impl Blockchain {

    pub fn new(vm_name: String, batch_size: usize) -> Self {
        Self {
            vm_name,
            current_block_number: 0,
            latest_chained_root: [0u8; 32],
            accumulated_records: Vec::new(),
            batch_size,
        }
    }

    pub fn from_checkpoint(
        vm_name: String,
        block_number: u64,
        latest_chained_root: [u8; 32],
        batch_size: usize,
    ) -> Self {
        Self {
            vm_name,
            current_block_number: block_number,
            latest_chained_root,
            accumulated_records: Vec::new(),
            batch_size,
        }
    }

    pub fn add_record(&mut self, record: EnergyRecord) -> Option<Block> {
        self.accumulated_records.push(record);

        if self.accumulated_records.len() >= self.batch_size {
            Some(self.create_block())
        } else {
            None
        }
    }

    pub fn flush(&mut self) -> Option<Block> {
        if self.accumulated_records.is_empty() {
            return None;
        }
        Some(self.create_block())
    }

    fn create_block(&mut self) -> Block {
        let records = std::mem::take(&mut self.accumulated_records);
        let timestamp = get_timestamp();

        let block = Block::new(
            self.current_block_number,
            self.vm_name.clone(),
            self.latest_chained_root,
            records,
            timestamp,
        );

        self.latest_chained_root = block.chained_root;
        self.current_block_number += 1;

        block
    }

    pub fn accumulated_count(&self) -> usize {
        self.accumulated_records.len()
    }

    pub fn latest_chained_root_hex(&self) -> String {
        hex::encode(self.latest_chained_root)
    }
}

pub fn compute_chained_root(prev: &[u8; 32], merkle: &[u8; 32]) -> [u8; 32] {

    sha256(&crate::pure::encode_chained_root(prev, merkle))
}

pub fn get_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let mut year = 1970u64;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }
    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

pub fn verify_blockchain(blocks: &[Block]) -> ChainVerifyResult {
    if blocks.is_empty() {
        return ChainVerifyResult::Valid { block_count: 0 };
    }

    let mut prev_chained_root = [0u8; 32];

    for (i, block) in blocks.iter().enumerate() {

        let block_result = block.verify();
        if !block_result.is_valid() {
            return ChainVerifyResult::BlockInvalid {
                block_number: block.block_number,
                reason: format!("{:?}", block_result),
            };
        }

        if block.prev_chained_root != prev_chained_root {
            return ChainVerifyResult::ChainBroken {
                block_number: block.block_number,
                expected_prev: hex::encode(prev_chained_root),
                actual_prev: hex::encode(block.prev_chained_root),
            };
        }

        if block.block_number != i as u64 {
            return ChainVerifyResult::BlockNumberGap {
                expected: i as u64,
                actual: block.block_number,
            };
        }

        prev_chained_root = block.chained_root;
    }

    ChainVerifyResult::Valid {
        block_count: blocks.len() as u64,
    }
}

#[derive(Debug, Clone)]
pub enum ChainVerifyResult {
    Valid { block_count: u64 },
    BlockInvalid { block_number: u64, reason: String },
    ChainBroken { block_number: u64, expected_prev: String, actual_prev: String },
    BlockNumberGap { expected: u64, actual: u64 },
}

impl ChainVerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ChainVerifyResult::Valid { .. })
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
    fn test_block_creation() {
        let records: Vec<EnergyRecord> = (1..=10).map(make_record).collect();
        let block = Block::genesis("test_vm".to_string(), records, "2026-02-06T10:00:00Z".to_string());

        assert_eq!(block.block_number, 0);
        assert_eq!(block.record_count, 10);
        assert_eq!(block.prev_chained_root, [0u8; 32]);
        assert!(block.verify().is_valid());
    }

    #[test]
    fn test_blockchain_accumulation() {
        let mut blockchain = Blockchain::new("test_vm".to_string(), 5);

        for i in 1..=4 {
            assert!(blockchain.add_record(make_record(i)).is_none());
        }
        assert_eq!(blockchain.accumulated_count(), 4);

        let block = blockchain.add_record(make_record(5));
        assert!(block.is_some());
        assert_eq!(blockchain.accumulated_count(), 0);
    }

    #[test]
    fn test_blockchain_chain() {
        let mut blockchain = Blockchain::new("test_vm".to_string(), 3);

        for i in 1..=3 {
            blockchain.add_record(make_record(i));
        }
        let block0 = blockchain.flush().unwrap();

        for i in 4..=6 {
            blockchain.add_record(make_record(i));
        }
        let block1 = blockchain.flush().unwrap();

        assert!(block1.verify_chain_link(&block0));
        assert_eq!(block1.prev_chained_root, block0.chained_root);
    }

    #[test]
    fn test_verify_blockchain() {
        let mut blockchain = Blockchain::new("test_vm".to_string(), 3);
        let mut blocks = Vec::new();

        for batch in 0..3 {
            for i in 0..3 {
                blockchain.add_record(make_record(batch * 3 + i + 1));
            }
            blocks.push(blockchain.flush().unwrap());
        }

        assert!(verify_blockchain(&blocks).is_valid());
    }

    #[test]
    fn test_tamper_detection() {
        let records: Vec<EnergyRecord> = (1..=4).map(make_record).collect();
        let mut block = Block::genesis("test_vm".to_string(), records, "2026-02-06T10:00:00Z".to_string());

        block.records[0] = make_record(999);

        assert!(!block.verify().is_valid());
    }
}
