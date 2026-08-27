use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Checkpoint {

    pub latest_chained_root: [u8; 32],

    pub block_count: u64,

    pub vm_name: String,

    pub last_updated: u64,
}

impl Checkpoint {

    pub fn new(vm_name: String) -> Self {
        Self {
            latest_chained_root: [0u8; 32],
            block_count: 0,
            vm_name,
            last_updated: current_timestamp(),
        }
    }

    pub fn update(&mut self, chained_root: [u8; 32], block_count: u64) {
        self.latest_chained_root = chained_root;
        self.block_count = block_count;
        self.last_updated = current_timestamp();
    }

    pub fn chained_root_hex(&self) -> String {
        hex::encode(self.latest_chained_root)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.latest_chained_root);
        bytes.extend_from_slice(&self.block_count.to_le_bytes());
        bytes.extend_from_slice(&self.last_updated.to_le_bytes());
        bytes.extend_from_slice(self.vm_name.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 48 {
            return None;
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes[0..32]);

        let count = u64::from_le_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35],
            bytes[36], bytes[37], bytes[38], bytes[39],
        ]);

        let timestamp = u64::from_le_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43],
            bytes[44], bytes[45], bytes[46], bytes[47],
        ]);

        let vm_name = String::from_utf8_lossy(&bytes[48..]).to_string();

        Some(Self {
            latest_chained_root: root,
            block_count: count,
            vm_name,
            last_updated: timestamp,
        })
    }
}

pub struct SealedStorage {

    path: String,

    seal_key: [u8; 32],
}

impl SealedStorage {

    pub fn new(path: &str) -> Self {

        let seal_key = derive_seal_key();

        Self {
            path: path.to_string(),
            seal_key,
        }
    }

    pub fn save(&self, checkpoint: &Checkpoint) -> Result<(), SealError> {
        let plaintext = checkpoint.to_bytes();

        let mac = compute_hmac(&self.seal_key, &plaintext);

        let mut sealed = Vec::new();
        sealed.extend_from_slice(&mac);
        sealed.extend_from_slice(&plaintext);

        fs::write(&self.path, &sealed)
            .map_err(|e| SealError::IoError(e.to_string()))?;

        println!("[SGX-SEAL] Checkpoint saved: block={}, root={}...",
            checkpoint.block_count,
            &checkpoint.chained_root_hex()[..16]
        );

        Ok(())
    }

    pub fn load(&self) -> Result<Option<Checkpoint>, SealError> {
        let path = Path::new(&self.path);
        if !path.exists() {
            return Ok(None);
        }

        let sealed = fs::read(&self.path)
            .map_err(|e| SealError::IoError(e.to_string()))?;

        if sealed.len() < 32 {
            return Err(SealError::InvalidData("Too short".to_string()));
        }

        let stored_mac = &sealed[0..32];
        let plaintext = &sealed[32..];

        let computed_mac = compute_hmac(&self.seal_key, plaintext);
        if stored_mac != computed_mac {
            return Err(SealError::TamperingDetected);
        }

        let checkpoint = Checkpoint::from_bytes(plaintext)
            .ok_or_else(|| SealError::InvalidData("Parse failed".to_string()))?;

        println!("[SGX-SEAL] Checkpoint loaded: block={}, root={}...",
            checkpoint.block_count,
            &checkpoint.chained_root_hex()[..16]
        );

        Ok(Some(checkpoint))
    }

    pub fn verify_against_db(
        &self,
        db_block_count: u64,
        db_latest_root: &str,
    ) -> VerifyResult {
        let checkpoint = match self.load() {
            Ok(Some(cp)) => cp,
            Ok(None) => return VerifyResult::NoCheckpoint,
            Err(e) => return VerifyResult::LoadError(format!("{:?}", e)),
        };

        if db_block_count != checkpoint.block_count {
            return VerifyResult::BlockCountMismatch {
                checkpoint: checkpoint.block_count,
                database: db_block_count,
            };
        }

        let cp_root = checkpoint.chained_root_hex();
        if db_latest_root != cp_root {
            return VerifyResult::RootMismatch {
                checkpoint: cp_root,
                database: db_latest_root.to_string(),
            };
        }

        VerifyResult::Valid
    }
}

#[derive(Debug, Clone)]
pub enum VerifyResult {
    Valid,
    NoCheckpoint,
    LoadError(String),
    BlockCountMismatch { checkpoint: u64, database: u64 },
    RootMismatch { checkpoint: String, database: String },
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerifyResult::Valid)
    }

    pub fn is_no_checkpoint(&self) -> bool {
        matches!(self, VerifyResult::NoCheckpoint)
    }
}

#[derive(Debug)]
pub enum SealError {
    IoError(String),
    InvalidData(String),
    TamperingDetected,
}

fn derive_seal_key() -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let _ = Sha256::new();
    crate::enclave_master_key(b"seal")
}

fn compute_hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);

    let result = mac.finalize().into_bytes();
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&result);
    hmac
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn anchor_master_key() -> [u8; 32] {
    crate::enclave_master_key(b"anchor")
}

pub fn sign_checkpoint(tenant: &str, block_number: u64, chained_root: &[u8; 32]) -> [u8; 32] {
    let mut derive_msg = Vec::with_capacity(3 + tenant.len());
    derive_msg.extend_from_slice(b"vm:");
    derive_msg.extend_from_slice(tenant.as_bytes());
    let key = compute_hmac(&anchor_master_key(), &derive_msg);

    let msg = crate::pure::encode_checkpoint_msg(tenant.as_bytes(), block_number, chained_root);
    compute_hmac(&key, &msg)
}

#[cfg(feature = "use_mbedtls")]
fn anchor_signing_key() -> Result<mbedtls::pk::Pk, String> {
    use mbedtls::bignum::Mpi;
    use mbedtls::ecp::EcGroup;
    use mbedtls::pk::{EcGroupId, Pk};
    use sha2::{Digest, Sha256};

    let mut material = crate::enclave_build_bound_key(b"anchor-ecdsa-p256-v2");
    for counter in 0u8..8 {
        let group = EcGroup::new(EcGroupId::SecP256R1).map_err(|e| format!("EcGroup: {:?}", e))?;
        if let Ok(scalar) = Mpi::from_binary(&material) {
            if let Ok(pk) = Pk::private_from_ec_components(group, scalar) {
                return Ok(pk);
            }
        }
        let mut h = Sha256::new();
        h.update(b"vpma-anchor-scalar-retry");
        h.update(material);
        h.update([counter]);
        material = h.finalize().into();
    }
    Err("could not derive a valid P-256 scalar from the enclave key".to_string())
}

#[cfg(feature = "use_mbedtls")]
fn anchor_sig_message(tenant: &str, block_number: u64, chained_root: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"VPMA-anchor-ecdsa-p256-v2\0");

    h.update(crate::pure::encode_checkpoint_msg(tenant.as_bytes(), block_number, chained_root));
    h.finalize().into()
}

#[cfg(feature = "use_mbedtls")]
pub fn public_anchor_signature(
    tenant: &str,
    block_number: u64,
    chained_root: &[u8; 32],
) -> Result<(String, String), String> {
    use mbedtls::hash::Type as MdType;
    use mbedtls::rng::{CtrDrbg, Rdseed};
    use std::sync::Arc as StdArc;

    let mut pk = anchor_signing_key()?;
    let digest = anchor_sig_message(tenant, block_number, chained_root);

    let mut rng = CtrDrbg::new(StdArc::new(Rdseed), None).map_err(|e| format!("rng: {:?}", e))?;

    let mut sig = vec![0u8; mbedtls::pk::ECDSA_MAX_LEN];
    let n = pk
        .sign_deterministic(MdType::Sha256, &digest, &mut sig, &mut rng)
        .map_err(|e| format!("sign: {:?}", e))?;
    sig.truncate(n);

    let pubkey = pk.write_public_der_vec().map_err(|e| format!("pubkey: {:?}", e))?;
    Ok((hex::encode(sig), hex::encode(pubkey)))
}

#[cfg(feature = "use_mbedtls")]
pub fn public_anchor_key_hex() -> Result<String, String> {
    let mut pk = anchor_signing_key()?;
    let der = pk.write_public_der_vec().map_err(|e| format!("pubkey: {:?}", e))?;
    Ok(hex::encode(der))
}

pub fn checkpoint_line(tenant: &str, block_number: u64, chained_root: &[u8; 32]) -> String {
    let sig = sign_checkpoint(tenant, block_number, chained_root);
    format!(
        "checkpoint-v1|{}|{}|{}|{}",
        tenant,
        block_number,
        hex::encode(chained_root),
        hex::encode(sig)
    )
}

pub fn verify_checkpoint_line(tenant: &str, line: &str) -> Option<(u64, [u8; 32])> {

    let parsed = crate::pure::parse_checkpoint_line(line.trim().as_bytes(), tenant.as_bytes())?;

    let expected = sign_checkpoint(tenant, parsed.block_number, &parsed.root);
    if !crate::pure::ct_eq_32(&expected, &parsed.sig) {
        return None;
    }

    Some((parsed.block_number, parsed.root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_checkpoint_serialization() {
        let mut cp = Checkpoint::new("test_vm".to_string());
        cp.update([0xAB; 32], 100);

        let bytes = cp.to_bytes();
        let restored = Checkpoint::from_bytes(&bytes).unwrap();

        assert_eq!(restored.latest_chained_root, [0xAB; 32]);
        assert_eq!(restored.block_count, 100);
        assert_eq!(restored.vm_name, "test_vm");
    }

    #[test]
    fn test_sealed_storage() {
        let path = "/tmp/test_checkpoint.sealed";
        let storage = SealedStorage::new(path);

        let mut cp = Checkpoint::new("test_vm".to_string());
        cp.update([0xCD; 32], 50);

        storage.save(&cp).unwrap();

        let loaded = storage.load().unwrap().unwrap();
        assert_eq!(loaded.block_count, 50);
        assert_eq!(loaded.latest_chained_root, [0xCD; 32]);

        fs::remove_file(path).ok();
    }

    #[test]
    fn test_tamper_detection() {
        let path = "/tmp/test_tamper.sealed";
        let storage = SealedStorage::new(path);

        let cp = Checkpoint::new("test_vm".to_string());
        storage.save(&cp).unwrap();

        let mut data = fs::read(path).unwrap();
        if data.len() > 40 {
            data[40] ^= 0xFF;
        }
        fs::write(path, &data).unwrap();

        let result = storage.load();
        assert!(matches!(result, Err(SealError::TamperingDetected)));

        fs::remove_file(path).ok();
    }
}
