//! Local chunk storage (outbox for my uploads, cache for media I view).
//!
//! Chunk addresses are public: anyone holding a post can compute them. If
//! files on disk were named by address (or held the chunk bytes as-is), a
//! seized device could be checked against a known post to prove its owner
//! viewed or posted it. So every file here is **named by a keyed hash** of
//! the address and **encrypted again** under a key derived from the identity
//! — without the passphrase, the folder is unlinkable noise.
//!
//! The cache is bounded and is not used at all in High-risk mode (viewed
//! media then lives only in memory).

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Upper bound for the viewed-media cache.
const CACHE_LIMIT: u64 = 1024 * 1024 * 1024;

#[derive(Clone)]
pub struct LocalChunks {
    key: std::sync::Arc<Zeroizing<[u8; 32]>>,
    outbox: PathBuf,
    cache: PathBuf,
}

impl LocalChunks {
    pub fn open(keys: &super::Keys) -> Result<Self> {
        let key = Zeroizing::new(blake3::derive_key("sentinel/v0/local-chunks", &keys.root().to_bytes()));
        let root = super::data_dir()?;
        let outbox = root.join("outbox");
        let cache = root.join("cache");
        std::fs::create_dir_all(&outbox)?;
        std::fs::create_dir_all(&cache)?;
        // Older builds cached chunks under their public addresses: remove.
        let _ = std::fs::remove_dir_all(root.join("media"));
        Ok(LocalChunks { key: std::sync::Arc::new(key), outbox, cache })
    }

    fn name(&self, addr: &[u8; 32]) -> String {
        data_encoding::HEXLOWER.encode(&blake3::keyed_hash(&self.key, addr).as_bytes()[..20])
    }

    fn seal(&self, ct: &[u8]) -> Vec<u8> {
        let nonce = sentinel_core::random_bytes::<24>();
        let mut out = nonce.to_vec();
        out.extend(XChaCha20Poly1305::new((&**self.key).into()).encrypt(XNonce::from_slice(&nonce), ct).expect("encrypt"));
        out
    }

    fn unseal(&self, b: &[u8], addr: &[u8; 32]) -> Option<Vec<u8>> {
        if b.len() < 24 {
            return None;
        }
        let ct = XChaCha20Poly1305::new((&**self.key).into()).decrypt(XNonce::from_slice(&b[..24]), &b[24..]).ok()?;
        (sentinel_core::media::address(&ct) == *addr).then_some(ct)
    }

    /// Keep a chunk I'm uploading until every host has it.
    pub fn put_outbox(&self, addr: &[u8; 32], ct: &[u8]) -> Result<()> {
        let path = self.outbox.join(self.name(addr));
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.seal(ct))?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn remove_outbox(&self, addr: &[u8; 32]) {
        let _ = std::fs::remove_file(self.outbox.join(self.name(addr)));
    }

    /// Cache a fetched chunk (skipped when `enabled` is false).
    pub fn put_cache(&self, addr: &[u8; 32], ct: &[u8], enabled: bool) {
        if !enabled {
            return;
        }
        let path = self.cache.join(self.name(addr));
        if path.exists() {
            return;
        }
        let _ = std::fs::write(&path, self.seal(ct));
    }

    /// A chunk from the outbox or cache, verified against its address.
    pub fn get(&self, addr: &[u8; 32]) -> Option<Vec<u8>> {
        let n = self.name(addr);
        for dir in [&self.outbox, &self.cache] {
            if let Ok(b) = std::fs::read(dir.join(&n)) {
                if let Some(ct) = self.unseal(&b, addr) {
                    return Some(ct);
                }
            }
        }
        None
    }

    /// Delete the oldest cache files beyond the size limit.
    pub fn trim_cache(&self) {
        let Ok(rd) = std::fs::read_dir(&self.cache) else { return };
        let mut files: Vec<(std::time::SystemTime, u64, PathBuf)> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let m = e.metadata().ok()?;
                Some((m.modified().ok()?, m.len(), e.path()))
            })
            .collect();
        let mut total: u64 = files.iter().map(|f| f.1).sum();
        if total <= CACHE_LIMIT {
            return;
        }
        files.sort_by_key(|f| f.0);
        for (_, len, p) in files {
            if total <= CACHE_LIMIT * 3 / 4 {
                break;
            }
            if std::fs::remove_file(&p).is_ok() {
                total -= len;
            }
        }
    }

    /// Remove every cached chunk (used when High-risk mode is turned on).
    pub fn clear_cache(&self) {
        if let Ok(rd) = std::fs::read_dir(&self.cache) {
            for e in rd.filter_map(|e| e.ok()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

pub fn not_found() -> anyhow::Error {
    anyhow!("media not available")
}
