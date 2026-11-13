//! One-time keys, handed out once each.
//!
//! An app leaves a few signed one-time keys per day in a bundle named by
//! the key that signed them (a different key every day, so bundles can't
//! be linked to each other or to a mailbox). Someone starting a
//! conversation takes one, and nobody else gets the same one: that is what
//! makes it one-time. This Pillar can't make keys for a bundle (it checks
//! the signatures, and so does whoever claims one); at worst it withholds
//! them, and the sender uses the card's fallback key instead.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use sentinel_core::dm;

/// Bundles live this long (a card lists a day's bundle from the day before
/// through the day itself; a day of slack for clocks).
const KEEP: Duration = Duration::from_secs(3 * 86_400);
/// Most bundles kept at once (about 1.5 KB each when full).
const MAX_BUNDLES: usize = 20_000;

static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn dir(store: &Path) -> PathBuf {
    store.join("prekeys")
}

fn path(store: &Path, bundle: &[u8; 32]) -> PathBuf {
    dir(store).join(data_encoding::HEXLOWER.encode(bundle))
}

/// Add entries to a bundle: only ones its key signed, each kept once, up
/// to `dm::MAX_PREKEYS`.
pub async fn put(store: &Path, bundle: &[u8; 32], entries: &[u8]) -> Result<(), &'static str> {
    if entries.is_empty() || entries.len() % dm::PREKEY_ENTRY != 0 || entries.len() > dm::MAX_PREKEYS * dm::PREKEY_ENTRY {
        return Err("invalid prekeys");
    }
    if entries.chunks_exact(dm::PREKEY_ENTRY).any(|e| dm::check_prekey(bundle, e).is_none()) {
        return Err("invalid prekeys");
    }
    let _guard = LOCK.lock().await;
    let p = path(store, bundle);
    let mut have = match std::fs::read(&p) {
        Ok(have) => have,
        Err(_) => {
            let _ = std::fs::create_dir_all(dir(store));
            if std::fs::read_dir(dir(store)).map(|d| d.count()).unwrap_or(0) >= MAX_BUNDLES {
                return Err("Pillar is full");
            }
            Vec::new()
        }
    };
    for e in entries.chunks_exact(dm::PREKEY_ENTRY) {
        if have.len() >= dm::MAX_PREKEYS * dm::PREKEY_ENTRY {
            break;
        }
        if !have.chunks_exact(dm::PREKEY_ENTRY).any(|h| h[..32] == e[..32]) {
            have.extend_from_slice(e);
        }
    }
    std::fs::write(&p, have).map_err(|_| "storage error")
}

/// Take one entry out of a bundle.
pub async fn claim(store: &Path, bundle: &[u8; 32]) -> Option<Vec<u8>> {
    let _guard = LOCK.lock().await;
    let p = path(store, bundle);
    let mut have = std::fs::read(&p).ok()?;
    if have.len() < dm::PREKEY_ENTRY || have.len() % dm::PREKEY_ENTRY != 0 {
        return None;
    }
    let entry = have.split_off(have.len() - dm::PREKEY_ENTRY);
    // Written back before the key goes out: it must never go out twice.
    std::fs::write(&p, have).ok()?;
    Some(entry)
}

/// Delete bundles past their time.
pub fn expire(store: &Path) {
    let Ok(rd) = std::fs::read_dir(dir(store)) else { return };
    for f in rd.flatten() {
        // Counted from the last upload or claim (creation time isn't
        // available everywhere).
        let old = f.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > KEEP);
        if old {
            let _ = std::fs::remove_file(f.path());
        }
    }
}

/// Claims seen lately, so one proof of work takes one key. Memory only.
#[derive(Default)]
pub struct Claims(Mutex<HashSet<[u8; 32]>>);

impl Claims {
    pub fn first_time(&self, bundle: &[u8; 32], salt: &[u8; 16]) -> bool {
        let mut m = bundle.to_vec();
        m.extend_from_slice(salt);
        let mut seen = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.len() >= 200_000 {
            seen.clear();
        }
        seen.insert(*blake3::hash(&m).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn each_key_goes_out_once_and_only_signed_keys_get_in() {
        let store = std::env::temp_dir().join(format!("sentinel-prekeys-{}", data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<8>())));
        let signer = dm::prekey_signer(&[7; 32], 100);
        let bundle = signer.verifying_key().to_bytes();
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let entries = dm::prekey_bundle(&signer, &keys);
        put(&store, &bundle, &entries).await.unwrap();
        // The same keys again are kept once.
        put(&store, &bundle, &entries).await.unwrap();
        // Someone else's keys for this bundle are refused.
        let other = dm::prekey_bundle(&dm::prekey_signer(&[8; 32], 100), &[[9u8; 32]]);
        assert!(put(&store, &bundle, &other).await.is_err());
        let mut got = Vec::new();
        while let Some(e) = claim(&store, &bundle).await {
            got.push(dm::check_prekey(&bundle, &e).expect("signed"));
        }
        got.sort();
        assert_eq!(got, keys);
        assert!(claim(&store, &[5; 32]).await.is_none());
        let claims = Claims::default();
        assert!(claims.first_time(&bundle, &[1; 16]));
        assert!(!claims.first_time(&bundle, &[1; 16]));
        let _ = std::fs::remove_dir_all(&store);
    }
}
