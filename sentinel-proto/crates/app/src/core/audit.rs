//! Proofs of storage, client side (spec §14.8).
//!
//! When one of my uploads finishes, I precompute a few single-use
//! challenges per Archive: a random 32-byte nonce and the keyed hash of a
//! random chunk that Archive should hold. Later, at random times unrelated
//! to anything I do, one challenge is sent over a fresh isolated circuit.
//! An Archive can only answer if it still has the exact bytes. Results feed
//! a local health score; Archives that keep failing get no new files.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use sentinel_core::wire::{Request, Response};
use serde::{Deserialize, Serialize};

use super::{request, unix_now, Core};

/// Challenges kept per Archive per file.
pub const PER_HOST: usize = 4;

#[derive(Clone, Serialize, Deserialize)]
pub struct Audit {
    pub host: String,
    pub addr: [u8; 32],
    pub nonce: [u8; 32],
    pub expected: [u8; 32],
    /// Not before this Unix time.
    pub due: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Health {
    pub passed: u32,
    pub failed: u32,
    pub last: u64,
}

impl Health {
    /// Repeatedly failing: stop giving it new files.
    pub fn unreliable(&self) -> bool {
        self.failed >= 2 && self.failed * 2 >= self.passed
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageHealth {
    pub archives: usize,
    pub passed: u32,
    pub failed: u32,
    pub unreliable: usize,
    pub pending: usize,
}

/// Random due time 1-30 days ahead (spread so checks reveal no pattern).
pub fn random_due() -> u64 {
    unix_now() + 86_400 + u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % (29 * 86_400)
}

impl Core {
    /// Background auditor: one due challenge every ~20-60 minutes.
    pub(super) async fn run_auditor(self: std::sync::Arc<Self>) {
        loop {
            let wait = 1200 + u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % 2400;
            tokio::time::sleep(Duration::from_secs(wait)).await;
            let _ = self.audit_once(false).await;
        }
    }

    /// Run one due challenge (`any`: one not yet due, for "Check now").
    pub async fn audit_once(&self, any: bool) -> Result<bool> {
        let (_, store) = self.unlocked()?;
        let now = unix_now();
        let due: Vec<usize> = store.audits.iter().enumerate().filter(|(_, a)| any || a.due <= now).map(|(i, _)| i).collect();
        if due.is_empty() {
            return Ok(false);
        }
        let pick = due[(u32::from_le_bytes(sentinel_core::random_bytes::<4>()) as usize) % due.len()];
        let a = store.audits[pick].clone();
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let ok = async {
            let mut s = net.connect_hedged(&a.host).await.ok()?;
            match request(&mut s, &Request::Prove { addr: a.addr, nonce: a.nonce }).await.ok()? {
                Response::Proof(p) => Some(p == a.expected),
                _ => Some(false),
            }
        }
        .await;
        self.update(|s| {
            // Single use: a nonce, once sent, is known to the Archive.
            s.audits.retain(|x| !(x.host == a.host && x.nonce == a.nonce));
            if let Some(ok) = ok {
                let h = s.archive_health.entry(a.host.clone()).or_default();
                if ok {
                    h.passed += 1;
                } else {
                    h.failed += 1;
                }
                h.last = now - now % 86_400;
            }
            // (Unreachable: try again later, no verdict.)
            if ok.is_none() {
                let mut retry = a.clone();
                retry.due = now + 6 * 3600;
                s.audits.push(retry);
            }
        })?;
        Ok(ok.unwrap_or(false))
    }

    pub fn storage_health(&self) -> Result<StorageHealth> {
        let (_, s) = self.unlocked()?;
        let mut hosts: HashMap<&str, ()> = HashMap::new();
        for a in &s.audits {
            hosts.insert(&a.host, ());
        }
        for h in s.archive_health.keys() {
            hosts.insert(h, ());
        }
        Ok(StorageHealth {
            archives: hosts.len(),
            passed: s.archive_health.values().map(|h| h.passed).sum(),
            failed: s.archive_health.values().map(|h| h.failed).sum(),
            unreliable: s.archive_health.values().filter(|h| h.unreliable()).count(),
            pending: s.audits.len(),
        })
    }
}
