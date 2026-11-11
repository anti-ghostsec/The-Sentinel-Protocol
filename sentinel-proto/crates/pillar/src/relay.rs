//! Messages a Pillar has taken on (mixed, or handed off by a sender whose
//! destination didn't answer) and couldn't pass on yet: kept on disk and
//! retried with growing gaps for up to [`KEEP_DAYS`], across restarts, so
//! a message is never stuck on the sender's device or lost because a
//! Pillar restarted.
//!
//! Only sealed packets are kept (their contents are unreadable here); files
//! are named by a hash and carry only the day they were written.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use futures::StreamExt;
use sentinel_core::mix::Step;

use crate::{random_below, write_coarse, MixCtx};

/// Give up after this many days.
pub(crate) const KEEP_DAYS: u64 = 7;
/// Most messages waiting at once (older ones are kept; new ones refused).
const MAX_WAITING: usize = 50_000;
/// Most bytes waiting at once (at most this, and at most an eighth of the
/// Pillar's quota): a flood of packets to Pillars that never answer can't
/// fill the disk.
pub(crate) const MAX_QUEUE_BYTES: u64 = 256 * 1024 * 1024;

fn dir(store: &Path) -> PathBuf {
    store.join("relay")
}

/// Bytes waiting in the queue (counted from disk once, then kept up to date).
fn queued(store: &Path) -> &'static AtomicU64 {
    static QUEUED: OnceLock<AtomicU64> = OnceLock::new();
    QUEUED.get_or_init(|| AtomicU64::new(crate::files_size(&dir(store))))
}

/// Whether one more file of `len` bytes may join a queue holding `files`
/// files and `bytes` bytes.
fn admit(files: usize, bytes: u64, len: u64, max_bytes: u64) -> bool {
    files < MAX_WAITING && bytes + len <= max_bytes
}

/// Keep a step that couldn't be carried out yet. False if the queue is full.
pub(crate) async fn keep(store: &Path, step: &Step, max_bytes: u64) -> bool {
    let d = dir(store);
    let _ = tokio::fs::create_dir_all(&d).await;
    let mut b = Vec::new();
    if ciborium::into_writer(step, &mut b).is_err() {
        return false;
    }
    let q = queued(store);
    let files = std::fs::read_dir(&d).map(|r| r.count()).unwrap_or(0);
    if !admit(files, q.load(Ordering::Relaxed), b.len() as u64, max_bytes) {
        return false;
    }
    let name = data_encoding::HEXLOWER.encode(&blake3::derive_key("sentinel/v1/relay-file", &b)[..16]);
    let path = d.join(name);
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return true; // the same step is already waiting
    }
    let ok = write_coarse(&path, &b).await.is_ok();
    if ok {
        q.fetch_add(b.len() as u64, Ordering::Relaxed);
    }
    ok
}

fn forget(store: &Path, len: u64) {
    let q = queued(store);
    let _ = q.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(len)));
}

fn age_days(m: &std::fs::Metadata) -> u64 {
    m.modified().ok().and_then(|t| t.elapsed().ok()).map(|e| e.as_secs() / 86_400).unwrap_or(0)
}

/// Retry what's waiting, forever: each one with growing gaps (5 minutes,
/// then up to 6 hours), several at once, each with a time limit.
pub(crate) async fn retry_loop(store: PathBuf, ctx: MixCtx) {
    let ctx = Arc::new(ctx);
    // When each file may be tried next, and how often it failed.
    let mut next: HashMap<String, (Instant, u32)> = HashMap::new();
    tokio::time::sleep(Duration::from_secs(60 + random_below(60))).await;
    loop {
        let d = dir(&store);
        let mut due = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let Ok(m) = e.metadata() else { continue };
                if age_days(&m) > KEEP_DAYS {
                    if std::fs::remove_file(e.path()).is_ok() {
                        forget(&store, m.len());
                    }
                    next.remove(&name);
                    continue;
                }
                if next.get(&name).is_none_or(|(t, _)| *t <= Instant::now()) {
                    due.push((name, e.path()));
                }
            }
        }
        let results: Vec<(String, bool)> = futures::stream::iter(due)
            .map(|(name, path)| {
                let ctx = Arc::clone(&ctx);
                let store = store.clone();
                async move {
                    let Ok(b) = tokio::fs::read(&path).await else { return (name, true) };
                    let Some(step) = ciborium::from_reader::<Step, _>(b.as_slice()).ok().filter(crate::step_target_ok) else {
                        // Unreadable, or (kept by an older version) not
                        // addressed to an onion service: dropped.
                        if tokio::fs::remove_file(&path).await.is_ok() {
                            forget(&store, b.len() as u64);
                        }
                        return (name, true);
                    };
                    let ok = matches!(tokio::time::timeout(Duration::from_secs(120), crate::mix_step(&ctx, &step)).await, Ok(Ok(())));
                    if ok && tokio::fs::remove_file(&path).await.is_ok() {
                        forget(&store, b.len() as u64);
                    }
                    (name, ok)
                }
            })
            .buffer_unordered(8)
            .collect()
            .await;
        for (name, ok) in results {
            if ok {
                next.remove(&name);
            } else {
                let fails = next.get(&name).map(|(_, f)| f + 1).unwrap_or(1);
                let gap = (300u64 << fails.min(7)).min(6 * 3600) + random_below(120);
                next.insert(name, (Instant::now() + Duration::from_secs(gap), fails));
            }
        }
        tokio::time::sleep(Duration::from_secs(120 + random_below(120))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_retry_queue_is_bounded_in_bytes_and_files() {
        assert!(admit(0, 0, 96 * 1024, MAX_QUEUE_BYTES));
        assert!(admit(10, MAX_QUEUE_BYTES - 1000, 1000, MAX_QUEUE_BYTES));
        assert!(!admit(10, MAX_QUEUE_BYTES - 1000, 1001, MAX_QUEUE_BYTES));
        assert!(!admit(MAX_WAITING, 0, 1, MAX_QUEUE_BYTES));
        // 50,000 of the largest packets no longer fit (that was ~4.8 GB).
        assert!(!admit(1000, 1000 * 96 * 1024, 96 * 1024, 64 * 1024 * 1024));
    }
}
