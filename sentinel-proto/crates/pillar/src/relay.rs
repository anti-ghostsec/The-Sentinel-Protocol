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
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use sentinel_core::mix::Step;

use crate::{random_below, write_coarse, MixCtx};

/// Give up after this many days.
pub(crate) const KEEP_DAYS: u64 = 7;
/// Most messages waiting at once (older ones are kept; new ones refused).
const MAX_WAITING: usize = 50_000;

fn dir(store: &Path) -> PathBuf {
    store.join("relay")
}

/// Keep a step that couldn't be carried out yet. False if the queue is full.
pub(crate) async fn keep(store: &Path, step: &Step) -> bool {
    let d = dir(store);
    let _ = tokio::fs::create_dir_all(&d).await;
    if std::fs::read_dir(&d).map(|r| r.count()).unwrap_or(0) >= MAX_WAITING {
        return false;
    }
    let mut b = Vec::new();
    if ciborium::into_writer(step, &mut b).is_err() {
        return false;
    }
    let name = data_encoding::HEXLOWER.encode(&blake3::derive_key("sentinel/v1/relay-file", &b)[..16]);
    write_coarse(&d.join(name), &b).await.is_ok()
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
                    let _ = std::fs::remove_file(e.path());
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
                async move {
                    let Ok(b) = tokio::fs::read(&path).await else { return (name, true) };
                    let Ok(step) = ciborium::from_reader::<Step, _>(b.as_slice()) else {
                        let _ = tokio::fs::remove_file(&path).await;
                        return (name, true);
                    };
                    let ok = matches!(tokio::time::timeout(Duration::from_secs(120), crate::mix_step(&ctx, &step)).await, Ok(Ok(())));
                    if ok {
                        let _ = tokio::fs::remove_file(&path).await;
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
