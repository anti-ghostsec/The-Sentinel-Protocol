//! Keeping the directory alive: a Pillar tests the Pillars and Archives it
//! lists at random times (each over its own circuit) and hands out only
//! ones that answered lately, so apps aren't sent to Pillars that are gone.
//!
//! What it learns stays in memory: nothing about other Pillars' uptime is
//! written to disk. Entries that keep failing are dropped from the lists.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt;
use sentinel_core::wire::{Request, Response};
use sentinel_net::SENTINEL_PORT;

use crate::{archives_path, exchange, known_path, random_below, read_known, Ctx, KNOWN_LOCK};

/// "Answered lately": within this long.
const RECENT: Duration = Duration::from_secs(6 * 3600);
/// Test an entry again after this long.
const RECHECK: Duration = Duration::from_secs(3 * 3600);
/// Drop an entry after this many failed tests in a row (with no answer in
/// the last day).
const DROP_AFTER: u32 = 3;
/// Entries tested per round, and at once.
const PER_ROUND: usize = 64;
const AT_ONCE: usize = 8;

#[derive(Default, Clone)]
struct Health {
    last_ok: Option<Instant>,
    last_check: Option<Instant>,
    fails: u32,
    oks: u32,
}

#[derive(Default)]
pub(crate) struct Directory {
    m: Mutex<HashMap<String, Health>>,
}

impl Directory {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Health>> {
        self.m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// It answered (a test, or the check before listing it).
    pub(crate) fn ok(&self, onion: &str) {
        let mut m = self.lock();
        let h = m.entry(onion.to_owned()).or_default();
        let now = Instant::now();
        h.last_ok = Some(now);
        h.last_check = Some(now);
        h.fails = 0;
        h.oks = h.oks.saturating_add(1);
    }

    /// It didn't answer. Returns whether to drop it from the lists.
    fn fail(&self, onion: &str) -> bool {
        let mut m = self.lock();
        let h = m.entry(onion.to_owned()).or_default();
        h.last_check = Some(Instant::now());
        h.fails = h.fails.saturating_add(1);
        let answered_today = h.last_ok.is_some_and(|t| t.elapsed() < Duration::from_secs(86_400));
        let drop = h.fails >= DROP_AFTER && !answered_today;
        if drop {
            m.remove(onion);
        }
        drop
    }

    /// Up to `n` of `list` to hand out: ones that answered lately first
    /// (the more reliable first, in random order among equals), then ones
    /// not tested yet; never ones that are failing.
    pub(crate) fn sample(&self, mut list: Vec<String>, n: usize) -> Vec<String> {
        shuffle(&mut list);
        let m = self.lock();
        let mut alive: Vec<(u32, String)> = Vec::new();
        let mut untested = Vec::new();
        for o in list {
            match m.get(&o) {
                Some(h) if h.last_ok.is_some_and(|t| t.elapsed() < RECENT) => alive.push((h.oks.min(8), o)),
                Some(h) if h.fails > 0 => {}
                _ => untested.push(o),
            }
        }
        // Stable sort: random order stays among equally reliable ones.
        alive.sort_by(|a, b| b.0.cmp(&a.0));
        alive.into_iter().map(|(_, o)| o).chain(untested).take(n).collect()
    }

    /// Entries due for a test: never tested, or not lately.
    fn due(&self, mut list: Vec<String>, n: usize) -> Vec<String> {
        shuffle(&mut list);
        let m = self.lock();
        list.retain(|o| m.get(o).and_then(|h| h.last_check).is_none_or(|t| t.elapsed() >= RECHECK));
        list.truncate(n);
        list
    }
}

fn shuffle(v: &mut [String]) {
    for i in (1..v.len()).rev() {
        v.swap(i, random_below(i as u64 + 1) as usize);
    }
}

/// Remove a Pillar from a list file.
async fn remove_known(list: &std::path::Path, onion: &str) {
    let _g = KNOWN_LOCK.lock().await;
    let Ok(t) = tokio::fs::read_to_string(list).await else { return };
    let kept: String = t.lines().filter(|l| l.split_whitespace().next() != Some(onion)).map(|l| format!("{l}\n")).collect();
    let _ = tokio::fs::write(list, kept).await;
}

/// Test the listed Pillars and Archives at random times, forever.
pub(crate) async fn check_loop(ctx: Arc<Ctx>) {
    tokio::time::sleep(Duration::from_secs(120 + random_below(120))).await;
    loop {
        let mut all = read_known(&known_path(&ctx.store)).await;
        for a in read_known(&archives_path(&ctx.store)).await {
            if !all.contains(&a) {
                all.push(a);
            }
        }
        all.retain(|o| *o != ctx.self_onion);
        let due = ctx.dir.due(all, PER_ROUND);
        futures::stream::iter(due)
            .for_each_concurrent(AT_ONCE, |onion| {
                let ctx = Arc::clone(&ctx);
                async move {
                    let answered = tokio::time::timeout(Duration::from_secs(60), async {
                        let mut s = ctx.tor.isolated_client().connect((onion.as_str(), SENTINEL_PORT)).await?;
                        anyhow::Ok(matches!(exchange(&mut s, &Request::Ping).await?, Response::Pong))
                    })
                    .await;
                    if matches!(answered, Ok(Ok(true))) {
                        ctx.dir.ok(&onion);
                    } else if ctx.dir.fail(&onion) {
                        remove_known(&known_path(&ctx.store), &onion).await;
                        remove_known(&archives_path(&ctx.store), &onion).await;
                    }
                }
            })
            .await;
        tokio::time::sleep(Duration::from_secs(600 + random_below(1200))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hands_out_answering_ones_first_and_never_failing_ones() {
        let d = Directory::default();
        let list: Vec<String> = ["good", "flaky", "dead", "new"].iter().map(|s| s.to_string()).collect();
        for _ in 0..5 {
            d.ok("good");
        }
        d.ok("flaky");
        d.fail("dead");
        let s = d.sample(list.clone(), 10);
        assert_eq!(s[0], "good", "the most reliable first");
        assert_eq!(s[1], "flaky");
        assert_eq!(s[2], "new", "untested ones after tested ones");
        assert!(!s.contains(&"dead".to_string()));
        assert_eq!(d.sample(list, 1), vec!["good".to_string()]);
        // Three failures in a row with no answer today: dropped.
        assert!(!d.fail("dead"));
        assert!(d.fail("dead"));
        // Due: everything except what was just tested.
        let due = d.due(vec!["good".into(), "other".into()], 10);
        assert_eq!(due, vec!["other".to_string()]);
    }
}
