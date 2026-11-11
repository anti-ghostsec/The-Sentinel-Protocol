//! Private mailbox polling (spec §10.2, threat #48).
//!
//! DMs and room messages are deposited under a short *shard prefix* of the
//! recipient's rotating inbox/room-box ID. I fetch whole prefixes — shared
//! with many other people — and try to open every blob with my keys
//! (inbox key, then each room's secret). Each prefix is fetched on its own
//! isolated circuit, at a random moment within the sync window, so a Pillar
//! can't link my prefixes by timing either.
//!
//! The prefix length is chosen **by me**, from the volume I actually see —
//! never by the Pillar. (A hostile Pillar answering "16 bits" would put each
//! person in their own shard and undo the whole point.) I only lengthen the
//! prefix when what I download is genuinely too much, and never beyond
//! `MAX_DEPTH`. (A Pillar can still pad its answers to make me split; the
//! fixed limit keeps every prefix shared with a sixteenth of its mailboxes.)

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use sentinel_core::dm;
use sentinel_core::room;
use sentinel_core::wire::{Request, Response};

use tauri::{AppHandle, Emitter};

use super::{request, request_timeout, Core};

/// Pillars keep mailbox deposits this many days.
const MAIL_KEEP_DAYS: u64 = 7;

/// Never split finer than this (16 prefixes): each prefix stays shared.
const MAX_DEPTH: u8 = dm::MAX_READ_DEPTH;
/// Lengthen the prefix only above this many blobs per poll window, shorten
/// below a quarter of it.
const SPLIT_ABOVE: usize = 4000;

#[derive(Default)]
pub struct MailState {
    /// Pillar -> (depth I chose, blobs seen last pass).
    depths: HashMap<String, (u8, usize)>,
    /// Last time each pillar was polled (for spreading fetches).
    last: HashMap<String, Instant>,
    /// Bumped by every re-scan (a key change resets reading positions).
    rescans: u64,
    /// Pillars that don't hold watches (older versions), and since when.
    no_watch: HashMap<String, Instant>,
}

/// An older Pillar's answer to a request it doesn't know.
const NO_WATCH: &str = "Pillar doesn't hold watches";
/// Ask an older Pillar again after this long (it may have been updated).
const NO_WATCH_RETRY: Duration = Duration::from_secs(6 * 3600);

impl Core {
    /// My own choice of prefix length for a Pillar, from what I observed.
    fn depth(&self, pillar: &str) -> u8 {
        self.with(|i| i.mail.depths.get(pillar).map(|(d, _)| *d).unwrap_or(0)).min(MAX_DEPTH)
    }

    /// My real prefixes on a Pillar plus padding: the same set all day (see
    /// `dm::padded_prefixes`), for fetches and watches alike.
    fn prefixes(key: &super::Keys, pillar: &str, bits: u8, ids: &[[u8; 32]]) -> BTreeSet<u16> {
        let real: BTreeSet<u16> = ids.iter().map(|id| dm::prefix_of(dm::shard_of(id), bits)).collect();
        let pad_secret = zeroize::Zeroizing::new(blake3::derive_key("sentinel/v1/mailbox-pad-secret", &key.root.to_bytes()));
        dm::padded_prefixes(&pad_secret, pillar, dm::today(), bits, &real)
    }

    fn observe(&self, pillar: &str, seen: usize) {
        self.with(|i| {
            let e = i.mail.depths.entry(pillar.to_owned()).or_insert((0, 0));
            if seen > SPLIT_ABOVE && e.0 < MAX_DEPTH {
                e.0 += 1;
            } else if seen < SPLIT_ABOVE / 4 && e.0 > 0 {
                e.0 -= 1;
            }
            e.1 = seen;
        });
    }

    /// Fetch every prefix I need and dispatch what I can open.
    /// Returns (new direct messages, new room messages).
    pub async fn poll_mail(&self) -> Result<(usize, usize)> {
        let (key, store) = self.unlocked()?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let today = dm::today();
        // Every day since I last read all my mail (messages go to the
        // sender's day's mailbox, and Pillars keep them 7 days), so nothing
        // sent while I was away is missed.
        let from = if store.mail_day == 0 { today.saturating_sub(1) } else { store.mail_day.max(today.saturating_sub(MAIL_KEEP_DAYS)) };
        let days: Vec<u64> = (from.min(today.saturating_sub(1))..=today).collect();
        let mut all_read = true;

        let ids = Core::mail_ids(&store, &days);
        let (mut dms, mut rooms) = (0, 0);
        for (pillar, list) in ids {
            let bits = self.depth(&pillar);
            // Always fetch a multiple of 4 prefixes (extra ones, the same
            // all day), so the Pillar can't count my inboxes and rooms.
            let prefixes = Core::prefixes(&key, &pillar, bits, &list);
            let many = prefixes.len() > 1;
            let mut seen_here = 0usize;
            // Fetch every prefix at the same time, each on its own circuit
            // and starting at its own random moment (so they don't arrive as
            // one identifiable burst); then open what came, in order.
            let cursors = self.unlocked()?.1.mail_cursors;
            let fetches = prefixes.into_iter().map(|prefix| {
                let ck = format!("{pillar}|{bits}|{prefix}");
                let start = cursors.get(&ck).copied().unwrap_or(0);
                let (net, pillar) = (net.clone(), pillar.clone());
                async move {
                    if many {
                        let gap = u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % 20;
                        tokio::time::sleep(std::time::Duration::from_secs(gap)).await;
                    }
                    let mut pages: Vec<Vec<(u64, Vec<u8>)>> = Vec::new();
                    let Ok(Ok(mut s)) = tokio::time::timeout(std::time::Duration::from_secs(90), self.stream_to(&net, &pillar)).await else { return (ck, None) };
                    let mut after = start;
                    for _page in 0..50 {
                        match request(&mut s, &Request::Fetch { bits, prefix, after }).await {
                            Ok(Response::Blobs(b)) if !b.is_empty() => {
                                after = b.iter().map(|(q, _)| *q).max().unwrap_or(after).max(after);
                                pages.push(b);
                            }
                            Ok(_) => break,
                            Err(_) => return (ck, Some((pages, false))),
                        }
                    }
                    (ck, Some((pages, true)))
                }
            });
            let fetched = futures::future::join_all(fetches).await;
            for (ck, got) in fetched {
                let Some((pages, complete)) = got else {
                    all_read = false;
                    continue;
                };
                all_read &= complete;
                seen_here += pages.iter().map(Vec::len).sum::<usize>();
                let (d, r, rescanned) = self.take_pages(&key, &pillar, &ck, pages)?;
                dms += d;
                rooms += r;
                if rescanned {
                    break;
                }
            }
            self.observe(&pillar, seen_here);
            self.with(|i| i.mail.last.insert(pillar.clone(), Instant::now()));
        }
        if all_read {
            self.update(|s| s.mail_day = today)?;
        }
        Ok((dms, rooms))
    }

    /// The mailbox IDs I read on each Pillar for these days: my inbox,
    /// my rooms (and their ask boxes), and a device link in progress.
    fn mail_ids(store: &super::Store, days: &[u64]) -> HashMap<String, Vec<[u8; 32]>> {
        let mut ids: HashMap<String, Vec<[u8; 32]>> = HashMap::new();
        if let (Some(p), Some(st)) = (store.pillar.clone(), store.dm.clone()) {
            for &d in days {
                ids.entry(p.clone()).or_default().push(dm::inbox_id(&st.fetch_secret, d));
            }
        }
        for r in &store.rooms {
            for &d in days {
                ids.entry(r.pillar.clone()).or_default().push(room::room_box(&r.secret, d).0);
                // Approval rooms: the admin and moderators also read the ask box.
                if let Some(ask) = &r.ask {
                    ids.entry(r.pillar.clone()).or_default().push(room::room_box(ask, d).0);
                }
            }
        }
        // Linking a device: its mailbox on the link code's Pillar.
        for (pillar, secret) in Core::link_boxes(store) {
            for &d in days {
                ids.entry(pillar.clone()).or_default().push(room::room_box(&secret, d).0);
            }
        }
        ids
    }

    /// Open fetched pages of one prefix (cursor key `ck`) in order and move
    /// its reading position on. Returns (new DMs, new room messages, true if
    /// an item reset the reading positions: stop and read again next time).
    fn take_pages(&self, key: &super::Keys, pillar: &str, ck: &str, pages: Vec<Vec<(u64, Vec<u8>)>>) -> Result<(usize, usize, bool)> {
        let (mut dms, mut rooms) = (0, 0);
        for blobs in pages {
            for (seq, blob) in blobs {
                let gen = self.with(|i| i.mail.rescans);
                let (d, r) = self.dispatch_blob(key, pillar, &blob);
                dms += d;
                rooms += r;
                // That item changed a key and reset the reading positions
                // (earlier blobs must be read again with the new key):
                // don't move them forward; the next read uses the new key.
                if self.with(|i| i.mail.rescans) != gen {
                    return Ok((dms, rooms, true));
                }
                self.update(|st| {
                    let c = st.mail_cursors.entry(ck.to_owned()).or_insert(0);
                    *c = (*c).max(seq);
                })?;
            }
        }
        Ok((dms, rooms, false))
    }

    /// Instant delivery: for every prefix I read today, keep one `Watch`
    /// held at its Pillar, each on its own isolated circuit, the same way
    /// as the fetches. The Pillar answers when a deposit lands in the
    /// prefix (shared with many people), so messages show up seconds after
    /// they're sent instead of at the next sync. The regular sync still
    /// reads everything (earlier days, Pillars that don't hold watches).
    ///
    /// Off with mixing or High-risk mode: there, fetches keep the fixed
    /// schedule, so a watcher of the network can't see my app react the
    /// moment a message is deposited.
    pub(crate) async fn run_mail_watch(self: Arc<Self>, app: AppHandle) {
        let mut running: HashSet<(String, u8, u16)> = HashSet::new();
        let mut started: HashSet<(String, u8, u16)> = HashSet::new();
        let mut tasks = FuturesUnordered::new();
        loop {
            let new: Vec<_> = self.watch_keys().into_iter().filter(|k| !running.contains(k)).collect();
            for k in new {
                running.insert(k.clone());
                // A prefix's first watch starts at a random moment, like the
                // fetches, so they don't arrive as one recognisable burst;
                // after an answer it's held again at once.
                let gap = if started.insert(k.clone()) { u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % 20 } else { 0 };
                let core = Arc::clone(&self);
                tasks.push(async move {
                    tokio::time::sleep(Duration::from_secs(gap)).await;
                    let r = core.watch_once(&k.0, k.1, k.2).await;
                    if r.as_ref().is_err_and(|e| !e.to_string().contains(NO_WATCH)) {
                        // Not connected, or a circuit failed: wait a little.
                        let pause = 5 + u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % 10;
                        tokio::time::sleep(Duration::from_secs(pause)).await;
                    }
                    (k, r)
                });
            }
            tokio::select! {
                Some((k, r)) = tasks.next() => {
                    running.remove(&k);
                    match r {
                        Ok((dms, rooms)) => {
                            if dms > 0 {
                                let _ = app.emit("messages", ());
                            }
                            if rooms > 0 {
                                let _ = app.emit("rooms", ());
                            }
                        }
                        // An older Pillar: leave it to the regular sync.
                        Err(e) if e.to_string().contains(NO_WATCH) => {
                            self.with(|i| i.mail.no_watch.insert(k.0.clone(), Instant::now()));
                        }
                        Err(_) => {}
                    }
                }
                // Look for new prefixes (a room joined, a new day, mixing switched).
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    }

    /// (Pillar, depth, prefix) to watch now, padded like the fetches;
    /// none while mixing or High-risk mode is on.
    fn watch_keys(&self) -> HashSet<(String, u8, u16)> {
        let Ok((key, store)) = self.unlocked() else { return HashSet::new() };
        if store.privacy.mix || store.privacy.high_risk || self.with(|i| i.net.is_none()) {
            return HashSet::new();
        }
        let mut keys = HashSet::new();
        for (pillar, list) in Core::mail_ids(&store, &[dm::today()]) {
            let skip = self.with(|i| i.mail.no_watch.get(&pillar).is_some_and(|t| t.elapsed() < NO_WATCH_RETRY));
            if skip {
                continue;
            }
            let bits = self.depth(&pillar);
            // Padded like the fetches (the same set all day).
            let prefixes = Core::prefixes(&key, &pillar, bits, &list);
            keys.extend(prefixes.into_iter().map(|p| (pillar.clone(), bits, p)));
        }
        keys
    }

    /// One held watch on a fresh isolated stream, then anything more in
    /// that prefix on the same stream. Returns (new DMs, new room messages).
    async fn watch_once(&self, pillar: &str, bits: u8, prefix: u16) -> Result<(usize, usize)> {
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let ck = format!("{pillar}|{bits}|{prefix}");
        let mut after = self.unlocked()?.1.mail_cursors.get(&ck).copied().unwrap_or(0);
        let mut s = tokio::time::timeout(Duration::from_secs(90), self.stream_to(&net, pillar)).await.context("no circuit")??;
        let hold = Duration::from_secs(sentinel_core::wire::WATCH_HOLD_SECS + 30);
        let mut pages = match request_timeout(&mut s, &Request::Watch { bits, prefix, after }, hold).await? {
            Response::Blobs(b) if b.is_empty() => return Ok((0, 0)),
            Response::Blobs(b) => vec![b],
            Response::Rejected(e) if e == "malformed request" => bail!("{NO_WATCH}"),
            other => bail!("watch: {other:?}"),
        };
        // A full page: read on, as a fetch would.
        for _ in 0..50 {
            after = pages.iter().flatten().map(|(q, _)| *q).max().unwrap_or(after).max(after);
            match request(&mut s, &Request::Fetch { bits, prefix, after }).await {
                Ok(Response::Blobs(b)) if !b.is_empty() => pages.push(b),
                _ => break,
            }
        }
        // The depth may have changed while it was held: those blobs still
        // open, but the cursor belongs to the old prefix and stays apart.
        let key = self.unlocked()?.0;
        let (d, r, _) = self.take_pages(&key, pillar, &ck, pages)?;
        Ok((d, r))
    }

    /// Try my inbox key, then every room on this Pillar. Blobs I handled
    /// before are skipped (re-scans after joining a room, Pillar replays).
    fn dispatch_blob(&self, key: &super::Keys, pillar: &str, blob: &[u8]) -> (usize, usize) {
        let fp = data_encoding::HEXLOWER.encode(&blake3::hash(blob).as_bytes()[..16]);
        let Ok((_, store)) = self.unlocked() else { return (0, 0) };
        if store.mail_seen.contains_key(&fp) {
            return (0, 0);
        }
        let mut handled = false;
        let mut out = (0, 0);
        if (store.link_offer.is_some() || store.link_join.is_some()) && self.link_blob(blob).unwrap_or(false) {
            return (1, 0);
        }
        if let Some(st) = &store.dm {
            if dm::unseal(&st.inbox_secret, blob).is_some() {
                handled = true;
                if self.receive_blob(key, blob).unwrap_or(false) {
                    out = (1, 0);
                }
            }
        }
        if !handled {
            'rooms: for r in store.rooms.iter().filter(|r| r.pillar == pillar) {
                for secret in std::iter::once(&r.secret).chain(r.ask.iter()) {
                    if room::open_blob(secret, blob).is_some() {
                        handled = true;
                        let n = self.apply_room_blob(key, &r.room_id, secret, blob).unwrap_or(false);
                        out = (0, n as usize);
                        break 'rooms;
                    }
                }
            }
        }
        if handled {
            let today = dm::today();
            let _ = self.update(|s| {
                s.mail_seen.insert(fp, today);
                if s.mail_seen.len() > 50_000 || today % 7 == 0 {
                    s.mail_seen.retain(|_, d| *d + 9 >= today);
                }
            });
        }
        out
    }

    /// Re-scan a Pillar's mailboxes from the start (after joining a room or
    /// a key change: its earlier blobs were fetched but couldn't be opened).
    pub(super) fn rescan_pillar(&self, pillar: &str) {
        let prefix = format!("{pillar}|");
        let _ = self.update(|s| s.mail_cursors.retain(|k, _| !k.starts_with(&prefix)));
        self.with(|i| i.mail.rescans += 1);
    }
}
