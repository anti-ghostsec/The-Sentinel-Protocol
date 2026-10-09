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
//! `MAX_DEPTH`.

use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use anyhow::{Context, Result};
use sentinel_core::dm;
use sentinel_core::room;
use sentinel_core::wire::{Request, Response};

use super::{request, Core};

/// Pillars keep mailbox deposits this many days.
const MAIL_KEEP_DAYS: u64 = 7;

/// Never split finer than this (256 prefixes): each prefix stays shared.
const MAX_DEPTH: u8 = 8;
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
}

impl Core {
    /// My own choice of prefix length for a Pillar, from what I observed.
    fn depth(&self, pillar: &str) -> u8 {
        self.with(|i| i.mail.depths.get(pillar).map(|(d, _)| *d).unwrap_or(0))
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

        // Which IDs I read, per Pillar.
        let mut ids: HashMap<String, Vec<[u8; 32]>> = HashMap::new();
        if let (Some(p), Some(st)) = (store.pillar.clone(), store.dm.clone()) {
            for &d in &days {
                ids.entry(p.clone()).or_default().push(dm::inbox_id(&st.fetch_secret, d));
            }
        }
        for r in &store.rooms {
            for &d in &days {
                ids.entry(r.pillar.clone()).or_default().push(room::room_box(&r.secret, d).0);
                // Approval rooms: the admin and moderators also read the ask box.
                if let Some(ask) = &r.ask {
                    ids.entry(r.pillar.clone()).or_default().push(room::room_box(ask, d).0);
                }
            }
        }

        // Linking a device: its mailbox on the link code's Pillar.
        for (pillar, secret) in Core::link_boxes(&store) {
            for &d in &days {
                ids.entry(pillar.clone()).or_default().push(room::room_box(&secret, d).0);
            }
        }
        let (mut dms, mut rooms) = (0, 0);
        for (pillar, list) in ids {
            let bits = self.depth(&pillar);
            let mut prefixes: BTreeSet<u16> = list.iter().map(|id| dm::prefix_of(dm::shard_of(id), bits)).collect();
            // Always fetch a multiple of 4 prefixes (random extra ones), so
            // the Pillar can't count how many inboxes and rooms I have.
            if bits > 0 {
                let space = 1u32 << bits;
                let target = (prefixes.len().div_ceil(4) * 4).min(space as usize);
                while prefixes.len() < target {
                    prefixes.insert((u32::from_le_bytes(sentinel_core::random_bytes::<4>()) % space) as u16);
                }
            }
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
                    let Ok(Ok(mut s)) = tokio::time::timeout(std::time::Duration::from_secs(90), net.connect_hedged(&pillar)).await else { return (ck, None) };
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
            'prefixes: for (ck, got) in fetched {
                let Some((pages, complete)) = got else {
                    all_read = false;
                    continue;
                };
                all_read &= complete;
                for blobs in pages {
                    seen_here += blobs.len();
                    for (seq, blob) in blobs {
                        let gen = self.with(|i| i.mail.rescans);
                        let (d, r) = self.dispatch_blob(&key, &pillar, &blob);
                        dms += d;
                        rooms += r;
                        // That item changed a key and reset the reading
                        // positions (earlier blobs must be read again with
                        // the new key): don't move them forward, and stop
                        // this pass; the next one reads with the new key.
                        if self.with(|i| i.mail.rescans) != gen {
                            break 'prefixes;
                        }
                        self.update(|st| {
                            let c = st.mail_cursors.entry(ck.clone()).or_insert(0);
                            *c = (*c).max(seq);
                        })?;
                    }
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
