//! Rotating mix keys and their replay lists.
//!
//! A Pillar's mix key changes every [`EPOCH_DAYS`] days (a *generation*).
//! The previous generation is still accepted until the next change, so a
//! key an app fetched while it was current keeps working for at least
//! `EPOCH_DAYS` after it was replaced; then its secret and its replay list
//! are deleted together. A replay needs the key that opens the packet, so
//! a generation's list only has to cover that generation's lifetime.
//!
//! The replay list holds keyed tags (a key derived from the generation's
//! secret), not packet hashes: once the secret is deleted, a seized list
//! can't be used to confirm that a captured packet passed through. While
//! a generation is live its secret is on disk (replay protection must
//! survive restarts), but whoever holds it could then open the packets
//! themselves anyway.
//!
//! Each list is bounded. When the current one is full the Pillar starts a
//! new generation at once instead of refusing packets, so filling it costs
//! an attacker the proof of work for a whole list and only makes apps
//! fetch a fresh key; it never switches mixing off.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sentinel_core::mix::{self, MixKey, MixSecret, Step};

/// Days a generation is current.
pub(crate) const EPOCH_DAYS: u64 = 14;

struct Gen {
    id: u64,
    start_day: u64,
    secret: MixSecret,
    tag_key: zeroize::Zeroizing<[u8; 32]>,
    seen: HashSet<[u8; 32]>,
}

impl Gen {
    fn new(id: u64, start_day: u64, secret: MixSecret) -> Self {
        let tag_key = zeroize::Zeroizing::new(blake3::derive_key("sentinel/v1/mix-seen-tag", secret.bytes()));
        Gen { id, start_day, secret, tag_key, seen: HashSet::new() }
    }

    fn tag(&self, packet_id: &[u8; 32]) -> [u8; 32] {
        *blake3::keyed_hash(&self.tag_key, packet_id).as_bytes()
    }
}

struct State {
    current: Gen,
    previous: Option<Gen>,
}

pub(crate) struct MixKeys {
    keys: PathBuf,
    seen: PathBuf,
    max_seen: usize,
    state: Mutex<State>,
}

/// What became of a packet.
pub(crate) enum Opened {
    /// Opened with generation `gen`; record it with [`MixKeys::record`].
    Step { step: Step, delay: u32, gen: u64, packet_id: [u8; 32] },
    /// Seen before.
    Replay,
    /// No live key opens it (garbage, or a key that was deleted).
    Invalid,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Recorded {
    New,
    Again,
    /// Its generation is gone or its list full (the app should fetch the key again).
    Stale,
}

fn read_gen(path: &Path) -> Option<(u64, MixSecret)> {
    let b = std::fs::read(path).ok()?;
    if b.len() != 40 {
        return None;
    }
    let secret: [u8; 32] = b[..32].try_into().ok()?;
    let start = u64::from_le_bytes(b[32..].try_into().ok()?);
    Some((start, MixSecret::from_bytes(secret)))
}

impl MixKeys {
    /// Load the live generations from `store` (or start the first). A
    /// key from before rotation (`mix.key`) becomes the current generation,
    /// so apps that cached it keep working through the grace period; the
    /// old, untagged replay list is deleted.
    pub(crate) fn load(store: &Path, today: u64, max_seen: usize) -> Self {
        let keys = store.join("mix-keys");
        let seen = store.join("mix-tags");
        let _ = std::fs::create_dir_all(&keys);
        let _ = std::fs::create_dir_all(&seen);
        let _ = std::fs::remove_dir_all(store.join("mix-seen"));
        let legacy = store.join("mix.key");
        let mut gens: Vec<Gen> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&keys) {
            for e in rd.flatten() {
                let Ok(id) = e.file_name().to_string_lossy().parse::<u64>() else { continue };
                if let Some((start, secret)) = read_gen(&e.path()) {
                    gens.push(Gen::new(id, start, secret));
                }
            }
        }
        if gens.is_empty() {
            let secret = match std::fs::read(&legacy).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
                Some(b) => MixSecret::from_bytes(b),
                None => MixSecret::generate(),
            };
            gens.push(Gen::new(1, today, secret));
        }
        gens.sort_by_key(|g| g.id);
        let current = gens.pop().expect("one generation");
        let previous = gens.pop();
        let mk = MixKeys { keys, seen, max_seen, state: Mutex::new(State { current, previous }) };
        {
            let mut st = mk.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            mk.save_gen(&st.current);
            let State { current, previous } = &mut *st;
            for g in std::iter::once(current).chain(previous.as_mut()) {
                let b = std::fs::read(mk.seen.join(g.id.to_string())).unwrap_or_default();
                g.seen.extend(b.as_chunks::<32>().0.iter().copied());
            }
            mk.forget_older(&st);
            mk.rotate_if_due(&mut st, today);
        }
        // The legacy key now lives (and dies) as a generation.
        let _ = std::fs::remove_file(&legacy);
        mk
    }

    fn save_gen(&self, g: &Gen) {
        let path = self.keys.join(g.id.to_string());
        if path.exists() {
            return;
        }
        let mut b = g.secret.bytes().to_vec();
        b.extend_from_slice(&g.start_day.to_le_bytes());
        let _ = std::fs::write(&path, &b);
        crate::coarsen_mtime(&path);
    }

    /// Delete every key and list that isn't the current or previous generation.
    fn forget_older(&self, st: &State) {
        let live = [Some(st.current.id), st.previous.as_ref().map(|g| g.id)];
        for dir in [&self.keys, &self.seen] {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let id = e.file_name().to_string_lossy().parse::<u64>().ok();
                    if !live.contains(&id) || id.is_none() {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        }
    }

    fn rotate(&self, st: &mut State, today: u64) {
        let next = Gen::new(st.current.id + 1, today, MixSecret::generate());
        self.save_gen(&next);
        let old = std::mem::replace(&mut st.current, next);
        st.previous = Some(old); // the generation before it is dropped (zeroized)
        self.forget_older(st);
    }

    fn rotate_if_due(&self, st: &mut State, today: u64) {
        if today >= st.current.start_day + EPOCH_DAYS {
            self.rotate(st, today);
        }
    }

    /// The key apps should use now.
    pub(crate) fn public(&self, today: u64) -> MixKey {
        let mut st = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.rotate_if_due(&mut st, today);
        st.current.secret.public()
    }

    /// Open a packet with a live key (the newest first).
    pub(crate) fn open(&self, packet: &[u8], today: u64) -> Opened {
        let packet_id = blake3::derive_key("sentinel/v0/mix-seen", packet);
        let secrets: Vec<(u64, MixSecret)> = {
            let mut st = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            self.rotate_if_due(&mut st, today);
            let State { current, previous } = &*st;
            let gens: Vec<&Gen> = std::iter::once(current).chain(previous.as_ref()).collect();
            if gens.iter().any(|g| g.seen.contains(&g.tag(&packet_id))) {
                return Opened::Replay;
            }
            gens.iter().map(|g| (g.id, MixSecret::from_bytes(*g.secret.bytes()))).collect()
        };
        // Opening is the slow part: done without holding the lock.
        for (gen, secret) in secrets {
            if let Some((step, delay)) = mix::unwrap(&secret, packet) {
                return Opened::Step { step, delay, gen, packet_id };
            }
        }
        Opened::Invalid
    }

    /// Remember an opened packet. A full current list starts a new
    /// generation (that packet is refused: apps fetch the new key).
    pub(crate) fn record(&self, gen: u64, packet_id: &[u8; 32], today: u64) -> Recorded {
        let mut st = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let is_current = st.current.id == gen;
        let max = self.max_seen;
        let Some(g) = (if is_current { Some(&mut st.current) } else { st.previous.as_mut().filter(|p| p.id == gen) }) else {
            return Recorded::Stale;
        };
        let tag = g.tag(packet_id);
        if g.seen.contains(&tag) {
            return Recorded::Again;
        }
        if g.seen.len() >= max {
            if is_current {
                self.rotate(&mut st, today);
            }
            return Recorded::Stale;
        }
        g.seen.insert(tag);
        let path = self.seen.join(gen.to_string());
        if std::fs::OpenOptions::new().create(true).append(true).open(&path).and_then(|mut f| f.write_all(&tag)).is_ok() {
            crate::coarsen_mtime(&path);
        }
        Recorded::New
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("sentinel-mixkeys-{}", data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<8>())))
    }

    fn packet(key: &MixKey, n: u8) -> Vec<u8> {
        let onion = "a".repeat(56) + ".onion";
        mix::handoff(key, Step::Deliver { pillar: onion, shard: n as u16, blob: vec![n; 100], nonce: 0 }).unwrap()
    }

    fn accept(mk: &MixKeys, p: &[u8], today: u64) -> Result<Recorded, &'static str> {
        match mk.open(p, today) {
            Opened::Step { gen, packet_id, .. } => Ok(mk.record(gen, &packet_id, today)),
            Opened::Replay => Err("replay"),
            Opened::Invalid => Err("invalid"),
        }
    }

    #[test]
    fn keys_rotate_with_a_grace_period_and_old_ones_are_deleted() {
        let store = tmp();
        let mk = MixKeys::load(&store, 100, 1000);
        let k1 = mk.public(100);
        let p1 = packet(&k1, 1);
        assert_eq!(accept(&mk, &p1, 100), Ok(Recorded::New));
        assert_eq!(accept(&mk, &p1, 101), Err("replay"));
        // A restart keeps the key and the replay list.
        drop(mk);
        let mk = MixKeys::load(&store, 101, 1000);
        assert_eq!(mk.public(101), k1);
        assert_eq!(accept(&mk, &p1, 101), Err("replay"));
        // Next generation: a new key; the old one still works (grace).
        let k2 = mk.public(100 + EPOCH_DAYS);
        assert_ne!(k1, k2);
        assert_eq!(accept(&mk, &packet(&k1, 2), 100 + EPOCH_DAYS), Ok(Recorded::New));
        assert_eq!(accept(&mk, &p1, 100 + EPOCH_DAYS), Err("replay"));
        // One more: the first key, its secret and its list are gone; the
        // old replay is now simply unreadable.
        let k3 = mk.public(100 + 2 * EPOCH_DAYS);
        assert_ne!(k3, k2);
        assert_eq!(accept(&mk, &p1, 100 + 2 * EPOCH_DAYS), Err("invalid"));
        assert_eq!(accept(&mk, &packet(&k2, 3), 100 + 2 * EPOCH_DAYS), Ok(Recorded::New));
        let ids: Vec<String> = std::fs::read_dir(store.join("mix-keys")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(ids.len(), 2);
        assert!(!store.join("mix-tags").join("1").exists());
        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn a_full_list_starts_a_new_key_instead_of_stopping_mixing() {
        let store = tmp();
        let mk = MixKeys::load(&store, 10, 3);
        let k1 = mk.public(10);
        let first = packet(&k1, 0);
        assert_eq!(accept(&mk, &first, 10), Ok(Recorded::New));
        for n in 1..3 {
            assert_eq!(accept(&mk, &packet(&k1, n), 10), Ok(Recorded::New));
        }
        // Full: this packet is refused and a new generation starts.
        assert_eq!(accept(&mk, &packet(&k1, 9), 10), Ok(Recorded::Stale));
        let k2 = mk.public(10);
        assert_ne!(k1, k2);
        // Packets for the new key are taken at once, the same day.
        assert_eq!(accept(&mk, &packet(&k2, 1), 10), Ok(Recorded::New));
        // Old packets are still recognised as replays; new ones for the
        // full key are refused (the app fetches the new key).
        assert_eq!(accept(&mk, &first, 10), Err("replay"));
        assert_eq!(accept(&mk, &packet(&k1, 5), 10), Ok(Recorded::Stale));
        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn the_replay_list_holds_keyed_tags_not_packet_hashes() {
        let store = tmp();
        let mk = MixKeys::load(&store, 50, 100);
        let p = packet(&mk.public(50), 1);
        assert_eq!(accept(&mk, &p, 50), Ok(Recorded::New));
        let list = std::fs::read(store.join("mix-tags").join("1")).unwrap();
        let id = blake3::derive_key("sentinel/v0/mix-seen", &p);
        assert_eq!(list.len(), 32);
        assert_ne!(list, id.to_vec());
        assert!(!list.windows(8).any(|w| id.windows(8).any(|x| x == w)));
        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn a_key_from_before_rotation_becomes_the_first_generation() {
        let store = tmp();
        std::fs::create_dir_all(store.join("mix-seen")).unwrap();
        std::fs::write(store.join("mix-seen").join("5"), [7u8; 32]).unwrap();
        let old = MixSecret::generate();
        std::fs::write(store.join("mix.key"), old.bytes()).unwrap();
        let mk = MixKeys::load(&store, 5, 100);
        assert_eq!(mk.public(5), old.public());
        assert!(!store.join("mix.key").exists() && !store.join("mix-seen").exists());
        let _ = std::fs::remove_dir_all(&store);
    }
}
