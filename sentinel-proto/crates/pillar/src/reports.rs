//! Reports about public content this Pillar holds (posts, room listings
//! and their media), and what the operator does about them.
//!
//! - Anyone can report public content (with a small proof of work, so fake
//!   reports cost something). Only content this Pillar actually holds is
//!   recorded; nobody learns from the answer whether it does.
//! - After [`HIDE_AFTER`] reports from different people (each reporter's
//!   token counts once, and doesn't say who they are), it's hidden from Discover until the
//!   operator decides: nobody has to be online for the first response, and
//!   one person can't delete a post with fake reports (hidden, not removed).
//!   Tokens can be made up, so each further report of an item needs more
//!   proof of work ([`bits_needed`]), and dismissed reports still count.
//! - The media pieces that removing deletes are read from the post itself
//!   (public posts open with the explore key), never taken from a reporter:
//!   otherwise anyone could report a bait post naming someone else's media.
//! - The operator removes it (deleted, and refused if uploaded again here)
//!   or keeps it (the reports are dismissed). Removing doesn't require
//!   looking at it.
//! - What was removed is remembered only here, as fingerprints, so the same
//!   files aren't accepted again. It's never shared or published.
//!
//! Private content (messages, rooms, follow-link posts) can't be read by a
//! Pillar, so it can't be reported here: room messages are reported to the
//! room's admin and moderators instead (see `sentinel_core::room::RoomReport`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sentinel_core::object::{Address, Envelope};
use sentinel_core::social::REPORT_CATEGORIES;

/// Reports (of any kind) before something is hidden from Discover.
pub const HIDE_AFTER: u32 = 3;
/// Most media pieces remembered for one report.
const MAX_CHUNKS: usize = 5000;
/// The most work a report needs (seconds on a phone).
const MAX_REPORT_BITS: u32 = 28;

static LOCK: Mutex<()> = Mutex::new(());

/// One reported item, as the operator sees it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    /// The post or listing (its address).
    pub address: String,
    /// Media pieces it points to that are stored here.
    pub chunks: Vec<String>,
    /// Reports per category (same order as `REPORT_CATEGORIES`).
    pub counts: Vec<u32>,
    /// Day it was first reported.
    pub day: u64,
    /// Hidden from Discover (enough reports) until the operator decides.
    pub hidden: bool,
    /// Reporters' tokens (each counted once; they don't say who).
    #[serde(default)]
    pub tokens: Vec<String>,
}

impl Report {
    pub fn total(&self) -> u32 {
        self.counts.iter().sum()
    }

    /// "child-abuse ×2, spam ×1".
    pub fn summary(&self) -> String {
        self.counts.iter().enumerate().filter(|(_, n)| **n > 0).map(|(i, n)| format!("{} ×{n}", REPORT_CATEGORIES.get(i).unwrap_or(&"?"))).collect::<Vec<_>>().join(", ")
    }
}

fn dir(store: &Path) -> PathBuf {
    store.join("reports")
}

fn hidden_path(store: &Path) -> PathBuf {
    store.join("hidden.txt")
}

fn removed_path(store: &Path) -> PathBuf {
    store.join("removed.txt")
}

fn read_set(path: &Path) -> HashSet<String> {
    std::fs::read_to_string(path).map(|t| t.lines().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty()).collect()).unwrap_or_default()
}

fn write_set(path: &Path, set: &HashSet<String>) {
    let mut v: Vec<&String> = set.iter().collect();
    v.sort();
    let text: String = v.into_iter().map(|a| format!("{a}\n")).collect();
    let _ = std::fs::write(path, text);
    crate::coarsen_path(path);
}

/// Addresses hidden from Discover.
pub(crate) fn hidden(store: &Path) -> HashSet<String> {
    read_set(&hidden_path(store))
}

/// Addresses (objects and media pieces) the operator removed.
pub(crate) fn removed(store: &Path) -> HashSet<String> {
    read_set(&removed_path(store))
}

fn today() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() / 86_400).unwrap_or(0)
}

/// Proof-of-work bits the next report of `address` needs: more for each
/// report it already had (dismissed ones included).
pub(crate) fn bits_needed(store: &Path, address: &[u8; 32]) -> u32 {
    let path = dir(store).join(Address(*address).to_text());
    let prior = std::fs::read(path).ok().and_then(|b| serde_json::from_slice::<Report>(&b).ok()).map_or(0, |r| r.tokens.len() as u32);
    (sentinel_core::social::REPORT_POW_BITS + 4 * prior.min(4)).min(MAX_REPORT_BITS)
}

/// The media pieces a public post points to (empty if `bytes` isn't the
/// post at `address`, or isn't public).
fn post_chunks(address: &[u8; 32], bytes: &[u8]) -> HashSet<[u8; 32]> {
    if Address::of(bytes).0 != *address {
        return HashSet::new();
    }
    let Ok(env) = Envelope::decode_verified(bytes) else { return HashSet::new() };
    match sentinel_core::social::open_record(&env, &[sentinel_core::seal::explore_key()]) {
        Some(sentinel_core::social::Record::Post(p)) => p.media.iter().flat_map(|m| m.chunks.iter().chain(m.manifest.iter()).copied()).collect(),
        _ => HashSet::new(),
    }
}

/// Record a report, if this Pillar holds the content. Returns whether the
/// item is now hidden from Discover. `post`: the post's bytes when this
/// node holds only its media (an Archive).
pub(crate) fn record(store: &Path, address: &[u8; 32], chunks: &[[u8; 32]], category: u8, token: &[u8; 32], post: &[u8]) -> bool {
    if usize::from(category) >= REPORT_CATEGORIES.len() {
        return false;
    }
    let addr = Address(*address).to_text();
    let held_post = std::fs::read(store.join(&addr)).ok();
    let of_post = post_chunks(address, held_post.as_deref().unwrap_or(post));
    let held_chunks: Vec<String> = chunks
        .iter()
        .take(MAX_CHUNKS)
        .filter(|c| of_post.contains(*c))
        .map(|c| Address(*c).to_text())
        .filter(|c| store.join("chunks").join(c).exists())
        .collect();
    if held_post.is_none() && held_chunks.is_empty() {
        return false;
    }
    let _g = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = std::fs::create_dir_all(dir(store));
    let path = dir(store).join(&addr);
    let mut r: Report = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    if r.address.is_empty() {
        r = Report { address: addr.clone(), day: today(), ..Default::default() };
    }
    r.counts.resize(REPORT_CATEGORIES.len(), 0);
    let t = data_encoding::HEXLOWER.encode(&token[..16]);
    if r.tokens.contains(&t) {
        return r.hidden; // this person already reported it
    }
    r.tokens.push(t);
    r.counts[usize::from(category)] = r.counts[usize::from(category)].saturating_add(1);
    for c in held_chunks {
        if !r.chunks.contains(&c) && r.chunks.len() < MAX_CHUNKS {
            r.chunks.push(c);
        }
    }
    if r.total() >= HIDE_AFTER && !r.hidden {
        r.hidden = true;
        let mut h = hidden(store);
        h.insert(addr.clone());
        write_set(&hidden_path(store), &h);
    }
    if let Ok(b) = serde_json::to_vec(&r) {
        let _ = std::fs::write(&path, b);
        crate::coarsen_path(&path);
    }
    r.hidden
}

/// Everything reported here, most reported first.
pub fn list(store: &Path) -> Vec<Report> {
    let mut out: Vec<Report> = std::fs::read_dir(dir(store))
        .map(|rd| rd.flatten().filter_map(|e| std::fs::read(e.path()).ok()).filter_map(|b| serde_json::from_slice(&b).ok()).collect())
        .unwrap_or_default();
    out.retain(|r| r.total() > 0); // dismissed, not reported again
    out.sort_by_key(|r| std::cmp::Reverse(r.total()));
    out
}

/// Remove reported content: delete the item and its media pieces here, and
/// refuse them if they're uploaded again.
pub fn remove(store: &Path, address: &str) -> anyhow::Result<()> {
    let address = address.trim();
    Address::from_text(address).ok_or_else(|| anyhow::anyhow!("not an address"))?;
    let _g = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let report: Report = std::fs::read(dir(store).join(address)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let mut gone = removed(store);
    gone.insert(address.to_owned());
    let _ = std::fs::remove_file(store.join(address));
    for c in &report.chunks {
        if Address::from_text(c).is_some() {
            let _ = std::fs::remove_file(store.join("chunks").join(c));
            gone.insert(c.clone());
        }
    }
    write_set(&removed_path(store), &gone);
    let mut h = hidden(store);
    h.remove(address);
    write_set(&hidden_path(store), &h);
    let _ = std::fs::remove_file(dir(store).join(address));
    Ok(())
}

/// Keep reported content: dismiss its reports (shown in Discover again).
/// The reporters' tokens are kept, so the same people can't hide it again
/// at once and new reports still cost more.
pub fn keep(store: &Path, address: &str) -> anyhow::Result<()> {
    let address = address.trim();
    Address::from_text(address).ok_or_else(|| anyhow::anyhow!("not an address"))?;
    let _g = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut h = hidden(store);
    h.remove(address);
    write_set(&hidden_path(store), &h);
    let path = dir(store).join(address);
    if let Some(mut r) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Report>(&b).ok()) {
        r.counts.iter_mut().for_each(|c| *c = 0);
        r.hidden = false;
        r.chunks.clear();
        if let Ok(b) = serde_json::to_vec(&r) {
            let _ = std::fs::write(&path, b);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_hide_then_the_operator_decides() {
        let store = std::env::temp_dir().join(format!("sentinel-reports-{}", u64::from_le_bytes(sentinel_core::random_bytes::<8>())));
        std::fs::create_dir_all(store.join("chunks")).unwrap();
        let chunk = [2u8; 32];
        let victims = [4u8; 32]; // someone else's media, also stored here
        let elsewhere = [3u8; 32];
        let media = sentinel_core::media::MediaRef {
            kind: "image".into(),
            mime: "image/png".into(),
            width: 1,
            height: 1,
            size: 10,
            key: [9; 32],
            chunks: vec![chunk],
            manifest: vec![],
            total: 0,
            name: None,
            archives: vec![],
            cleaned: true,
            v: 1,
            ec: None,
        };
        let author = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let post = sentinel_core::social::post_envelope_full(&author, &[6; 32], "hi", &[], true, vec![media]).unwrap().encode().unwrap();
        let held = Address::of(&post).0;
        std::fs::write(store.join(Address(held).to_text()), &post).unwrap();
        std::fs::write(store.join("chunks").join(Address(chunk).to_text()), b"piece").unwrap();
        std::fs::write(store.join("chunks").join(Address(victims).to_text()), b"theirs").unwrap();
        // Content not held here: nothing recorded.
        let (t1, t2, t3) = ([11u8; 32], [12u8; 32], [13u8; 32]);
        assert!(!record(&store, &elsewhere, &[], 0, &t1, &[]));
        // A bait report naming someone else's media: nothing to remove.
        assert!(!record(&store, &elsewhere, &[victims], 0, &t1, &[]));
        assert!(list(&store).is_empty());
        // Two people: shown; the same person again doesn't count; a third
        // person hides it.
        assert_eq!(bits_needed(&store, &held), sentinel_core::social::REPORT_POW_BITS);
        assert!(!record(&store, &held, &[chunk, elsewhere, victims], 0, &t1, &[]));
        assert!(bits_needed(&store, &held) > sentinel_core::social::REPORT_POW_BITS, "each further report costs more");
        assert!(!record(&store, &held, &[], 4, &t2, &[]));
        assert!(!record(&store, &held, &[], 0, &t2, &[]));
        assert!(record(&store, &held, &[], 0, &t3, &[]));
        let a = Address(held).to_text();
        assert!(hidden(&store).contains(&a));
        let r = &list(&store)[0];
        assert_eq!(r.total(), 3);
        assert_eq!(r.chunks, vec![Address(chunk).to_text()], "only the post's own pieces held here");
        assert_eq!(r.summary(), "child-abuse ×2, spam ×1");
        // Kept: shown again, reports dismissed.
        keep(&store, &a).unwrap();
        assert!(!hidden(&store).contains(&a));
        assert!(list(&store).is_empty());
        // The same people can't hide it again.
        assert!(!record(&store, &held, &[], 0, &t1, &[]) && !record(&store, &held, &[], 0, &t2, &[]) && !record(&store, &held, &[], 0, &t3, &[]));
        assert!(list(&store).is_empty());
        // Reported again, then removed: deleted and remembered.
        record(&store, &held, &[chunk], 0, &[14; 32], &[]);
        remove(&store, &a).unwrap();
        assert!(!store.join(&a).exists());
        assert!(!store.join("chunks").join(Address(chunk).to_text()).exists());
        let gone = removed(&store);
        assert!(gone.contains(&a) && gone.contains(&Address(chunk).to_text()));
        assert!(list(&store).is_empty());
        assert!(store.join("chunks").join(Address(victims).to_text()).exists(), "others' media untouched");
        // An Archive (media only) is given the post along with the report.
        let archive = store.join("archive");
        std::fs::create_dir_all(archive.join("chunks")).unwrap();
        std::fs::write(archive.join("chunks").join(Address(chunk).to_text()), b"piece").unwrap();
        std::fs::write(archive.join("chunks").join(Address(victims).to_text()), b"theirs").unwrap();
        record(&archive, &held, &[chunk, victims], 0, &t1, &post);
        assert_eq!(list(&archive)[0].chunks, vec![Address(chunk).to_text()]);
        let _ = std::fs::remove_dir_all(&store);
    }
}
