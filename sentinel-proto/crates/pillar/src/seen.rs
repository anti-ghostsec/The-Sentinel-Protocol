//! Ids seen lately (mixed packets, mailbox deposits), kept on disk so a
//! restart doesn't forget them: a replayed packet or a deposit sent twice
//! is recognised for as long as the set keeps it.
//!
//! One file per day (`<day>`, the ids back to back, 32 bytes each); days
//! older than `keep_days` are dropped. The set never forgets early to make
//! room: when it holds `max` ids, new ones are refused until old days expire.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Seen {
    /// Not seen before; now remembered.
    New,
    /// Seen before.
    Again,
    /// Not seen before, but the set is full.
    Full,
}

pub(crate) struct SeenSet {
    dir: PathBuf,
    keep_days: u64,
    max: usize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    days: BTreeMap<u64, HashSet<[u8; 32]>>,
    total: usize,
}

impl SeenSet {
    /// Load what's kept in `dir` (made if missing).
    pub(crate) fn load(dir: &Path, keep_days: u64, max: usize, today: u64) -> Self {
        let _ = std::fs::create_dir_all(dir);
        let mut inner = Inner::default();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let Ok(day) = e.file_name().to_string_lossy().parse::<u64>() else { continue };
                if day + keep_days < today {
                    let _ = std::fs::remove_file(e.path());
                    continue;
                }
                let b = std::fs::read(e.path()).unwrap_or_default();
                let set = inner.days.entry(day).or_default();
                for id in b.as_chunks::<32>().0 {
                    if set.insert(*id) {
                        inner.total += 1;
                    }
                }
            }
        }
        SeenSet { dir: dir.to_owned(), keep_days, max, inner: Mutex::new(inner) }
    }

    fn expire(&self, inner: &mut Inner, today: u64) {
        while let Some((&day, _)) = inner.days.first_key_value() {
            if day + self.keep_days >= today {
                break;
            }
            if let Some(set) = inner.days.remove(&day) {
                inner.total -= set.len();
            }
            let _ = std::fs::remove_file(self.dir.join(day.to_string()));
        }
    }

    /// Whether `id` was seen within the last `keep_days`.
    pub(crate) fn contains(&self, id: &[u8; 32]) -> bool {
        let inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.days.values().any(|s| s.contains(id))
    }

    /// Remember `id` (on `today`), unless it was seen already or the set is full.
    pub(crate) fn add(&self, id: [u8; 32], today: u64) -> Seen {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.expire(&mut inner, today);
        if inner.days.values().any(|s| s.contains(&id)) {
            return Seen::Again;
        }
        if inner.total >= self.max {
            return Seen::Full;
        }
        let path = self.dir.join(today.to_string());
        let written = std::fs::OpenOptions::new().create(true).append(true).open(&path).and_then(|mut f| f.write_all(&id));
        if written.is_ok() {
            crate::coarsen_mtime(&path);
        }
        inner.days.entry(today).or_default().insert(id);
        inner.total += 1;
        Seen::New
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("sentinel-seen-{}", data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<8>())))
    }

    #[test]
    fn ids_are_remembered_across_restarts_until_they_expire() {
        let dir = tmp();
        let s = SeenSet::load(&dir, 3, 100, 1000);
        assert_eq!(s.add([1; 32], 1000), Seen::New);
        assert_eq!(s.add([1; 32], 1001), Seen::Again);
        assert_eq!(s.add([2; 32], 1001), Seen::New);
        drop(s);
        // A restart: still known.
        let s = SeenSet::load(&dir, 3, 100, 1002);
        assert!(s.contains(&[1; 32]) && s.contains(&[2; 32]));
        assert_eq!(s.add([1; 32], 1003), Seen::Again);
        // Day 1000 is forgotten after 3 days; day 1001 is kept a day longer.
        assert_eq!(s.add([3; 32], 1004), Seen::New);
        assert!(!s.contains(&[1; 32]) && s.contains(&[2; 32]));
        assert!(!dir.join("1000").exists());
        drop(s);
        let s = SeenSet::load(&dir, 3, 100, 1005);
        assert!(!s.contains(&[2; 32]) && s.contains(&[3; 32]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_full_set_refuses_rather_than_forgets() {
        let dir = tmp();
        let s = SeenSet::load(&dir, 2, 2, 10);
        assert_eq!(s.add([1; 32], 10), Seen::New);
        assert_eq!(s.add([2; 32], 10), Seen::New);
        assert_eq!(s.add([3; 32], 10), Seen::Full);
        assert_eq!(s.add([1; 32], 11), Seen::Again); // still recognised
        // Once the old day expires there is room again.
        assert_eq!(s.add([3; 32], 13), Seen::New);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
