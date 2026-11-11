//! Daily limits on stored objects, per author.
//!
//! Proof of work alone makes filling a Pillar cost CPU time, but not much.
//! On top of it each author may store at most [`AUTHOR_BYTES_PER_DAY`] and
//! [`AUTHOR_OBJECTS_PER_DAY`] a day. Author keys cost nothing to make, so
//! an author this Pillar holds nothing from pays [`NEW_AUTHOR_EXTRA_BITS`]
//! more proof of work (256 times as much), and at most
//! [`NEW_AUTHORS_PER_DAY`] new authors are taken a day. Filling the
//! object share of a default 2 GB Pillar then needs about 1,500 authors,
//! more than a day to bring them in, and each one's first object costs a
//! few seconds of a whole machine.
//!
//! Counts are kept in memory (a restart resets the day's counts).
//!
//! [`NEW_AUTHOR_EXTRA_BITS`]: sentinel_core::social::NEW_AUTHOR_EXTRA_BITS

use std::collections::HashMap;
use std::sync::Mutex;

pub(crate) const AUTHOR_BYTES_PER_DAY: u64 = 1024 * 1024;
pub(crate) const AUTHOR_OBJECTS_PER_DAY: u32 = 100;
pub(crate) const NEW_AUTHORS_PER_DAY: u32 = 1000;

#[derive(Default)]
struct Day {
    day: u64,
    authors: HashMap<[u8; 32], (u64, u32)>,
    new_authors: u32,
}

#[derive(Default)]
pub(crate) struct AuthorLimits(Mutex<Day>);

impl AuthorLimits {
    /// Count an object of `len` bytes from `author` (`new`: the Pillar holds
    /// nothing from it yet), or say why it's refused.
    pub(crate) fn admit(&self, author: &[u8; 32], len: u64, new: bool, today: u64) -> Result<(), &'static str> {
        let mut d = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if d.day != today {
            *d = Day { day: today, ..Day::default() };
        }
        if new && !d.authors.contains_key(author) && d.new_authors >= NEW_AUTHORS_PER_DAY {
            return Err("this Pillar takes no more new authors today");
        }
        let (bytes, count) = d.authors.get(author).copied().unwrap_or((0, 0));
        if bytes + len > AUTHOR_BYTES_PER_DAY || count >= AUTHOR_OBJECTS_PER_DAY {
            return Err("daily limit for this author reached");
        }
        if new && !d.authors.contains_key(author) {
            d.new_authors += 1;
        }
        d.authors.insert(*author, (bytes + len, count + 1));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_author_has_a_daily_budget() {
        let l = AuthorLimits::default();
        let a = [1u8; 32];
        assert!(l.admit(&a, AUTHOR_BYTES_PER_DAY - 10, false, 5).is_ok());
        assert!(l.admit(&a, 11, false, 5).is_err());
        assert!(l.admit(&a, 10, false, 5).is_ok());
        // Another author isn't affected; the next day starts afresh.
        assert!(l.admit(&[2u8; 32], 1000, false, 5).is_ok());
        assert!(l.admit(&a, 1000, false, 6).is_ok());
        for _ in 1..AUTHOR_OBJECTS_PER_DAY {
            assert!(l.admit(&a, 1, false, 6).is_ok());
        }
        assert!(l.admit(&a, 1, false, 6).is_err());
    }

    #[test]
    fn new_authors_are_limited_per_day() {
        let l = AuthorLimits::default();
        for i in 0..NEW_AUTHORS_PER_DAY {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_le_bytes());
            assert!(l.admit(&a, 100, true, 1).is_ok());
        }
        assert!(l.admit(&[0xFF; 32], 100, true, 1).is_err());
        // Authors already known here still post, and new ones come back tomorrow.
        assert!(l.admit(&[0xEE; 32], 100, false, 1).is_ok());
        assert!(l.admit(&[0xFF; 32], 100, true, 2).is_ok());
    }
}
