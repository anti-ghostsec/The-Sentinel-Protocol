//! Proof-of-work stamps (spec §10.4.7–8, §16).
//!
//! A stamp makes an anonymous action (follow notice, boost) cost real
//! compute, so inflating counts with fake identities is expensive, without
//! requiring any identity. `BLAKE3(domain ‖ data ‖ nonce)` must have at least
//! `bits` leading zero bits.

/// Default difficulty: ~260k hashes on average (well under a second on a
/// laptop, but 1M fake follows would cost real compute).
pub const DEFAULT_BITS: u32 = 18;

fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

fn digest(domain: &str, data: &[u8], nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(domain);
    h.update(data);
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Find a nonce satisfying `bits` for `data` (CPU-bound; run off the UI thread).
pub fn stamp(domain: &str, data: &[u8], bits: u32) -> u64 {
    let mut nonce = u64::from_le_bytes(crate::random_bytes::<8>());
    loop {
        if leading_zero_bits(&digest(domain, data, nonce)) >= bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Same as `stamp`, using all but one processor core (for the big
/// stamps, like free credits). Same difficulty, same kind of answer.
pub fn stamp_parallel(domain: &str, data: &[u8], bits: u32) -> u64 {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let threads = std::thread::available_parallelism().map(|n| n.get().saturating_sub(1)).unwrap_or(1).clamp(1, 32);
    if threads == 1 {
        return stamp(domain, data, bits);
    }
    let found = AtomicBool::new(false);
    let answer = AtomicU64::new(0);
    let mut base = blake3::Hasher::new_derive_key(domain);
    base.update(data);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| {
                let mut nonce = u64::from_le_bytes(crate::random_bytes::<8>());
                while !found.load(Ordering::Relaxed) {
                    for _ in 0..4096 {
                        let mut h = base.clone();
                        h.update(&nonce.to_le_bytes());
                        if leading_zero_bits(h.finalize().as_bytes()) >= bits {
                            if !found.swap(true, Ordering::SeqCst) {
                                answer.store(nonce, Ordering::SeqCst);
                            }
                            return;
                        }
                        nonce = nonce.wrapping_add(1);
                    }
                }
            });
        }
    });
    answer.load(Ordering::SeqCst)
}

pub fn check(domain: &str, data: &[u8], nonce: u64, bits: u32) -> bool {
    leading_zero_bits(&digest(domain, data, nonce)) >= bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_and_check() {
        let n = stamp("test/pow", b"hello", 10);
        assert!(check("test/pow", b"hello", n, 10));
        assert!(!check("test/pow", b"other", n, 24));
    }

    #[test]
    fn parallel_stamps_check_the_same_way() {
        let n = stamp_parallel("test/pow", b"hello", 14);
        assert!(check("test/pow", b"hello", n, 14));
    }
}
