//! Erasure coding of media chunks (spec §5.7 step 5, §14.7).
//!
//! Encrypted chunks are grouped into stripes of `data` chunks; each stripe
//! gets `parity` Reed-Solomon chunks computed over the *ciphertext*, the same
//! size as data chunks and indistinguishable from them. Chunks are spread
//! across Archives so that losing any one Archive loses at most `parity`
//! chunks of a stripe — the stripe can always be rebuilt.
//!
//! Layout in the manifest: data chunk addresses `[0, total)`, then parity
//! addresses stripe by stripe. A short final stripe is padded with virtual
//! all-zero chunks (never stored or fetched).

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};

/// Data chunks per stripe.
pub const DATA: usize = 10;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Layout {
    pub data: u8,
    pub parity: u8,
    /// Number of Archives the chunks are spread over.
    pub hosts: u8,
}

impl Layout {
    /// Parity sized so any single Archive can disappear: with `hosts`
    /// Archives, each holds at most ceil(n / hosts) chunks of a stripe, which
    /// must not exceed the parity. Needs at least 3 Archives (with fewer,
    /// plain replication is as good).
    pub fn for_hosts(hosts: usize) -> Option<Layout> {
        if hosts < 3 {
            return None;
        }
        let hosts = hosts.min(16);
        let mut parity = 1;
        while (DATA + parity).div_ceil(hosts) > parity {
            parity += 1;
        }
        Some(Layout { data: DATA as u8, parity: parity as u8, hosts: hosts as u8 })
    }

    pub fn stripes(&self, total: u64) -> u64 {
        total.div_ceil(self.data as u64)
    }

    pub fn parity_chunks(&self, total: u64) -> u64 {
        self.stripes(total) * self.parity as u64
    }

    /// Manifest position of parity chunk `p` of stripe `s`.
    pub fn parity_pos(&self, total: u64, s: u64, p: u64) -> u64 {
        total + s * self.parity as u64 + p
    }

    /// Which Archive (index into the reference's list) holds a chunk:
    /// position `t` within stripe `s` (data 0..data, parity after), rotated
    /// per stripe so load is even.
    pub fn host_of(&self, s: u64, t: u64) -> usize {
        ((s + t) % self.hosts as u64) as usize
    }

    fn codec(&self) -> ReedSolomon {
        ReedSolomon::new(self.data as usize, self.parity as usize).expect("valid shard counts")
    }

    /// Parity chunks for one stripe of equal-size ciphertext chunks (a short
    /// final stripe is padded with zero chunks).
    pub fn encode(&self, stripe: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let len = stripe.first().map(|c| c.len()).unwrap_or(0);
        let mut shards: Vec<Vec<u8>> = stripe.to_vec();
        shards.resize(self.data as usize, vec![0u8; len]);
        shards.extend((0..self.parity).map(|_| vec![0u8; len]));
        self.codec().encode(&mut shards).expect("equal-size shards");
        shards.split_off(self.data as usize)
    }

    /// Rebuild a stripe's data chunks from any `data` of its chunks.
    /// `have[t]` holds chunk `t` (data then parity) if fetched; virtual
    /// padding chunks of a short stripe (`real` data chunks) are supplied
    /// here as zeros. Returns the `real` data chunks.
    pub fn reconstruct(&self, mut have: Vec<Option<Vec<u8>>>, real: usize) -> Option<Vec<Vec<u8>>> {
        let n = (self.data + self.parity) as usize;
        have.resize(n, None);
        let len = have.iter().flatten().next()?.len();
        for slot in have.iter_mut().take(self.data as usize).skip(real) {
            *slot = Some(vec![0u8; len]);
        }
        self.codec().reconstruct_data(&mut have).ok()?;
        Some(have.into_iter().take(real).map(|c| c.unwrap_or_default()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_survives_losing_any_one_archive() {
        for hosts in 3..=12 {
            let l = Layout::for_hosts(hosts).unwrap();
            let n = (l.data + l.parity) as u64;
            for lost in 0..hosts {
                let gone = (0..n).filter(|t| l.host_of(0, *t) == lost).count();
                assert!(gone <= l.parity as usize, "hosts={hosts} lost={lost}");
            }
        }
        assert!(Layout::for_hosts(2).is_none());
        assert_eq!(Layout::for_hosts(4).unwrap().parity, 4); // 1.4x
        assert_eq!(Layout::for_hosts(6).unwrap().parity, 2); // 1.2x
    }

    #[test]
    fn rebuild_short_stripe_after_losses() {
        let l = Layout::for_hosts(4).unwrap();
        let real = 7; // short final stripe
        let stripe: Vec<Vec<u8>> = (0..real).map(|i| vec![i as u8 * 3 + 1; 64]).collect();
        let parity = l.encode(&stripe);
        assert_eq!(parity.len(), l.parity as usize);
        // Lose 4 chunks: 3 data + 1 parity.
        let mut have: Vec<Option<Vec<u8>>> = stripe.iter().cloned().map(Some).collect();
        have.resize(l.data as usize, None);
        have.extend(parity.into_iter().map(Some));
        have[0] = None;
        have[2] = None;
        have[6] = None;
        have[l.data as usize] = None;
        let back = l.reconstruct(have, real).unwrap();
        assert_eq!(back, stripe);
    }
}
