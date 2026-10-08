//! The mint's quantum-safe ledger (spec §13): per key period, the public
//! list of note commitments, the signed checkpoints of it, and the spent
//! nullifiers. Nothing else: no accounts, no balances, no record of who
//! asked for what.
//!
//! Files (in the Pillar's store): `pq-notes-<epoch>.bin` (32 bytes per
//! commitment, in order), `pq-checkpoints-<epoch>.cbor`, and
//! `pq-spent-<epoch>.bin` (32 bytes per nullifier). Periods that can no
//! longer be spent are deleted.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{bail, Result};
use sentinel_core::credits;
use sentinel_core::pq::{HybridPublic, HybridSigner};
use sentinel_core::pqcash::{self, Checkpoint, Digest, SignedCheckpoint, Tree};

pub struct PqLedger {
    signer: HybridSigner,
    trees: Mutex<HashMap<u32, Tree>>,
    checkpoints: Mutex<HashMap<u32, Vec<SignedCheckpoint>>>,
    spent: Mutex<HashMap<u32, HashSet<[u8; 32]>>>,
}

fn notes_path(store: &Path, e: u32) -> PathBuf {
    store.join(format!("pq-notes-{e}.bin"))
}

fn cps_path(store: &Path, e: u32) -> PathBuf {
    store.join(format!("pq-checkpoints-{e}.cbor"))
}

fn spent_path(store: &Path, e: u32) -> PathBuf {
    store.join(format!("pq-spent-{e}.bin"))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn append_file(path: &Path, bytes: &[u8]) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = std::io::Write::write_all(&mut f, bytes);
    }
}

impl PqLedger {
    pub fn load(store: &Path, mint_seed: &[u8; 32]) -> Self {
        let now = credits::current_epoch();
        let (mut trees, mut cps, mut spent) = (HashMap::new(), HashMap::new(), HashMap::new());
        for e in [now.saturating_sub(1), now] {
            let leaves: Vec<Digest> = std::fs::read(notes_path(store, e))
                .map(|b| b.chunks_exact(32).filter_map(|c| pqcash::digest_from_bytes(c.try_into().ok()?)).collect())
                .unwrap_or_default();
            trees.insert(e, Tree::from_leaves(leaves).unwrap_or_default());
            let list: Vec<SignedCheckpoint> = std::fs::read(cps_path(store, e)).ok().and_then(|b| ciborium::from_reader(b.as_slice()).ok()).unwrap_or_default();
            cps.insert(e, list);
            let set: HashSet<[u8; 32]> = std::fs::read(spent_path(store, e)).map(|b| b.chunks_exact(32).map(|c| c.try_into().expect("32")).collect()).unwrap_or_default();
            spent.insert(e, set);
        }
        let l = PqLedger { signer: pqcash::mint_signer(mint_seed), trees: Mutex::new(trees), checkpoints: Mutex::new(cps), spent: Mutex::new(spent) };
        l.prune(store);
        l
    }

    /// Sign a list of vouched Pillars (see `sentinel_core::directory`).
    pub fn sign_vouch(&self, body: sentinel_core::directory::Vouch) -> sentinel_core::directory::SignedVouch {
        sentinel_core::directory::sign_vouch(&self.signer, body)
    }

    pub fn public(&self) -> HybridPublic {
        self.signer.public()
    }

    /// Add commitments to the current list: (epoch, first position).
    pub fn append(&self, store: &Path, cms: &[[u8; 32]]) -> Option<(u32, u64)> {
        let digests: Vec<Digest> = cms.iter().map(pqcash::digest_from_bytes).collect::<Option<_>>()?;
        let e = credits::current_epoch();
        let mut trees = lock(&self.trees);
        let tree = trees.entry(e).or_default();
        let first = tree.push(&digests)? as u64;
        append_file(&notes_path(store, e), &cms.concat());
        Some((e, first))
    }

    pub fn leaves(&self, epoch: u32, from: u64) -> (u64, Vec<[u8; 32]>) {
        let trees = lock(&self.trees);
        let Some(t) = trees.get(&epoch) else { return (0, Vec::new()) };
        let from = usize::try_from(from).unwrap_or(usize::MAX).min(t.len());
        let to = (from + pqcash::LEAVES_PER_REPLY).min(t.len());
        (t.len() as u64, t.leaves()[from..to].iter().map(pqcash::digest_bytes).collect())
    }

    /// Sign a checkpoint of each spendable list that grew since the last
    /// one (or has none yet).
    pub fn checkpoint(&self, store: &Path, mint: &str) {
        let now = credits::current_epoch();
        let snapshot: Vec<(u32, Tree)> = lock(&self.trees).iter().filter(|(e, _)| credits::spendable(**e, now)).map(|(e, t)| (*e, t.clone())).collect();
        for (e, tree) in snapshot {
            let last = lock(&self.checkpoints).get(&e).and_then(|l| l.last().cloned());
            if last.as_ref().is_some_and(|l| l.body.size == tree.len() as u64) {
                continue;
            }
            // Hashing a large list takes a moment: done outside the locks.
            let root = pqcash::digest_bytes(&tree.root());
            let body = Checkpoint { mint: mint.to_owned(), epoch: e, seq: last.map(|l| l.body.seq + 1).unwrap_or(0), size: tree.len() as u64, root };
            let signed = pqcash::sign_checkpoint(&self.signer, body);
            let mut cps = lock(&self.checkpoints);
            let list = cps.entry(e).or_default();
            list.push(signed);
            let mut b = Vec::new();
            if ciborium::into_writer(&*list, &mut b).is_ok() {
                let _ = std::fs::write(cps_path(store, e), b);
            }
        }
    }

    pub fn latest_checkpoint(&self, epoch: u32) -> Option<SignedCheckpoint> {
        lock(&self.checkpoints).get(&epoch).and_then(|l| l.last().cloned())
    }

    /// Spend notes of `epoch` (checked proofs, bound to `commitments`) and
    /// add `commitments` to the current list. All or nothing.
    pub fn swap(&self, store: &Path, epoch: u32, proofs: &[Vec<u8>], commitments: &[[u8; 32]]) -> Result<(u32, u64, usize)> {
        let now = credits::current_epoch();
        if !credits::spendable(epoch, now) || proofs.is_empty() || proofs.len() > pqcash::MAX_PROOFS || commitments.is_empty() || commitments.len() > credits::MAX_BATCH {
            bail!("bad swap");
        }
        let bind = pqcash::swap_bind(epoch, commitments);
        let roots: HashSet<[u8; 32]> = lock(&self.checkpoints).get(&epoch).map(|l| l.iter().map(|c| c.body.root).collect()).unwrap_or_default();
        let mut nullifiers = Vec::new();
        for p in proofs {
            // Cheap checks first (replays, other lists, other payees), then
            // the proof itself.
            let unspent = |s: &pqcash::Spend| {
                let spent = lock(&self.spent);
                let set = spent.get(&epoch);
                s.nullifiers.iter().all(|n| set.is_none_or(|x| !x.contains(&pqcash::digest_bytes(n))))
            };
            let s = pqcash::verify_if(p, |s| s.bind == bind && roots.contains(&pqcash::digest_bytes(&s.root)) && unspent(s)).map_err(|_| anyhow::anyhow!("invalid or already spent"))?;
            nullifiers.extend(s.nullifiers.iter().map(pqcash::digest_bytes));
        }
        if nullifiers.len() != commitments.len() {
            bail!("bad swap");
        }
        {
            let mut spent = lock(&self.spent);
            let set = spent.entry(epoch).or_default();
            let mut seen = HashSet::new();
            if nullifiers.iter().any(|n| set.contains(n) || !seen.insert(*n)) {
                bail!("already spent");
            }
            for n in &nullifiers {
                set.insert(*n);
            }
            append_file(&spent_path(store, epoch), &nullifiers.concat());
        }
        let (e, first) = self.append(store, commitments).ok_or_else(|| anyhow::anyhow!("bad commitments"))?;
        Ok((e, first, nullifiers.len()))
    }

    /// Forget periods that can no longer be spent.
    pub fn prune(&self, store: &Path) {
        let now = credits::current_epoch();
        lock(&self.trees).retain(|e, _| credits::spendable(*e, now));
        lock(&self.checkpoints).retain(|e, _| credits::spendable(*e, now));
        lock(&self.spent).retain(|e, _| credits::spendable(*e, now));
        if let Ok(rd) = std::fs::read_dir(store) {
            for f in rd.flatten() {
                let name = f.file_name().to_string_lossy().into_owned();
                let e = ["pq-notes-", "pq-checkpoints-", "pq-spent-"]
                    .iter()
                    .find_map(|p| name.strip_prefix(p))
                    .and_then(|r| r.split('.').next())
                    .and_then(|e| e.parse::<u32>().ok());
                if e.is_some_and(|e| !credits::spendable(e, now)) {
                    let _ = std::fs::remove_file(f.path());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::pqcash::Note;

    fn store() -> PathBuf {
        let d = std::env::temp_dir().join(format!("sentinel-pqmint-{}", data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<8>())));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cms(notes: &[Note]) -> Vec<[u8; 32]> {
        notes.iter().map(|n| pqcash::digest_bytes(&n.commitment())).collect()
    }

    #[test]
    fn notes_are_spent_once_with_proofs_against_signed_checkpoints() {
        let st = store();
        let seed = [5u8; 32];
        let l = PqLedger::load(&st, &seed);
        // Rewards: three notes join the list; a checkpoint is signed.
        let mine: Vec<Note> = (0..3).map(|_| Note::random()).collect();
        l.append(&st, &cms(&[Note::random(), Note::random()])).unwrap();
        let (epoch, first) = l.append(&st, &cms(&mine)).unwrap();
        assert_eq!(first, 2);
        // Not spendable before a checkpoint covers them.
        let (_, leaves) = l.leaves(epoch, 0);
        let leaves: Vec<_> = leaves.iter().filter_map(pqcash::digest_from_bytes).collect();
        l.checkpoint(&st, "mint");
        let cp = l.latest_checkpoint(epoch).unwrap();
        assert!(pqcash::verify_checkpoint(&l.public(), &cp));
        assert_eq!(cp.body.size, 5);
        // Spend two of them into two fresh notes.
        let fresh: Vec<Note> = (0..2).map(|_| Note::random()).collect();
        let spend: Vec<(Note, u64)> = mine[..2].iter().enumerate().map(|(i, n)| (n.clone(), first + i as u64)).collect();
        let proofs = pqcash::swap_proofs(&leaves, &cp.body, epoch, &spend, &cms(&fresh)).unwrap();
        // A proof redirected to someone else's fresh notes is refused.
        assert!(l.swap(&st, epoch, &proofs, &cms(&[Note::random(), Note::random()])).is_err());
        let (_, new_first, n) = l.swap(&st, epoch, &proofs, &cms(&fresh)).unwrap();
        assert_eq!((new_first, n), (5, 2));
        // The same notes can't be spent again (even with a fresh proof).
        let again = pqcash::swap_proofs(&leaves, &cp.body, epoch, &spend, &cms(&[Note::random(), Note::random()])).unwrap();
        let err = l.swap(&st, epoch, &again, &cms(&[Note::random(), Note::random()])).unwrap_err().to_string();
        assert!(err.contains("bind") || err.contains("already spent") || err.contains("invalid"), "{err}");
        let other: Vec<Note> = (0..2).map(|_| Note::random()).collect();
        let again = pqcash::swap_proofs(&leaves, &cp.body, epoch, &spend, &cms(&other)).unwrap();
        assert!(l.swap(&st, epoch, &again, &cms(&other)).unwrap_err().to_string().contains("already spent"));
        // The fresh notes aren't in a checkpoint yet: their owner must wait.
        let (_, all) = l.leaves(epoch, 0);
        let all: Vec<_> = all.iter().filter_map(pqcash::digest_from_bytes).collect();
        assert_eq!(pqcash::swap_proofs(&all, &cp.body, epoch, &[(fresh[0].clone(), 5)], &cms(&[Note::random()])), Err(pqcash::PqError::NotYet));
        // A list the mint never signed (a made-up root) is refused.
        let mut fake = Tree::default();
        fake.push(&[mine[2].commitment()]);
        let p = pqcash::prove(&fake, &[(mine[2].clone(), 0)], &pqcash::swap_bind(epoch, &cms(&[Note::random()]))).unwrap();
        assert!(l.swap(&st, epoch, &[p], &cms(&[Note::random()])).is_err());
        // Everything survives a restart (lists, checkpoints, spent tags).
        let l2 = PqLedger::load(&st, &seed);
        assert_eq!(l2.leaves(epoch, 0).0, 7);
        assert_eq!(l2.latest_checkpoint(epoch), Some(cp));
        assert!(l2.swap(&st, epoch, &again, &cms(&other)).unwrap_err().to_string().contains("already spent"));
        let _ = std::fs::remove_dir_all(st);
    }
}
