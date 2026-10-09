//! Credits on a node (spec §14.7, §21.1): the mint, paid pinning, and
//! earning by contributing storage.
//!
//! **Mint** (a duty of the network's established Pillars, not a separate
//! role): adds notes for swaps (payments) and rewards for Archives (there
//! are no free credits) and keeps only nullifiers of spent tokens, per key
//! epoch (older epochs are deleted), plus public supply counts — no
//! accounts, no balances, no transaction graph.
//!
//! **Earned class**: the mint seeds each Archive with *filler* chunks it can
//! regenerate from a secret seed (so the mint stores nothing), challenges
//! random ones over isolated circuits, and pays Archives that keep passing.
//! Rewards are delivered by the mint connecting to the Archive's own onion,
//! so only its operator receives them; the mint learns which onion earned,
//! never who runs it.
//!
//! **Pinning**: a reader or uploader pays credits to keep chunks past the
//! free 90-day expiry; the Archive swaps the tokens at the mint (they become
//! its operator's credits).
//!
//! **Quantum-safe notes** (`pqcash`, `pqmint`): all new credits are notes
//! in the mint's public list, spent with zero-knowledge proofs. Old blind
//! tokens are no longer issued; they can only be traded in for notes.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sentinel_core::credits::{self, Token};
use sentinel_core::pqcash;

use crate::pqmint::PqLedger;
use sentinel_core::object::Address;
use sentinel_core::wire::{Request, Response};
use sentinel_core::{media, pow};

use super::{exchange, Ctx};

/// Filler chunks the mint keeps on each Archive (verifies real storage).
const FILLER_TARGET: u64 = 32;
/// Most credits one Archive earns per day.
const MAX_DAILY_REWARD: u32 = 3;

#[derive(Default, Serialize, Deserialize, Clone)]
struct FillerState {
    count: u64,
    passes: u32,
    fails: u32,
    last_reward_day: u64,
}

pub struct MintState {
    mint: credits::Mint,
    seed: [u8; 32],
    /// Spent nullifiers per epoch (only spendable epochs are kept).
    spent: Mutex<HashMap<u32, HashSet<[u8; 32]>>>,
    /// Public supply figures per epoch: (issued, spent).
    stats: Mutex<HashMap<u32, (u64, u64)>>,
    archives: Mutex<HashMap<String, FillerState>>,
    /// Quantum-safe notes: lists, checkpoints, spent nullifiers.
    pub pq: PqLedger,
    /// Pillars' reward scores (see `earning`), and the last day shares
    /// were handed out.
    pillars: Mutex<HashMap<String, crate::earning::Score>>,
    /// The signed vouched list, remade at most once an hour: (hour, CBOR).
    vouch_cache: Mutex<Option<(u64, Vec<u8>)>>,
    share_day: Mutex<u64>,
}

pub struct Econ {
    pub mint: Option<MintState>,
    /// The network's mints (credits are bundles from a majority of them).
    pub mints: Vec<String>,
    /// Other mints' checkpoint keys (first seen, kept for this run).
    pq_pks: Mutex<HashMap<String, sentinel_core::pq::HybridPublic>>,
}

/// A reward exchange in progress on one stream. Kept per stream, so an
/// offer sent by anyone else (on another stream) can't spoil the real one.
pub struct RewardState(Option<(String, Vec<pqcash::Note>)>);

impl RewardState {
    pub fn new() -> Self {
        RewardState(None)
    }
}

/// Reward requests (they need per-stream state); None for anything else.
pub async fn handle_reward(req: &Request, ctx: &Ctx, st: &mut RewardState) -> Option<Response> {
    Some(match req {
        Request::RewardOfferPq { count, mint } => {
            // Only listed mints can pay; anyone else's offer is refused.
            if !ctx.econ.mints.contains(mint) {
                return Some(Response::Rejected("not a mint of this network".into()));
            }
            let n = (*count as usize).clamp(1, MAX_DAILY_REWARD as usize);
            let notes: Vec<pqcash::Note> = (0..n).map(|_| pqcash::Note::random()).collect();
            let cms = notes.iter().map(|n| pqcash::digest_bytes(&n.commitment())).collect();
            st.0 = Some((mint.clone(), notes));
            Response::Commitments(cms)
        }
        Request::RewardAppended { mint, epoch, first } => {
            let Some((m, notes)) = st.0.take() else { return Some(Response::Rejected("no offer".into())) };
            if m != *mint || !credits::issue_epoch_ok_now(*epoch) {
                return Some(Response::Rejected("no offer".into()));
            }
            // Positions are only a hint: spending finds the notes in the
            // mint's signed list (and fails if they aren't there).
            add_rewards(&ctx.store, mint, notes.iter().enumerate().map(|(i, n)| Token::from_note(n, *epoch, first + i as u64)).collect());
            Response::Pong
        }
        _ => return None,
    })
}

fn day() -> u64 {
    // Test builds: a "day" of SENTINEL_TEST_DAY_SECS seconds, counted from
    // a year after the pool started, to watch earning live in minutes.
    #[cfg(feature = "test-hooks")]
    if let Some(secs) = std::env::var("SENTINEL_TEST_DAY_SECS").ok().and_then(|s| s.parse::<u64>().ok()).filter(|s| *s > 0) {
        static START: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        let start = *START.get_or_init(now);
        return crate::earning::POOL_START_DAY + 365 + (now() - start) / secs;
    }
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() / 86_400).unwrap_or(0)
}

fn now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn pins_path(store: &Path) -> PathBuf {
    store.join("pins.txt")
}

fn rewards_path(store: &Path) -> PathBuf {
    store.join("rewards.json")
}

/// Pinned chunk names (address text) -> until (Unix time).
pub fn load_pins(store: &Path) -> HashMap<String, u64> {
    std::fs::read_to_string(pins_path(store))
        .map(|t| {
            t.lines()
                .filter_map(|l| {
                    let (a, u) = l.split_once(' ')?;
                    Some((a.to_owned(), u.parse().ok()?))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Take (and delete) the credit parts this node has earned: (mint, token).
/// Test builds: how many earned parts are really in this mint's list.
#[cfg(feature = "test-hooks")]
pub fn check_rewards(mint_store: &Path, parts: &[(String, Token)]) -> Result<(usize, usize)> {
    let seed: [u8; 32] = std::fs::read(mint_store.join("mint-seed.bin"))?.as_slice().try_into().map_err(|_| anyhow::anyhow!("bad mint seed"))?;
    let ledger = crate::pqmint::PqLedger::load(mint_store, &seed);
    let found = parts
        .iter()
        .filter(|(_, t)| {
            t.note().is_some_and(|(note, i)| ledger.leaves(t.epoch, i).1.first() == Some(&pqcash::digest_bytes(&note.commitment())))
        })
        .count();
    Ok((found, parts.len()))
}

pub fn take_rewards(store: &Path) -> Vec<(String, Token)> {
    let path = rewards_path(store);
    let t: Vec<(String, Token)> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let _ = std::fs::remove_file(path);
    t
}

fn add_rewards(store: &Path, mint: &str, new: Vec<Token>) {
    let path = rewards_path(store);
    let mut all: Vec<(String, Token)> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    all.extend(new.into_iter().map(|t| (mint.to_owned(), t)));
    if let Ok(b) = serde_json::to_vec(&all) {
        let _ = std::fs::write(path, b);
    }
}

fn spent_path(store: &Path, epoch: u32) -> PathBuf {
    store.join(format!("nullifiers-{epoch}.bin"))
}

impl Econ {
    /// A Pillar on the network's mint list mints; others don't.
    pub fn load(store: &Path, self_onion: &str, mints: Vec<String>) -> Result<Econ> {
        let mint = if mints.iter().any(|m| m == self_onion) {
            let seed_path = store.join("mint-seed.bin");
            let seed: [u8; 32] = match std::fs::read(&seed_path) {
                Ok(b) if b.len() == 32 => b.try_into().unwrap(),
                _ => {
                    let s = sentinel_core::random_bytes::<32>();
                    std::fs::write(&seed_path, s)?;
                    s
                }
            };
            let now = credits::current_epoch();
            let mut spent = HashMap::new();
            for e in [now.saturating_sub(1), now] {
                let set: HashSet<[u8; 32]> =
                    std::fs::read(spent_path(store, e)).map(|b| b.chunks_exact(32).map(|c| c.try_into().unwrap()).collect()).unwrap_or_default();
                spent.insert(e, set);
            }
            let _ = std::fs::remove_file(store.join("nullifiers.bin")); // pre-epoch format
            let stats = std::fs::read(store.join("mint-stats.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            let archives = std::fs::read(store.join("mint-archives.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            let pillars = std::fs::read(store.join("mint-pillars.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            let share_day = std::fs::read_to_string(store.join("mint-share-day.txt")).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0);
            // Issuers check spend proofs all day: keep the proof circuit.
            std::thread::spawn(pqcash::warm_up);
            let m = MintState { mint: credits::Mint::from_seed(&seed), seed, spent: Mutex::new(spent), stats: Mutex::new(stats), archives: Mutex::new(archives), pq: PqLedger::load(store, &seed), pillars: Mutex::new(pillars), share_day: Mutex::new(share_day), vouch_cache: Mutex::new(None) };
            m.prune(store);
            Some(m)
        } else {
            None
        };
        Ok(Econ { mint, mints, pq_pks: Mutex::new(HashMap::new()) })
    }
}

impl MintState {
    pub fn public_key(&self) -> Vec<u8> {
        self.mint.public_key()
    }

    /// Mark tokens spent if all are valid, spendable now and unspent (all
    /// or nothing).
    fn spend(&self, store: &Path, tokens: &[Token]) -> bool {
        let now = credits::current_epoch();
        let mut spent = self.spent.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut seen = HashSet::new();
        for t in tokens {
            let n = t.nullifier();
            if !credits::spendable(t.epoch, now) || !self.mint.valid(t) || spent.get(&t.epoch).is_some_and(|s| s.contains(&n)) || !seen.insert((t.epoch, n)) {
                return false;
            }
        }
        for (e, n) in seen {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(spent_path(store, e)) {
                let _ = std::io::Write::write_all(&mut f, &n);
            }
            spent.entry(e).or_default().insert(n);
            self.stats.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(e).or_default().1 += 1;
        }
        drop(spent);
        self.save_stats(store);
        true
    }

    /// Count notes added to the list (public supply figures).
    fn count_issued(&self, store: &Path, epoch: u32, n: usize) {
        self.stats.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(epoch).or_default().0 += n as u64;
        self.save_stats(store);
    }

    fn count_spent(&self, store: &Path, epoch: u32, n: usize) {
        self.stats.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(epoch).or_default().1 += n as u64;
        self.save_stats(store);
    }

    fn save_stats(&self, store: &Path) {
        if let Ok(b) = serde_json::to_vec(&*self.stats.lock().unwrap_or_else(std::sync::PoisonError::into_inner)) {
            let _ = std::fs::write(store.join("mint-stats.json"), b);
        }
    }

    /// Forget spent lists of epochs that can no longer be spent.
    fn prune(&self, store: &Path) {
        let now = credits::current_epoch();
        self.spent.lock().unwrap_or_else(std::sync::PoisonError::into_inner).retain(|e, _| credits::spendable(*e, now));
        if let Ok(rd) = std::fs::read_dir(store) {
            for f in rd.flatten() {
                let name = f.file_name().to_string_lossy().into_owned();
                if let Some(e) = name.strip_prefix("nullifiers-").and_then(|r| r.strip_suffix(".bin")).and_then(|e| e.parse::<u32>().ok()) {
                    if !credits::spendable(e, now) {
                        let _ = std::fs::remove_file(f.path());
                    }
                }
            }
        }
    }

    fn filler(&self, onion: &str, i: u64) -> Vec<u8> {
        let mut m = self.seed.to_vec();
        m.extend_from_slice(onion.as_bytes());
        let key = blake3::derive_key("sentinel/v0/mint-filler", &m);
        media::encrypt_chunk(&key, i, &[])
    }

    fn save(&self, store: &Path) {
        if let Ok(b) = serde_json::to_vec(&*self.archives.lock().unwrap_or_else(std::sync::PoisonError::into_inner)) {
            let _ = std::fs::write(store.join("mint-archives.json"), b);
        }
        if let Ok(b) = serde_json::to_vec(&*self.pillars.lock().unwrap_or_else(std::sync::PoisonError::into_inner)) {
            let _ = std::fs::write(store.join("mint-pillars.json"), b);
        }
    }

    /// Once a day: work out each Pillar's share and add it to what it's owed
    /// (delivered on the next visit; at most a week's worth waits).
    /// The Pillars this issuer has seen answer its random checks for weeks
    /// (reward weight built up, checked in the last two days), most
    /// reliable first, signed. Apps try these first when they connect.
    fn vouched(&self, self_onion: &str) -> Vec<u8> {
        let hour = now() / 3600;
        let mut cache = self.vouch_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((h, b)) = cache.as_ref() {
            if *h == hour {
                return b.clone();
            }
        }
        let today = day();
        let mut good: Vec<(String, f64)> = self
            .pillars
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, s)| s.earning_weight() >= crate::earning::VOUCH_WEIGHT && s.day + 2 >= today)
            .map(|(o, s)| (o.clone(), s.earning_weight()))
            .collect();
        good.sort_by(|a, b| b.1.total_cmp(&a.1));
        let body = sentinel_core::directory::Vouch { mint: self_onion.to_owned(), day: today, pillars: good.into_iter().map(|(o, _)| o).collect() };
        let b = cbor(&self.pq.sign_vouch(body));
        *cache = Some((hour, b.clone()));
        b
    }

    fn share_out(&self, store: &Path) {
        let today = day();
        let mut sd = self.share_day.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if *sd >= today {
            return;
        }
        let mut pillars = self.pillars.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for s in pillars.values_mut() {
            s.roll(today);
        }
        for (onion, n) in crate::earning::shares(&mut pillars, today) {
            if let Some(s) = pillars.get_mut(&onion) {
                s.owed = (s.owed + n).min(crate::earning::MAX_DAILY * 7);
            }
        }
        *sd = today;
        let _ = std::fs::write(store.join("mint-share-day.txt"), today.to_string());
    }
}

/// Handle a credits request (None = not a credits request).
pub async fn handle(req: &Request, ctx: &Ctx) -> Option<Response> {
    let econ = &ctx.econ;
    Some(match req {
        Request::MintKey => match &econ.mint {
            Some(m) => Response::MintKey(m.mint.public_key()),
            None => Response::NotFound,
        },
        Request::MintStats => match &econ.mint {
            Some(m) => {
                let mut v: Vec<(u32, u64, u64)> = m.stats.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().map(|(e, (i, s))| (*e, *i, *s)).collect();
                v.sort();
                Response::MintStats(v)
            }
            None => Response::NotFound,
        },
        // Old blind tokens are no longer issued (a quantum computer could
        // forge them); they can only be traded in for notes (PqUpgrade).
        Request::MintFaucet { .. } | Request::MintSwap { .. } => Response::Rejected("Sentinel now uses quantum-safe credits: please update the app".into()),
        // Checking proofs is heavy: a few at a time, off the async threads.
        Request::PqSwap { .. } => {
            static CHECKS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
            let _permit = CHECKS.get_or_init(|| tokio::sync::Semaphore::new(2)).acquire().await.ok()?;
            return tokio::task::block_in_place(|| handle_pq(req, ctx));
        }
        Request::Vouched | Request::PqMintKey | Request::PqUpgrade { .. } | Request::PqLeaves { .. } | Request::PqCheckpoint { .. } => return handle_pq(req, ctx),
        Request::Pin { addrs, months, bundles } => match pin(ctx, addrs, *months, bundles).await {
            Ok(n) => Response::Count(n),
            Err(e) => Response::Rejected(e.to_string()),
        },
        _ => return None,
    })
}

/// Quantum-safe mint requests (none of them wait on the network).
pub fn handle_pq(req: &Request, ctx: &Ctx) -> Option<Response> {
    let store = &ctx.store;
    let econ = &ctx.econ;
    Some(match req {
        Request::Vouched => match &econ.mint {
            Some(m) => Response::Object(m.vouched(&ctx.self_onion)),
            None => Response::NotFound,
        },
        Request::PqMintKey => match &econ.mint {
            Some(m) => Response::Object(cbor(&m.pq.public())),
            None => Response::NotFound,
        },
        Request::PqSwap { epoch, proofs, commitments } => {
            let Some(m) = &econ.mint else { return Some(Response::NotFound) };
            // (Checking a proof takes a few milliseconds.)
            match Some(m.pq.swap(store, *epoch, proofs, commitments)) {
                Some(Ok((new_epoch, first, n))) => {
                    m.count_spent(store, *epoch, n);
                    m.count_issued(store, new_epoch, n);
                    Response::PqAppended { epoch: new_epoch, first }
                }
                Some(Err(e)) => Response::Rejected(e.to_string()),
                None => Response::Rejected("mint error".into()),
            }
        }
        Request::PqUpgrade { tokens, commitments } => {
            let Some(m) = &econ.mint else { return Some(Response::NotFound) };
            if tokens.is_empty() || tokens.len() != commitments.len() || tokens.len() > credits::MAX_BATCH || tokens.iter().any(Token::is_pq) {
                return Some(Response::Rejected("bad upgrade".into()));
            }
            if !m.spend(store, tokens) {
                return Some(Response::Rejected("invalid or already spent".into()));
            }
            match m.pq.append(store, commitments) {
                Some((epoch, first)) => {
                    m.count_issued(store, epoch, commitments.len());
                    Response::PqAppended { epoch, first }
                }
                None => Response::Rejected("bad request".into()),
            }
        }
        Request::PqLeaves { epoch, from } => match &econ.mint {
            Some(m) => {
                let (total, leaves) = m.pq.leaves(*epoch, *from);
                Response::PqLeaves { total, leaves }
            }
            None => Response::NotFound,
        },
        Request::PqCheckpoint { epoch } => match econ.mint.as_ref().and_then(|m| m.pq.latest_checkpoint(*epoch)) {
            Some(c) => Response::Object(cbor(&c)),
            None => Response::NotFound,
        },
        _ => return None,
    })
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

/// One request to a mint (myself directly, others over an isolated circuit).
async fn ask_mint(ctx: &Ctx, mint: &str, req: Request) -> Result<Response> {
    if mint == ctx.self_onion {
        return handle_pq(&req, ctx).context("mint error");
    }
    let mut s = ctx.tor.isolated_client().connect((mint, sentinel_net::SENTINEL_PORT)).await?;
    exchange(&mut s, &req).await
}

/// A mint's checkpoint key: pinned by the fingerprint shipped with the app
/// when there is one, else the first one seen (kept for this run).
async fn pq_key(ctx: &Ctx, mint: &str) -> Result<sentinel_core::pq::HybridPublic> {
    if let Some(k) = ctx.econ.pq_pks.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(mint).cloned() {
        return Ok(k);
    }
    let Response::Object(b) = ask_mint(ctx, mint, Request::PqMintKey).await? else { bail!("mint unreachable") };
    let k: sentinel_core::pq::HybridPublic = ciborium::from_reader(b.as_slice()).context("bad mint key")?;
    if let Some(fp) = sentinel_net::builtin_pq_fingerprint(mint) {
        if pqcash::key_fingerprint(&k) != fp {
            bail!("the mint's key doesn't match the one built into Sentinel");
        }
    }
    let mut pks = ctx.econ.pq_pks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(pks.entry(mint.to_owned()).or_insert(k).clone())
}

/// A mint's list for one key period and its latest signed checkpoint.
async fn pq_list(ctx: &Ctx, mint: &str, epoch: u32) -> Result<(Vec<pqcash::Digest>, pqcash::Checkpoint)> {
    let pk = pq_key(ctx, mint).await?;
    let Response::Object(b) = ask_mint(ctx, mint, Request::PqCheckpoint { epoch }).await? else { bail!("no checkpoint yet") };
    let cp: pqcash::SignedCheckpoint = ciborium::from_reader(b.as_slice()).context("bad checkpoint")?;
    if !pqcash::verify_checkpoint(&pk, &cp) || cp.body.mint != mint || cp.body.epoch != epoch {
        bail!("the mint's checkpoint isn't signed correctly");
    }
    // A list can't be bigger than the tree holds (no endless downloads).
    if cp.body.size > 1u64 << pqcash::DEPTH {
        bail!("the credit issuer's checkpoint is impossible");
    }
    let mut leaves = Vec::new();
    while (leaves.len() as u64) < cp.body.size {
        let Response::PqLeaves { leaves: more, .. } = ask_mint(ctx, mint, Request::PqLeaves { epoch, from: leaves.len() as u64 }).await? else { bail!("mint error") };
        if more.is_empty() {
            bail!("the mint's list is shorter than its checkpoint");
        }
        leaves.extend(more.iter().filter_map(pqcash::digest_from_bytes));
    }
    Ok((leaves, cp.body))
}

/// Swap tokens at one mint for fresh notes of this node's (kept with its
/// rewards). Notes are spent with proofs; old blind tokens are traded in.
async fn swap_at(ctx: &Ctx, mint: &str, tokens: &[Token]) -> Result<()> {
    let (pq, old): (Vec<Token>, Vec<Token>) = tokens.iter().cloned().partition(Token::is_pq);
    if !old.is_empty() {
        let notes: Vec<pqcash::Note> = old.iter().map(|_| pqcash::Note::random()).collect();
        let commitments = notes.iter().map(|n| pqcash::digest_bytes(&n.commitment())).collect();
        match ask_mint(ctx, mint, Request::PqUpgrade { tokens: old, commitments }).await? {
            Response::PqAppended { epoch, first } => add_rewards(&ctx.store, mint, notes.iter().enumerate().map(|(i, n)| Token::from_note(n, epoch, first + i as u64)).collect()),
            Response::Rejected(r) => bail!(r),
            _ => bail!("mint error"),
        }
    }
    let mut by_epoch: HashMap<u32, Vec<(pqcash::Note, u64)>> = HashMap::new();
    for t in &pq {
        let note = t.note().context("bad credit")?;
        by_epoch.entry(t.epoch).or_default().push(note);
    }
    for (epoch, notes) in by_epoch {
        let (leaves, cp) = pq_list(ctx, mint, epoch).await?;
        for chunk in notes.chunks(pqcash::SLOTS * pqcash::MAX_PROOFS) {
            let fresh: Vec<pqcash::Note> = chunk.iter().map(|_| pqcash::Note::random()).collect();
            let commitments: Vec<[u8; 32]> = fresh.iter().map(|n| pqcash::digest_bytes(&n.commitment())).collect();
            let (l, c, ch, cm) = (leaves.clone(), cp.clone(), chunk.to_vec(), commitments.clone());
            let proofs = tokio::task::spawn_blocking(move || pqcash::swap_proofs(&l, &c, epoch, &ch, &cm)).await?.map_err(|e| anyhow::anyhow!("{e}"))?;
            match ask_mint(ctx, mint, Request::PqSwap { epoch, proofs, commitments }).await? {
                Response::PqAppended { epoch: e, first } => add_rewards(&ctx.store, mint, fresh.iter().enumerate().map(|(i, n)| Token::from_note(n, e, first + i as u64)).collect()),
                Response::Rejected(r) => bail!(r),
                _ => bail!("mint error"),
            }
        }
    }
    Ok(())
}

/// Take payment: every part of every bundle redeemed at its own mint.
async fn take_payment(ctx: &Ctx, bundles: &[credits::Bundle]) -> Result<()> {
    let t = credits::threshold(ctx.econ.mints.len());
    if bundles.iter().any(|b| !b.valid_shape(&ctx.econ.mints, t)) {
        bail!("credits from unknown mints");
    }
    let mut by_mint: HashMap<String, Vec<Token>> = HashMap::new();
    for b in bundles {
        for (m, tok) in &b.parts {
            by_mint.entry(m.clone()).or_default().push(tok.clone());
        }
    }
    for (m, toks) in by_mint {
        swap_at(ctx, &m, &toks).await?;
    }
    Ok(())
}

async fn pin(ctx: &Ctx, addrs: &[[u8; 32]], months: u32, bundles: &[credits::Bundle]) -> Result<u64> {
    if addrs.is_empty() || addrs.len() > 100_000 || !(1..=24).contains(&months) {
        bail!("bad pin request");
    }
    let held: Vec<&[u8; 32]> = addrs.iter().filter(|a| ctx.store.join("chunks").join(Address(**a).to_text()).is_file()).collect();
    let price = credits::pin_price(held.len() as u64 * media::CHUNK_CT as u64, months);
    if (bundles.len() as u64) < price || bundles.len() > credits::MAX_BATCH {
        bail!("this pin costs {price} credits");
    }
    take_payment(ctx, bundles).await?;
    let until = now() + months as u64 * 30 * 86_400;
    let mut pins = load_pins(&ctx.store);
    for a in &held {
        let e = pins.entry(Address(**a).to_text()).or_insert(0);
        *e = (*e).max(until);
    }
    let text: String = pins.iter().map(|(a, u)| format!("{a} {u}\n")).collect();
    std::fs::write(pins_path(&ctx.store), text)?;
    Ok(held.len() as u64)
}

/// Mint duty: keep filler on every known Archive, challenge it, and pay
/// Archives that keep passing (at random times, over isolated circuits).
pub async fn mint_loop(ctx: Arc<Ctx>) {
    let Some(m) = &ctx.econ.mint else { return };
    tokio::time::sleep(Duration::from_secs(ctx.mint_interval.clamp(10, 120))).await;
    loop {
        let archives: Vec<String> = std::fs::read_to_string(ctx.store.join("known-archives.txt")).map(|t| crate::read_known_text(&t)).unwrap_or_default();
        // Up to 8 at a time, each with a time limit: gone or fake nodes in
        // the lists can't hold up everyone else's checks and rewards.
        use futures::StreamExt;
        futures::stream::iter(archives.iter().filter(|a| **a != ctx.self_onion))
            .for_each_concurrent(8, |a| async {
                let _ = tokio::time::timeout(Duration::from_secs(240), tend_archive(&ctx, m, a)).await;
            })
            .await;
        // Pillars earn too (checks, then shares; see `earning`).
        m.share_out(&ctx.store);
        let pillars: Vec<String> = std::fs::read_to_string(ctx.store.join("known-pillars.txt")).map(|t| crate::read_known_text(&t)).unwrap_or_default();
        futures::stream::iter(pillars.iter().filter(|p| **p != ctx.self_onion))
            .for_each_concurrent(8, |p| async {
                if tokio::time::timeout(Duration::from_secs(240), tend_pillar(&ctx, m, p)).await.is_err() {
                    // Too slow counts as a failed check.
                    let mut ps = m.pillars.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    ps.entry(p.clone()).or_default().record(day(), false);
                }
            })
            .await;
        m.save(&ctx.store);
        m.prune(&ctx.store);
        let base = ctx.mint_interval.max(10);
        let wait = base + u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % (base * 2);
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}

async fn tend_archive(ctx: &Ctx, m: &MintState, onion: &str) -> Result<()> {
    let st = m.archives.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(onion).cloned().unwrap_or_default();
    let mut st = st;
    let mut s = ctx.tor.isolated_client().connect((onion, sentinel_net::SENTINEL_PORT)).await?;
    // Top up filler (it is regenerated from the seed, never stored here).
    for _ in 0..4 {
        if st.count >= FILLER_TARGET {
            break;
        }
        let data = m.filler(onion, st.count);
        let h = media::address(&data);
        let nonce = tokio::task::spawn_blocking(move || pow::stamp(media::CHUNK_POW_DOMAIN, &h, media::CHUNK_POW_BITS)).await?;
        match exchange(&mut s, &Request::PutChunk { data, nonce }).await? {
            Response::Stored(_) => st.count += 1,
            _ => break,
        }
    }
    // Challenge one random filler chunk.
    if st.count > 0 {
        let i = u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % st.count;
        let data = m.filler(onion, i);
        let nonce = sentinel_core::random_bytes::<32>();
        let ok = matches!(exchange(&mut s, &Request::Prove { addr: media::address(&data), nonce }).await, Ok(Response::Proof(p)) if p == media::proof(&nonce, &data));
        if ok {
            st.passes += 1;
        } else {
            st.fails += 1;
            st.count = st.count.min(i); // re-seed from the lost one
        }
    }
    // Daily reward for Archives with passes and no recent failures.
    let today = day();
    if st.last_reward_day < today && st.passes > 0 && st.fails == 0 {
        let amount = (1 + st.count / 16).min(MAX_DAILY_REWARD as u64) as u32;
        if let Response::Commitments(cms) = exchange(&mut s, &Request::RewardOfferPq { count: amount, mint: ctx.self_onion.clone() }).await? {
            if !cms.is_empty() && cms.len() <= MAX_DAILY_REWARD as usize {
                if let Some((epoch, first)) = m.pq.append(&ctx.store, &cms) {
                    m.count_issued(&ctx.store, epoch, cms.len());
                    if matches!(exchange(&mut s, &Request::RewardAppended { mint: ctx.self_onion.clone(), epoch, first }).await, Ok(Response::Pong)) {
                        st.last_reward_day = today;
                        st.passes = 0;
                    }
                }
            }
        }
    }
    if st.last_reward_day + 7 < today {
        st.fails = 0; // forgive old failures after a quiet week
    }
    m.archives.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(onion.to_owned(), st);
    Ok(())
}

/// Mint duty: sign a checkpoint of the note lists every few minutes (only
/// when they grew), so new notes become spendable and everyone sees the
/// same lists.
pub async fn checkpoint_loop(ctx: Arc<Ctx>) {
    let Some(m) = &ctx.econ.mint else { return };
    loop {
        let (store, onion) = (ctx.store.clone(), ctx.self_onion.clone());
        let c2 = Arc::clone(&ctx);
        let _ = tokio::task::spawn_blocking(move || {
            if let Some(m) = &c2.econ.mint {
                m.pq.checkpoint(&store, &onion);
            }
        })
        .await;
        m.pq.prune(&ctx.store);
        tokio::time::sleep(Duration::from_secs(pqcash::CHECKPOINT_SECS)).await;
    }
}

/// A sealed test item from a throwaway key: to the Pillar it looks like
/// anyone's post, so it can't serve checks while neglecting real content.
fn probe_item() -> Option<Vec<u8>> {
    let key = ed25519_dalek::SigningKey::from_bytes(&sentinel_core::random_bytes::<32>());
    let len = 200 + (sentinel_core::random_bytes::<2>()[0] as usize) * 3;
    let body: Vec<u8> = (0..len).map(|_| sentinel_core::random_bytes::<1>()[0]).collect();
    sentinel_core::seal::seal(&key, "post", body, &[sentinel_core::random_bytes::<32>()], Vec::new()).ok()?.encode().ok()
}

/// Check one Pillar: it answers, still serves the test item from an
/// earlier day, and takes a new one; then pay what it's owed.
async fn tend_pillar(ctx: &Ctx, m: &MintState, onion: &str) {
    let today = day();
    let mut st = m.pillars.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(onion).cloned().unwrap_or_default();
    st.roll(today);
    let check = async {
        let mut s = tokio::time::timeout(Duration::from_secs(120), ctx.tor.isolated_client().connect((onion, sentinel_net::SENTINEL_PORT))).await??;
        if !matches!(exchange(&mut s, &Request::Ping).await?, Response::Pong) {
            return Ok::<bool, anyhow::Error>(false);
        }
        let mut ok = true;
        // Test items due today (stored 1 to 30 days ago, at random).
        // (One that isn't answered stays due; see `Score::roll`.)
        for addr in st.due_probes(today) {
            let had = matches!(exchange(&mut s, &Request::Get(Address(addr))).await?, Response::Object(b) if Address::of(&b).0 == addr);
            st.probe_answered(addr, today, had);
            ok &= had;
        }
        if st.wants_probe(today) {
            let item = probe_item().context("probe")?;
            match exchange(&mut s, &Request::Put(item)).await? {
                Response::Stored(a) => st.add_probe(a.0, today, u64::from_le_bytes(sentinel_core::random_bytes::<8>())),
                _ => ok = false,
            }
        }
        // Pay what's owed (only to a Pillar that's doing its job right now).
        if ok && st.owed > 0 {
            let n = st.owed.min(crate::earning::MAX_DAILY);
            if let Response::Commitments(cms) = exchange(&mut s, &Request::RewardOfferPq { count: n, mint: ctx.self_onion.clone() }).await? {
                if !cms.is_empty() && cms.len() <= n as usize {
                    if let Some((epoch, first)) = m.pq.append(&ctx.store, &cms) {
                        m.count_issued(&ctx.store, epoch, cms.len());
                        if matches!(exchange(&mut s, &Request::RewardAppended { mint: ctx.self_onion.clone(), epoch, first }).await, Ok(Response::Pong)) {
                            st.owed -= cms.len() as u32;
                        }
                    }
                }
            }
        }
        Ok(ok)
    };
    let passed = matches!(check.await, Ok(true));
    st.record(today, passed);
    m.pillars.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(onion.to_owned(), st);
}
