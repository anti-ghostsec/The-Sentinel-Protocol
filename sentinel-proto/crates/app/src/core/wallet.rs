//! Credits wallet (spec §21.1). Tokens live only inside the encrypted store;
//! every network action involving them goes over a fresh isolated circuit.
//!
//! Threshold mints: the wallet holds *parts* (one token from one mint). A
//! credit is parts from a majority of the network's mints, assembled when
//! spent ([`credits::assemble`]), so no single mint operator can inflate or
//! double-spend, and none can link issuing to spending.
//!
//! - **Earned**: parts my own Archive earned are collected each sync.
//!   (There are no free credits: only work or someone paying you.)
//! - **Sent**: credits someone sends me in a private message are swapped
//!   for my own at once (see `send_credits`).
//! - **Spend**: pin files beyond the free expiry; pay for room access
//!   (see rooms). A payee always swaps received parts at their mints at once,
//!   so a payer can't spend them again.
//! - Mint keys are pinned (built in, else first seen and kept), so a mint
//!   can't hand different users different keys to tag their credits. Keys
//!   rotate by epoch, derived from the pinned key; parts from an older epoch
//!   are refreshed automatically on sync.
//! - Mints are the network's established Pillars (see `default_mints`);
//!   there is nothing for users to set up.
//! - Redeems go in small batches of varying size, each on its own circuit,
//!   so a mint can't recognise a payment by its amount.
//! - **Quantum-safe notes** (`pqcash`): every part is a note in its mint's
//!   public list, spent with a zero-knowledge proof. The wallet downloads
//!   the list in fixed pages (the same requests for everyone), over a
//!   different circuit from the spend, checks it against the mint's signed
//!   checkpoint, and remembers checkpoints: a mint that signs two lists
//!   that disagree is caught and never used again. Old blind tokens are
//!   traded in for notes on the next sync.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use anyhow::{bail, Context, Result};
use sentinel_core::credits::{self, Bundle, Token};
use sentinel_core::pqcash::{self, Digest, Note};
use sentinel_core::wire::{Request, Response};
use serde::Serialize;

use super::{request, request_timeout, Core, Store};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletView {
    pub balance: usize,
    pub mint: bool,
    pub mints: usize,
    pub threshold: usize,
    /// Credit parts still being swapped in (earned, received or checked).
    pub pending: usize,
}

/// What became of a token handed to its mint.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum Fate {
    /// Redeemed: a fresh part of mine replaced it.
    Swapped,
    /// The mint refused it (invalid or already spent).
    Spent,
    /// The mint couldn't be asked (or the answer was lost): retry later.
    Unknown,
}

/// The network's mints: my own list if I set one, else the built-in one.
pub(super) fn mints_of(s: &Store) -> Vec<String> {
    if s.mints.is_empty() { sentinel_net::default_mints() } else { s.mints.clone() }
}

/// Whole credits in the wallet.
pub(super) fn balance(s: &Store) -> usize {
    let m = mints_of(s);
    credits::capacity(&s.parts, &m, credits::threshold(m.len()))
}

/// Tokens from before key epochs (prototype format) can't be redeemed
/// under the epoch keys; drop them, along with parts past their last
/// spendable epoch.
pub(super) fn migrate(s: &mut Store) -> bool {
    let now = credits::current_epoch();
    let before = s.wallet.len() + s.pending_rewards.len() + s.parts.len() + s.pending_parts.len();
    s.wallet.clear();
    s.pending_rewards.clear();
    // Notes, and old blind tokens still worth trading in.
    let live = |(_, t): &(String, Token)| (t.v == credits::TOKEN_VERSION || t.is_pq()) && credits::spendable(t.epoch, now);
    s.parts.retain(live);
    s.pending_parts.retain(live);
    before != s.parts.len() + s.pending_parts.len()
}

impl Core {
    pub fn wallet(&self) -> Result<WalletView> {
        let (_, s) = self.unlocked()?;
        let m = mints_of(&s);
        Ok(WalletView { balance: balance(&s), mint: !m.is_empty(), mints: m.len(), threshold: credits::threshold(m.len()), pending: s.pending_parts.len() })
    }

    /// A mint's checkpoint key: checked against the fingerprint built into
    /// the app when there is one, else the one I saw first (pinned).
    async fn pq_key(&self, mint: &str) -> Result<sentinel_core::pq::HybridPublic> {
        if let Some(k) = self.unlocked()?.1.pq_mint_keys.get(mint) {
            return Ok(k.clone());
        }
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let mut s = net.connect_hedged(mint).await?;
        let Response::Object(b) = request(&mut s, &Request::PqMintKey).await? else { bail!("the credit issuer didn't answer") };
        let k: sentinel_core::pq::HybridPublic = ciborium::from_reader(b.as_slice()).context("bad issuer key")?;
        if let Some(fp) = sentinel_net::builtin_pq_fingerprint(mint) {
            if pqcash::key_fingerprint(&k) != fp {
                bail!("the credit issuer's key doesn't match the one built into Sentinel");
            }
        }
        self.update(|s| {
            s.pq_mint_keys.entry(mint.to_owned()).or_insert_with(|| k.clone());
        })?;
        // Whatever got stored first wins (a racing fetch can't swap it).
        self.unlocked()?.1.pq_mint_keys.get(mint).cloned().context("issuer key")
    }

    /// A mint's list for one key period, as of its latest signed checkpoint
    /// (checked against every checkpoint I've seen from it).
    async fn pq_list(&self, mint: &str, epoch: u32) -> Result<(Vec<Digest>, pqcash::Checkpoint)> {
        if self.unlocked()?.1.pq_cheaters.iter().any(|m| m == mint) {
            bail!("This credit issuer was caught showing different lists to different people, so Sentinel no longer uses it.");
        }
        let pk = self.pq_key(mint).await?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let mut s = net.connect_hedged(mint).await?;
        let Response::Object(b) = request(&mut s, &Request::PqCheckpoint { epoch }).await? else { bail!("the credit issuer has no signed list yet") };
        let cp: pqcash::SignedCheckpoint = ciborium::from_reader(b.as_slice()).context("bad checkpoint")?;
        if !pqcash::verify_checkpoint(&pk, &cp) || cp.body.mint != mint || cp.body.epoch != epoch {
            bail!("the credit issuer's checkpoint isn't signed correctly");
        }
        // A list can't be bigger than the tree holds (no endless downloads).
        if cp.body.size > 1u64 << pqcash::DEPTH {
            bail!("the credit issuer's checkpoint is impossible");
        }
        let mut caught = false;
        self.update(|s| {
            let seen = s.pq_checkpoints.entry(mint.to_owned()).or_default();
            if seen.iter().any(|old| pqcash::contradicts(old, &cp.body)) {
                caught = true;
                s.pq_cheaters.push(mint.to_owned());
            } else if !seen.contains(&cp.body) {
                seen.push(cp.body.clone());
                if seen.len() > 64 {
                    seen.remove(0);
                }
            }
        })?;
        if caught {
            bail!("This credit issuer signed two lists that disagree (it may be trying to tag people), so Sentinel no longer uses it.");
        }
        // Whole pages only (everyone asks for the same ones), reusing pages
        // already downloaded this session.
        let key = (mint.to_owned(), epoch);
        let page = pqcash::LEAVES_PER_REPLY;
        let mut leaves: Vec<Digest> = leaf_cache().lock().expect("lock").get(&key).cloned().unwrap_or_default();
        leaves.truncate(leaves.len() / page * page);
        while (leaves.len() as u64) < cp.body.size {
            let Response::PqLeaves { leaves: more, .. } = request(&mut s, &Request::PqLeaves { epoch, from: leaves.len() as u64 }).await? else { bail!("the credit issuer didn't answer") };
            if more.is_empty() {
                bail!("the credit issuer's list is shorter than its checkpoint");
            }
            leaves.extend(more.iter().filter_map(pqcash::digest_from_bytes));
        }
        leaf_cache().lock().expect("lock").insert(key, leaves.clone());
        Ok((leaves, cp.body))
    }

    fn add_parts(&self, mint: &str, t: Vec<Token>) -> Result<()> {
        self.update(|s| s.parts.extend(t.into_iter().map(|t| (mint.to_owned(), t))))
    }

    /// Credits I sent that never arrived come back:
    /// - a message still undelivered after a day is cancelled and its
    ///   credits swapped back to me;
    /// - delivered ones are checked after 8 days (messages disappear after
    ///   7): if the receiver never collected them, I take them back; if
    ///   they did, the issuer refuses, which confirms they arrived.
    ///   Either way nothing is lost.
    pub(super) async fn reclaim_unclaimed(&self) -> usize {
        let now = sentinel_core::social::coarse_minute();
        let (undelivered_after, check_after) = reclaim_after();
        let Ok((_, s)) = self.unlocked() else { return 0 };
        let due: Vec<super::SentCredits> = s
            .sent_credits
            .iter()
            .filter(|r| {
                let delivered = s.conversations.iter().find(|c| c.author == r.to).and_then(|c| c.messages.iter().find(|m| m.mine && m.minute == r.minute && m.text == r.text)).is_none_or(|m| m.sent);
                let age = now.saturating_sub(r.minute);
                (!delivered && age > undelivered_after) || age > check_after
            })
            .cloned()
            .collect();
        if due.is_empty() {
            return 0;
        }
        // Stop trying to deliver the undelivered ones.
        let _ = self.update(|st| {
            for r in &due {
                if let Some(m) = st.conversations.iter_mut().find(|c| c.author == r.to).and_then(|c| c.messages.iter_mut().find(|m| m.mine && m.minute == r.minute && m.text == r.text)) {
                    if !m.sent {
                        m.out.clear();
                        m.sent = true;
                        m.text = format!("{} (not delivered; the credits came back to you)", m.text);
                    }
                }
            }
        });
        let mut back = 0;
        for r in due {
            let fates = self.redeem(&r.parts, true).await;
            back += fates.iter().filter(|f| **f == Fate::Swapped).count();
            let done = fates.iter().all(|f| *f != Fate::Unknown);
            let retry: Vec<(String, Token)> = r.parts.iter().cloned().zip(fates).filter(|(_, f)| *f == Fate::Unknown).map(|(p, _)| p).collect();
            let _ = self.update(|st| {
                st.sent_credits.retain(|x| !(x.to == r.to && x.minute == r.minute && x.text == r.text));
                if !done {
                    st.sent_credits.push(super::SentCredits { parts: retry.clone(), ..r.clone() });
                }
            });
            if back > 0 {
                sentinel_net::note(format!("Sentinel: {back} credit part(s) I sent weren't collected and came back"));
            }
        }
        back
    }

    /// Import credits a Pillar earned (`pillar --take-credits <file>`): they
    /// are swapped for my own at once, so the file is worthless afterwards.
    pub async fn import_credits(&self, path: &std::path::Path) -> Result<usize> {
        if std::fs::metadata(path)?.len() > 4 * 1024 * 1024 {
            bail!("That file is too large to be a credits file.");
        }
        let parts: Vec<(String, Token)> = serde_json::from_slice(&std::fs::read(path)?).context("That isn't a credits file from a Pillar.")?;
        let mints = mints_of(&self.unlocked()?.1);
        let parts: Vec<(String, Token)> = parts.into_iter().filter(|(m, _)| mints.contains(m)).collect();
        if parts.is_empty() {
            bail!("There are no credits in that file.");
        }
        let fates = self.redeem(&parts, false).await;
        let got = fates.iter().filter(|f| **f == Fate::Swapped).count();
        let retry: Vec<(String, Token)> = parts.into_iter().zip(fates).filter(|(_, f)| *f == Fate::Unknown).map(|(p, _)| p).collect();
        if !retry.is_empty() {
            self.update(|s| s.pending_parts.extend(retry))?;
        }
        Ok(got)
    }

    /// Send whole credits to someone I can message. They travel inside the
    /// end-to-end encrypted message, and the recipient's app swaps them for
    /// its own at once, so I can't spend them again.
    pub fn send_credits(self: &std::sync::Arc<Self>, app: tauri::AppHandle, author: &str, amount: usize) -> Result<()> {
        if amount == 0 || amount > credits::MAX_BATCH {
            bail!("Send between 1 and {} credits at a time.", credits::MAX_BATCH);
        }
        let bundles = self.take_bundles(amount)?;
        let text = if amount == 1 { "Sent you 1 credit.".to_string() } else { format!("Sent you {amount} credits.") };
        if let Err(e) = self.send_dm_with(app, author, &text, bundles.clone(), None, None) {
            self.refund(bundles);
            return Err(e);
        }
        Ok(())
    }

    /// Spend parts at one mint for fresh notes of mine: notes with proofs
    /// (made off the async threads; a second or more each), old blind
    /// tokens traded in. Refusals ("spent", "invalid") start with
    /// "payment rejected"; anything else can be retried.
    async fn swap_at(&self, mint: &str, tokens: Vec<Token>) -> Result<Vec<Token>> {
        let (pq, old): (Vec<Token>, Vec<Token>) = tokens.into_iter().partition(Token::is_pq);
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let mut out = Vec::new();
        let appended = |r: Response, notes: &[Note]| -> Result<Vec<Token>> {
            match r {
                Response::PqAppended { epoch, first } if credits::issue_epoch_ok_now(epoch) => Ok(notes.iter().enumerate().map(|(i, n)| Token::from_note(n, epoch, first + i as u64)).collect()),
                Response::Rejected(r) => bail!("payment rejected: {r}"),
                _ => bail!("the credit issuer didn't answer"),
            }
        };
        if !old.is_empty() {
            let notes: Vec<Note> = old.iter().map(|_| Note::random()).collect();
            let commitments = notes.iter().map(|n| pqcash::digest_bytes(&n.commitment())).collect();
            let mut s = net.connect_hedged(mint).await?;
            out.extend(appended(request(&mut s, &Request::PqUpgrade { tokens: old, commitments }).await?, &notes)?);
        }
        let mut by_epoch: HashMap<u32, Vec<(Note, u64)>> = HashMap::new();
        for t in &pq {
            by_epoch.entry(t.epoch).or_default().push(t.note().context("bad credit")?);
        }
        for (epoch, notes) in by_epoch {
            let (leaves, cp) = self.pq_list(mint, epoch).await?;
            for chunk in notes.chunks(pqcash::SLOTS * pqcash::MAX_PROOFS) {
                let fresh: Vec<Note> = chunk.iter().map(|_| Note::random()).collect();
                let commitments: Vec<[u8; 32]> = fresh.iter().map(|n| pqcash::digest_bytes(&n.commitment())).collect();
                let (l, c, ch, cm) = (leaves.clone(), cp.clone(), chunk.to_vec(), commitments.clone());
                let proofs = tokio::task::spawn_blocking(move || pqcash::swap_proofs(&l, &c, epoch, &ch, &cm)).await?.map_err(|e| match e {
                    pqcash::PqError::NotInTree => anyhow::anyhow!("payment rejected: these credits aren't in the issuer's list"),
                    e => anyhow::anyhow!("{e}"),
                })?;
                // A different circuit from the list download.
                let mut s = net.connect_hedged(mint).await?;
                let r = request_timeout(&mut s, &Request::PqSwap { epoch, proofs, commitments }, std::time::Duration::from_secs(180)).await?;
                out.extend(appended(r, &fresh)?);
            }
        }
        Ok(out)
    }

    /// Redeem parts at their mints for fresh parts of mine (added to the
    /// wallet). `singly`: one token per request, so one spent token can't
    /// sink the rest. Otherwise batches of 1-8 (random), each on its own
    /// circuit: a mint sees many small swaps, not "a payment of 37".
    /// Returns each input's fate, in order.
    pub(super) async fn redeem(&self, parts: &[(String, Token)], singly: bool) -> Vec<Fate> {
        let mut fate = vec![Fate::Unknown; parts.len()];
        let mut by_mint: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, (m, _)) in parts.iter().enumerate() {
            by_mint.entry(m.as_str()).or_default().push(i);
        }
        for (m, idx) in by_mint {
            let mut chunks: Vec<&[usize]> = Vec::new();
            let mut rest = idx.as_slice();
            while !rest.is_empty() {
                let size = if singly { 1 } else { 1 + (sentinel_core::random_bytes::<1>()[0] as usize % 8) };
                let (a, b) = rest.split_at(size.min(rest.len()));
                chunks.push(a);
                rest = b;
            }
            for chunk in chunks {
                let toks = chunk.iter().map(|&i| parts[i].1.clone()).collect();
                let short: String = m.chars().take(6).collect();
                let f = match self.swap_at(m, toks).await {
                    Ok(fresh) => {
                        sentinel_net::note(format!("Sentinel: swapped {} credit part(s) at issuer {short}…", chunk.len()));
                        let _ = self.add_parts(m, fresh);
                        Fate::Swapped
                    }
                    Err(e) if e.to_string().starts_with("payment rejected") => {
                        sentinel_net::note(format!("Sentinel: issuer {short}… refused {} credit part(s): {e:#}", chunk.len()));
                        Fate::Spent
                    }
                    Err(e) => {
                        sentinel_net::note(format!("Sentinel: credit swap at issuer {short}… will retry: {e:#}"));
                        Fate::Unknown
                    }
                };
                for &i in chunk {
                    fate[i] = f;
                }
            }
        }
        fate
    }

    /// Take `n` credits out of the wallet (put back with `refund` on failure).
    pub(super) fn take_bundles(&self, n: usize) -> Result<Vec<Bundle>> {
        let mut out = None;
        self.update(|s| {
            let m = mints_of(s);
            out = credits::assemble(&mut s.parts, &m, credits::threshold(m.len()), n);
        })?;
        out.with_context(|| format!("This needs {n} credits."))
    }

    pub(super) fn refund(&self, b: Vec<Bundle>) {
        let _ = self.update(|s| s.parts.extend(b.into_iter().flat_map(|b| b.parts)));
    }

    /// Credits whose fate is unknown (maybe spent by the other side): checked
    /// part by part at the mints on the next syncs; unspent ones come back.
    pub(super) fn quarantine(&self, b: Vec<Bundle>) {
        let _ = self.update(|s| s.pending_parts.extend(b.into_iter().flat_map(|b| b.parts)));
    }

    /// Parts my hosted Archive earned: move them into my wallet (swapped, so
    /// the Archive's copy is worthless if its disk is ever seized). Also
    /// re-checks quarantined parts and refreshes parts from an older key
    /// epoch before they expire. Returns parts gained.
    pub(super) async fn collect_rewards(&self) -> Result<usize> {
        let role = format!("{}-host", super::role());
        let mut earned = match sentinel_net::data_root(&role) {
            Ok(root) => pillar::take_rewards(&root.join("objects")),
            Err(_) => Vec::new(),
        };
        let now = credits::current_epoch();
        let mut pending = Vec::new();
        self.update(|s| {
            migrate(s);
            pending = std::mem::take(&mut s.pending_parts);
            // Older-epoch parts, and old blind tokens: swap for current notes
            // (same redeem path).
            let (old, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut s.parts).into_iter().partition(|(_, t)| credits::needs_refresh(t.epoch, now) || !t.is_pq());
            s.parts = keep;
            earned.extend(old);
        })?;
        let back = self.reclaim_unclaimed().await;
        if earned.is_empty() && pending.is_empty() {
            return Ok(back);
        }
        let f1 = self.redeem(&earned, false).await;
        let f2 = self.redeem(&pending, true).await;
        let mut got = 0;
        let mut retry = Vec::new();
        for (p, f) in earned.into_iter().zip(f1).chain(pending.into_iter().zip(f2)) {
            match f {
                Fate::Swapped => got += 1,
                Fate::Spent => {}
                Fate::Unknown => retry.push(p),
            }
        }
        if !retry.is_empty() {
            self.update(|s| s.pending_parts.extend(retry))?;
        }
        Ok(got)
    }

    /// Pin one media item on its Archives for `months` (1-24): chunks stay
    /// past the free 90-day expiry. Anyone can pin anything they can read
    /// (popular content gets kept by its readers).
    pub async fn pin_media(&self, post_id: &str, index: usize, months: u32) -> Result<u64> {
        let (addrs_by_host, _) = self.media_placement(post_id, index).await?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let mut pinned = 0;
        for (host, addrs) in addrs_by_host {
            let price = credits::pin_price(addrs.len() as u64 * sentinel_core::media::CHUNK_CT as u64, months) as usize;
            let bundles = self.take_bundles(price)?;
            // Connecting can fail safely (nothing was sent); after sending,
            // the Archive may already have redeemed the parts even if the
            // answer is lost, so an unclear outcome quarantines them.
            let mut s = match net.connect_hedged(&host).await {
                Ok(s) => s,
                Err(e) => {
                    self.refund(bundles);
                    return Err(e);
                }
            };
            let req = Request::Pin { addrs: addrs.clone(), months, bundles: bundles.clone() };
            match request_timeout(&mut s, &req, std::time::Duration::from_secs(240)).await {
                Ok(Response::Count(n)) => pinned += n,
                // Refused before taking payment (price, bad request, shape): safe.
                Ok(Response::Rejected(r)) if r.starts_with("this pin costs") || r == "bad pin request" || r == "credits from unknown mints" => {
                    self.refund(bundles);
                    bail!(r);
                }
                Ok(Response::Rejected(r)) => {
                    self.quarantine(bundles);
                    bail!(r);
                }
                Ok(_) => {
                    self.quarantine(bundles);
                    bail!("the Archive didn't answer");
                }
                Err(e) => {
                    self.quarantine(bundles);
                    return Err(e);
                }
            }
        }
        Ok(pinned)
    }

    /// Credits needed to pin an item for `months`.
    pub async fn pin_quote(&self, post_id: &str, index: usize, months: u32) -> Result<u64> {
        let (by_host, _) = self.media_placement(post_id, index).await?;
        Ok(by_host.iter().map(|(_, a)| credits::pin_price(a.len() as u64 * sentinel_core::media::CHUNK_CT as u64, months)).sum())
    }
}

/// Mints' lists downloaded this session (public data; memory only).
fn leaf_cache() -> &'static Mutex<HashMap<(String, u32), Vec<Digest>>> {
    static C: OnceLock<Mutex<HashMap<(String, u32), Vec<Digest>>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// Minutes before credits in an undelivered message come back, and before
/// delivered ones are checked. Test builds can shorten both
/// (SENTINEL_TEST_RECLAIM_MINUTES) to watch it happen live.
fn reclaim_after() -> (u64, u64) {
    #[cfg(feature = "test-hooks")]
    if let Some(m) = std::env::var("SENTINEL_TEST_RECLAIM_MINUTES").ok().and_then(|v| v.parse::<u64>().ok()) {
        return (m, m);
    }
    (24 * 60, 8 * 24 * 60)
}
