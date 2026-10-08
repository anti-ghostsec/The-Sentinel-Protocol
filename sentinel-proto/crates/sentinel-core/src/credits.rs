//! Sentinel credits (spec §21.1): anonymous, non-withdrawable e-cash, built
//! so it could later become a withdrawable private currency without changing
//! what's in people's wallets.
//!
//! A credit part is a token `(input, output)` where `output = F(k_e, input)`
//! for a mint's key `k_e` in epoch `e`, issued **blindly** with a
//! *verifiable* OPRF (RFC 9497 VOPRF, Ristretto255):
//! - The mint never sees `input` when issuing, so it can't link a token it
//!   issued to the token later spent (unlinkability).
//! - Every issuance carries a DLEQ proof against the mint's key, so a mint
//!   can't quietly use a different key per user to tag them.
//! - Spending reveals `input`; the mint records a nullifier so a token can't
//!   be spent twice. Paying someone = they swap my tokens for fresh blinded
//!   ones of their own (redeem + reissue in one step).
//!
//! **Threshold mints**: a credit is a [`Bundle`] of parts from `t` different
//! mints (a majority of the network's `n`). Each part is issued blindly by
//! its own mint and redeemed only there, so inflating or double-spending
//! needs `t` operators to collude, while privacy holds against all of them
//! together (each part is blinded independently).
//!
//! **Epochs**: mint keys rotate every [`EPOCH_SECS`]. Each epoch key is
//! `k_e = k + H(e)`, so its public key `K + H(e)·G` is derived by anyone from
//! the one long-term public key that ships with the app: rotation never
//! gives a mint a chance to hand out per-user keys. Tokens are spendable in
//! their epoch and the next; wallets refresh older ones automatically. That
//! keeps spent lists bounded (old ones are deleted) and gives every epoch an
//! auditable supply (issued minus spent), which a future withdrawable
//! currency needs.
//!
//! Every token carries a format version and is worth exactly one unit, so
//! amounts never fingerprint a token.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use voprf::{BlindedElement, CipherSuite, EvaluationElement, Group, Proof, Ristretto255, VoprfClient, VoprfServer};

type Cs = Ristretto255;

/// Token format version (blind tokens: issued only until the switch to
/// quantum-safe notes; kept so old ones can be traded in).
pub const TOKEN_VERSION: u8 = 1;
/// Quantum-safe notes (see `pqcash`): `input` is the note's secret and
/// `output` its position in the issuer's list (8 bytes).
pub const PQ_TOKEN_VERSION: u8 = 2;
/// Length of a key epoch (180 days).
pub const EPOCH_SECS: u64 = 180 * 86_400;
/// Near an epoch boundary, issuance under either neighbour is accepted.
const BOUNDARY_GRACE_SECS: u64 = 86_400;

/// One credit part (one unit, from one mint).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Token {
    #[serde(default)]
    pub v: u8,
    #[serde(default)]
    pub epoch: u32,
    pub input: [u8; 32],
    pub output: Vec<u8>,
}

impl Token {
    /// A quantum-safe note as a credit part.
    pub fn from_note(note: &crate::pqcash::Note, epoch: u32, index: u64) -> Token {
        Token { v: PQ_TOKEN_VERSION, epoch, input: crate::pqcash::digest_bytes(&note.secret), output: index.to_le_bytes().to_vec() }
    }

    /// The note and its position, for a quantum-safe part.
    pub fn note(&self) -> Option<(crate::pqcash::Note, u64)> {
        if self.v != PQ_TOKEN_VERSION {
            return None;
        }
        let secret = crate::pqcash::digest_from_bytes(&self.input)?;
        let index = u64::from_le_bytes(self.output.as_slice().try_into().ok()?);
        Some((crate::pqcash::Note { secret }, index))
    }

    pub fn is_pq(&self) -> bool {
        self.v == PQ_TOKEN_VERSION
    }

    /// What the mint stores when the token is spent (not the token itself).
    pub fn nullifier(&self) -> [u8; 32] {
        if let Some((n, _)) = self.note() {
            return crate::pqcash::digest_bytes(&n.nullifier());
        }
        let mut m = self.epoch.to_le_bytes().to_vec();
        m.extend_from_slice(&self.input);
        blake3::derive_key("sentinel/v1/credit-nullifier", &m)
    }
}

/// Epoch of a Unix time.
pub fn epoch_at(unix: u64) -> u32 {
    (unix / EPOCH_SECS) as u32
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The current epoch.
pub fn current_epoch() -> u32 {
    epoch_at(unix_now())
}

/// Can a token of `epoch` still be spent in epoch `now`? (Its own and the next.)
pub fn spendable(epoch: u32, now: u32) -> bool {
    epoch == now || epoch.checked_add(1) == Some(now)
}

/// Should the wallet refresh a token of `epoch` (it's from an older epoch)?
pub fn needs_refresh(epoch: u32, now: u32) -> bool {
    epoch < now
}

/// May a mint issue under `epoch` at `unix`? Only the current epoch, plus
/// the neighbour within a day of a boundary (clock differences). Anything
/// else could be used to sort users into groups.
pub fn issue_epoch_ok(epoch: u32, unix: u64) -> bool {
    epoch == epoch_at(unix) || epoch == epoch_at(unix.saturating_sub(BOUNDARY_GRACE_SECS)) || epoch == epoch_at(unix + BOUNDARY_GRACE_SECS)
}

/// Same, for now.
pub fn issue_epoch_ok_now(epoch: u32) -> bool {
    issue_epoch_ok(epoch, unix_now())
}

fn epoch_tweak(epoch: u32) -> Scalar {
    let mut h = blake3::Hasher::new_derive_key("sentinel/v1/mint-epoch");
    h.update(&epoch.to_le_bytes());
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A mint's public key for `epoch`, derived from its long-term public key.
pub fn epoch_key(master_pk: &[u8], epoch: u32) -> Option<Vec<u8>> {
    let p = CompressedRistretto::from_slice(master_pk).ok()?.decompress()?;
    let e = p + RISTRETTO_BASEPOINT_TABLE * &epoch_tweak(epoch);
    Some(e.compress().to_bytes().to_vec())
}

/// Client-side state for tokens being issued.
pub struct Pending {
    inputs: Vec<[u8; 32]>,
    states: Vec<VoprfClient<Cs>>,
}

/// Prepare `n` fresh token requests: (state to keep, blinded elements to send).
pub fn blind(n: usize) -> (Pending, Vec<Vec<u8>>) {
    let mut rng = rand_core::OsRng;
    let mut inputs = Vec::with_capacity(n);
    let mut states = Vec::with_capacity(n);
    let mut blinded = Vec::with_capacity(n);
    for _ in 0..n {
        let input = crate::random_bytes::<32>();
        let r = VoprfClient::<Cs>::blind(&input, &mut rng).expect("32-byte input");
        blinded.push(r.message.serialize().to_vec());
        inputs.push(input);
        states.push(r.state);
    }
    (Pending { inputs, states }, blinded)
}

/// Unblind a mint's answer for `epoch`, verifying its proof against the
/// epoch key derived from the mint's pinned long-term key.
pub fn finalize(p: &Pending, evals: &[Vec<u8>], proof: &[u8], master_pk: &[u8], epoch: u32) -> Option<Vec<Token>> {
    if evals.len() != p.states.len() {
        return None;
    }
    let ek = epoch_key(master_pk, epoch)?;
    let pk = <Cs as CipherSuite>::Group::deserialize_elem(&ek).ok()?;
    let messages: Vec<EvaluationElement<Cs>> = evals.iter().map(|e| EvaluationElement::deserialize(e).ok()).collect::<Option<_>>()?;
    let proof = Proof::<Cs>::deserialize(proof).ok()?;
    let inputs: Vec<&[u8]> = p.inputs.iter().map(|i| i.as_slice()).collect();
    let outputs = VoprfClient::batch_finalize(&inputs, &p.states, &messages, &proof, pk).ok()?;
    let mut out = Vec::new();
    for (input, o) in p.inputs.iter().zip(outputs) {
        out.push(Token { v: TOKEN_VERSION, epoch, input: *input, output: o.ok()?.to_vec() });
    }
    Some(out)
}

/// One credit under threshold mints: one token from each of `t` mints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bundle {
    /// (mint onion, token issued by that mint).
    pub parts: Vec<(String, Token)>,
}

impl Bundle {
    /// Well-formed for this network: parts from `t` distinct listed mints.
    pub fn valid_shape(&self, mints: &[String], t: usize) -> bool {
        let mut seen: Vec<&String> = Vec::new();
        for (m, _) in &self.parts {
            if !mints.contains(m) || seen.contains(&m) {
                return false;
            }
            seen.push(m);
        }
        seen.len() >= t
    }
}

/// Majority threshold for `n` mints.
pub fn threshold(n: usize) -> usize {
    n / 2 + 1
}

/// Parts held per listed mint.
fn counts(parts: &[(String, Token)], mints: &[String]) -> Vec<(String, usize)> {
    mints.iter().map(|m| (m.clone(), parts.iter().filter(|(pm, _)| pm == m).count())).collect()
}

/// Plan one credit: the `t` mints with the most parts left (greedy on the
/// largest counts is optimal for building the most bundles).
fn plan_one(counts: &mut [(String, usize)], t: usize) -> Option<Vec<String>> {
    if t == 0 || counts.len() < t {
        return None;
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    if counts[t - 1].1 == 0 {
        return None;
    }
    Some(counts[..t].iter_mut().map(|(m, c)| {
        *c -= 1;
        m.clone()
    }).collect())
}

/// How many whole credits these parts make.
pub fn capacity(parts: &[(String, Token)], mints: &[String], t: usize) -> usize {
    let mut c = counts(parts, mints);
    let mut n = 0;
    while plan_one(&mut c, t).is_some() {
        n += 1;
    }
    n
}

/// Take `k` credits out of `parts` (untouched if there aren't enough).
pub fn assemble(parts: &mut Vec<(String, Token)>, mints: &[String], t: usize, k: usize) -> Option<Vec<Bundle>> {
    let mut c = counts(parts, mints);
    let plans: Vec<Vec<String>> = (0..k).map(|_| plan_one(&mut c, t)).collect::<Option<_>>()?;
    let mut out = Vec::with_capacity(k);
    for plan in plans {
        let mut b = Bundle { parts: Vec::with_capacity(t) };
        for m in plan {
            let i = parts.iter().position(|(pm, _)| *pm == m).expect("counted");
            b.parts.push(parts.swap_remove(i));
        }
        out.push(b);
    }
    Some(out)
}

/// A mint's secret (kept by a mint node only).
pub struct Mint {
    master: Scalar,
}

impl Mint {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = blake3::Hasher::new_derive_key("sentinel/v1/mint-master");
        h.update(seed);
        let mut wide = [0u8; 64];
        h.finalize_xof().fill(&mut wide);
        Mint { master: Scalar::from_bytes_mod_order_wide(&wide) }
    }

    /// The long-term public key (published once; epoch keys derive from it).
    pub fn public_key(&self) -> Vec<u8> {
        (RISTRETTO_BASEPOINT_TABLE * &self.master).compress().to_bytes().to_vec()
    }

    fn server(&self, epoch: u32) -> Option<VoprfServer<Cs>> {
        VoprfServer::new_with_key(&(self.master + epoch_tweak(epoch)).to_bytes()).ok()
    }

    /// Evaluate blinded requests under `epoch`; returns (evaluations, proof).
    pub fn issue(&self, epoch: u32, blinded: &[Vec<u8>]) -> Option<(Vec<Vec<u8>>, Vec<u8>)> {
        if blinded.is_empty() || blinded.len() > MAX_BATCH {
            return None;
        }
        let server = self.server(epoch)?;
        let elems: Vec<BlindedElement<Cs>> = blinded.iter().map(|b| BlindedElement::deserialize(b).ok()).collect::<Option<_>>()?;
        let r = server.batch_blind_evaluate(&mut rand_core::OsRng, &elems).ok()?;
        Some((r.messages.iter().map(|m| m.serialize().to_vec()).collect(), r.proof.serialize().to_vec()))
    }

    /// Is this a token this mint issued? (Spent-ness and epoch are checked separately.)
    pub fn valid(&self, t: &Token) -> bool {
        t.v == TOKEN_VERSION && self.server(t.epoch).and_then(|s| s.evaluate(&t.input).ok()).is_some_and(|o| o.as_slice() == t.output.as_slice())
    }
}

/// Most tokens per request.
pub const MAX_BATCH: usize = 64;
/// Price of keeping `bytes` pinned on one Archive for `months`: 1 credit per
/// started GB-month.
pub fn pin_price(bytes: u64, months: u32) -> u64 {
    bytes.div_ceil(1_000_000_000).max(1) * months.max(1) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blind_issue_verify_and_unlinkable() {
        let mint = Mint::from_seed(&[7; 32]);
        let (p, blinded) = blind(3);
        let (evals, proof) = mint.issue(5, &blinded).unwrap();
        let tokens = finalize(&p, &evals, &proof, &mint.public_key(), 5).unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(tokens.iter().all(|t| mint.valid(t) && t.epoch == 5 && t.v == TOKEN_VERSION));
        // The mint saw only blinded elements, never the inputs it now sees.
        for t in &tokens {
            assert!(!blinded.iter().any(|b| b.windows(32).any(|w| w == t.input)));
        }
        // Forged token fails; a different mint key's tokens fail; the same
        // token relabelled with another epoch fails.
        let mut forged = tokens[0].clone();
        forged.input[0] ^= 1;
        assert!(!mint.valid(&forged));
        assert!(!Mint::from_seed(&[8; 32]).valid(&tokens[0]));
        let mut moved = tokens[0].clone();
        moved.epoch = 6;
        assert!(!mint.valid(&moved));
        assert_ne!(moved.nullifier(), tokens[0].nullifier());
    }

    #[test]
    fn epoch_keys_derive_from_the_public_key_alone() {
        let mint = Mint::from_seed(&[3; 32]);
        let (p, blinded) = blind(2);
        let (evals, proof) = mint.issue(9, &blinded).unwrap();
        // Verified with the epoch-9 key derived from the long-term key...
        assert!(finalize(&p, &evals, &proof, &mint.public_key(), 9).is_some());
        // ...and rejected under any other epoch's key.
        assert!(finalize(&p, &evals, &proof, &mint.public_key(), 10).is_none());
        assert_ne!(epoch_key(&mint.public_key(), 9), epoch_key(&mint.public_key(), 10));
    }

    #[test]
    fn epoch_rules() {
        assert!(spendable(4, 4) && spendable(4, 5) && !spendable(4, 6) && !spendable(5, 4));
        assert!(needs_refresh(4, 5) && !needs_refresh(5, 5));
        let start = 7 * EPOCH_SECS;
        assert!(issue_epoch_ok(7, start + 1000));
        assert!(issue_epoch_ok(6, start + 1000), "just after a boundary, the old epoch is still fine");
        assert!(!issue_epoch_ok(6, start + 3 * 86_400));
        assert!(!issue_epoch_ok(9, start + 1000));
    }

    #[test]
    fn bundles_need_a_majority_of_distinct_mints() {
        let mints: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let t = threshold(mints.len());
        assert_eq!(t, 2);
        let tok = Token { v: 1, epoch: 0, input: [0; 32], output: vec![] };
        let ok = Bundle { parts: vec![("a".into(), tok.clone()), ("c".into(), tok.clone())] };
        let dup = Bundle { parts: vec![("a".into(), tok.clone()), ("a".into(), tok.clone())] };
        let stranger = Bundle { parts: vec![("a".into(), tok.clone()), ("z".into(), tok.clone())] };
        assert!(ok.valid_shape(&mints, t));
        assert!(!dup.valid_shape(&mints, t));
        assert!(!stranger.valid_shape(&mints, t));
    }

    #[test]
    fn assembling_uses_parts_from_distinct_mints() {
        let mints: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let tok = |i: u8| Token { v: 1, epoch: 0, input: [i; 32], output: vec![] };
        // a:3 b:2 c:1 -> 3 credits of 2 parts (ab, ac, ab).
        let mut parts: Vec<(String, Token)> = vec![("a".into(), tok(1)), ("a".into(), tok(2)), ("a".into(), tok(3)), ("b".into(), tok(4)), ("b".into(), tok(5)), ("c".into(), tok(6))];
        assert_eq!(capacity(&parts, &mints, 2), 3);
        assert!(assemble(&mut parts, &mints, 2, 4).is_none());
        assert_eq!(parts.len(), 6, "a failed take leaves the wallet alone");
        let got = assemble(&mut parts, &mints, 2, 3).unwrap();
        assert!(parts.is_empty());
        assert!(got.iter().all(|b| b.valid_shape(&mints, 2)));
        // Parts from unlisted mints never count.
        let stray = vec![("z".into(), tok(9)), ("a".into(), tok(8))];
        assert_eq!(capacity(&stray, &mints, 2), 0);
    }

    #[test]
    fn tagging_with_another_key_is_detected() {
        // A mint answering with a different key than it published (to tag a
        // user) fails the client's proof check.
        let published = Mint::from_seed(&[1; 32]);
        let tagging = Mint::from_seed(&[2; 32]);
        let (p, blinded) = blind(2);
        let (evals, proof) = tagging.issue(0, &blinded).unwrap();
        assert!(finalize(&p, &evals, &proof, &published.public_key(), 0).is_none());
    }
}
