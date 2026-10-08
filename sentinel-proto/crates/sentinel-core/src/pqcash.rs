//! Quantum-safe credits (spec §13): notes in a public list, spent with a
//! zero-knowledge proof built only from hash functions.
//!
//! Today's credits (`credits`) use blind tokens on an elliptic curve. Their
//! privacy already survives quantum computers (blinding hides a token
//! perfectly), but their **unforgeability doesn't**: a quantum computer
//! could work out an issuer's secret key from its public key and print
//! credits. These notes fix that while keeping the same privacy:
//!
//! - A **note** is a random secret only its owner knows. The issuer adds
//!   its *commitment* `H(secret, "note")` to a public, append-only Merkle
//!   tree (one per issuer per key period). Commitments look random, so the
//!   list reveals nothing.
//! - **Spending** reveals the note's *nullifier* `H(secret, "spent")` and a
//!   zero-knowledge proof that "this nullifier belongs to some commitment in
//!   the tree with this root", without saying which. The issuer refuses a
//!   nullifier it has seen before (no double spending) and can't link the
//!   spend to the moment the note was issued (no tracing).
//! - The proof (Plonky2: PLONK with FRI, Poseidon over the Goldilocks
//!   field) rests only on hash functions, which quantum computers don't
//!   meaningfully break. Its zero-knowledge mode is on, so it reveals
//!   nothing about the secret, the path or the position.
//! - One proof spends up to [`SLOTS`] notes; unused slots are switched off
//!   (the issuer sees how many notes were spent, never which).
//! - Every proof carries a **binding** value (a hash of what the spend is
//!   for, e.g. the fresh commitments it pays into), so a proof can't be
//!   reused for anything else.
//!
//! Honest limits: the proof's security is *conjectured* at about 128 bits
//! classically (FRI's usual assumptions); against quantum computers the
//! hash-based parts lose roughly a third of that. Proofs are large (about
//! 130–170 KB) and take a second or two to make on a computer, longer on a
//! phone. Nothing here has been independently reviewed yet.

use std::sync::{Arc, Mutex, OnceLock, Weak};

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, Field64, PrimeField64};
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::CompressedProofWithPublicInputs;
use serde::{Deserialize, Serialize};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// Depth of an issuer's note tree: up to about a million notes per issuer
/// per key period.
pub const DEPTH: usize = 20;
/// Notes one proof can spend.
pub const SLOTS: usize = 4;
/// Largest proof accepted.
pub const MAX_PROOF: usize = 400 * 1024;

/// Four field elements (a Poseidon output), as canonical numbers.
pub type Digest = [u64; 4];

const NOTE_DOMAIN: u64 = 0x6e6f7465; // "note"
const SPENT_DOMAIN: u64 = 0x7370656e; // "spen"

fn to_f(d: &Digest) -> [F; 4] {
    d.map(F::from_canonical_u64)
}

fn from_hash(h: HashOut<F>) -> Digest {
    h.elements.map(|e| e.to_canonical_u64())
}

fn h(inputs: &[F]) -> Digest {
    from_hash(PoseidonHash::hash_no_pad(inputs))
}

/// Is every part a valid field element?
fn canonical(d: &Digest) -> bool {
    d.iter().all(|&x| x < F::ORDER)
}

/// Bytes <-> digest (32 bytes, little-endian, canonical only).
pub fn digest_bytes(d: &Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, x) in d.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
    }
    out
}

pub fn digest_from_bytes(b: &[u8; 32]) -> Option<Digest> {
    let mut d = [0u64; 4];
    for (i, x) in d.iter_mut().enumerate() {
        *x = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().ok()?);
    }
    canonical(&d).then_some(d)
}

/// A note: a secret only its owner knows.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Note {
    pub secret: Digest,
}

impl Note {
    /// A fresh note (uniform field elements from the OS random source).
    pub fn random() -> Self {
        let mut s = [0u64; 4];
        for x in s.iter_mut() {
            // Rejection sampling: uniform below the field order.
            loop {
                let v = u64::from_le_bytes(crate::random_bytes::<8>());
                if v < F::ORDER {
                    *x = v;
                    break;
                }
            }
        }
        Note { secret: s }
    }

    /// What goes into the issuer's public list.
    pub fn commitment(&self) -> Digest {
        let s = to_f(&self.secret);
        h(&[s[0], s[1], s[2], s[3], F::from_canonical_u64(NOTE_DOMAIN)])
    }

    /// What the issuer records when it's spent.
    pub fn nullifier(&self) -> Digest {
        let s = to_f(&self.secret);
        h(&[s[0], s[1], s[2], s[3], F::from_canonical_u64(SPENT_DOMAIN)])
    }
}

fn node(l: &Digest, r: &Digest) -> Digest {
    let (a, b) = (to_f(l), to_f(r));
    h(&[a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]])
}

/// Hashes of empty subtrees, per level (level 0: an empty leaf).
fn zeros() -> &'static [Digest; DEPTH + 1] {
    static Z: OnceLock<[Digest; DEPTH + 1]> = OnceLock::new();
    Z.get_or_init(|| {
        let mut z = [[0u64; 4]; DEPTH + 1];
        for i in 1..=DEPTH {
            z[i] = node(&z[i - 1], &z[i - 1]);
        }
        z
    })
}

/// An issuer's append-only note list, as everyone can rebuild it from the
/// commitments in order.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    leaves: Vec<Digest>,
}

impl Tree {
    pub fn from_leaves(leaves: Vec<Digest>) -> Option<Self> {
        (leaves.len() <= 1 << DEPTH && leaves.iter().all(canonical)).then_some(Tree { leaves })
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaves(&self) -> &[Digest] {
        &self.leaves
    }

    /// Add commitments; returns the index of the first.
    pub fn push(&mut self, cms: &[Digest]) -> Option<usize> {
        if self.leaves.len() + cms.len() > 1 << DEPTH || !cms.iter().all(canonical) {
            return None;
        }
        let at = self.leaves.len();
        self.leaves.extend_from_slice(cms);
        Some(at)
    }

    /// All levels (level 0: leaves), only as far as there are nodes.
    fn levels(&self) -> Vec<Vec<Digest>> {
        let z = zeros();
        let mut levels = vec![self.leaves.clone()];
        for d in 0..DEPTH {
            let cur = &levels[d];
            let next: Vec<Digest> = cur.chunks(2).map(|p| node(&p[0], p.get(1).unwrap_or(&z[d]))).collect();
            levels.push(next);
        }
        levels
    }

    pub fn root(&self) -> Digest {
        self.levels()[DEPTH].first().copied().unwrap_or(zeros()[DEPTH])
    }

    /// The siblings from a leaf up to the root.
    pub fn path(&self, index: usize) -> Option<Vec<Digest>> {
        if index >= self.leaves.len() {
            return None;
        }
        let z = zeros();
        let levels = self.levels();
        Some((0..DEPTH).map(|d| levels[d].get((index >> d) ^ 1).copied().unwrap_or(z[d])).collect())
    }

    pub fn position(&self, cm: &Digest) -> Option<usize> {
        self.leaves.iter().position(|l| l == cm)
    }
}

struct Slot {
    enabled: BoolTarget,
    secret: [Target; 4],
    bits: Vec<BoolTarget>,
    siblings: Vec<HashOutTarget>,
}

struct Circuit {
    data: CircuitData<F, C, D>,
    root: [Target; 4],
    bind: [Target; 4],
    slots: Vec<Slot>,
}

fn config() -> CircuitConfig {
    let mut c = CircuitConfig::standard_recursion_zk_config();
    // About 128 bits (conjectured): 36 queries at rate 1/8 plus 20 bits of
    // grinding, instead of the library's 100-bit default. (Measured: the
    // newer "PolyFri" zero-knowledge mode is ~30x faster, but its masks for
    // the permutation argument can't be made larger than the number of
    // openings the verifier sees, so it could leak which note was spent;
    // the classic row blinding is used until that's solved.)
    c.security_bits = 128;
    c.fri_config.proof_of_work_bits = 20;
    c.fri_config.num_query_rounds = 36;
    // Zero-knowledge on (row blinding): the proof reveals nothing about
    // the secret, the path or the position.
    assert!(c.uses_row_blinding_zk());
    c
}

/// The spend circuit (the same on every device). It takes a few hundred
/// MB, so it's only kept while in use, unless [`warm_up`] asked to keep
/// it (computers and Pillars; phones build it per payment, so a phone in
/// the background isn't the first app the system closes).
fn circuit() -> Arc<Circuit> {
    static SHARED: Mutex<Weak<Circuit>> = Mutex::new(Weak::new());
    let mut shared = SHARED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(c) = shared.upgrade() {
        return c;
    }
    let c = Arc::new(build_circuit());
    *shared = Arc::downgrade(&c);
    c
}

fn build_circuit() -> Circuit {
    {
        let mut b = CircuitBuilder::<F, D>::new(config());
        let root: [Target; 4] = std::array::from_fn(|_| b.add_virtual_public_input());
        let bind: [Target; 4] = std::array::from_fn(|_| b.add_virtual_public_input());
        let note_dom = b.constant(F::from_canonical_u64(NOTE_DOMAIN));
        let spent_dom = b.constant(F::from_canonical_u64(SPENT_DOMAIN));
        let mut slots = Vec::new();
        for _ in 0..SLOTS {
            let enabled = b.add_virtual_bool_target_safe();
            b.register_public_input(enabled.target);
            let secret: [Target; 4] = std::array::from_fn(|_| b.add_virtual_target());
            let nf = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![secret[0], secret[1], secret[2], secret[3], spent_dom]);
            b.register_public_inputs(&nf.elements);
            let leaf = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![secret[0], secret[1], secret[2], secret[3], note_dom]);
            let bits: Vec<BoolTarget> = (0..DEPTH).map(|_| b.add_virtual_bool_target_safe()).collect();
            let siblings: Vec<HashOutTarget> = (0..DEPTH).map(|_| b.add_virtual_hash()).collect();
            let mut cur = leaf;
            for d in 0..DEPTH {
                // bit 0: we're the left child.
                let l: Vec<Target> = (0..4).map(|k| b.select(bits[d], siblings[d].elements[k], cur.elements[k])).collect();
                let r: Vec<Target> = (0..4).map(|k| b.select(bits[d], cur.elements[k], siblings[d].elements[k])).collect();
                cur = b.hash_n_to_hash_no_pad::<PoseidonHash>([l, r].concat());
            }
            // A switched-on slot must reach the public root.
            for k in 0..4 {
                let diff = b.sub(cur.elements[k], root[k]);
                let gated = b.mul(enabled.target, diff);
                b.assert_zero(gated);
            }
            slots.push(Slot { enabled, secret, bits, siblings });
        }
        let data = b.build::<C>();
        Circuit { data, root, bind, slots }
    }
}

/// What a spend proves, as the issuer checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    pub root: Digest,
    pub bind: Digest,
    /// Nullifiers of the notes spent (switched-off slots left out).
    pub nullifiers: Vec<Digest>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PqError {
    #[error("too many notes for one proof")]
    TooMany,
    #[error("a note isn't in the list")]
    NotInTree,
    #[error("the proof couldn't be made: {0}")]
    Prove(String),
    #[error("the proof is invalid")]
    Invalid,
    #[error("these credits aren't in the issuer's signed list yet; try again in a few minutes")]
    NotYet,
}

/// Prove that `notes` (1..=SLOTS, each at its index in `tree`) are in the
/// list, binding the proof to `bind`. Returns the proof bytes.
pub fn prove(tree: &Tree, notes: &[(Note, usize)], bind: &Digest) -> Result<Vec<u8>, PqError> {
    if notes.is_empty() || notes.len() > SLOTS {
        return Err(PqError::TooMany);
    }
    let c = circuit();
    let root = tree.root();
    let mut pw = PartialWitness::new();
    let set = |pw: &mut PartialWitness<F>, t: Target, v: u64| pw.set_target(t, F::from_canonical_u64(v)).map_err(|e| PqError::Prove(e.to_string()));
    for k in 0..4 {
        set(&mut pw, c.root[k], root[k])?;
        set(&mut pw, c.bind[k], bind[k])?;
    }
    for (i, slot) in c.slots.iter().enumerate() {
        let (note, index, on) = match notes.get(i) {
            Some((n, idx)) => {
                if tree.leaves.get(*idx) != Some(&n.commitment()) {
                    return Err(PqError::NotInTree);
                }
                (n.clone(), *idx, true)
            }
            // A switched-off slot: a throwaway note at a random position.
            None => (Note::random(), (u32::from_le_bytes(crate::random_bytes::<4>()) as usize) & ((1 << DEPTH) - 1), false),
        };
        let path = if on { tree.path(index).ok_or(PqError::NotInTree)? } else { (0..DEPTH).map(|_| Note::random().secret).collect() };
        pw.set_bool_target(slot.enabled, on).map_err(|e| PqError::Prove(e.to_string()))?;
        for k in 0..4 {
            set(&mut pw, slot.secret[k], note.secret[k])?;
        }
        for d in 0..DEPTH {
            pw.set_bool_target(slot.bits[d], (index >> d) & 1 == 1).map_err(|e| PqError::Prove(e.to_string()))?;
            pw.set_hash_target(slot.siblings[d], HashOut { elements: to_f(&path[d]) }).map_err(|e| PqError::Prove(e.to_string()))?;
        }
    }
    let proof = c.data.prove(pw).map_err(|e| PqError::Prove(e.to_string()))?;
    // Compressed: shared parts of the query paths are sent once (~15%).
    let compressed = c.data.compress(proof).map_err(|e| PqError::Prove(e.to_string()))?;
    Ok(compressed.to_bytes())
}

/// Build the spend circuit ahead of time (about a second and a half) and
/// keep it, so payments don't wait for it. Not on phones (memory).
pub fn warm_up() {
    static KEEP: OnceLock<Arc<Circuit>> = OnceLock::new();
    let _ = KEEP.get_or_init(circuit);
}

/// Check a spend proof; returns what it proves.
pub fn verify(proof: &[u8]) -> Result<Spend, PqError> {
    verify_if(proof, |_| true)
}

/// Check a spend proof, but first run `precheck` on what it claims (cheap:
/// spent tags, root, binding), so a replayed or misdirected proof is
/// turned away before the expensive check.
pub fn verify_if(proof: &[u8], precheck: impl Fn(&Spend) -> bool) -> Result<Spend, PqError> {
    if proof.len() > MAX_PROOF {
        return Err(PqError::Invalid);
    }
    // Hostile bytes must never bring the caller down.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let c = circuit();
        let p = CompressedProofWithPublicInputs::<F, C, D>::from_bytes(proof.to_vec(), &c.data.common).map_err(|_| PqError::Invalid)?;
        let pi: Vec<u64> = p.public_inputs.iter().map(|x| x.to_canonical_u64()).collect();
        let claimed = public_values(&pi)?;
        if !precheck(&claimed) {
            return Err(PqError::Invalid);
        }
        c.data.verify_compressed(p).map_err(|_| PqError::Invalid)?;
        Ok(claimed)
    }))
    .unwrap_or(Err(PqError::Invalid))
}

fn public_values(pi: &[u64]) -> Result<Spend, PqError> {
    if pi.len() != 8 + SLOTS * 5 || pi.iter().step_by(1).skip(8).step_by(5).any(|b| *b > 1) {
        return Err(PqError::Invalid);
    }
    let root: Digest = pi[0..4].try_into().expect("4");
    let bind: Digest = pi[4..8].try_into().expect("4");
    let mut nullifiers = Vec::new();
    for s in 0..SLOTS {
        let base = 8 + s * 5;
        if pi[base] == 1 {
            nullifiers.push(pi[base + 1..base + 5].try_into().expect("4"));
        }
    }
    if nullifiers.is_empty() {
        return Err(PqError::Invalid);
    }
    Ok(Spend { root, bind, nullifiers })
}

/// The binding value for a spend: a hash of what it's for (the fresh
/// commitments it pays into, a request id...).
pub fn bind_of(context: &[u8]) -> Digest {
    let k = blake3::derive_key("sentinel/v1/pq-spend-bind", context);
    // Four 62-bit pieces: always canonical.
    std::array::from_fn(|i| u64::from_le_bytes(k[i * 8..i * 8 + 8].try_into().expect("8")) >> 2)
}

/// Most proofs in one swap request (messages are at most 2 MB).
pub const MAX_PROOFS: usize = 8;
/// Most leaves in one answer to a list request.
pub const LEAVES_PER_REPLY: usize = 8192;
/// How often an issuer signs a checkpoint of its list (seconds).
pub const CHECKPOINT_SECS: u64 = 600;

/// What a swap's proofs are bound to: the key period of the notes spent
/// and the fresh commitments they pay into.
pub fn swap_bind(epoch: u32, commitments: &[[u8; 32]]) -> Digest {
    let mut c = epoch.to_le_bytes().to_vec();
    for cm in commitments {
        c.extend_from_slice(cm);
    }
    bind_of(&c)
}

/// An issuer's signing key for checkpoints (from its mint seed).
pub fn mint_signer(mint_seed: &[u8; 32]) -> crate::pq::HybridSigner {
    crate::pq::HybridSigner::from_secret(&blake3::derive_key("sentinel/v1/pq-mint-signing", mint_seed))
}

/// Short fingerprint of an issuer's signing key (what the app ships with).
pub fn key_fingerprint(pk: &crate::pq::HybridPublic) -> [u8; 32] {
    let mut b = pk.ed.to_vec();
    b.extend_from_slice(&pk.dsa);
    blake3::derive_key("sentinel/v1/pq-mint-key-fingerprint", &b)
}

/// An issuer's statement: "my list for this key period had `size` notes,
/// with this root". Proofs are only accepted against checkpoints, so the
/// issuer can't quietly show one person a list of their own to tag them:
/// two signed checkpoints that disagree are proof it cheated.
/// Make the proofs for spending `notes` (note, position) of key period
/// `epoch` into `commitments`, against the list as of checkpoint `cp`
/// (`leaves`: the list as downloaded, at least `cp.size` long). Slow:
/// a second or more per proof.
pub fn swap_proofs(leaves: &[Digest], cp: &Checkpoint, epoch: u32, notes: &[(Note, u64)], commitments: &[[u8; 32]]) -> Result<Vec<Vec<u8>>, PqError> {
    if notes.is_empty() || notes.len().div_ceil(SLOTS) > MAX_PROOFS {
        return Err(PqError::TooMany);
    }
    let size = usize::try_from(cp.size).map_err(|_| PqError::Invalid)?;
    let tree = Tree::from_leaves(leaves.get(..size).ok_or(PqError::NotYet)?.to_vec()).ok_or(PqError::Invalid)?;
    if digest_bytes(&tree.root()) != cp.root {
        return Err(PqError::Invalid);
    }
    let mut placed = Vec::new();
    for (n, idx) in notes {
        let cm = n.commitment();
        let at = match usize::try_from(*idx) {
            Ok(i) if tree.leaves().get(i) == Some(&cm) => i,
            _ => match tree.position(&cm) {
                Some(i) => i,
                // Not in this checkpoint: issued after it (wait) or never.
                None if leaves.contains(&cm) => return Err(PqError::NotYet),
                None => return Err(PqError::NotInTree),
            },
        };
        placed.push((n.clone(), at));
    }
    let bind = swap_bind(epoch, commitments);
    placed.chunks(SLOTS).map(|c| prove(&tree, c, &bind)).collect()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    pub mint: String,
    pub epoch: u32,
    pub seq: u64,
    pub size: u64,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub body: Checkpoint,
    pub ed: Vec<u8>,
    pub dsa: Vec<u8>,
}

const CHECKPOINT_CTX: &[u8] = b"sentinel/v1/pq-checkpoint";

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

pub fn sign_checkpoint(signer: &crate::pq::HybridSigner, body: Checkpoint) -> SignedCheckpoint {
    let (ed, dsa) = signer.sign(&cbor(&body), CHECKPOINT_CTX);
    SignedCheckpoint { body, ed, dsa }
}

pub fn verify_checkpoint(pk: &crate::pq::HybridPublic, s: &SignedCheckpoint) -> bool {
    pk.verify(&cbor(&s.body), CHECKPOINT_CTX, &s.ed, &s.dsa)
}

/// Do two (validly signed) checkpoints contradict each other? Same issuer
/// and key period, and either the same number or the same size with a
/// different root, or an older number with a bigger list.
pub fn contradicts(a: &Checkpoint, b: &Checkpoint) -> bool {
    if a.mint != b.mint || a.epoch != b.epoch {
        return false;
    }
    (a.seq == b.seq && (a.root != b.root || a.size != b.size)) || (a.size == b.size && a.root != b.root) || (a.seq < b.seq && a.size > b.size) || (b.seq < a.seq && b.size > a.size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_with(notes: &[Note], extra: usize) -> Tree {
        let mut t = Tree::default();
        for _ in 0..extra {
            t.push(&[Note::random().commitment()]);
        }
        t.push(&notes.iter().map(Note::commitment).collect::<Vec<_>>());
        t
    }

    #[test]
    fn paths_rebuild_the_root() {
        let notes: Vec<Note> = (0..5).map(|_| Note::random()).collect();
        let t = tree_with(&notes, 3);
        let root = t.root();
        for i in 0..t.len() {
            let path = t.path(i).unwrap();
            let mut cur = t.leaves()[i];
            for (d, sib) in path.iter().enumerate() {
                cur = if (i >> d) & 1 == 0 { node(&cur, sib) } else { node(sib, &cur) };
            }
            assert_eq!(cur, root);
        }
        assert_eq!(Tree::default().root(), zeros()[DEPTH]);
    }

    #[test]
    fn spend_proves_membership_without_revealing_which() {
        let notes: Vec<Note> = (0..3).map(|_| Note::random()).collect();
        let t = tree_with(&notes, 5);
        let bind = bind_of(b"pay into these");
        let spend: Vec<(Note, usize)> = notes.iter().map(|n| (n.clone(), t.position(&n.commitment()).unwrap())).collect();
        let started = std::time::Instant::now();
        let proof = prove(&t, &spend, &bind).unwrap();
        eprintln!("proof: {} KB in {:?}", proof.len() / 1024, started.elapsed());
        let s = verify(&proof).unwrap();
        assert_eq!(s.root, t.root());
        assert_eq!(s.bind, bind);
        assert_eq!(s.nullifiers, notes.iter().map(Note::nullifier).collect::<Vec<_>>());
        // Nullifiers and commitments don't match each other.
        assert!(notes.iter().all(|n| n.nullifier() != n.commitment()));
    }

    #[test]
    fn notes_outside_the_list_and_tampering_fail() {
        let inside = Note::random();
        let t = tree_with(std::slice::from_ref(&inside), 2);
        // A note that was never issued can't be proven.
        assert_eq!(prove(&t, &[(Note::random(), 0)], &[0; 4]), Err(PqError::NotInTree));
        let proof = prove(&t, &[(inside.clone(), 2)], &bind_of(b"a")).unwrap();
        // Any change to the proof (including its public values) is refused.
        let mut bad = proof.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        assert_eq!(verify(&bad), Err(PqError::Invalid));
        let mut bad2 = proof.clone();
        bad2[8] ^= 1; // inside the public values (the root)
        assert_eq!(verify(&bad2), Err(PqError::Invalid));
        assert!(verify(&proof).is_ok());
    }

    #[test]
    fn checkpoints_are_signed_and_contradictions_show() {
        let signer = mint_signer(&[3; 32]);
        let pk = signer.public();
        let cp = Checkpoint { mint: "m".into(), epoch: 1, seq: 4, size: 10, root: [1; 32] };
        let s = sign_checkpoint(&signer, cp.clone());
        assert!(verify_checkpoint(&pk, &s));
        let mut forged = s.clone();
        forged.body.root = [2; 32];
        assert!(!verify_checkpoint(&pk, &forged));
        assert!(!verify_checkpoint(&mint_signer(&[4; 32]).public(), &s));
        let other = Checkpoint { root: [2; 32], ..cp.clone() };
        assert!(contradicts(&cp, &other));
        assert!(!contradicts(&cp, &Checkpoint { seq: 5, size: 12, root: [9; 32], ..cp.clone() }));
        assert!(contradicts(&cp, &Checkpoint { seq: 5, size: 9, root: [9; 32], ..cp.clone() }));
    }

    #[test]
    fn digests_round_trip_and_reject_non_canonical() {
        let d = Note::random().secret;
        assert_eq!(digest_from_bytes(&digest_bytes(&d)), Some(d));
        assert_eq!(digest_from_bytes(&[0xff; 32]), None);
    }
}
