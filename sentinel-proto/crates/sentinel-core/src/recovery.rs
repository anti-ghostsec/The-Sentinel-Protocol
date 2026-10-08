//! Account recovery and key rotation (spec section 6).
//!
//! - **Recovery words:** 21 words (256 bits plus a check word that catches
//!   typos) written down on paper. From them come:
//!   - the account's identity key, one per *generation* (0, 1, 2, …), so a
//!     lost device is recovered just by typing the words on a new one;
//!   - the feed key of each generation;
//!   - a **recovery key** (hybrid Ed25519 + ML-DSA-65, so quantum-safe).
//! - Profiles carry a **pin** of the recovery key. Followers keep the first
//!   pin they see; a thief holding the account key can't change it.
//! - **Moving to a new key** (the device was taken, or to upgrade): the
//!   recovery key signs a *succession* "generation g (old key) → g+1 (new
//!   key)". Followers check it against their pin and switch. It's filed under
//!   the recovery key, which followers also read.
//! - The succession is sealed like any post, with the old feed key, so only
//!   followers (and the owner, who can rebuild every feed key from the
//!   words) can read it: to a Pillar it looks like any other sealed object,
//!   and it can't link the old and new keys.
//! - Optionally the succession carries the new feed key sealed with the old
//!   one (device lost: followers keep reading). If the device was *taken*,
//!   it doesn't: whoever has the device can't follow along, and people need
//!   the new follow link for private posts.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::object::Envelope;
use crate::pq::{HybridPublic, HybridSigner};

pub const WORDS: usize = 21;
pub const KIND_SUCCESSION: &str = "succession";
const CTX: &[u8] = b"sentinel/v0/succession";

/// The recovery secret behind the words.
pub struct RecoverySecret(Zeroizing<[u8; 32]>);

fn derive(label: &str, secret: &[u8; 32], n: u32) -> Zeroizing<[u8; 32]> {
    let mut m = Zeroizing::new(secret.to_vec());
    m.extend_from_slice(&n.to_le_bytes());
    Zeroizing::new(blake3::derive_key(label, &m))
}

impl RecoverySecret {
    pub fn generate() -> Self {
        RecoverySecret(Zeroizing::new(crate::random_bytes::<32>()))
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        RecoverySecret(Zeroizing::new(b))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The identity key of generation `gen`.
    pub fn identity(&self, gen: u32) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&derive("sentinel/v0/recovery-identity", &self.0, gen))
    }

    /// The feed key of generation `gen`.
    pub fn feed_key(&self, gen: u32) -> [u8; 32] {
        *derive("sentinel/v0/recovery-feed", &self.0, gen)
    }

    pub fn signer(&self) -> HybridSigner {
        HybridSigner::from_secret(&derive("sentinel/v0/recovery-key", &self.0, 0))
    }

    pub fn pin(&self) -> RecoveryPin {
        RecoveryPin::of(&self.signer().public())
    }

    /// The 21 words (20 carry the secret, the last is a check word).
    pub fn words(&self) -> Vec<String> {
        let list = crate::identity::wordlist();
        let mut n = *self.0;
        let mut out = Vec::with_capacity(WORDS);
        for _ in 0..WORDS - 1 {
            // n = n / 7776, collecting the remainder (big-endian bytes).
            let mut rem: u32 = 0;
            for b in n.iter_mut() {
                let cur = (rem << 8) | u32::from(*b);
                *b = (cur / 7776) as u8;
                rem = cur % 7776;
            }
            out.push(list[rem as usize].to_string());
        }
        out.push(list[check_index(&self.0)].to_string());
        out
    }

    /// Read the words back (separated by spaces or commas, any case; a few
/// words contain a hyphen, so hyphens aren't separators). The check word
/// must match.
    pub fn from_words(text: &str) -> Option<Self> {
        let list = crate::identity::wordlist();
        let words: Vec<String> = text.split(|c: char| c.is_whitespace() || c == ',').filter(|w| !w.is_empty()).map(|w| w.to_lowercase()).collect();
        if words.len() != WORDS {
            return None;
        }
        let idx: Vec<usize> = words.iter().map(|w| list.iter().position(|l| l == w)).collect::<Option<_>>()?;
        // n = sum(idx[i] * 7776^i), most significant last.
        let mut n = [0u8; 32];
        for &d in idx[..WORDS - 1].iter().rev() {
            let mut carry = d as u32;
            for b in n.iter_mut().rev() {
                let cur = u32::from(*b) * 7776 + carry;
                *b = cur as u8;
                carry = cur >> 8;
            }
            if carry != 0 {
                return None;
            }
        }
        (check_index(&n) == idx[WORDS - 1]).then(|| RecoverySecret(Zeroizing::new(n)))
    }
}

fn check_index(secret: &[u8; 32]) -> usize {
    let h = blake3::derive_key("sentinel/v0/recovery-check", secret);
    (u16::from_le_bytes([h[0], h[1]]) as usize) % 7776
}

/// What followers pin: the recovery key's Ed25519 half (where successions
/// are filed) and a hash of the whole hybrid key.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct RecoveryPin {
    pub ed: [u8; 32],
    pub commit: [u8; 32],
}

impl RecoveryPin {
    pub fn of(p: &HybridPublic) -> Self {
        let mut m = p.ed.to_vec();
        m.extend_from_slice(&p.dsa);
        RecoveryPin { ed: p.ed, commit: blake3::derive_key("sentinel/v0/recovery-pin", &m) }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Succession {
    pub old: [u8; 32],
    pub new: [u8; 32],
    /// The new key's generation.
    pub gen: u32,
    /// The new feed key sealed with the old one (device lost), or none
    /// (device taken: private posts need the new follow link).
    pub feed: Option<Vec<u8>>,
    pub minute: u64,
    /// The new key's ML-DSA-65 key (followers pin it at once).
    #[serde(default)]
    pub new_pq: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Signed {
    body: Succession,
    by: HybridPublic,
    ed_sig: Vec<u8>,
    dsa_sig: Vec<u8>,
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

fn seal_feed(old_feed: &[u8; 32], new_feed: &[u8; 32], new_author: &[u8; 32]) -> Vec<u8> {
    let key = blake3::derive_key("sentinel/v0/succession-feed", &[old_feed.as_slice(), new_author].concat());
    let nonce = crate::random_bytes::<24>();
    let mut out = nonce.to_vec();
    out.extend(XChaCha20Poly1305::new((&key).into()).encrypt(XNonce::from_slice(&nonce), new_feed.as_slice()).expect("encrypt"));
    out
}

/// A follower holding the old feed key: the new one.
pub fn open_feed(s: &Succession, old_feed: &[u8; 32]) -> Option<[u8; 32]> {
    let b = s.feed.as_ref()?;
    let key = blake3::derive_key("sentinel/v0/succession-feed", &[old_feed.as_slice(), &s.new].concat());
    let pt = XChaCha20Poly1305::new((&key).into()).decrypt(XNonce::from_slice(b.get(..24)?), b.get(24..)?).ok()?;
    pt.try_into().ok()
}

/// Sign a move from generation `gen - 1` to `gen`, as a public envelope
/// filed under the recovery key. `carry_feed`: seal the new feed key with
/// the old one (only if the device was lost, not taken).
pub fn succession(r: &RecoverySecret, gen: u32, carry_feed: bool) -> Option<Vec<u8>> {
    let old = r.identity(gen.checked_sub(1)?).verifying_key().to_bytes();
    succession_from(r, old, &r.feed_key(gen - 1), carry_feed, gen)
}

/// The same from any current key (older accounts whose key wasn't derived
/// from recovery words). Sealed with `old_feed`; carries the new feed key
/// if `carry`.
pub fn succession_from(r: &RecoverySecret, old: [u8; 32], old_feed: &[u8; 32], carry: bool, gen: u32) -> Option<Vec<u8>> {
    if gen == 0 {
        return None;
    }
    let new = r.identity(gen).verifying_key().to_bytes();
    let feed = carry.then(|| seal_feed(old_feed, &r.feed_key(gen), &new));
    let body = Succession { old, new, gen, feed, minute: crate::social::coarse_minute(), new_pq: Some(crate::pq::identity_dsa_public(&r.identity(gen))) };
    let signer = r.signer();
    let (ed_sig, dsa_sig) = signer.sign(&cbor(&body), CTX);
    let signed = Signed { body, by: signer.public(), ed_sig, dsa_sig };
    crate::seal::seal(signer.ed_key(), KIND_SUCCESSION, cbor(&signed), &[*old_feed], vec![]).ok()?.encode().ok()
}

/// Check a succession envelope against a pinned recovery key, opening it
/// with the old feed key.
pub fn verify(env: &Envelope, pin: &RecoveryPin, old_feed: &[u8; 32]) -> Option<Succession> {
    if env.author != pin.ed {
        return None;
    }
    let (kind, plain) = crate::seal::open(env, &[*old_feed])?;
    if kind != KIND_SUCCESSION {
        return None;
    }
    let s: Signed = ciborium::from_reader(plain.as_slice()).ok()?;
    if RecoveryPin::of(&s.by) != *pin || !s.by.verify(&cbor(&s.body), CTX, &s.ed_sig, &s.dsa_sig) {
        return None;
    }
    (s.body.gen > 0 && s.body.old != s.body.new).then_some(s.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_round_trip_and_catch_typos() {
        for _ in 0..500 {
            let r = RecoverySecret::generate();
            let w = r.words();
            assert_eq!(w.len(), WORDS);
            let back = RecoverySecret::from_words(&w.join(" ").to_uppercase()).unwrap();
            assert_eq!(back.bytes(), r.bytes());
        }
        let r = RecoverySecret::from_bytes([0xff; 32]);
        assert_eq!(RecoverySecret::from_words(&r.words().join(",")).unwrap().bytes(), &[0xff; 32]);
        let mut w = RecoverySecret::generate().words();
        w.swap(0, 1);
        assert!(RecoverySecret::from_words(&w.join(" ")).is_none() || w[0] == w[1], "a swap is caught by the check word");
        assert!(RecoverySecret::from_words("too few words").is_none());
    }

    #[test]
    fn successions_need_the_pinned_recovery_key() {
        let r = RecoverySecret::generate();
        let pin = r.pin();
        let bytes = succession(&r, 1, true).unwrap();
        let env = Envelope::decode_verified(&bytes).unwrap();
        let s = verify(&env, &pin, &r.feed_key(0)).unwrap();
        // Without the old feed key (a Pillar, a stranger): unreadable.
        assert!(verify(&env, &pin, &[7; 32]).is_none());
        assert_eq!(s.old, r.identity(0).verifying_key().to_bytes());
        assert_eq!(s.new, r.identity(1).verifying_key().to_bytes());
        // Followers with the old feed key get the new one.
        assert_eq!(open_feed(&s, &r.feed_key(0)), Some(r.feed_key(1)));
        assert_eq!(open_feed(&s, &[9; 32]), None);
        // "Device taken": no feed key carried over.
        let taken = verify(&Envelope::decode_verified(&succession(&r, 2, false).unwrap()).unwrap(), &pin, &r.feed_key(1)).unwrap();
        assert!(taken.feed.is_none());
        // Someone else's recovery key (a thief making their own): refused.
        let thief = RecoverySecret::generate();
        let forged = Envelope::decode_verified(&succession(&thief, 1, true).unwrap()).unwrap();
        assert!(verify(&forged, &pin, &thief.feed_key(0)).is_none());
        assert!(verify(&forged, &pin, &r.feed_key(0)).is_none());
        // Different generations give different keys; generation 0 can't be "moved to".
        assert_ne!(r.identity(0).to_bytes(), r.identity(1).to_bytes());
        assert!(succession(&r, 0, true).is_none());
    }
}
