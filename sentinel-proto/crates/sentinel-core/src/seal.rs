//! Sealed objects (spec §12.4): everything a Pillar stores is ciphertext.
//!
//! An object is encrypted with a fresh random content key. The content key is
//! wrapped in fixed-count "slots" under the keys allowed to read it:
//! - the author's **feed key** (shared only through their follow link), and,
//!   for discoverable posts,
//! - **topic keys** (derived from topic names) and the **explore key**.
//!
//! The outer envelope is signed by the author over the ciphertext, so a
//! Pillar can reject forgeries and spam without being able to read anything.
//! It sees only: the author key (needed to index it), the discovery shard
//! numbers (each covers many topics), and a ciphertext padded to a size bucket.
//!
//! **Post-quantum signature:** inside the encryption, every object also
//! carries an ML-DSA-65 signature by the author's account (derived from its
//! key). Followers who pinned the author's ML-DSA key (from their profile)
//! accept only objects that carry a valid one, so even a quantum computer
//! that can forge the outer Ed25519 signature can't forge a post.
//!
//! Honest limit: topic and explore keys are derivable by anyone running the
//! software, so discoverable posts protect a host from *bulk* scanning and
//! accidental exposure, not from an operator who deliberately acts as a
//! reader. Followers-only content (feed key) and DMs/rooms are unreadable to
//! Pillars.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::object::Envelope;

pub const KIND_SEALED: &str = "sealed";
/// Slots per object, always (feed + up to 6 topic keys + explore). Unused slots hold
/// random bytes so the count reveals nothing.
pub const SLOTS: usize = 8;
/// Plaintext is padded to a multiple of this before encryption.
const PAD: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Slot {
    #[serde(with = "serde_bytes_vec")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    pub wrapped: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedBody {
    /// Discovery shards this object belongs to (empty if not discoverable).
    pub shards: Vec<u16>,
    pub slots: Vec<Slot>,
    #[serde(with = "serde_bytes_vec")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    pub ct: Vec<u8>,
}

/// Plaintext inside a sealed object.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Inner {
    kind: String,
    #[serde(with = "serde_bytes_vec")]
    body: Vec<u8>,
    /// Padding (random length up to the bucket boundary).
    #[serde(with = "serde_bytes_vec")]
    pad: Vec<u8>,
    /// ML-DSA-65 signature by the author's account (empty in old objects).
    #[serde(default, with = "serde_bytes_vec")]
    pq: Vec<u8>,
}

const PQ_CTX: &[u8] = b"sentinel/v0/sealed";

fn pq_message(author: &[u8; 32], kind: &str, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(48 + kind.len() + body.len());
    m.extend_from_slice(author);
    m.extend_from_slice(&(kind.len() as u32).to_be_bytes());
    m.extend_from_slice(kind.as_bytes());
    m.extend_from_slice(&(body.len() as u64).to_be_bytes());
    m.extend_from_slice(body);
    m
}

/// Check an object's post-quantum signature against the author's pinned
/// ML-DSA-65 key.
pub fn verify_pq(author: &[u8; 32], kind: &str, body: &[u8], sig: &[u8], dsa_public: &[u8]) -> bool {
    !sig.is_empty() && crate::pq::dsa_verify(dsa_public, &pq_message(author, kind, body), PQ_CTX, sig)
}

pub fn topic_key(topic: &str) -> [u8; 32] {
    blake3::derive_key("sentinel/v0/topic-key", topic.as_bytes())
}

pub fn explore_key() -> [u8; 32] {
    blake3::derive_key("sentinel/v0/explore-key", b"")
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

fn aead(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

/// Seal `body` (an inner object of `kind`) so that holders of any of
/// `readers` can open it, and sign the result as `author`.
pub fn seal(author: &SigningKey, kind: &str, body: Vec<u8>, readers: &[[u8; 32]], shards: Vec<u16>) -> Result<Envelope, &'static str> {
    if readers.is_empty() || readers.len() > SLOTS {
        return Err("bad reader count");
    }
    let content_key = crate::random_bytes::<32>();
    let pq = crate::pq::dsa_sign(&crate::pq::identity_dsa_seed(author), &pq_message(&author.verifying_key().to_bytes(), kind, &body), PQ_CTX).unwrap_or_default();
    let mut inner = Inner { kind: kind.to_owned(), body, pad: Vec::new(), pq };
    let unpadded = cbor(&inner).len();
    let target = unpadded.div_ceil(PAD) * PAD + PAD;
    inner.pad = vec![0u8; target.saturating_sub(unpadded + 3)];
    let nonce = crate::random_bytes::<24>();
    let ct = aead(&content_key).encrypt(XNonce::from_slice(&nonce), cbor(&inner).as_slice()).map_err(|_| "encrypt")?;

    let mut slots: Vec<Slot> = readers
        .iter()
        .map(|k| {
            let n = crate::random_bytes::<24>();
            let wrapped = aead(k).encrypt(XNonce::from_slice(&n), content_key.as_slice()).expect("wrap");
            Slot { nonce: n.to_vec(), wrapped }
        })
        .collect();
    while slots.len() < SLOTS {
        // Indistinguishable dummy: 32-byte "key" + 16-byte tag of random data.
        slots.push(Slot { nonce: crate::random_bytes::<24>().to_vec(), wrapped: crate::random_bytes::<48>().to_vec() });
    }
    // Shuffle so the feed-key slot isn't always first.
    for i in (1..slots.len()).rev() {
        let j = (crate::random_bytes::<1>()[0] as usize) % (i + 1);
        slots.swap(i, j);
    }
    let sealed = SealedBody { shards, slots, nonce: nonce.to_vec(), ct };
    Ok(Envelope::sign(author, KIND_SEALED, cbor(&sealed)))
}

pub fn sealed_body(env: &Envelope) -> Option<SealedBody> {
    (env.kind == KIND_SEALED).then(|| ciborium::from_reader(env.body.as_slice()).ok()).flatten()
}

/// Try each candidate key against each slot; on success return the inner
/// object's (kind, body).
pub fn open(env: &Envelope, candidates: &[[u8; 32]]) -> Option<(String, Vec<u8>)> {
    open_full(env, candidates).map(|(k, b, _)| (k, b))
}

/// Like `open`, but only if the post-quantum signature checks out against
/// `pinned` (the author's ML-DSA key) when there is one.
pub fn open_pinned(env: &Envelope, candidates: &[[u8; 32]], pinned: Option<&[u8]>) -> Option<(String, Vec<u8>)> {
    let (kind, body, pq) = open_full(env, candidates)?;
    match pinned {
        Some(k) if !verify_pq(&env.author, &kind, &body, &pq, k) => None,
        _ => Some((kind, body)),
    }
}

/// (kind, body, post-quantum signature).
pub fn open_full(env: &Envelope, candidates: &[[u8; 32]]) -> Option<(String, Vec<u8>, Vec<u8>)> {
    let sealed = sealed_body(env)?;
    let nonce = XNonce::from_slice(sealed.nonce.get(..24)?);
    for k in candidates {
        for slot in &sealed.slots {
            if slot.nonce.len() != 24 {
                continue;
            }
            let Ok(ck) = aead(k).decrypt(XNonce::from_slice(&slot.nonce), slot.wrapped.as_slice()) else { continue };
            let Ok(ck): Result<[u8; 32], _> = ck.try_into() else { continue };
            let Ok(plain) = aead(&ck).decrypt(nonce, sealed.ct.as_slice()) else { continue };
            let inner: Inner = ciborium::from_reader(plain.as_slice()).ok()?;
            return Some((inner.kind, inner.body, inner.pq));
        }
    }
    None
}

mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        match ciborium::value::Value::deserialize(d)? {
            ciborium::value::Value::Bytes(b) => Ok(b),
            _ => Err(serde::de::Error::custom("expected bytes")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_with_right_key_only() {
        let author = crate::identity::generate();
        let feed = crate::random_bytes::<32>();
        let env = seal(&author, "post", b"secret words".to_vec(), &[feed], vec![]).unwrap();
        let bytes = env.encode().unwrap();
        let env = Envelope::decode_verified(&bytes).unwrap(); // Pillar can verify
        assert!(!bytes.windows(12).any(|w| w == b"secret words")); // ...but not read
        assert_eq!(open(&env, &[feed]).unwrap(), ("post".to_owned(), b"secret words".to_vec()));
        assert!(open(&env, &[crate::random_bytes::<32>()]).is_none());
        assert_eq!(sealed_body(&env).unwrap().slots.len(), SLOTS);
    }

    #[test]
    fn post_quantum_signature_inside() {
        let author = crate::identity::generate();
        let feed = crate::random_bytes::<32>();
        let pin = crate::pq::identity_dsa_public(&author);
        let env = seal(&author, "post", b"hello".to_vec(), &[feed], vec![]).unwrap();
        assert_eq!(open_pinned(&env, &[feed], Some(&pin)).unwrap().1, b"hello".to_vec());
        // Someone else's ML-DSA key pinned (or a forger without the account's
        // key): refused.
        let other = crate::pq::identity_dsa_public(&crate::identity::generate());
        assert!(open_pinned(&env, &[feed], Some(&other)).is_none());
        // A re-signed outer envelope (as a quantum forger could make) with the
        // same inner content but another author: the inner signature doesn't match.
        let forger = crate::identity::generate();
        let forged = seal(&forger, "post", b"hello".to_vec(), &[feed], vec![]).unwrap();
        assert!(open_pinned(&forged, &[feed], Some(&pin)).is_none());
        // Without a pin (not followed), it opens as before.
        assert!(open_pinned(&env, &[feed], None).is_some());
    }

    #[test]
    fn topic_and_explore_keys_open_discoverable() {
        let author = crate::identity::generate();
        let feed = crate::random_bytes::<32>();
        let env = seal(&author, "post", b"hi".to_vec(), &[feed, topic_key("robotics"), explore_key()], vec![3, 64]).unwrap();
        assert!(open(&env, &[topic_key("robotics")]).is_some());
        assert!(open(&env, &[explore_key()]).is_some());
        assert!(open(&env, &[topic_key("cooking")]).is_none());
        assert_eq!(sealed_body(&env).unwrap().shards, vec![3, 64]);
    }

    #[test]
    fn sizes_are_bucketed() {
        let author = crate::identity::generate();
        let k = crate::random_bytes::<32>();
        let a = seal(&author, "post", vec![1; 10], &[k], vec![]).unwrap();
        let b = seal(&author, "post", vec![1; 120], &[k], vec![]).unwrap();
        assert_eq!(sealed_body(&a).unwrap().ct.len(), sealed_body(&b).unwrap().ct.len());
    }
}
