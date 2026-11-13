//! A post-quantum ratchet around each conversation's Olm messages.
//!
//! Olm's Double Ratchet is built on X25519, which a large quantum computer
//! breaks. The sealed-sender layer around it is hybrid (X25519 + ML-KEM),
//! but its ML-KEM key lives for a month and can't be deleted early: someone
//! who records traffic and later gets hold of a device could open every
//! recorded message's outer layer, and then only Olm is left.
//!
//! So each side also keeps short-lived ML-KEM-768 keys per conversation:
//!
//! - Every message carries the sender's newest public key.
//! - Every message, once the other side's key is known, is encrypted under
//!   a fresh ML-KEM shared secret made for that key (a new encapsulation
//!   per message), around the Olm ciphertext.
//! - When the other side has used my key, my next message brings a new one
//!   and the old secret key is deleted a few days later (kept that long
//!   for messages still on their way).
//!
//! What this gives: a message is safe unless both Olm and this layer are
//! broken; deleted keys can't open recorded messages (forward secrecy
//! against a quantum attacker); and a stolen state stops working as soon
//! as each side has sent once more (the keys it holds are replaced).
//!
//! What it doesn't: the first messages, until a reply, have only the
//! sealed-sender layer's ML-KEM; and who is talking is still proven by
//! Olm's classical keys, so an attacker with a quantum computer who is in
//! the middle from the first message could impersonate (not read back).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A replaced key is kept this many days (a deposit waits at most 7).
const KEEP_DAYS: u64 = 8;
/// Most of my keys kept per conversation.
const MAX_KEYS: usize = 12;

#[derive(Clone, Serialize, Deserialize)]
struct Own {
    seed: Vec<u8>,
    public: Vec<u8>,
    id: [u8; 8],
    /// The other side has encrypted to it.
    used: bool,
    /// Day it was replaced (0: it's my newest).
    retired: u64,
}

impl Drop for Own {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// One conversation's ratchet state (kept with its Olm session).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PqRatchet {
    /// My keys, oldest first.
    mine: Vec<Own>,
    /// The other side's newest key.
    theirs: Option<Vec<u8>>,
}

/// What a message carries for the ratchet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    /// The sender's newest ML-KEM public key.
    #[serde(with = "bytes")]
    pub key: Vec<u8>,
    /// ML-KEM ciphertext for the recipient's key `to` (empty: the sender
    /// didn't know a key yet, and the body isn't encrypted by this layer).
    #[serde(default, with = "bytes")]
    pub ct: Vec<u8>,
    #[serde(default)]
    pub to: [u8; 8],
}

fn key_id(public: &[u8]) -> [u8; 8] {
    let mut id = [0u8; 8];
    id.copy_from_slice(&blake3::hash(public).as_bytes()[..8]);
    id
}

fn message_key(ss: &[u8; 32], bind: &[u8], ct: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    let mut m = zeroize::Zeroizing::new(ss.to_vec());
    m.extend_from_slice(blake3::hash(ct).as_bytes());
    m.extend_from_slice(bind);
    zeroize::Zeroizing::new(blake3::derive_key("sentinel/v1/dm-pq-ratchet", &m))
}

impl PqRatchet {
    /// Whether messages to the other side are encrypted by this layer yet.
    pub fn established(&self) -> bool {
        self.theirs.is_some()
    }

    /// Wrap `plain` (an Olm ciphertext) for sending. `bind` ties the
    /// result to this conversation (both Olm identities).
    pub fn seal(&mut self, today: u64, bind: &[u8], plain: &[u8]) -> (Header, Vec<u8>) {
        // A new key of mine once the last one has been used.
        if self.mine.last().is_none_or(|k| k.used) {
            if let Some(k) = self.mine.last_mut() {
                k.retired = today.max(1);
            }
            let seed = crate::pq::kem_seed();
            let public = crate::pq::kem_public(&seed);
            self.mine.push(Own { seed: seed.to_vec(), id: key_id(&public), public, used: false, retired: 0 });
        }
        self.prune(today);
        let key = self.mine.last().expect("just made").public.clone();
        let sealed = self.theirs.as_deref().and_then(|theirs| {
            let (ct, ss) = crate::pq::encapsulate(theirs)?;
            let nonce = crate::random_bytes::<24>();
            let k = message_key(&ss, bind, &ct);
            let mut body = nonce.to_vec();
            body.extend(XChaCha20Poly1305::new((&*k).into()).encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: &key }).ok()?);
            Some((ct, key_id(theirs), body))
        });
        match sealed {
            Some((ct, to, body)) => (Header { key, ct, to }, body),
            None => (Header { key, ct: Vec::new(), to: [0; 8] }, plain.to_vec()),
        }
    }

    /// Unwrap a received message's body. The caller keeps the changed
    /// state only if the Olm message inside turns out to be genuine.
    pub fn open(&mut self, today: u64, bind: &[u8], header: &Header, body: &[u8]) -> Option<Vec<u8>> {
        let plain = if header.ct.is_empty() {
            body.to_vec()
        } else {
            let own = self.mine.iter_mut().find(|k| k.id == header.to)?;
            let seed: [u8; 64] = own.seed.as_slice().try_into().ok()?;
            let seed = zeroize::Zeroizing::new(seed);
            let ss = crate::pq::decapsulate(&seed, &header.ct)?;
            if body.len() < 24 {
                return None;
            }
            let k = message_key(&ss, bind, &header.ct);
            let plain = XChaCha20Poly1305::new((&*k).into()).decrypt(XNonce::from_slice(&body[..24]), Payload { msg: &body[24..], aad: &header.key }).ok()?;
            own.used = true;
            plain
        };
        if header.key.len() == crate::pq::KEM_PUBLIC {
            self.theirs = Some(header.key.clone());
        }
        self.prune(today);
        Some(plain)
    }

    /// Delete replaced keys past their time.
    fn prune(&mut self, today: u64) {
        self.mine.retain(|k| k.retired == 0 || k.retired + KEEP_DAYS >= today);
        if self.mine.len() > MAX_KEYS {
            let extra = self.mine.len() - MAX_KEYS;
            self.mine.drain(..extra);
        }
    }
}

/// Byte strings as CBOR byte strings (and plain lists elsewhere).
mod bytes {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = a.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIND: &[u8] = b"alice and bob";

    fn pass(from: &mut PqRatchet, to: &mut PqRatchet, day: u64, text: &[u8]) -> (Header, Vec<u8>) {
        let (h, body) = from.seal(day, BIND, text);
        assert_eq!(to.open(day, BIND, &h, &body).as_deref(), Some(text));
        (h, body)
    }

    #[test]
    fn both_sides_ratchet_once_they_have_heard_from_each_other() {
        let (mut a, mut b) = (PqRatchet::default(), PqRatchet::default());
        // Alice's first messages: she knows no key of Bob's yet.
        let (h1, body1) = pass(&mut a, &mut b, 10, b"hi");
        assert!(h1.ct.is_empty() && body1 == b"hi");
        let (h2, _) = pass(&mut a, &mut b, 10, b"still me");
        assert_eq!(h1.key, h2.key, "same key until Bob has used it");
        // Bob replies: encrypted to Alice's key, carrying his.
        let (h3, body3) = pass(&mut b, &mut a, 10, b"hello");
        assert_eq!(h3.ct.len(), crate::pq::KEM_CT);
        assert!(!body3.windows(5).any(|w| w == b"hello"));
        // Alice's key was used: her next message brings a new one.
        let (h4, _) = pass(&mut a, &mut b, 10, b"how are you");
        assert_ne!(h4.key, h1.key);
        assert_eq!(h4.ct.len(), crate::pq::KEM_CT);
        // And Bob's next brings a new one of his.
        let (h5, _) = pass(&mut b, &mut a, 10, b"fine");
        assert_ne!(h5.key, h3.key);
        // Every message has its own encapsulation.
        let (h6, _) = pass(&mut b, &mut a, 10, b"and you?");
        assert_ne!(h5.ct, h6.ct);
    }

    #[test]
    fn late_and_out_of_order_messages_open_and_old_keys_are_deleted() {
        let (mut a, mut b) = (PqRatchet::default(), PqRatchet::default());
        pass(&mut a, &mut b, 10, b"1");
        pass(&mut b, &mut a, 10, b"2");
        // Bob sends two; the second arrives first, then Alice replies.
        let (h_late, body_late) = b.seal(10, BIND, b"late");
        pass(&mut b, &mut a, 10, b"on time");
        pass(&mut a, &mut b, 10, b"reply");
        pass(&mut b, &mut a, 11, b"next");
        assert_eq!(a.open(12, BIND, &h_late, &body_late).as_deref(), Some(&b"late"[..]));

        // A recorded message, and the state stolen long afterwards.
        let (h_old, body_old) = b.seal(12, BIND, b"recorded");
        assert!(a.clone().open(12, BIND, &h_old, &body_old).is_some());
        assert!(a.open(12, BIND, &h_old, &body_old).is_some());
        for day in 13..13 + 3 {
            pass(&mut a, &mut b, day, b"x");
            pass(&mut b, &mut a, day, b"y");
        }
        assert!(a.clone().open(15, BIND, &h_old, &body_old).is_some(), "still within the days a deposit can wait");
        pass(&mut a, &mut b, 40, b"much later");
        assert!(a.open(40, BIND, &h_old, &body_old).is_none(), "the key it was sent to is gone");
        assert!(a.mine.len() <= MAX_KEYS);
    }

    #[test]
    fn wrong_conversation_or_changed_bytes_fail() {
        let (mut a, mut b) = (PqRatchet::default(), PqRatchet::default());
        pass(&mut a, &mut b, 10, b"1");
        let (h, body) = b.seal(10, BIND, b"secret");
        assert!(a.clone().open(10, b"someone else", &h, &body).is_none());
        let mut changed = body.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(a.clone().open(10, BIND, &h, &changed).is_none());
        // The sender's new key is bound to the message it came with.
        let mut swapped = h.clone();
        swapped.key = crate::pq::kem_public(&crate::pq::kem_seed());
        assert!(a.clone().open(10, BIND, &swapped, &body).is_none());
        // Someone without Alice's keys gets nothing.
        assert!(PqRatchet::default().open(10, BIND, &h, &body).is_none());
        assert!(a.open(10, BIND, &h, &body).is_some());
    }

    #[test]
    fn headers_travel_as_cbor() {
        let mut a = PqRatchet::default();
        let (h, _) = a.seal(1, BIND, b"x");
        let mut out = Vec::new();
        ciborium::into_writer(&h, &mut out).unwrap();
        assert!(out.len() < crate::pq::KEM_PUBLIC + 40, "keys are byte strings, not lists of numbers");
        let back: Header = ciborium::from_reader(out.as_slice()).unwrap();
        assert_eq!(back.key, h.key);
        // The state survives being stored.
        let mut stored = Vec::new();
        ciborium::into_writer(&a, &mut stored).unwrap();
        let again: PqRatchet = ciborium::from_reader(stored.as_slice()).unwrap();
        assert_eq!(again.mine[0].public, a.mine[0].public);
    }
}
