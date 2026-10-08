//! Linking another device to an account (spec section 6).
//!
//! 1. The existing device makes a **link code**: `sentinel://link/<pillar>#<secret>`
//!    (shown once, typed or copied to the new device; never sent over the
//!    network).
//! 2. The new device leaves a **request** (its own messaging card and a key
//!    for the answer) in a mailbox only holders of the code can find, sealed
//!    with the code's secret.
//! 3. Both devices show a short **check code** computed from the code and the
//!    request. The person confirms they match on the existing device; anyone
//!    who glimpsed the link code and raced to use it would produce a
//!    different check code.
//! 4. The existing device answers with the account (its identity, follows,
//!    rooms, settings), sealed to the key in the request.
//!
//! Each device keeps its own messaging keys; contacts send to every device.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::social::ContactCard;

/// `sentinel://link/<pillar host>#<secret>`.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkCode {
    pub pillar: String,
    pub secret: [u8; 32],
}

fn b32(b: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(b).to_lowercase()
}

impl LinkCode {
    pub fn new(pillar: &str) -> Self {
        LinkCode { pillar: pillar.to_owned(), secret: crate::random_bytes::<32>() }
    }

    pub fn to_text(&self) -> String {
        format!("sentinel://link/{}#{}", self.pillar.trim_end_matches(".onion"), b32(&self.secret))
    }

    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.trim().strip_prefix("sentinel://link/")?;
        let (host, secret) = rest.split_once('#')?;
        let host = host.to_ascii_lowercase();
        if host.len() != 56 || !host.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)) {
            return None;
        }
        let secret = data_encoding::BASE32_NOPAD.decode(secret.trim().to_uppercase().as_bytes()).ok()?.try_into().ok()?;
        Some(LinkCode { pillar: format!("{host}.onion"), secret })
    }

    /// The mailbox key the request and answer travel under.
    pub fn box_secret(&self) -> [u8; 32] {
        blake3::derive_key("sentinel/v0/link-box", &self.secret)
    }
}

/// What the new device sends.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LinkRequest {
    /// The new device's own messaging card.
    pub card: ContactCard,
    /// X25519 key the answer is sealed to.
    pub answer_to: [u8; 32],
    /// ML-KEM key the answer is also sealed to (post-quantum).
    pub answer_kem: Vec<u8>,
    /// A name for the device (shown when confirming), e.g. "Phone".
    pub device: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LinkBlob {
    Request(LinkRequest),
    /// The account, sealed to the request's keys (opaque to this module).
    Answer { to: [u8; 32], sealed: Vec<u8> },
}

const PAD: usize = 1024;

fn key(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("sentinel/v0/link-seal", secret)
}

/// Seal for the link mailbox (padded; only holders of the code can open it).
pub fn seal(code: &LinkCode, blob: &LinkBlob) -> Vec<u8> {
    let mut plain = Vec::new();
    ciborium::into_writer(blob, &mut plain).expect("encode");
    let len = (plain.len() as u32).to_le_bytes();
    let target = plain.len().div_ceil(PAD) * PAD + PAD;
    plain.resize(target - 4, 0);
    plain.extend_from_slice(&len);
    let nonce = crate::random_bytes::<24>();
    let mut out = nonce.to_vec();
    out.extend(XChaCha20Poly1305::new((&key(&code.secret)).into()).encrypt(XNonce::from_slice(&nonce), plain.as_slice()).expect("encrypt"));
    out
}

pub fn open(code: &LinkCode, b: &[u8]) -> Option<LinkBlob> {
    let plain = XChaCha20Poly1305::new((&key(&code.secret)).into()).decrypt(XNonce::from_slice(b.get(..24)?), b.get(24..)?).ok()?;
    let len = u32::from_le_bytes(plain.get(plain.len().checked_sub(4)?..)?.try_into().ok()?) as usize;
    ciborium::from_reader(plain.get(..len)?).ok()
}

/// The check code both devices show: 8 digits from the link secret and the
/// request (so a different request gives a different code).
pub fn check_code(code: &LinkCode, req: &LinkRequest) -> String {
    let mut m = code.secret.to_vec();
    let mut r = Vec::new();
    ciborium::into_writer(req, &mut r).expect("encode");
    m.extend_from_slice(&r);
    let h = blake3::derive_key("sentinel/v0/link-check", &m);
    let n = u64::from_le_bytes(h[..8].try_into().unwrap()) % 100_000_000;
    format!("{:04}-{:04}", n / 10_000, n % 10_000)
}

/// Seal the account for the new device (hybrid: X25519 + ML-KEM-768).
pub fn seal_answer(req: &LinkRequest, account: &[u8]) -> Option<Vec<u8>> {
    crate::pq::seal("sentinel/v0/link-answer", &req.answer_to, &req.answer_to, Some(&req.answer_kem), account)
}

/// The public key a new device asks the answer to be sealed to.
pub fn answer_public(answer_secret: &[u8; 32]) -> [u8; 32] {
    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*answer_secret)).as_bytes()
}

/// New device: open the account with the secrets behind the request.
pub fn open_answer(answer_secret: &[u8; 32], answer_kem_seed: &[u8; 64], sealed: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let to = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*answer_secret)).as_bytes();
    crate::pq::open("sentinel/v0/link-answer", &to, answer_secret, Some(answer_kem_seed), sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> ContactCard {
        ContactCard { olm_identity: [1; 32], one_time_keys: vec![], fallback_key: None, inbox_pub: [2; 32], inbox_ids: vec![], pillar: "x".into(), minute: 0, inbox_kem: None }
    }

    #[test]
    fn link_round_trip() {
        let code = LinkCode::new(&format!("{}.onion", "a".repeat(56)));
        assert_eq!(LinkCode::parse(&code.to_text()), Some(code.clone()));
        let answer_secret = crate::random_bytes::<32>();
        let kem = crate::pq::kem_seed();
        let req = LinkRequest {
            card: card(),
            answer_to: *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(answer_secret)).as_bytes(),
            answer_kem: crate::pq::kem_public(&kem),
            device: "Phone".into(),
        };
        let sealed = seal(&code, &LinkBlob::Request(req.clone()));
        let Some(LinkBlob::Request(got)) = open(&code, &sealed) else { panic!() };
        assert_eq!(got, req);
        // Someone without the code can't open it.
        assert!(open(&LinkCode::new("b"), &sealed).is_none());
        // Same check code on both sides; another request gives another one.
        assert_eq!(check_code(&code, &got), check_code(&code, &req));
        let mut other = req.clone();
        other.device = "Laptop".into();
        assert_ne!(check_code(&code, &other), check_code(&code, &req));
        // The account reaches only the requesting device.
        let s = seal_answer(&req, b"the account").unwrap();
        assert_eq!(&**open_answer(&answer_secret, &kem, &s).unwrap(), b"the account");
        assert!(open_answer(&crate::random_bytes::<32>(), &kem, &s).is_none());
    }
}
