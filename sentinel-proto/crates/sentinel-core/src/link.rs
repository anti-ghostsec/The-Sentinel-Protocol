//! Linking another device to an account (spec section 6).
//!
//! 1. The existing device makes a **link code**: `sentinel://link/<pillar>#<secret>`
//!    (shown once, typed or copied to the new device; never sent over the
//!    network).
//! 2. The new device leaves a **request** (its own messaging card and a key
//!    for the answer) in a mailbox only holders of the code can find, sealed
//!    with the code's secret.
//! 3. Both devices show a short **check code**. Anyone who glimpsed the link
//!    code can read and write this mailbox, so the code mixes a random value
//!    from each side, fixed in turn so neither can be chosen to match:
//!    the request carries a *commitment* to the new device's value; the
//!    existing device answers with its own value ([`LinkBlob::Challenge`]);
//!    only then does the new device reveal its value ([`LinkBlob::Reveal`]).
//!    Someone in the middle has to fix their values before seeing the
//!    others', so their codes match by chance only (1 in 10^8).
//! 4. The person confirms the codes match on both devices. The existing
//!    device then answers with the account (its identity, follows, rooms,
//!    settings), sealed to the key in the request and tagged with a key from
//!    both values; the new device takes it only after the person confirmed
//!    there too, and only with that tag.
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
    /// Commitment to the new device's value ([`commit`]).
    #[serde(default)]
    pub commit: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LinkBlob {
    Request(LinkRequest),
    /// The account, sealed to the request's keys (opaque to this module),
    /// tagged with [`answer_tag`].
    Answer {
        to: [u8; 32],
        sealed: Vec<u8>,
        #[serde(default)]
        tag: [u8; 32],
    },
    /// Existing device -> new device: my value for this request (by
    /// [`request_id`]).
    Challenge { request: [u8; 32], nonce: [u8; 32] },
    /// New device -> existing device: the value the request committed to.
    Reveal { request: [u8; 32], nonce: [u8; 32] },
}

/// A request's ID (what challenges and reveals refer to).
pub fn request_id(req: &LinkRequest) -> [u8; 32] {
    let mut r = Vec::new();
    ciborium::into_writer(req, &mut r).expect("encode");
    blake3::derive_key("sentinel/v1/link-request-id", &r)
}

/// The commitment a request carries to the new device's value.
pub fn commit(nonce: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("sentinel/v1/link-commit", nonce)
}

fn mixed(context: &str, code: &LinkCode, req: &LinkRequest, mine: &[u8; 32], theirs: &[u8; 32]) -> [u8; 32] {
    let mut m = code.secret.to_vec();
    m.extend_from_slice(&request_id(req));
    m.extend_from_slice(mine);
    m.extend_from_slice(theirs);
    blake3::derive_key(context, &m)
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

/// The check code both devices show: 8 digits from the link secret, the
/// request and both devices' values. `None` if `new_value` isn't the one
/// the request committed to.
pub fn check_code(code: &LinkCode, req: &LinkRequest, new_value: &[u8; 32], existing_value: &[u8; 32]) -> Option<String> {
    if commit(new_value) != req.commit {
        return None;
    }
    let h = mixed("sentinel/v1/link-check", code, req, new_value, existing_value);
    let n = u64::from_le_bytes(h[..8].try_into().unwrap()) % 100_000_000;
    Some(format!("{:04}-{:04}", n / 10_000, n % 10_000))
}

/// The tag on the account handed over: only someone holding both values of
/// the exchange the person checked can make it.
pub fn answer_tag(code: &LinkCode, req: &LinkRequest, new_value: &[u8; 32], existing_value: &[u8; 32], sealed: &[u8]) -> [u8; 32] {
    let k = mixed("sentinel/v1/link-answer-tag", code, req, new_value, existing_value);
    *blake3::keyed_hash(&k, sealed).as_bytes()
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
        ContactCard { olm_identity: [1; 32], one_time_keys: vec![], fallback_key: None, inbox_pub: [2; 32], inbox_ids: vec![], pillar: "x".into(), minute: 0, inbox_kem: None, prekey_days: vec![] }
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
            commit: commit(&[1; 32]),
        };
        let sealed = seal(&code, &LinkBlob::Request(req.clone()));
        let Some(LinkBlob::Request(got)) = open(&code, &sealed) else { panic!() };
        assert_eq!(got, req);
        // Someone without the code can't open it.
        assert!(open(&LinkCode::new("b"), &sealed).is_none());
        // Same check code on both sides; another request or value gives
        // another one; a value the request didn't commit to gives none.
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(check_code(&code, &got, &a, &b).is_some());
        assert_eq!(check_code(&code, &got, &a, &b), check_code(&code, &req, &a, &b));
        let mut other = req.clone();
        other.device = "Laptop".into();
        assert_ne!(check_code(&code, &other, &a, &b), check_code(&code, &req, &a, &b));
        assert_ne!(check_code(&code, &req, &a, &[3; 32]), check_code(&code, &req, &a, &b));
        assert!(check_code(&code, &req, &[9; 32], &b).is_none());
        assert_ne!(answer_tag(&code, &req, &a, &b, b"x"), answer_tag(&code, &req, &a, &[3; 32], b"x"));
        // The account reaches only the requesting device.
        let s = seal_answer(&req, b"the account").unwrap();
        assert_eq!(&**open_answer(&answer_secret, &kem, &s).unwrap(), b"the account");
        assert!(open_answer(&crate::random_bytes::<32>(), &kem, &s).is_none());
    }
}
