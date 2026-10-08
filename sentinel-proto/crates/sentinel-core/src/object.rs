//! Signed, content-addressed objects (spec §5.1).
//!
//! The signature covers the exact stored bytes of `type` + `body`, so no
//! re-encoding is needed to verify (avoids canonicalisation bugs).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain-separation prefix so object signatures can never be confused with
/// signatures made by the same key for another purpose.
const SIG_DOMAIN: &[u8] = b"sentinel/v0/object-sig\0";

/// Maximum accepted encoded object size (DoS bound).
pub const MAX_OBJECT_LEN: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ObjectError {
    #[error("object encoding error")]
    Encoding,
    #[error("object too large")]
    TooLarge,
    #[error("bad signature")]
    BadSignature,
    #[error("bad public key")]
    BadKey,
}

/// Content address: BLAKE3-256 of the encoded envelope.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub fn of(bytes: &[u8]) -> Self {
        Address(*blake3::hash(bytes).as_bytes())
    }
    pub fn to_text(&self) -> String {
        data_encoding::BASE32_NOPAD.encode(&self.0).to_lowercase()
    }
    pub fn from_text(s: &str) -> Option<Self> {
        let v = data_encoding::BASE32_NOPAD
            .decode(s.trim().to_uppercase().as_bytes())
            .ok()?;
        Some(Address(v.try_into().ok()?))
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Address({})", self.to_text())
    }
}

/// Signed envelope. `author` is the public signing key (stands in for the DID
/// in this prototype; identity logs/rotation are a later milestone).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub author: [u8; 32],
    #[serde(with = "serde_bytes_compat")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes_compat")]
    pub sig: Vec<u8>,
}

impl Envelope {
    fn signed_message(kind: &str, author: &[u8; 32], body: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(SIG_DOMAIN.len() + kind.len() + 40 + body.len());
        m.extend_from_slice(SIG_DOMAIN);
        m.extend_from_slice(&(kind.len() as u32).to_be_bytes());
        m.extend_from_slice(kind.as_bytes());
        m.extend_from_slice(author);
        m.extend_from_slice(&(body.len() as u64).to_be_bytes());
        m.extend_from_slice(body);
        m
    }

    pub fn sign(key: &SigningKey, kind: &str, body: Vec<u8>) -> Self {
        let author = key.verifying_key().to_bytes();
        let sig = key.sign(&Self::signed_message(kind, &author, &body));
        Envelope { v: 0, kind: kind.to_owned(), author, body, sig: sig.to_bytes().to_vec() }
    }

    pub fn verify(&self) -> Result<(), ObjectError> {
        let vk = VerifyingKey::from_bytes(&self.author).map_err(|_| ObjectError::BadKey)?;
        let sig_bytes: [u8; 64] =
            self.sig.as_slice().try_into().map_err(|_| ObjectError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(&Self::signed_message(&self.kind, &self.author, &self.body), &sig)
            .map_err(|_| ObjectError::BadSignature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|_| ObjectError::Encoding)?;
        if out.len() > MAX_OBJECT_LEN {
            return Err(ObjectError::TooLarge);
        }
        Ok(out)
    }

    /// Decode and verify. Never returns an unverified envelope.
    pub fn decode_verified(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.len() > MAX_OBJECT_LEN {
            return Err(ObjectError::TooLarge);
        }
        let env: Envelope = ciborium::from_reader(bytes).map_err(|_| ObjectError::Encoding)?;
        env.verify()?;
        Ok(env)
    }
}

/// Encode `Vec<u8>` as a CBOR byte string rather than an array of integers.
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let b: ciborium::value::Value = Deserialize::deserialize(d)?;
        match b {
            ciborium::value::Value::Bytes(b) => Ok(b),
            _ => Err(serde::de::Error::custom("expected bytes")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let key = SigningKey::from_bytes(&crate::random_bytes::<32>());
        let env = Envelope::sign(&key, "post", b"hello".to_vec());
        let bytes = env.encode().unwrap();
        assert!(Envelope::decode_verified(&bytes).is_ok());

        let mut bad = env.clone();
        bad.body = b"hellp".to_vec();
        assert!(Envelope::decode_verified(&bad.encode().unwrap()).is_err());

        let mut bad_kind = env;
        bad_kind.kind = "profile".into();
        assert!(Envelope::decode_verified(&bad_kind.encode().unwrap()).is_err());
    }

    #[test]
    fn address_text_roundtrip() {
        let a = Address::of(b"x");
        assert_eq!(Address::from_text(&a.to_text()), Some(a));
    }
}
