//! Finding live Pillars when many listed ones are gone.
//!
//! Credit issuers check every Pillar they know at random times for months
//! (to pay them, see the Pillar's `earning`), so they know which ones have
//! really been there. Each issuer signs a short list of those ("vouched"
//! Pillars); apps try them first. Building a place on it takes weeks of
//! answering random checks, so flooding the directory with fake or dead
//! Pillars doesn't push them aside. The list only changes which Pillars an
//! app tries first: everything a Pillar serves is checked on its own.

use serde::{Deserialize, Serialize};

use crate::pq::{HybridPublic, HybridSigner};

/// At most this many Pillars in one vouched list.
pub const MAX_VOUCHED: usize = 64;
/// Apps ignore vouched lists older than this (days).
pub const VOUCH_MAX_AGE_DAYS: u64 = 3;

const VOUCH_CTX: &[u8] = b"sentinel/v1/vouched-pillars";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vouch {
    /// The issuer's own onion address.
    pub mint: String,
    /// The day (days since 1970) it was made.
    pub day: u64,
    pub pillars: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedVouch {
    pub body: Vouch,
    pub ed: Vec<u8>,
    pub dsa: Vec<u8>,
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

pub fn sign_vouch(signer: &HybridSigner, mut body: Vouch) -> SignedVouch {
    body.pillars.truncate(MAX_VOUCHED);
    let (ed, dsa) = signer.sign(&cbor(&body), VOUCH_CTX);
    SignedVouch { body, ed, dsa }
}

/// A vouched list's Pillars, if it's signed by `pk`, comes from `mint`,
/// and is recent (relative to `today`).
pub fn check_vouch(pk: &HybridPublic, mint: &str, today: u64, s: &SignedVouch) -> Option<Vec<String>> {
    let ok = s.body.mint == mint
        && s.body.day + VOUCH_MAX_AGE_DAYS >= today
        && s.body.day <= today + 1
        && s.body.pillars.len() <= MAX_VOUCHED
        && pk.verify(&cbor(&s.body), VOUCH_CTX, &s.ed, &s.dsa);
    ok.then(|| s.body.pillars.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vouched_lists_are_signed_recent_and_from_the_right_issuer() {
        let signer = crate::pqcash::mint_signer(&[7; 32]);
        let pk = signer.public();
        let body = Vouch { mint: "a.onion".into(), day: 100, pillars: vec!["p.onion".into()] };
        let s = sign_vouch(&signer, body);
        assert_eq!(check_vouch(&pk, "a.onion", 101, &s), Some(vec!["p.onion".to_string()]));
        assert!(check_vouch(&pk, "b.onion", 101, &s).is_none(), "another issuer's name");
        assert!(check_vouch(&pk, "a.onion", 110, &s).is_none(), "too old");
        let mut t = s.clone();
        t.body.pillars.push("x.onion".into());
        assert!(check_vouch(&pk, "a.onion", 101, &t).is_none(), "changed after signing");
        let other = crate::pqcash::mint_signer(&[8; 32]).public();
        assert!(check_vouch(&other, "a.onion", 101, &s).is_none(), "another key");
    }
}
