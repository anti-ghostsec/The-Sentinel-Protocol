//! Mixed sending (spec section 10): a message (a mailbox deposit) travels
//! through two Pillars before it's deposited, and each holds it for a random
//! time first.
//!
//! Tor hides who is talking, but an observer who can watch a great deal of
//! the network (the threat Tor itself says it can't stop) could match the
//! moment someone sends with the moment a deposit appears. With mixing, a
//! deposit appears minutes later, from a Pillar that isn't the sender, among
//! everyone else's mixed messages.
//!
//! - Each hop is sealed to that Pillar's mix key (X25519 + ML-KEM-768), so a
//!   hop learns only the next step: the first doesn't see the destination,
//!   the second doesn't see who sent it (it came from the first).
//! - The delay at each hop is chosen by the sender at random (exponential,
//!   mean two minutes, at most ten).
//! - Packets are padded to fixed sizes.
//! - A Pillar's mix key is fetched straight from it over Tor (its onion
//!   address authenticates it).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const CONTEXT: &str = "sentinel/v0/mix";
/// Packets are padded to a multiple of this.
const PAD: usize = 8 * 1024;
/// Largest packet a Pillar accepts.
pub const MAX_PACKET: usize = 96 * 1024;
pub const MIX_POW_DOMAIN: &str = "sentinel/v0/mix-pow";
pub const MIX_POW_BITS: u32 = 12;

/// A Pillar's public mix key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MixKey {
    pub x25519: [u8; 32],
    pub kem: Vec<u8>,
}

impl MixKey {
    pub fn encode(&self) -> Vec<u8> {
        cbor(self)
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        ciborium::from_reader(b).ok().filter(|k: &MixKey| k.kem.len() == crate::pq::KEM_PUBLIC)
    }
}

/// A Pillar's mix secret (kept in a file beside its data).
pub struct MixSecret(Zeroizing<[u8; 32]>);

impl MixSecret {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        MixSecret(Zeroizing::new(b))
    }

    pub fn generate() -> Self {
        MixSecret(Zeroizing::new(crate::random_bytes::<32>()))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn x25519(&self) -> [u8; 32] {
        blake3::derive_key("sentinel/v0/mix-x25519", self.0.as_ref())
    }

    fn kem_seed(&self) -> Zeroizing<[u8; 64]> {
        crate::pq::kem_seed_from("sentinel/v0/mix-kem", &self.0, 0)
    }

    pub fn public(&self) -> MixKey {
        let x = x25519_dalek::StaticSecret::from(self.x25519());
        MixKey { x25519: *x25519_dalek::PublicKey::from(&x).as_bytes(), kem: crate::pq::kem_public(&self.kem_seed()) }
    }
}

/// What a hop does with a packet once its delay has passed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Step {
    /// Pass the inner packet on to another Pillar.
    Forward { to: String, packet: Vec<u8> },
    /// Deposit into a mailbox shard on a Pillar.
    Deliver { pillar: String, shard: u16, blob: Vec<u8>, nonce: u64 },
}

#[derive(Serialize, Deserialize)]
struct Layer {
    step: Step,
    delay_secs: u32,
    pad: Vec<u8>,
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

/// A random delay: exponential with a two-minute mean, 5 s to 10 min.
pub fn random_delay() -> u32 {
    let u = (u32::from_le_bytes(crate::random_bytes::<4>()) as f64 + 1.0) / (u32::MAX as f64 + 2.0);
    ((-u.ln() * 120.0) as u32).clamp(5, 600)
}

fn seal_layer(key: &MixKey, step: Step, delay_secs: u32) -> Option<Vec<u8>> {
    let mut layer = Layer { step, delay_secs, pad: Vec::new() };
    let len = cbor(&layer).len();
    let target = len.div_ceil(PAD) * PAD;
    layer.pad = vec![0u8; target.saturating_sub(len + 4)];
    crate::pq::seal(CONTEXT, &key.x25519, &key.x25519, Some(&key.kem), &cbor(&layer))
}

/// Wrap a deposit for a route of mix Pillars (first hop first). Returns the
/// packet to hand to the first Pillar.
pub fn wrap(route: &[(String, MixKey)], deliver: Step) -> Option<Vec<u8>> {
    let (last_onion, last_key) = route.last()?;
    let _ = last_onion;
    let mut packet = seal_layer(last_key, deliver, random_delay())?;
    for i in (0..route.len() - 1).rev() {
        let next = route[i + 1].0.clone();
        packet = seal_layer(&route[i].1, Step::Forward { to: next, packet }, random_delay())?;
    }
    (packet.len() <= MAX_PACKET).then_some(packet)
}

/// A hand-off: one layer, for one Pillar to deliver right away (and keep
/// retrying for days if the destination doesn't answer), so a message
/// leaves the sender's device even when its destination is down.
pub fn handoff(via: &MixKey, deliver: Step) -> Option<Vec<u8>> {
    let packet = seal_layer(via, deliver, 0)?;
    (packet.len() <= MAX_PACKET).then_some(packet)
}

/// A Pillar opens its layer: (what to do, after how long).
pub fn unwrap(secret: &MixSecret, packet: &[u8]) -> Option<(Step, u32)> {
    if packet.len() > MAX_PACKET {
        return None;
    }
    let kem = secret.kem_seed();
    let x = secret.x25519();
    let public = secret.public();
    let plain = crate::pq::open(CONTEXT, &public.x25519, &x, Some(&kem), packet)?;
    let layer: Layer = ciborium::from_reader(plain.as_slice()).ok()?;
    Some((layer.step, layer.delay_secs.min(600)))
}

/// Proof-of-work input for handing a packet to a Pillar (anti-flooding).
pub fn pow_data(packet: &[u8]) -> Vec<u8> {
    blake3::derive_key("sentinel/v0/mix-pow-data", packet).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_hops_each_see_only_their_step() {
        let (a, b) = (MixSecret::generate(), MixSecret::generate());
        let route = vec![("a.onion".to_string(), a.public()), ("b.onion".to_string(), b.public())];
        let deliver = Step::Deliver { pillar: "dest.onion".into(), shard: 7, blob: vec![1, 2, 3], nonce: 9 };
        let p = wrap(&route, deliver.clone()).unwrap();
        // The first hop learns only "forward to b", not the destination.
        let (step, d1) = unwrap(&a, &p).unwrap();
        assert!(d1 >= 5 && d1 <= 600);
        let Step::Forward { to, packet } = step else { panic!() };
        assert_eq!(to, "b.onion");
        assert!(unwrap(&b, &p).is_none(), "b can't open a's layer");
        // The second hop delivers.
        let (step2, _) = unwrap(&b, &packet).unwrap();
        assert_eq!(step2, deliver);
        assert!(unwrap(&a, &packet).is_none());
        // Same size whatever's inside (padded).
        let p2 = wrap(&route, Step::Deliver { pillar: "x".into(), shard: 1, blob: vec![0; 3000], nonce: 1 }).unwrap();
        assert_eq!(p.len(), p2.len());
    }
}
