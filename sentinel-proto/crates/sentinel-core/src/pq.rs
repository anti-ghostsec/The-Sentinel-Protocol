//! Post-quantum protection (spec section 18): hybrids, so a message or a
//! signature is safe as long as *either* the classical or the post-quantum
//! algorithm holds.
//!
//! - **Key exchange:** X25519 + ML-KEM-768 (FIPS 203). Someone recording
//!   traffic today to decrypt with a quantum computer later ("harvest now,
//!   decrypt later") also has to break ML-KEM.
//! - **Signatures:** Ed25519 + ML-DSA-65 (FIPS 204), for things that must
//!   stay trustworthy for years, like signed updates.
//!
//! Symmetric parts (XChaCha20-Poly1305, BLAKE3, Argon2id, all with 256-bit
//! keys) already hold up against quantum computers.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ml_dsa::{MlDsa65, Signature, SigningKey as DsaSigningKey, VerifyingKey as DsaVerifyingKey};
use ml_kem::{Decapsulate as _, KeyExport as _, MlKem768};
use zeroize::Zeroizing;

/// ML-KEM-768 public key size.
pub const KEM_PUBLIC: usize = 1184;
/// ML-KEM-768 ciphertext size.
pub const KEM_CT: usize = 1088;
/// ML-DSA-65 public key and signature sizes.
pub const DSA_PUBLIC: usize = 1952;
pub const DSA_SIG: usize = 3309;

type Dk = ml_kem::DecapsulationKey<MlKem768>;
type Ek = ml_kem::EncapsulationKey<MlKem768>;

/// A new ML-KEM key: its 64-byte seed (the secret).
pub fn kem_seed() -> Zeroizing<[u8; 64]> {
    let mut s = Zeroizing::new([0u8; 64]);
    s[..32].copy_from_slice(&crate::random_bytes::<32>());
    s[32..].copy_from_slice(&crate::random_bytes::<32>());
    s
}

fn dk(seed: &[u8; 64]) -> Dk {
    Dk::from_seed((*seed).into())
}

/// The public key for a seed.
pub fn kem_public(seed: &[u8; 64]) -> Vec<u8> {
    dk(seed).encapsulation_key().to_bytes().to_vec()
}

/// Encapsulate to a public key: (ciphertext, shared secret).
pub fn encapsulate(public: &[u8]) -> Option<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let key: &ml_kem::Key<Ek> = public.try_into().ok()?;
    let ek = Ek::new(key).ok()?;
    // FIPS 203 encapsulation with fresh randomness from the OS.
    let m = Zeroizing::new(crate::random_bytes::<32>());
    let (ct, ss) = ek.encapsulate_deterministic(&(*m).into());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&ss);
    Some((ct.to_vec(), out))
}

pub fn decapsulate(seed: &[u8; 64], ct: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let ct: &ml_kem::Ciphertext<MlKem768> = ct.try_into().ok()?;
    let ss = dk(seed).decapsulate(ct);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&ss);
    Some(out)
}

/// An ML-KEM seed derived from a secret this device already keeps (so no
/// new key needs storing), for period `n` (e.g. a month, for rotation).
pub fn kem_seed_from(label: &str, secret: &[u8; 32], n: u64) -> Zeroizing<[u8; 64]> {
    let mut m = Zeroizing::new(secret.to_vec());
    m.extend_from_slice(&n.to_le_bytes());
    let mut s = Zeroizing::new([0u8; 64]);
    s[..32].copy_from_slice(&blake3::derive_key(&format!("{label}/d"), &m));
    s[32..].copy_from_slice(&blake3::derive_key(&format!("{label}/z"), &m));
    s
}

fn hybrid_key(context: &str, bind: &[u8], x: &[u8; 32], eph_pub: &[u8; 32], kem: Option<&[u8; 32]>, kem_ct: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut m = Zeroizing::new(Vec::with_capacity(96 + bind.len() + kem_ct.len()));
    m.extend_from_slice(bind);
    m.extend_from_slice(x);
    m.extend_from_slice(eph_pub);
    if let Some(k) = kem {
        m.extend_from_slice(k);
        m.extend_from_slice(kem_ct);
    }
    Zeroizing::new(blake3::derive_key(context, &m))
}

/// Seal `plain` to someone's X25519 key and (when they have one) ML-KEM key.
/// `context` binds it to its purpose (and e.g. a room ID).
/// Format: eph_pub(32) | kem_ct_len(2) | kem_ct | nonce(24) | ciphertext.
/// `bind` ties it to something (e.g. a room ID): opening needs the same.
pub fn seal(context: &str, bind: &[u8], to_x25519: &[u8; 32], to_kem: Option<&[u8]>, plain: &[u8]) -> Option<Vec<u8>> {
    let eph = x25519_dalek::StaticSecret::from(crate::random_bytes::<32>());
    let eph_pub = x25519_dalek::PublicKey::from(&eph);
    let x = eph.diffie_hellman(&x25519_dalek::PublicKey::from(*to_x25519));
    let (kem_ct, kem_ss) = match to_kem {
        Some(pk) => {
            let (ct, ss) = encapsulate(pk)?;
            (ct, Some(ss))
        }
        None => (Vec::new(), None),
    };
    let key = hybrid_key(context, bind, x.as_bytes(), eph_pub.as_bytes(), kem_ss.as_deref(), &kem_ct);
    let nonce = crate::random_bytes::<24>();
    let ct = XChaCha20Poly1305::new(key.as_ref().into()).encrypt(XNonce::from_slice(&nonce), plain).ok()?;
    let mut out = Vec::with_capacity(32 + 2 + kem_ct.len() + 24 + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&(kem_ct.len() as u16).to_le_bytes());
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Open a [`seal`]. A sealed blob that used ML-KEM needs the KEM seed.
pub fn open(context: &str, bind: &[u8], my_x25519: &[u8; 32], my_kem: Option<&[u8; 64]>, b: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let eph_pub: [u8; 32] = b.get(..32)?.try_into().ok()?;
    let n = u16::from_le_bytes(b.get(32..34)?.try_into().ok()?) as usize;
    let kem_ct = b.get(34..34 + n)?;
    let rest = b.get(34 + n..)?;
    if rest.len() < 24 + 16 {
        return None;
    }
    let x = x25519_dalek::StaticSecret::from(*my_x25519).diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub));
    let kem_ss = if n == 0 { None } else { Some(decapsulate(my_kem?, kem_ct)?) };
    let key = hybrid_key(context, bind, x.as_bytes(), &eph_pub, kem_ss.as_deref(), kem_ct);
    XChaCha20Poly1305::new(key.as_ref().into()).decrypt(XNonce::from_slice(&rest[..24]), &rest[24..]).ok().map(Zeroizing::new)
}

// ---- signatures ----

/// An ML-DSA-65 public key for a 32-byte seed.
pub fn dsa_public(seed: &[u8; 32]) -> Vec<u8> {
    let sk = DsaSigningKey::<MlDsa65>::from_seed(&(*seed).into());
    sk.expanded_key().verifying_key().encode().to_vec()
}

/// Sign with ML-DSA-65 (deterministic; `ctx` separates purposes).
pub fn dsa_sign(seed: &[u8; 32], msg: &[u8], ctx: &[u8]) -> Option<Vec<u8>> {
    let sk = DsaSigningKey::<MlDsa65>::from_seed(&(*seed).into());
    sk.expanded_key().sign_deterministic(msg, ctx).ok().map(|s| s.encode().to_vec())
}

pub fn dsa_verify(public: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(enc) = <&ml_dsa::EncodedVerifyingKey<MlDsa65>>::try_from(public) else { return false };
    let vk = DsaVerifyingKey::<MlDsa65>::decode(enc);
    let Ok(sig) = Signature::<MlDsa65>::try_from(sig) else { return false };
    vk.verify_with_context(msg, ctx, &sig)
}

/// An account's ML-DSA-65 key, derived from its Ed25519 seed. Nothing new
/// to store; and a quantum computer that recovers the Ed25519 secret scalar
/// from the public key still can't get the seed (it's behind a hash), so
/// it can't get this key either.
pub fn identity_dsa_seed(id: &ed25519_dalek::SigningKey) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key("sentinel/v0/identity-mldsa65", id.as_bytes()))
}

pub fn identity_dsa_public(id: &ed25519_dalek::SigningKey) -> Vec<u8> {
    dsa_public(&identity_dsa_seed(id))
}

/// A hybrid signing key: Ed25519 + ML-DSA-65 from one 32-byte secret.
pub struct HybridSigner {
    ed: ed25519_dalek::SigningKey,
    dsa_seed: Zeroizing<[u8; 32]>,
}

/// Its public half: Ed25519 key and ML-DSA-65 key.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HybridPublic {
    pub ed: [u8; 32],
    pub dsa: Vec<u8>,
}

impl HybridSigner {
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let ed = ed25519_dalek::SigningKey::from_bytes(&blake3::derive_key("sentinel/v0/hybrid-ed25519", secret));
        let dsa_seed = Zeroizing::new(blake3::derive_key("sentinel/v0/hybrid-mldsa65", secret));
        HybridSigner { ed, dsa_seed }
    }

    pub fn public(&self) -> HybridPublic {
        HybridPublic { ed: self.ed.verifying_key().to_bytes(), dsa: dsa_public(&self.dsa_seed) }
    }

    /// The Ed25519 half (e.g. to sign an envelope filed under this key).
    pub fn ed_key(&self) -> &ed25519_dalek::SigningKey {
        &self.ed
    }

    /// Both signatures over `msg` (in context `ctx`).
    pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer;
        let mut m = ctx.to_vec();
        m.extend_from_slice(msg);
        (self.ed.sign(&m).to_bytes().to_vec(), dsa_sign(&self.dsa_seed, msg, ctx).unwrap_or_default())
    }
}

impl HybridPublic {
    /// Both must verify.
    pub fn verify(&self, msg: &[u8], ctx: &[u8], ed_sig: &[u8], dsa_sig: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.ed) else { return false };
        let Ok(sig) = ed25519_dalek::Signature::from_slice(ed_sig) else { return false };
        let mut m = ctx.to_vec();
        m.extend_from_slice(msg);
        vk.verify(&m, &sig).is_ok() && dsa_verify(&self.dsa, msg, ctx, dsa_sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_seal_needs_both_keys() {
        let x = crate::random_bytes::<32>();
        let x_pub = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(x)).as_bytes();
        let seed = kem_seed();
        let pk = kem_public(&seed);
        assert_eq!(pk.len(), KEM_PUBLIC);
        let b = seal("test", b"r1", &x_pub, Some(&pk), b"room secret").unwrap();
        assert_eq!(&**open("test", b"r1", &x, Some(&seed), &b).unwrap(), b"room secret");
        // Without the ML-KEM key, or with another one: no.
        assert!(open("test", b"r1", &x, None, &b).is_none());
        assert!(open("test", b"r1", &x, Some(&kem_seed()), &b).is_none());
        assert!(open("test", b"r2", &x, Some(&seed), &b).is_none(), "bound to r1");
        // Wrong context or X25519 key: no.
        assert!(open("other", b"r1", &x, Some(&seed), &b).is_none());
        assert!(open("test", b"r1", &crate::random_bytes::<32>(), Some(&seed), &b).is_none());
        // Classical-only still works for people without an ML-KEM key yet.
        let c = seal("test", b"", &x_pub, None, b"hi").unwrap();
        assert_eq!(&**open("test", b"", &x, None, &c).unwrap(), b"hi");
        // Derived seeds: stable per (secret, period), different across them.
        let a = kem_seed_from("t", &[1; 32], 5);
        assert_eq!(*a, *kem_seed_from("t", &[1; 32], 5));
        assert_ne!(*a, *kem_seed_from("t", &[1; 32], 6));
    }

    #[test]
    fn hybrid_signatures_need_both() {
        let s = HybridSigner::from_secret(&[3u8; 32]);
        let p = s.public();
        assert_eq!(p.dsa.len(), DSA_PUBLIC);
        let (ed, dsa) = s.sign(b"release 1.2", b"update");
        assert_eq!(dsa.len(), DSA_SIG);
        assert!(p.verify(b"release 1.2", b"update", &ed, &dsa));
        assert!(!p.verify(b"release 1.3", b"update", &ed, &dsa));
        assert!(!p.verify(b"release 1.2", b"other", &ed, &dsa));
        let other = HybridSigner::from_secret(&[4u8; 32]);
        let (ed2, dsa2) = other.sign(b"release 1.2", b"update");
        assert!(!p.verify(b"release 1.2", b"update", &ed, &dsa2), "a swapped ML-DSA signature fails");
        assert!(!p.verify(b"release 1.2", b"update", &ed2, &dsa), "a swapped Ed25519 signature fails");
    }
}
