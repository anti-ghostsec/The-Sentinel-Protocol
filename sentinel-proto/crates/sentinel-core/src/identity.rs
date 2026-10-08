//! Identity key storage, encrypted at rest (spec §18).
//!
//! File format (v2): `magic(8) | salt(16) | nonce(24) | sealed key(48) |
//! emergency slot(248)`. Key derivation: Argon2id, 256 MiB and 3 passes, so
//! a seized file resists offline passphrase guessing even with GPU farms.
//! Magic bytes are arbitrary, so the file doesn't announce what it is. v0
//! (64 MiB) and v1 files (no emergency slot) are still readable.
//!
//! **Emergency (duress) passphrase:** the slot holds a decoy name and
//! connection mode sealed under a second passphrase. Typing that passphrase
//! at unlock tells the app to wipe the real account and open an empty decoy.
//! When no emergency passphrase is set, the slot is random bytes of the same
//! size, so nobody can tell from the file whether one exists. Unlocking
//! always derives both keys (in parallel), so timing doesn't tell either.
//!
//! **Key file (optional):** like VeraCrypt's keyfiles. The contents of a
//! file the person chooses (a photo, anything) are mixed into the real
//! passphrase's key, so unlocking needs the passphrase *and* that exact
//! file; guessing passphrases against a seized key file is hopeless without
//! it. Nothing in the key file says whether one is used. The emergency
//! passphrase never needs it (it has to work when someone forces you).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

/// Old format (64 MiB).
const MAGIC_V0: &[u8; 8] = b"AETHK\0v0";
/// 256 MiB, no emergency slot.
const MAGIC_V1: &[u8; 8] = &[0x9e, 0x3b, 0xd1, 0x57, 0x0c, 0xa4, 0x62, 0xf8];
/// Current format: 256 MiB plus the emergency slot.
const MAGIC_V2: &[u8; 8] = &[0x41, 0xc7, 0x0e, 0x96, 0xb2, 0x5d, 0xf3, 0x18];
const HEAD: usize = 8 + 16 + 24 + 48;
/// Decoy plaintext: mode(1) | name length(1) | name | zero padding.
const DECOY_PLAIN: usize = 192;
/// Emergency slot: salt(16) | nonce(24) | sealed decoy(192 + 16).
const SLOT: usize = 16 + 24 + DECOY_PLAIN + 16;

/// What the emergency passphrase opens.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoy {
    pub name: String,
    /// Connect through bridges (so the decoy never connects less carefully
    /// than the real account did).
    pub bridges: bool,
}

/// Result of unlocking.
pub enum Opened {
    Real(SigningKey),
    /// The emergency passphrase: wipe the real account, open the decoy.
    Emergency(Decoy),
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("wrong passphrase or corrupted key file")]
    Decrypt,
    #[error("not an Sentinel key file")]
    Format,
    #[error("key derivation failed")]
    Kdf,
}

/// How much of a key file counts (like VeraCrypt: the first 1 MiB).
const KEYFILE_READ: usize = 1 << 20;
/// Smallest usable key file.
pub const KEYFILE_MIN: usize = 64;

/// A key file's fingerprint (what gets mixed in). `None` if it's too small.
pub fn keyfile_digest(bytes: &[u8]) -> Option<[u8; 32]> {
    (bytes.len() >= KEYFILE_MIN).then(|| blake3::derive_key("sentinel/v0/keyfile", &bytes[..bytes.len().min(KEYFILE_READ)]))
}

/// The real passphrase's key, with the key file mixed in when there is one.
fn real_key(passphrase: &[u8], salt: &[u8; 16], mib: u32, keyfile: Option<&[u8; 32]>) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let k = derive_key(passphrase, salt, mib)?;
    Ok(match keyfile {
        None => k,
        Some(kf) => {
            let mut m = Zeroizing::new([0u8; 64]);
            m[..32].copy_from_slice(k.as_ref());
            m[32..].copy_from_slice(kf);
            Zeroizing::new(blake3::derive_key("sentinel/v0/passphrase-with-keyfile", m.as_ref()))
        }
    })
}

fn derive_key(passphrase: &[u8], salt: &[u8; 16], mib: u32) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let params = Params::new(mib * 1024, 3, 1, Some(32)).map_err(|_| IdentityError::Kdf)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| IdentityError::Kdf)?;
    Ok(out)
}

/// EFF large diceware wordlist (7776 words; SHA-256 addd3553…6b903e).
const WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

/// A random passphrase of `words` diceware words (~12.9 bits each from the
/// OS random generator): 7 words ≈ 90 bits, out of reach of offline
/// cracking even against a seized file.
/// The 7,776 diceware words.
pub(crate) fn wordlist() -> Vec<&'static str> {
    WORDLIST.lines().filter_map(|l| l.split('\t').nth(1)).collect()
}

pub fn generate_passphrase(words: usize) -> Zeroizing<String> {
    let list = wordlist();
    debug_assert_eq!(list.len(), 7776);
    let mut out = Zeroizing::new(String::new());
    for i in 0..words {
        // Rejection sampling: no modulo bias.
        let idx = loop {
            let r = u16::from_le_bytes(crate::random_bytes::<2>()) as usize & 0x1FFF;
            if r < list.len() {
                break r;
            }
        };
        if i > 0 {
            out.push('-');
        }
        out.push_str(list[idx]);
    }
    out
}

/// Rough strength estimate in bits (character-class model; a generated
/// diceware passphrase is credited with its true entropy by the caller).
pub fn estimate_bits(pass: &str) -> u32 {
    let mut pool = 0u32;
    if pass.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if pass.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if pass.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if pass.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 33;
    }
    let distinct = pass.chars().collect::<std::collections::HashSet<_>>().len() as f64;
    let len = (pass.chars().count() as f64).min(distinct * 2.0);
    (len * (pool.max(1) as f64).log2()) as u32
}

pub fn generate() -> SigningKey {
    let seed = Zeroizing::new(crate::random_bytes::<32>());
    SigningKey::from_bytes(&seed)
}

/// Seal a key with no emergency passphrase (the slot is random).
pub fn seal(key: &SigningKey, passphrase: &[u8], keyfile: Option<&[u8; 32]>) -> Result<Vec<u8>, IdentityError> {
    seal_with_slot(key, passphrase, keyfile, &random_slot())
}

/// Re-seal under a new passphrase, keeping the emergency slot as it is.
pub fn reseal(old: &[u8], key: &SigningKey, passphrase: &[u8], keyfile: Option<&[u8; 32]>) -> Result<Vec<u8>, IdentityError> {
    let slot = if old.len() == HEAD + SLOT && &old[..8] == MAGIC_V2 { old[HEAD..].to_vec() } else { random_slot() };
    seal_with_slot(key, passphrase, keyfile, &slot)
}

/// Set (or with `None`, remove) the emergency passphrase. The caller has
/// already opened `old` with the real passphrase (it holds `key`).
pub fn set_emergency(old: &[u8], key: &SigningKey, passphrase: &[u8], keyfile: Option<&[u8; 32]>, emergency: Option<(&[u8], &Decoy)>) -> Result<Vec<u8>, IdentityError> {
    let slot = match emergency {
        None => random_slot(),
        Some((pass, decoy)) => {
            if pass == passphrase {
                return Err(IdentityError::Format);
            }
            let mut plain = Zeroizing::new([0u8; DECOY_PLAIN]);
            let name = decoy.name.as_bytes();
            if name.len() > DECOY_PLAIN - 2 {
                return Err(IdentityError::Format);
            }
            plain[0] = decoy.bridges as u8;
            plain[1] = name.len() as u8;
            plain[2..2 + name.len()].copy_from_slice(name);
            let salt = crate::random_bytes::<16>();
            let nonce = crate::random_bytes::<24>();
            let k = derive_key(pass, &salt, 256)?;
            let ct = XChaCha20Poly1305::new(k.as_ref().into()).encrypt(XNonce::from_slice(&nonce), plain.as_ref()).map_err(|_| IdentityError::Decrypt)?;
            let mut slot = Vec::with_capacity(SLOT);
            slot.extend_from_slice(&salt);
            slot.extend_from_slice(&nonce);
            slot.extend_from_slice(&ct);
            slot
        }
    };
    let _ = old;
    seal_with_slot(key, passphrase, keyfile, &slot)
}

fn random_slot() -> Vec<u8> {
    let mut v = Vec::with_capacity(SLOT);
    while v.len() < SLOT {
        v.extend_from_slice(&crate::random_bytes::<32>());
    }
    v.truncate(SLOT);
    v
}

fn seal_with_slot(key: &SigningKey, passphrase: &[u8], keyfile: Option<&[u8; 32]>, slot: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let salt = crate::random_bytes::<16>();
    let nonce = crate::random_bytes::<24>();
    let k = real_key(passphrase, &salt, 256, keyfile)?;
    let cipher = XChaCha20Poly1305::new(k.as_ref().into());
    let secret = Zeroizing::new(key.to_bytes());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), secret.as_ref())
        .map_err(|_| IdentityError::Decrypt)?;
    let mut out = Vec::with_capacity(HEAD + SLOT);
    out.extend_from_slice(MAGIC_V2);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(slot);
    Ok(out)
}

/// Unlock with whichever passphrase was typed. Both keys are always
/// derived, side by side, so success, failure and the emergency
/// passphrase all take the same time.
pub fn open_any(file: &[u8], passphrase: &[u8], keyfile: Option<&[u8; 32]>) -> Result<Opened, IdentityError> {
    if !(file.len() == HEAD + SLOT && &file[..8] == MAGIC_V2) {
        return open_v1(file, passphrase, keyfile).map(Opened::Real);
    }
    let salt: [u8; 16] = file[8..24].try_into().unwrap();
    let slot = &file[HEAD..];
    let esalt: [u8; 16] = slot[..16].try_into().unwrap();
    let (main, emergency) = std::thread::scope(|sc| {
        let e = sc.spawn(|| derive_key(passphrase, &esalt, 256));
        let m = real_key(passphrase, &salt, 256, keyfile);
        (m, e.join().unwrap_or(Err(IdentityError::Kdf)))
    });
    let main = main?;
    let emergency = emergency?;
    let real = XChaCha20Poly1305::new(main.as_ref().into()).decrypt(XNonce::from_slice(&file[24..48]), &file[48..HEAD]);
    let decoy = XChaCha20Poly1305::new(emergency.as_ref().into()).decrypt(XNonce::from_slice(&slot[16..40]), &slot[40..]);
    if let Ok(pt) = real {
        let pt = Zeroizing::new(pt);
        let seed: [u8; 32] = pt.as_slice().try_into().map_err(|_| IdentityError::Format)?;
        return Ok(Opened::Real(SigningKey::from_bytes(&Zeroizing::new(seed))));
    }
    if let Ok(pt) = decoy {
        let pt = Zeroizing::new(pt);
        let len = pt[1] as usize;
        let name = String::from_utf8(pt.get(2..2 + len).ok_or(IdentityError::Format)?.to_vec()).map_err(|_| IdentityError::Format)?;
        return Ok(Opened::Emergency(Decoy { name, bridges: pt[0] == 1 }));
    }
    Err(IdentityError::Decrypt)
}

/// The same slow work as sealing a new key file, on throwaway input. A
/// normal unlock does this so it takes as long as one with the emergency
/// passphrase (which wipes and seals a new account): the time an unlock
/// takes doesn't tell which passphrase was typed.
pub fn equalize_unlock_time() {
    let salt = crate::random_bytes::<16>();
    let junk = crate::random_bytes::<32>();
    let _ = derive_key(&junk, &salt, 256);
}

/// Older files without the emergency slot (re-seal them after unlocking,
/// so every file looks the same).
pub fn needs_upgrade(file: &[u8]) -> bool {
    !(file.len() == HEAD + SLOT && &file[..8] == MAGIC_V2)
}

/// Unlock with the real passphrase only.
pub fn open(file: &[u8], passphrase: &[u8], keyfile: Option<&[u8; 32]>) -> Result<SigningKey, IdentityError> {
    match open_any(file, passphrase, keyfile)? {
        Opened::Real(k) => Ok(k),
        Opened::Emergency(_) => Err(IdentityError::Decrypt),
    }
}

fn open_v1(file: &[u8], passphrase: &[u8], keyfile: Option<&[u8; 32]>) -> Result<SigningKey, IdentityError> {
    if file.len() < 8 + 16 + 24 {
        return Err(IdentityError::Format);
    }
    let mib = match &file[..8] {
        m if m == MAGIC_V1 => 256,
        m if m == MAGIC_V0 => 64,
        _ => return Err(IdentityError::Format),
    };
    let salt: [u8; 16] = file[8..24].try_into().unwrap();
    let nonce = &file[24..48];
    let k = real_key(passphrase, &salt, mib, keyfile)?;
    let cipher = XChaCha20Poly1305::new(k.as_ref().into());
    let pt = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), &file[48..])
            .map_err(|_| IdentityError::Decrypt)?,
    );
    let seed: [u8; 32] = pt.as_slice().try_into().map_err(|_| IdentityError::Format)?;
    Ok(SigningKey::from_bytes(&Zeroizing::new(seed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emergency_passphrase_opens_the_decoy_and_is_invisible_otherwise() {
        let key = generate();
        let plain = seal(&key, b"real passphrase one", None).unwrap();
        let decoy = Decoy { name: "Sam".into(), bridges: true };
        let with = set_emergency(&plain, &key, b"real passphrase one", None, Some((b"emergency words", &decoy))).unwrap();
        // Same size and shape with or without an emergency passphrase.
        assert_eq!(plain.len(), with.len());
        assert_eq!(plain[..8], with[..8]);
        assert!(matches!(open_any(&with, b"real passphrase one", None).unwrap(), Opened::Real(k) if k.to_bytes() == key.to_bytes()));
        match open_any(&with, b"emergency words", None).unwrap() {
            Opened::Emergency(d) => assert_eq!(d, decoy),
            Opened::Real(_) => panic!("emergency opened the real key"),
        }
        assert!(open_any(&with, b"something else", None).is_err());
        assert!(open(&with, b"emergency words", None).is_err(), "the plain open never treats it as real");
        // Changing the passphrase keeps the emergency slot; removing it works.
        let changed = reseal(&with, &key, b"new real passphrase", None).unwrap();
        assert!(matches!(open_any(&changed, b"emergency words", None).unwrap(), Opened::Emergency(_)));
        let removed = set_emergency(&changed, &key, b"new real passphrase", None, None).unwrap();
        assert!(open_any(&removed, b"emergency words", None).is_err());
        // The emergency passphrase can't be the real one.
        assert!(set_emergency(&plain, &key, b"same", None, Some((b"same", &decoy))).is_err());
    }

    #[test]
    fn passphrases_are_random_words() {
        let a = generate_passphrase(7);
        let b = generate_passphrase(7);
        assert_ne!(*a, *b);
        assert_eq!(a.split('-').count(), 7);
        assert!(estimate_bits("aaaaaaaaaaaa") < 40);
        assert!(estimate_bits("correct-Horse-battery-7-staple") > 60);
    }

    #[test]
    fn seal_open_roundtrip_and_wrong_pass() {
        let k = generate();
        let f = seal(&k, b"correct horse", None).unwrap();
        assert_eq!(open(&f, b"correct horse", None).unwrap().to_bytes(), k.to_bytes());
        assert!(open(&f, b"wrong", None).is_err());
    }

    #[test]
    fn key_file_is_needed_invisible_and_skipped_by_the_emergency_passphrase() {
        let key = generate();
        let photo: Vec<u8> = (0..5000u32).map(|i| (i * 31 % 251) as u8).collect();
        let kf = keyfile_digest(&photo).unwrap();
        let plain = seal(&key, b"real passphrase one", None).unwrap();
        let with = seal(&key, b"real passphrase one", Some(&kf)).unwrap();
        // Nothing in the file says a key file is used.
        assert_eq!(plain.len(), with.len());
        assert_eq!(plain[..8], with[..8]);
        assert_eq!(open(&with, b"real passphrase one", Some(&kf)).unwrap().to_bytes(), key.to_bytes());
        // The passphrase alone, or with another file, fails like a wrong passphrase.
        assert!(open(&with, b"real passphrase one", None).is_err());
        let mut edited = photo.clone();
        edited[10] ^= 1;
        assert!(open(&with, b"real passphrase one", Some(&keyfile_digest(&edited).unwrap())).is_err());
        // Tiny files are refused; only the first 1 MiB counts.
        assert!(keyfile_digest(&[1u8; 10]).is_none());
        let mut big = vec![7u8; KEYFILE_READ + 10];
        let d = keyfile_digest(&big).unwrap();
        big[KEYFILE_READ + 5] = 9;
        assert_eq!(keyfile_digest(&big).unwrap(), d);
        // The emergency passphrase works with no key file (you may be forced).
        let decoy = Decoy { name: "Sam".into(), bridges: false };
        let both = set_emergency(&with, &key, b"real passphrase one", Some(&kf), Some((b"emergency words", &decoy))).unwrap();
        assert!(matches!(open_any(&both, b"emergency words", None).unwrap(), Opened::Emergency(_)));
        assert!(matches!(open_any(&both, b"emergency words", Some(&kf)).unwrap(), Opened::Emergency(_)));
        assert!(matches!(open_any(&both, b"real passphrase one", Some(&kf)).unwrap(), Opened::Real(_)));
        // Changing the passphrase keeps (or changes) the key file as asked.
        let re = reseal(&both, &key, b"another passphrase", Some(&kf)).unwrap();
        assert!(open(&re, b"another passphrase", None).is_err());
        assert!(open(&re, b"another passphrase", Some(&kf)).is_ok());
    }
}
