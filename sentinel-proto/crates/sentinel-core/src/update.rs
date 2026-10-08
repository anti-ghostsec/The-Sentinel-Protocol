//! Signed updates (spec section 21). Sentinel will never be in an app store:
//! it's handed from person to person and carried by Pillars. So an update is
//! a single **bundle** file that is safe to get from anywhere:
//!
//! - It is signed by the **release keys** pinned in the app, each with a
//!   hybrid signature (Ed25519 + ML-DSA-65, so a future quantum computer
//!   can't forge one). A majority of the listed keys must sign: no single
//!   person (or stolen key) can push an update.
//! - Every file in it is named in the signed manifest with its size and
//!   BLAKE3 hash, so a Pillar or a friend passing it on can't change a byte.
//! - The version must be newer than the installed one (no downgrades to an
//!   older, weaker release).
//!
//! - **The same update for everyone.** Pillars pass every signed release on
//!   to each other, and an app only takes a release that at least two
//!   different Pillars carry, identically. A special update made for one
//!   person would have to be planted across the network, where everyone
//!   can see it.
//! - **A waiting period.** Apps offer a release only after they've seen it
//!   for three days, so a bad one can be noticed and revoked first.
//! - **Revocation.** A majority of the release keys can sign a revocation of
//!   a release; it spreads the same way, and apps then refuse it.
//!
//! Format: `MAGIC(8) | header length (u32 LE) | header (CBOR) | files`, the
//! files' bytes back to back in manifest order.

use serde::{Deserialize, Serialize};

use crate::pq::HybridPublic;

const MAGIC: &[u8; 8] = &[0x53, 0x75, 0xb2, 0x0f, 0x61, 0x9c, 0x2d, 0x7e];
const CTX: &[u8] = b"sentinel/v0/update";
/// Largest header accepted (manifest + signatures).
pub const MAX_HEADER: usize = 256 * 1024;
/// Largest bundle accepted.
pub const MAX_BUNDLE: u64 = 1 << 30;

/// How long an app waits after first seeing a release before offering it.
pub const WAIT_SECS: u64 = 3 * 86_400;
/// How many different Pillars must carry a release before an app takes it.
pub const MIN_SOURCES: usize = 2;
const REVOKE_CTX: &[u8] = b"sentinel/v0/update-revoke";

/// Release keys pinned in this build: one per line, `<ed25519 hex> <ML-DSA-65 hex>`.
const RELEASE_KEYS: &str = include_str!("../data/release_keys.txt");

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    /// Path inside the install folder (e.g. `Sentinel.exe`, `ffmpeg/avutil-60.dll`).
    pub path: String,
    pub size: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    /// What it updates: `app` (the Windows app), `app-android` (the phone
    /// app) or `pillar` (the server).
    pub product: String,
    pub platform: String,
    /// `major.minor.patch`.
    pub version: String,
    /// Short notes shown before installing.
    pub notes: String,
    pub files: Vec<FileEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseSig {
    pub ed: [u8; 32],
    pub ed_sig: Vec<u8>,
    pub dsa_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub manifest: Manifest,
    pub sigs: Vec<ReleaseSig>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum UpdateError {
    #[error("this isn't a Sentinel update")]
    Format,
    #[error("the update isn't signed by enough of Sentinel's release keys")]
    Unsigned,
    #[error("the update is for another product or system")]
    Product,
    #[error("this update is not newer than the version you have")]
    NotNewer,
    #[error("a file in the update was changed or is incomplete")]
    Tampered,
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

pub fn hash_file(bytes: &[u8]) -> [u8; 32] {
    blake3::derive_key("sentinel/v0/update-file", bytes)
}

/// The same hash, fed piece by piece (for files too big to hold at once).
pub fn file_hasher() -> blake3::Hasher {
    blake3::Hasher::new_derive_key("sentinel/v0/update-file")
}

/// `major.minor.patch` as numbers.
pub fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let mut it = v.trim().split('.').map(|p| p.parse::<u32>().ok());
    let r = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(r)
}

/// File names inside the install folder: plain names, optionally in one
/// known subfolder. Nothing can be written outside the app's own folder.
pub fn safe_path(p: &str) -> bool {
    let ok = |s: &str| !s.is_empty() && s.len() <= 100 && s != "." && s != ".." && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._- ".contains(&b));
    match p.split_once('/') {
        None => ok(p),
        Some((dir, name)) => matches!(dir, "ffmpeg" | "resources") && ok(name) && !name.contains('/'),
    }
}

/// The pinned release keys.
pub fn release_keys() -> Vec<HybridPublic> {
    parse_keys(RELEASE_KEYS)
}

fn parse_keys(text: &str) -> Vec<HybridPublic> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (ed, dsa) = l.split_once(' ')?;
            let ed: [u8; 32] = data_encoding::HEXLOWER.decode(ed.as_bytes()).ok()?.try_into().ok()?;
            let dsa = data_encoding::HEXLOWER.decode(dsa.trim().as_bytes()).ok()?;
            (dsa.len() == crate::pq::DSA_PUBLIC).then_some(HybridPublic { ed, dsa })
        })
        .collect()
}

/// Signatures needed: a majority of the listed keys.
pub fn threshold(keys: usize) -> usize {
    keys / 2 + 1
}

/// The text line that pins a release key (for `release_keys.txt`).
pub fn key_line(p: &HybridPublic) -> String {
    format!("{} {}", data_encoding::HEXLOWER.encode(&p.ed), data_encoding::HEXLOWER.encode(&p.dsa))
}

/// A release's identity: the hash of its signed manifest.
pub fn manifest_id(m: &Manifest) -> [u8; 32] {
    blake3::derive_key("sentinel/v0/update-manifest-id", &cbor(m))
}

/// "This release must not be installed."
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Revocation {
    pub product: String,
    pub version: String,
    pub manifest: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationDoc {
    pub revocation: Revocation,
    pub sigs: Vec<ReleaseSig>,
}

/// Release tooling: sign a revocation with one release key.
pub fn sign_revocation(signer: &crate::pq::HybridSigner, r: &Revocation) -> ReleaseSig {
    let (ed_sig, dsa_sig) = signer.sign(&cbor(r), REVOKE_CTX);
    ReleaseSig { ed: signer.public().ed, ed_sig, dsa_sig }
}

/// A revocation counts only with a majority of the release keys.
pub fn verify_revocation(doc: &RevocationDoc, keys: &[HybridPublic]) -> bool {
    let msg = cbor(&doc.revocation);
    let mut good: Vec<[u8; 32]> = Vec::new();
    for s in &doc.sigs {
        if !good.contains(&s.ed) && keys.iter().any(|k| k.ed == s.ed && k.verify(&msg, REVOKE_CTX, &s.ed_sig, &s.dsa_sig)) {
            good.push(s.ed);
        }
    }
    !keys.is_empty() && good.len() >= threshold(keys.len())
}

/// Merge revocations, keeping only valid ones, one per release.
pub fn merge_revocations(into: &mut Vec<RevocationDoc>, more: Vec<RevocationDoc>, keys: &[HybridPublic]) -> bool {
    let mut changed = false;
    for d in more {
        if into.len() < 1000 && !into.iter().any(|x| x.revocation.manifest == d.revocation.manifest) && verify_revocation(&d, keys) {
            into.push(d);
            changed = true;
        }
    }
    changed
}

pub fn encode_revocations(list: &[RevocationDoc]) -> Vec<u8> {
    cbor(&list)
}

/// One revocation (a `.revoke` file from release-revoke).
pub fn decode_revocation(b: &[u8]) -> Option<RevocationDoc> {
    ciborium::from_reader(b).ok()
}

pub fn encode_revocation(d: &RevocationDoc) -> Vec<u8> {
    cbor(d)
}

pub fn decode_revocations(b: &[u8]) -> Vec<RevocationDoc> {
    ciborium::from_reader(b).unwrap_or_default()
}

/// Check a bundle file piece by piece (it can be large). Returns its
/// manifest. `platform`: `None` accepts the bundle's own (Pillars pass on
/// bundles for every system).
pub fn verify_bundle_file(path: &std::path::Path, keys: &[HybridPublic], product: &str, platform: Option<&str>, current: &str) -> Result<Manifest, UpdateError> {
    use std::io::{Read, Seek};
    let mut f = std::fs::File::open(path).map_err(|_| UpdateError::Format)?;
    let mut prefix = vec![0u8; 12 + MAX_HEADER];
    let mut n = 0;
    while n < prefix.len() {
        let k = f.read(&mut prefix[n..]).map_err(|_| UpdateError::Format)?;
        if k == 0 {
            break;
        }
        n += k;
    }
    let (h, start) = read_header(&prefix[..n])?;
    let platform = platform.unwrap_or(&h.manifest.platform).to_owned();
    verify_header(&h, keys, product, &platform, current)?;
    f.seek(std::io::SeekFrom::Start(start as u64)).map_err(|_| UpdateError::Format)?;
    let mut buf = vec![0u8; 1 << 20];
    for e in &h.manifest.files {
        let mut hasher = file_hasher();
        let mut left = e.size;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            f.read_exact(&mut buf[..want]).map_err(|_| UpdateError::Tampered)?;
            hasher.update(&buf[..want]);
            left -= want as u64;
        }
        if *hasher.finalize().as_bytes() != e.hash {
            return Err(UpdateError::Tampered);
        }
    }
    if f.read(&mut buf[..1]).map_err(|_| UpdateError::Format)? != 0 {
        return Err(UpdateError::Tampered);
    }
    Ok(h.manifest)
}

/// Release tooling: sign a manifest with one release key.
pub fn sign(signer: &crate::pq::HybridSigner, m: &Manifest) -> ReleaseSig {
    let (ed_sig, dsa_sig) = signer.sign(&cbor(m), CTX);
    ReleaseSig { ed: signer.public().ed, ed_sig, dsa_sig }
}

/// Release tooling: build a bundle from a header and the files' bytes.
pub fn pack(header: &Header, files: &[Vec<u8>]) -> Vec<u8> {
    let h = cbor(header);
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(h.len() as u32).to_le_bytes());
    out.extend_from_slice(&h);
    for f in files {
        out.extend_from_slice(f);
    }
    out
}

/// Read a bundle's header (without checking anything). Returns the header
/// and where the files start.
pub fn read_header(prefix: &[u8]) -> Result<(Header, usize), UpdateError> {
    if prefix.len() < 12 || &prefix[..8] != MAGIC {
        return Err(UpdateError::Format);
    }
    let n = u32::from_le_bytes(prefix[8..12].try_into().unwrap()) as usize;
    if n > MAX_HEADER || prefix.len() < 12 + n {
        return Err(UpdateError::Format);
    }
    let h: Header = ciborium::from_reader(&prefix[12..12 + n]).map_err(|_| UpdateError::Format)?;
    Ok((h, 12 + n))
}

/// Check the header against `keys` (normally [`release_keys`]): signatures,
/// product, platform, safe paths and that it's newer than `current`.
pub fn verify_header(h: &Header, keys: &[HybridPublic], product: &str, platform: &str, current: &str) -> Result<(), UpdateError> {
    let m = &h.manifest;
    if m.product != product || m.platform != platform {
        return Err(UpdateError::Product);
    }
    if m.files.is_empty() || m.files.len() > 200 || !m.files.iter().all(|f| safe_path(&f.path)) || m.notes.chars().count() > 2000 {
        return Err(UpdateError::Format);
    }
    let total: u64 = m.files.iter().map(|f| f.size).sum();
    if total > MAX_BUNDLE {
        return Err(UpdateError::Format);
    }
    let newer = match (parse_version(&m.version), parse_version(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    };
    if !newer {
        return Err(UpdateError::NotNewer);
    }
    if keys.is_empty() {
        return Err(UpdateError::Unsigned);
    }
    let msg = cbor(m);
    let mut good: Vec<[u8; 32]> = Vec::new();
    for s in &h.sigs {
        if good.contains(&s.ed) {
            continue; // one vote per key
        }
        if let Some(k) = keys.iter().find(|k| k.ed == s.ed) {
            if k.verify(&msg, CTX, &s.ed_sig, &s.dsa_sig) {
                good.push(s.ed);
            }
        }
    }
    if good.len() < threshold(keys.len()) {
        return Err(UpdateError::Unsigned);
    }
    Ok(())
}

/// Check a whole bundle in memory; returns the manifest and each file's bytes.
pub fn open_bundle<'a>(bundle: &'a [u8], keys: &[HybridPublic], product: &str, platform: &str, current: &str) -> Result<(Manifest, Vec<&'a [u8]>), UpdateError> {
    let (h, start) = read_header(bundle)?;
    verify_header(&h, keys, product, platform, current)?;
    let mut at = start;
    let mut files = Vec::new();
    for f in &h.manifest.files {
        let end = at.checked_add(f.size as usize).ok_or(UpdateError::Tampered)?;
        let data = bundle.get(at..end).ok_or(UpdateError::Tampered)?;
        if hash_file(data) != f.hash {
            return Err(UpdateError::Tampered);
        }
        files.push(data);
        at = end;
    }
    if at != bundle.len() {
        return Err(UpdateError::Tampered);
    }
    Ok((h.manifest, files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::HybridSigner;

    fn manifest(v: &str, files: &[(&str, &[u8])]) -> Manifest {
        Manifest {
            product: "app".into(),
            platform: "windows-x64".into(),
            version: v.into(),
            notes: "fixes".into(),
            files: files.iter().map(|(p, b)| FileEntry { path: (*p).into(), size: b.len() as u64, hash: hash_file(b) }).collect(),
        }
    }

    #[test]
    fn bundles_need_a_majority_of_release_keys_and_untouched_files() {
        let signers: Vec<HybridSigner> = (1..=3u8).map(|i| HybridSigner::from_secret(&[i; 32])).collect();
        let keys: Vec<HybridPublic> = signers.iter().map(|s| s.public()).collect();
        assert_eq!(parse_keys(&keys.iter().map(key_line).collect::<Vec<_>>().join("\n")), keys);
        let exe = b"new program".to_vec();
        let m = manifest("0.2.0", &[("Sentinel.exe", &exe)]);
        let one = Header { manifest: m.clone(), sigs: vec![sign(&signers[0], &m)] };
        let two = Header { manifest: m.clone(), sigs: vec![sign(&signers[0], &m), sign(&signers[2], &m)] };
        let dup = Header { manifest: m.clone(), sigs: vec![sign(&signers[0], &m), sign(&signers[0], &m)] };
        let b1 = pack(&one, &[exe.clone()]);
        let b2 = pack(&two, &[exe.clone()]);
        let bd = pack(&dup, &[exe.clone()]);
        // 1 of 3 isn't enough, the same key twice isn't either; 2 of 3 is.
        assert_eq!(open_bundle(&b1, &keys, "app", "windows-x64", "0.1.0").unwrap_err(), UpdateError::Unsigned);
        assert_eq!(open_bundle(&bd, &keys, "app", "windows-x64", "0.1.0").unwrap_err(), UpdateError::Unsigned);
        let (got, files) = open_bundle(&b2, &keys, "app", "windows-x64", "0.1.0").unwrap();
        assert_eq!(got.version, "0.2.0");
        assert_eq!(files[0], exe.as_slice());
        // Not newer: refused (no downgrades).
        assert_eq!(open_bundle(&b2, &keys, "app", "windows-x64", "0.2.0").unwrap_err(), UpdateError::NotNewer);
        // A changed byte anywhere in the files: refused.
        let mut bad = b2.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(open_bundle(&bad, &keys, "app", "windows-x64", "0.1.0").unwrap_err(), UpdateError::Tampered);
        // Extra bytes appended: refused.
        let mut long = b2.clone();
        long.push(0);
        assert_eq!(open_bundle(&long, &keys, "app", "windows-x64", "0.1.0").unwrap_err(), UpdateError::Tampered);
        // Changing the manifest (e.g. the notes) breaks the signatures.
        let mut h2 = two.clone();
        h2.manifest.notes = "install me".into();
        assert_eq!(open_bundle(&pack(&h2, &[exe.clone()]), &keys, "app", "windows-x64", "0.1.0").unwrap_err(), UpdateError::Unsigned);
        // Another product: refused.
        assert_eq!(open_bundle(&b2, &keys, "pillar", "windows-x64", "0.1.0").unwrap_err(), UpdateError::Product);
    }

    #[test]
    fn revocations_need_a_majority_too() {
        let signers: Vec<HybridSigner> = (1..=3u8).map(|i| HybridSigner::from_secret(&[i; 32])).collect();
        let keys: Vec<HybridPublic> = signers.iter().map(|s| s.public()).collect();
        let m = manifest("0.2.0", &[("Sentinel.exe", b"x")]);
        let r = Revocation { product: "app".into(), version: "0.2.0".into(), manifest: manifest_id(&m) };
        let one = RevocationDoc { revocation: r.clone(), sigs: vec![sign_revocation(&signers[0], &r)] };
        let two = RevocationDoc { revocation: r.clone(), sigs: vec![sign_revocation(&signers[0], &r), sign_revocation(&signers[1], &r)] };
        assert!(!verify_revocation(&one, &keys));
        assert!(verify_revocation(&two, &keys));
        // A release signature can't be reused as a revocation (separate context).
        let rs = sign(&signers[0], &m);
        let fake = RevocationDoc { revocation: r.clone(), sigs: vec![rs.clone(), rs] };
        assert!(!verify_revocation(&fake, &keys));
        let mut list = Vec::new();
        assert!(merge_revocations(&mut list, vec![one, two.clone(), two], &keys));
        assert_eq!(list.len(), 1);
        assert_eq!(decode_revocations(&encode_revocations(&list)).len(), 1);
    }

    #[test]
    fn paths_stay_inside_the_app_folder() {
        for ok in ["Sentinel.exe", "pillar.exe", "ffmpeg/avutil-60.dll"] {
            assert!(safe_path(ok), "{ok}");
        }
        for bad in ["../evil.exe", "..", "C:/Windows/x.dll", "a\\b.exe", "ffmpeg/../x", "other/x.dll", "/x", "ffmpeg/", ""] {
            assert!(!safe_path(bad), "{bad}");
        }
        assert_eq!(parse_version("0.10.2"), Some((0, 10, 2)));
        assert!(parse_version("1.2").is_none() && parse_version("1.2.3.4").is_none());
        assert!(parse_version("0.10.0") > parse_version("0.9.9"));
    }
}
