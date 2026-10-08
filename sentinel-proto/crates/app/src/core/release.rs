//! Release key holders, inside the app (spec section 14): make a release
//! key on a USB stick, look inside an update, sign it, or revoke it. The
//! same as `sentinel-cli release-*`, for people who don't use a terminal.
//! The secret is only ever read from the file the person picks, used for
//! one signature, and wiped from memory.

use std::path::Path;

use anyhow::{bail, Context, Result};
use sentinel_core::pq::HybridSigner;
use sentinel_core::update;
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleView {
    pub product: String,
    pub platform: String,
    pub version: String,
    pub notes: String,
    /// (path, size in bytes, fingerprint) of each file inside.
    pub files: Vec<(String, u64, String)>,
    pub signatures: usize,
    pub needed: usize,
    /// Signed by enough release keys for apps to accept it.
    pub valid: bool,
    /// The key used just now already signed it.
    pub signed_by_me: bool,
}

fn signer(path: &Path) -> Result<HybridSigner> {
    let b = Zeroizing::new(std::fs::read(path).context("couldn't read the key file")?);
    let secret: Zeroizing<[u8; 32]> = Zeroizing::new(b.as_slice().try_into().map_err(|_| anyhow::anyhow!("That isn't a release key file."))?);
    Ok(HybridSigner::from_secret(&secret))
}

/// Is this path on a removable drive (a USB stick)?
pub fn removable(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let Some(root) = path.ancestors().last().map(|r| r.as_os_str().to_owned()) else { return false };
        let mut w: Vec<u16> = root.encode_wide().collect();
        if !w.ends_with(&[b'\\' as u16]) {
            w.push(b'\\' as u16);
        }
        w.push(0);
        // DRIVE_REMOVABLE = 2
        unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(w.as_ptr()) == 2 }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

/// Make a new release key and save its secret at `path`. Returns the public
/// line to send to whoever builds the next release.
pub fn create_key(path: &Path) -> Result<String> {
    if path.exists() {
        bail!("A file is already there; pick a new name.");
    }
    let secret = Zeroizing::new(sentinel_core::random_bytes::<32>());
    std::fs::write(path, secret.as_slice())?;
    Ok(update::key_line(&HybridSigner::from_secret(&secret).public()))
}

/// Look inside an update file (nothing is changed).
pub fn inspect(bundle: &Path, me: Option<&HybridSigner>) -> Result<BundleView> {
    let bytes = std::fs::read(bundle)?;
    let (h, start) = update::read_header(&bytes).map_err(|_| anyhow::anyhow!("That isn't a Sentinel update file."))?;
    let keys = update::release_keys();
    let mut at = start;
    let mut files = Vec::new();
    for f in &h.manifest.files {
        let end = (at + f.size as usize).min(bytes.len());
        let ok = update::hash_file(&bytes[at..end]) == f.hash;
        let fp = data_encoding::HEXLOWER.encode(&f.hash[..8]);
        files.push((f.path.clone(), f.size, if ok { fp } else { "DAMAGED".into() }));
        at = end;
    }
    let valid = update::open_bundle(&bytes, &keys, &h.manifest.product, &h.manifest.platform, "0.0.0").is_ok();
    Ok(BundleView {
        product: h.manifest.product.clone(),
        platform: h.manifest.platform.clone(),
        version: h.manifest.version.clone(),
        notes: h.manifest.notes.clone(),
        files,
        signatures: h.sigs.len(),
        needed: update::threshold(keys.len()),
        valid,
        signed_by_me: me.is_some_and(|m| h.sigs.iter().any(|s| s.ed == m.public().ed)),
    })
}

/// Add my signature to an update file (in place).
pub fn sign(bundle: &Path, key: &Path) -> Result<BundleView> {
    let s = signer(key)?;
    let bytes = std::fs::read(bundle)?;
    let (mut h, start) = update::read_header(&bytes).map_err(|_| anyhow::anyhow!("That isn't a Sentinel update file."))?;
    let me = s.public();
    if !update::release_keys().iter().any(|k| k.ed == me.ed) {
        bail!("This key isn't one of the release keys in this version of Sentinel yet. It counts once a release that lists it is installed.");
    }
    h.sigs.retain(|x| x.ed != me.ed);
    h.sigs.push(update::sign(&s, &h.manifest));
    let mut out = update::pack(&h, &[]);
    out.extend_from_slice(&bytes[start..]);
    let tmp = bundle.with_extension("tmp");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, bundle)?;
    inspect(bundle, Some(&s))
}

/// Sign "never install this update", into `<update file>.revoke` next to it.
/// Returns (file written, signatures, needed, valid).
pub fn revoke(bundle: &Path, key: &Path) -> Result<(String, usize, usize, bool)> {
    let s = signer(key)?;
    let bytes = std::fs::read(bundle)?;
    let (h, _) = update::read_header(&bytes).map_err(|_| anyhow::anyhow!("That isn't a Sentinel update file."))?;
    let r = update::Revocation { product: h.manifest.product.clone(), version: h.manifest.version.clone(), manifest: update::manifest_id(&h.manifest) };
    let out = bundle.with_extension("revoke");
    let mut doc = std::fs::read(&out).ok().and_then(|b| update::decode_revocation(&b)).filter(|d| d.revocation == r).unwrap_or(update::RevocationDoc { revocation: r, sigs: Vec::new() });
    let me = s.public().ed;
    doc.sigs.retain(|x| x.ed != me);
    doc.sigs.push(update::sign_revocation(&s, &doc.revocation));
    std::fs::write(&out, update::encode_revocation(&doc))?;
    let keys = update::release_keys();
    Ok((out.display().to_string(), doc.sigs.len(), update::threshold(keys.len()), update::verify_revocation(&doc, &keys)))
}
