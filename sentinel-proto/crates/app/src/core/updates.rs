//! Updates for the app (spec section 21): signed bundles fetched from
//! Pillars over Tor, or handed over as a file.
//!
//! - Checks run a few minutes after connecting (at a random moment), then
//!   every 6–12 hours, asking the account's Pillar and the seed Pillars.
//! - A bundle is downloaded in 1 MiB pieces (resumable) and checked in full:
//!   release-key signatures (hybrid, post-quantum), newer version, every
//!   file's hash. Only then can it be installed.
//! - Installing swaps the app's files in place (Windows lets a running
//!   program's file be renamed), rolls back if anything fails, and restarts.
//!   On phones the bundle holds the new APK, handed to the system installer
//!   (which asks the person, and only accepts an APK signed with the same
//!   key as the installed app).
//! - The downloaded bundle is kept, and this device's own Pillar (if it runs
//!   one) passes it on: updates spread from Pillar to Pillar.
//! - **Same for everyone:** a release is only taken when at least two
//!   different Pillars carry it, identically, and it's offered only after
//!   three days (unless it was handed over as a file). Revocations signed by
//!   a majority of the release keys are collected from Pillars too.

use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sentinel_core::update::{self, Manifest};
use sentinel_core::wire::{Request, Response};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use super::{request, Core};

#[cfg(not(target_os = "android"))]
pub const PRODUCT: &str = "app";
#[cfg(not(target_os = "android"))]
pub const PLATFORM: &str = "windows-x64";
#[cfg(target_os = "android")]
pub const PRODUCT: &str = "app-android";
#[cfg(target_os = "android")]
pub const PLATFORM: &str = "android";
/// The APK's name inside a phone bundle.
#[cfg(target_os = "android")]
const APK: &str = "sentinel.apk";

pub fn current() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Shared by every profile on this computer (they're the same install).
pub fn dir() -> Option<PathBuf> {
    sentinel_net::data_root("updates").ok()
}

fn ready_path() -> Option<PathBuf> {
    Some(dir()?.join(format!("{PRODUCT}.bin")))
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateView {
    pub current: String,
    /// A verified update waiting to be installed.
    pub ready: Option<ReadyView>,
    /// Download progress (0–1) while fetching.
    pub progress: Option<f32>,
    pub checking: bool,
    pub message: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReadyView {
    pub version: String,
    pub notes: String,
    pub size_mb: u64,
    /// When it may be installed (Unix time): three days after it was first
    /// seen, or right away if it was handed over as a file.
    pub installable_at: u64,
    /// Different Pillars seen carrying this exact release.
    pub sources: usize,
    /// Handed over as a file (not checked against the network).
    pub handed: bool,
}

/// What I know about a release I've seen: when first, which Pillars carry
/// it (as short hashes, not their addresses), and whether it was handed over.
#[derive(Serialize, serde::Deserialize, Clone, Default)]
struct Seen {
    first: u64,
    #[serde(default)]
    sources: Vec<[u8; 8]>,
    #[serde(default)]
    handed: bool,
}

fn seen_path() -> Option<PathBuf> {
    Some(dir()?.join("seen.json"))
}

fn load_seen() -> std::collections::HashMap<String, Seen> {
    seen_path().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_seen(m: &std::collections::HashMap<String, Seen>) {
    if let (Some(p), Ok(b)) = (seen_path(), serde_json::to_vec(m)) {
        let _ = std::fs::write(p, b);
    }
}

/// Note that `pillar` carries release `id` (and when I first saw it).
fn note_seen(id: &[u8; 32], pillar: Option<&str>, handed: bool) -> Seen {
    let mut m = load_seen();
    let e = m.entry(data_encoding::HEXLOWER.encode(id)).or_insert_with(|| Seen { first: super::unix_now(), ..Default::default() });
    if let Some(p) = pillar {
        let h: [u8; 8] = blake3::derive_key("sentinel/v0/update-source", p.as_bytes())[..8].try_into().unwrap();
        if !e.sources.contains(&h) && e.sources.len() < 32 {
            e.sources.push(h);
        }
    }
    e.handed |= handed;
    let out = e.clone();
    if m.len() > 50 {
        let mut by_age: Vec<(String, u64)> = m.iter().map(|(k, v)| (k.clone(), v.first)).collect();
        by_age.sort_by_key(|x| x.1);
        for (k, _) in by_age.into_iter().take(m.len() - 50) {
            m.remove(&k);
        }
    }
    save_seen(&m);
    out
}

/// Revocations collected from Pillars (shared with this device's Pillar).
fn revocations() -> Vec<update::RevocationDoc> {
    let Some(d) = dir() else { return Vec::new() };
    let mut list = Vec::new();
    if let Ok(b) = std::fs::read(d.join("revoked.cbor")) {
        update::merge_revocations(&mut list, update::decode_revocations(&b), &update::release_keys());
    }
    list
}

fn add_revocations(more: Vec<update::RevocationDoc>) {
    let Some(d) = dir() else { return };
    let mut list = revocations();
    if update::merge_revocations(&mut list, more, &update::release_keys()) {
        let _ = std::fs::write(d.join("revoked.cbor"), update::encode_revocations(&list));
    }
}

fn is_revoked(id: &[u8; 32]) -> bool {
    revocations().iter().any(|r| r.revocation.manifest == *id)
}

/// Check a bundle file completely, reading it piece by piece. Returns its
/// manifest and where the files start.
pub fn verify_file(path: &Path) -> Result<(Manifest, u64)> {
    let mut f = std::fs::File::open(path)?;
    let mut prefix = vec![0u8; 12 + update::MAX_HEADER];
    let n = read_up_to(&mut f, &mut prefix)?;
    prefix.truncate(n);
    let (h, start) = update::read_header(&prefix)?;
    update::verify_header(&h, &update::release_keys(), PRODUCT, PLATFORM, current())?;
    f.seek(std::io::SeekFrom::Start(start as u64))?;
    let mut buf = vec![0u8; 1 << 20];
    for e in &h.manifest.files {
        let mut hasher = update::file_hasher();
        let mut left = e.size;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            f.read_exact(&mut buf[..want]).map_err(|_| update::UpdateError::Tampered)?;
            hasher.update(&buf[..want]);
            left -= want as u64;
        }
        if *hasher.finalize().as_bytes() != e.hash {
            return Err(update::UpdateError::Tampered.into());
        }
    }
    if f.read(&mut buf[..1])? != 0 {
        return Err(update::UpdateError::Tampered.into());
    }
    Ok((h.manifest, start as u64))
}

fn read_up_to(f: &mut std::fs::File, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let k = f.read(&mut buf[n..])?;
        if k == 0 {
            break;
        }
        n += k;
    }
    Ok(n)
}

/// The verified update waiting here, if any (header check only; the full
/// check runs again before installing).
pub fn ready() -> Option<ReadyView> {
    let path = ready_path()?;
    let mut f = std::fs::File::open(&path).ok()?;
    let mut prefix = vec![0u8; 12 + update::MAX_HEADER];
    let n = read_up_to(&mut f, &mut prefix).ok()?;
    let (h, _) = update::read_header(&prefix[..n]).ok()?;
    update::verify_header(&h, &update::release_keys(), PRODUCT, PLATFORM, current()).ok()?;
    let id = update::manifest_id(&h.manifest);
    if is_revoked(&id) {
        let _ = std::fs::remove_file(&path); // revoked: never offered, never passed on
        return None;
    }
    let seen = note_seen(&id, None, false);
    let size: u64 = h.manifest.files.iter().map(|f| f.size).sum();
    Some(ReadyView {
        version: h.manifest.version,
        notes: h.manifest.notes,
        size_mb: size.div_ceil(1_000_000),
        installable_at: if seen.handed { seen.first } else { seen.first + update::WAIT_SECS },
        sources: seen.sources.len(),
        handed: seen.handed,
    })
}

/// The release waiting here (its manifest id), from the header only.
fn ready_id() -> Option<[u8; 32]> {
    let mut f = std::fs::File::open(ready_path()?).ok()?;
    let mut prefix = vec![0u8; 12 + update::MAX_HEADER];
    let n = read_up_to(&mut f, &mut prefix).ok()?;
    let (h, _) = update::read_header(&prefix[..n]).ok()?;
    Some(update::manifest_id(&h.manifest))
}

/// Replace the app's files with the bundle's, then start the new version.
/// Anything that fails part-way is put back as it was.
#[cfg(target_os = "android")]
pub fn install(bundle: &Path) -> Result<()> {
    let (m, start) = verify_file(bundle)?;
    let mut f = std::fs::File::open(bundle)?;
    f.seek(std::io::SeekFrom::Start(start))?;
    let mut offset = 0u64;
    for e in &m.files {
        if e.path == APK {
            f.seek(std::io::SeekFrom::Current(offset as i64))?;
            let apk = dir().context("no update folder")?.join(APK);
            let mut out = std::fs::File::create(&apk)?;
            std::io::copy(&mut (&mut f).take(e.size), &mut out)?;
            out.sync_all()?;
            return crate::android::install_apk(&apk);
        }
        offset += e.size;
    }
    bail!("this update has no app for phones in it")
}

#[cfg(not(target_os = "android"))]
pub fn install(bundle: &Path) -> Result<()> {
    let (m, start) = verify_file(bundle)?;
    let exe = std::env::current_exe()?;
    let home = exe.parent().context("no install folder")?.to_path_buf();
    // 1. Write every new file next to its old one.
    let mut f = std::fs::File::open(bundle)?;
    f.seek(std::io::SeekFrom::Start(start))?;
    let mut buf = vec![0u8; 1 << 20];
    let mut staged: Vec<(PathBuf, PathBuf)> = Vec::new();
    let result = (|| -> Result<()> {
        for e in &m.files {
            let dest = home.join(&e.path);
            if let Some(p) = dest.parent() {
                std::fs::create_dir_all(p)?;
            }
            let new = suffixed(&dest, ".new");
            let mut out = std::fs::File::create(&new)?;
            staged.push((new.clone(), dest));
            let mut left = e.size;
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                f.read_exact(&mut buf[..want])?;
                out.write_all(&buf[..want])?;
                left -= want as u64;
            }
            out.sync_all()?;
        }
        Ok(())
    })();
    if let Err(e) = result {
        for (new, _) in &staged {
            let _ = std::fs::remove_file(new);
        }
        return Err(e);
    }
    // 2. Swap: old file aside (works even for the running program), new in.
    let mut swapped: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    for (new, dest) in &staged {
        let old = old_name(dest);
        let _ = std::fs::remove_file(&old);
        let moved_old = if dest.exists() {
            if let Err(e) = std::fs::rename(dest, &old) {
                rollback(&swapped, &staged);
                bail!("couldn't replace {}: {e}", dest.display());
            }
            Some(old)
        } else {
            None
        };
        if let Err(e) = std::fs::rename(new, dest) {
            if let Some(o) = &moved_old {
                let _ = std::fs::rename(o, dest);
            }
            rollback(&swapped, &staged);
            bail!("couldn't install {}: {e}", dest.display());
        }
        swapped.push((dest.clone(), moved_old));
    }
    Ok(())
}

fn suffixed(dest: &Path, ext: &str) -> PathBuf {
    let mut s = dest.as_os_str().to_owned();
    s.push(ext);
    PathBuf::from(s)
}

fn old_name(dest: &Path) -> PathBuf {
    suffixed(dest, ".old")
}

fn rollback(swapped: &[(PathBuf, Option<PathBuf>)], staged: &[(PathBuf, PathBuf)]) {
    for (dest, old) in swapped.iter().rev() {
        let _ = std::fs::remove_file(dest);
        if let Some(o) = old {
            let _ = std::fs::rename(o, dest);
        }
    }
    for (new, _) in staged {
        let _ = std::fs::remove_file(new);
    }
}

/// At start: remove the files an update set aside. The previous version
/// may still be closing, so keep trying for a little while.
pub fn cleanup_old() {
    std::thread::spawn(|| {
        // Half-written new files only on the first pass (an install started
        // later in this run must not lose its staged files).
        for pass in 0..20 {
            if !cleanup_once(pass == 0) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    });
}

/// Returns whether anything is still left.
fn cleanup_once(new_too: bool) -> bool {
    let mut left = false;
    let Some(home) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) else { return false };
    for d in [home.clone(), home.join("ffmpeg"), home.join("resources")] {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if (n.ends_with(".old") || (new_too && n.ends_with(".new"))) && std::fs::remove_file(e.path()).is_err() {
                    left = true;
                }
            }
        }
    }
    left
}

/// Start the freshly installed app (a separate process), so the caller can exit.
pub fn relaunch() -> Result<()> {
    let exe = std::env::current_exe()?;
    // The running image may report its set-aside name; start the real one.
    let name = exe.file_name().map(|n| n.to_string_lossy().trim_end_matches(".old").to_string()).unwrap_or_else(|| "Sentinel.exe".into());
    let target = exe.with_file_name(name);
    let mut cmd = std::process::Command::new(target);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(DETACHED_PROCESS);
    }
    cmd.spawn()?;
    Ok(())
}

impl Core {
    pub fn update_view(&self) -> UpdateView {
        let mut v = self.with(|i| i.update.clone());
        v.current = current().into();
        if v.progress.is_none() {
            v.ready = ready();
        }
        v
    }

    fn set_update(&self, app: &AppHandle, f: impl FnOnce(&mut UpdateView)) {
        self.with(|i| f(&mut i.update));
        let _ = app.emit("update", ());
    }

    /// Background checks: a few minutes after connecting, then every 6–12 h.
    pub(super) async fn run_update_checks(self: Arc<Self>, app: AppHandle) {
        let r = |lo: u64, hi: u64| lo + u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % (hi - lo);
        tokio::time::sleep(Duration::from_secs(r(120, 1200))).await;
        loop {
            let _ = self.check_updates(&app).await;
            tokio::time::sleep(Duration::from_secs(r(6 * 3600, 12 * 3600))).await;
        }
    }

    /// Ask several Pillars what they carry; take a newer release only when
    /// at least two of them carry the very same one, then download it.
    pub async fn check_updates(&self, app: &AppHandle) -> Result<bool> {
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let (_, store) = self.unlocked()?;
        let mut pillars: Vec<String> = store.pillar.iter().cloned().collect();
        for s in sentinel_net::seed_pillars() {
            if !pillars.contains(&s) {
                pillars.push(s);
            }
        }
        // Plus a few others from the directory, at random.
        let mut known = store.known_pillars.clone();
        for _ in 0..known.len() {
            let i = (u32::from_le_bytes(sentinel_core::random_bytes::<4>()) as usize) % known.len();
            let j = (u32::from_le_bytes(sentinel_core::random_bytes::<4>()) as usize) % known.len();
            known.swap(i, j);
        }
        for k in known {
            if pillars.len() >= 6 {
                break;
            }
            if !pillars.contains(&k) {
                pillars.push(k);
            }
        }
        self.set_update(app, |u| {
            u.checking = true;
            u.message = None;
        });
        // release id -> (version, prefix, size, Pillars carrying it)
        let mut offers: std::collections::HashMap<[u8; 32], (String, Vec<u8>, u64, Vec<String>)> = std::collections::HashMap::new();
        let mut reached = 0;
        for p in &pillars {
            let Ok(mut s) = net.connect_hedged(p).await else { continue };
            reached += 1;
            if let Ok(Response::Object(b)) = request(&mut s, &Request::UpdateRevocations).await {
                add_revocations(update::decode_revocations(&b));
            }
            let Ok(Response::Update { prefix, size }) = request(&mut s, &Request::UpdateInfo { product: PRODUCT.into() }).await else { continue };
            let Ok((h, _)) = update::read_header(&prefix) else { continue };
            if update::verify_header(&h, &update::release_keys(), PRODUCT, PLATFORM, current()).is_err() || size > update::MAX_BUNDLE {
                continue; // nothing newer here (or not genuine)
            }
            let id = update::manifest_id(&h.manifest);
            if is_revoked(&id) {
                continue;
            }
            note_seen(&id, Some(p), false);
            offers.entry(id).or_insert_with(|| (h.manifest.version.clone(), prefix.clone(), size, Vec::new())).3.push(p.clone());
        }
        // The newest release carried by enough Pillars.
        let mut best: Option<([u8; 32], (String, Vec<u8>, u64, Vec<String>))> = None;
        let mut lonely: Option<String> = None;
        for (id, o) in offers {
            if o.3.len() < update::MIN_SOURCES {
                lonely = Some(o.0.clone());
                continue;
            }
            let newer = best.as_ref().is_none_or(|(_, b)| update::parse_version(&o.0) > update::parse_version(&b.0));
            if newer {
                best = Some((id, o));
            }
        }
        let mut found = false;
        let mut err = None;
        if let Some((id, (_, prefix, size, sources))) = best {
            let already = ready().is_some() && ready_id() == Some(id);
            if already {
                found = true;
            } else {
                match self.fetch_from(app, &net, &sources, &prefix, size).await {
                    Ok(()) => found = true,
                    Err(e) => err = Some(e.to_string()),
                }
            }
        }
        self.set_update(app, |u| {
            u.checking = false;
            u.progress = None;
            u.message = if found {
                None
            } else if let Some(e) = &err {
                Some(format!("Couldn't download the update right now ({e})."))
            } else if let Some(v) = &lonely {
                Some(format!("Version {v} is on only one Pillar so far. Sentinel waits until several carry the very same update, so everyone gets the same one."))
            } else if reached == 0 {
                Some("Couldn't reach any Pillar right now.".into())
            } else {
                Some("You have the latest version.".into())
            };
        });
        Ok(found)
    }

    /// Download a release from the Pillars that carry it (several circuits,
    /// spread over those Pillars), resumable; checked in full at the end.
    async fn fetch_from(&self, app: &AppHandle, net: &sentinel_net::transport::Net, sources: &[String], prefix: &[u8], size: u64) -> Result<()> {
        let dir = dir().context("no update folder")?;
        let part = dir.join(format!("{PRODUCT}.part"));
        let have_path = dir.join(format!("{PRODUCT}.have"));
        let id_path = dir.join(format!("{PRODUCT}.id"));
        // Pieces of UPDATE_CHUNK bytes; which ones are done is kept beside
        // the download, so it resumes after a restart (same bundle only).
        let chunk = sentinel_core::wire::UPDATE_CHUNK as u64;
        let pieces = size.div_ceil(chunk) as usize;
        let id = blake3::hash(prefix).as_bytes().to_vec();
        let mut have = std::fs::read(&have_path).unwrap_or_default();
        if std::fs::read(&id_path).ok().as_deref() != Some(id.as_slice()) || have.len() != pieces || !part.exists() {
            let f = std::fs::File::create(&part)?;
            f.set_len(size)?;
            have = vec![0u8; pieces];
            std::fs::write(&have_path, &have)?;
            std::fs::write(&id_path, &id)?;
        }
        let todo: std::collections::VecDeque<usize> = (0..pieces).filter(|i| have[*i] == 0).collect();
        let done = std::sync::atomic::AtomicUsize::new(pieces - todo.len());
        let queue = std::sync::Mutex::new(todo);
        let state = std::sync::Mutex::new((std::fs::OpenOptions::new().write(true).open(&part)?, have));
        // Several circuits at once: one Tor circuit is slow for big files.
        let results = {
            let (queue, state, done, have_path) = (&queue, &state, &done, &have_path);
            let worker = |k: usize| async move {
                let pillar = &sources[k % sources.len()];
                let mut conn = None;
                let mut failures = 0;
                loop {
                    let Some(i) = queue.lock().unwrap().pop_front() else { return Ok::<(), anyhow::Error>(()) };
                    if conn.is_none() {
                        conn = net.connect_hedged(pillar).await.ok();
                    }
                    let got = match conn.as_mut() {
                        Some(c) => match request(c, &Request::UpdateChunk { product: PRODUCT.into(), offset: i as u64 * chunk }).await {
                            Ok(Response::Object(b)) if !b.is_empty() => Some(b),
                            _ => None,
                        },
                        None => None,
                    };
                    let Some(b) = got else {
                        queue.lock().unwrap().push_back(i);
                        conn = None;
                        failures += 1;
                        if failures >= 4 {
                            bail!("the Pillar stopped sending the update");
                        }
                        continue;
                    };
                    let want = (size - i as u64 * chunk).min(chunk) as usize;
                    if b.len() < want {
                        queue.lock().unwrap().push_back(i);
                        continue;
                    }
                    {
                        let mut st = state.lock().unwrap();
                        st.0.seek(std::io::SeekFrom::Start(i as u64 * chunk))?;
                        st.0.write_all(&b[..want])?;
                        st.1[i] = 1;
                        let _ = std::fs::write(&have_path, &st.1);
                    }
                    let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    self.set_update(app, |u| u.progress = Some(n as f32 / pieces as f32));
                }
            };
            futures::future::join_all((0..4).map(worker)).await
        };
        if done.load(std::sync::atomic::Ordering::Relaxed) < pieces {
            return Err(results.into_iter().find_map(|r| r.err()).unwrap_or_else(|| anyhow::anyhow!("download incomplete")));
        }
        state.lock().unwrap().0.sync_all()?;
        drop(state);
        let _ = std::fs::remove_file(&have_path);
        let _ = std::fs::remove_file(&id_path);
        // Every byte checked before it counts as ready.
        if let Err(e) = verify_file(&part) {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
        std::fs::rename(&part, dir.join(format!("{PRODUCT}.bin")))?;
        Ok(())
    }

    /// An update handed over as a file: checked, kept (so this device's
    /// Pillar can pass it on), then installed.
    pub fn take_update_file(&self, path: &Path) -> Result<ReadyView> {
        let (m, _) = verify_file(path)?;
        let id = update::manifest_id(&m);
        if is_revoked(&id) {
            bail!("This update was revoked by Sentinel's release keys. Don't install it.");
        }
        let seen = note_seen(&id, None, true);
        let dest = ready_path().context("no update folder")?;
        if path != dest {
            let tmp = dest.with_extension("tmp");
            std::fs::copy(path, &tmp)?;
            std::fs::rename(&tmp, &dest)?;
        }
        let size: u64 = m.files.iter().map(|f| f.size).sum();
        Ok(ReadyView { version: m.version, notes: m.notes, size_mb: size.div_ceil(1_000_000), installable_at: seen.first, sources: seen.sources.len(), handed: true })
    }

    /// Install the waiting update and restart.
    pub fn install_update(&self, app: &AppHandle) -> Result<()> {
        let path = ready_path().context("no update folder")?;
        let r = ready().context("No update is waiting.")?;
        if !r.handed && r.sources < update::MIN_SOURCES {
            bail!("Waiting until several Pillars carry this same update.");
        }
        if super::unix_now() < r.installable_at {
            bail!("This update can be installed after its waiting period (three days after it first appeared), so a bad release can be caught first.");
        }
        install(&path)?;
        // Phones: the system installer takes over (it asks first, then
        // replaces and restarts the app).
        #[cfg(not(target_os = "android"))]
        {
            self.lock();
            relaunch()?;
            app.exit(0);
        }
        #[cfg(target_os = "android")]
        let _ = app;
        Ok(())
    }
}
