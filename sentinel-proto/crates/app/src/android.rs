//! Phones: files and media through the app's Android side (`MediaPlugin.kt`).
//!
//! - Picking: the system hands out content links, not paths; the picked
//!   files are copied into the app's private cache and used from there.
//! - Saving: written to the private cache, then copied to the chosen place
//!   ([`finish_save`]) and removed.
//! - Updates: a verified APK is handed to the system installer.
//! - Audio and video are rebuilt with the phone's own encoders (Media3) into
//!   a fresh MP4, then cleaned of any metadata left, as on desktops.
//!
//! The private cache is emptied every time the app starts.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::Wry;

static HANDLE: OnceLock<PluginHandle<Wry>> = OnceLock::new();
/// Files being saved: (private path, chosen place).
static SAVES: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());

pub fn init() -> TauriPlugin<Wry> {
    Builder::<Wry>::new("sentinel-media")
        .setup(|_, api| {
            let _ = HANDLE.set(api.register_android_plugin("protocol.sentinel.app", "MediaPlugin")?);
            Ok(())
        })
        .build()
}

#[derive(Serialize)]
struct Pick {
    many: bool,
}
#[derive(Deserialize)]
struct Picked {
    paths: Vec<String>,
}

/// Pick files (copies in the private cache). Blocking.
pub fn pick(many: bool) -> Vec<PathBuf> {
    let Some(h) = HANDLE.get() else { return Vec::new() };
    h.run_mobile_plugin::<Picked>("pickFiles", Pick { many }).map(|p| p.paths.into_iter().map(PathBuf::from).collect()).unwrap_or_default()
}

#[derive(Serialize)]
struct Save {
    name: String,
}
#[derive(Deserialize)]
struct Chosen {
    uri: Option<String>,
    path: Option<String>,
}

/// Choose where to save; returns a private path to write to, then call
/// [`finish_save`]. Blocking.
pub fn save(name: String) -> Option<PathBuf> {
    let c = HANDLE.get()?.run_mobile_plugin::<Chosen>("saveFile", Save { name }).ok()?;
    let (uri, path) = (c.uri?, PathBuf::from(c.path?));
    SAVES.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push((path.clone(), uri));
    Some(path)
}

#[derive(Serialize)]
struct Copy {
    path: String,
    uri: String,
}

/// Move a written file to the place chosen for it. Blocking.
pub fn finish_save(path: &Path) -> anyhow::Result<()> {
    let uri = {
        let mut s = SAVES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(i) = s.iter().position(|(p, _)| p == path) else { return Ok(()) };
        s.remove(i).1
    };
    let h = HANDLE.get().ok_or_else(|| anyhow::anyhow!("saving isn't available"))?;
    let r = h.run_mobile_plugin::<serde_json::Value>("copyToUri", Copy { path: path.to_string_lossy().into(), uri });
    let _ = std::fs::remove_file(path);
    r.map(|_| ()).map_err(|e| anyhow::anyhow!("couldn't save the file: {e}"))
}

#[derive(Serialize)]
struct Rebuild {
    input: String,
    output: String,
}
#[derive(Deserialize)]
struct Out {
    path: String,
}

/// Rebuild audio or video into a fresh MP4 in the private cache. None if
/// the phone can't (the file is then cleaned in place, or refused).
/// Blocking; can take a while for long videos.
pub fn rebuild(input: &Path) -> Option<PathBuf> {
    let h = HANDLE.get()?;
    let out = h.run_mobile_plugin::<Out>("outputPath", serde_json::json!({})).ok()?.path;
    h.run_mobile_plugin::<serde_json::Value>("rebuildMedia", Rebuild { input: input.to_string_lossy().into(), output: out.clone() }).ok()?;
    let out = PathBuf::from(out);
    out.is_file().then_some(out)
}

#[derive(Serialize)]
struct Install {
    path: String,
}

/// Hand a verified APK to the system installer (it asks the person first).
/// Blocking.
pub fn install_apk(apk: &Path) -> anyhow::Result<()> {
    let h = HANDLE.get().ok_or_else(|| anyhow::anyhow!("installing isn't available"))?;
    h.run_mobile_plugin::<serde_json::Value>("installApk", Install { path: apk.to_string_lossy().into() }).map(|_| ()).map_err(|e| anyhow::anyhow!("{e}"))
}
