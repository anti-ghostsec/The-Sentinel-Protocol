//! Disguise mode (spec section 6): while locked, Sentinel looks and works like a
//! calculator. Typing the person's code and pressing = opens the real unlock
//! screen. The window is titled "Calculator" with a calculator icon, and the
//! Start menu and desktop shortcuts are renamed to match.
//!
//! The setting has to be readable before unlock, so it lives in a small file
//! beside the account (the code only as a salted hash). Wipes keep it: a
//! disguise that vanished after an emergency unlock would be a tell.
//!
//! Honest limits (stated in the app): Task Manager and the installed-apps list
//! still name Sentinel, and anyone who knows about this disguise knows to try
//! it. It hides Sentinel from a glance, not from a search.

use std::path::PathBuf;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

pub const TITLE: &str = "Calculator";
const REAL_TITLE: &str = "The Sentinel Protocol";
const FILE: &str = "look.json";
#[cfg(desktop)]
const CALC_ICON: &[u8] = include_bytes!("../icons/disguise-calculator.png");
#[cfg(desktop)]
const REAL_ICON: &[u8] = include_bytes!("../icons/128x128.png");

#[derive(Serialize, Deserialize, Clone)]
struct Look {
    kind: String,
    salt: [u8; 16],
    hash: [u8; 32],
    /// Shortcut folders where I renamed Sentinel's shortcut (restored when
    /// the disguise is turned off).
    #[serde(default)]
    renamed: Vec<PathBuf>,
}

fn path() -> Option<PathBuf> {
    Some(sentinel_net::data_root(&crate::core::role()).ok()?.join(FILE))
}

fn read() -> Option<Look> {
    serde_json::from_slice(&std::fs::read(path()?).ok()?).ok()
}

fn digest(salt: &[u8; 16], code: &str) -> [u8; 32] {
    let key = blake3::derive_key("sentinel/v0/disguise-code", salt);
    *blake3::keyed_hash(&key, code.as_bytes()).as_bytes()
}

pub fn active() -> bool {
    read().is_some()
}

/// Is this the code that opens the unlock screen?
pub fn check(code: &str) -> bool {
    read().is_some_and(|l| {
        let d = digest(&l.salt, code);
        // Constant-time compare.
        d.iter().zip(l.hash.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    })
}

/// Turn the disguise on with this code (4–12 digits), or off (`None`).
pub fn set(code: Option<&str>) -> Result<()> {
    let p = path().ok_or_else(|| anyhow::anyhow!("no data folder"))?;
    match code {
        Some(c) => {
            if !(4..=12).contains(&c.len()) || !c.bytes().all(|b| b.is_ascii_digit()) {
                bail!("The code must be 4 to 12 digits.");
            }
            let salt = sentinel_core::random_bytes::<16>();
            let renamed = read().map(|l| l.renamed).unwrap_or_default();
            let mut look = Look { kind: "calculator".into(), salt, hash: digest(&salt, c), renamed };
            look.renamed = shortcuts::disguise(&look.renamed);
            write(&p, &serde_json::to_vec(&look)?)
        }
        None => {
            if let Some(l) = read() {
                shortcuts::restore(&l.renamed);
            }
            let _ = std::fs::remove_file(&p);
            Ok(())
        }
    }
}

fn write(p: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, p)?;
    Ok(())
}

/// The raw setting, kept across a wipe (see module docs).
pub fn take_raw() -> Option<Vec<u8>> {
    std::fs::read(path()?).ok()
}

pub fn put_raw(bytes: &[u8]) {
    if let Some(p) = path() {
        let _ = write(&p, bytes);
    }
}

/// At start: re-apply the shortcut names (an update or reinstall puts the
/// real ones back).
pub fn reapply_shortcuts() {
    if let Some(mut l) = read() {
        let renamed = shortcuts::disguise(&l.renamed);
        if renamed != l.renamed {
            l.renamed = renamed;
            if let (Some(p), Ok(b)) = (path(), serde_json::to_vec(&l)) {
                let _ = write(&p, &b);
            }
        }
    }
}

/// Window title and icon to match.
pub fn apply_window(w: &tauri::WebviewWindow) {
    let on = active();
    let _ = w.set_title(if on { TITLE } else { REAL_TITLE });
    // Phones have no window icon (the launcher icon is set by the system).
    #[cfg(desktop)]
    if let Ok(img) = tauri::image::Image::from_bytes(if on { CALC_ICON } else { REAL_ICON }) {
        let _ = w.set_icon(img);
    }
}

#[cfg(windows)]
mod shortcuts {
    use std::path::{Path, PathBuf};

    use windows::core::{Interface, HSTRING, PWSTR};
    use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED};
    use windows::Win32::UI::Shell::{IShellLinkW, SHGetKnownFolderPath, ShellLink, FOLDERID_Desktop, FOLDERID_Programs, KF_FLAG_DEFAULT};

    const REAL: &str = "The Sentinel Protocol.lnk";
    const FAKE: &str = "Calculator.lnk";

    /// Only the real install touches shortcuts (test profiles never do).
    fn enabled() -> bool {
        crate::core::role() == "app"
    }

    fn folders() -> Vec<PathBuf> {
        let mut out = Vec::new();
        for id in [&FOLDERID_Programs, &FOLDERID_Desktop] {
            unsafe {
                if let Ok(p) = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None) {
                    if let Ok(s) = PWSTR(p.0).to_string() {
                        out.push(PathBuf::from(s));
                    }
                    CoTaskMemFree(Some(p.0 as _));
                }
            }
        }
        out
    }

    /// Write a shortcut to this program with the given icon.
    fn make(at: &Path, icon: &str, description: &str) -> bool {
        let Ok(exe) = std::env::current_exe() else { return false };
        unsafe {
            let Ok(link) = CoCreateInstance::<_, IShellLinkW>(&ShellLink, None, CLSCTX_INPROC_SERVER) else { return false };
            let ok = link.SetPath(&HSTRING::from(exe.as_os_str())).is_ok()
                && link.SetWorkingDirectory(&HSTRING::from(exe.parent().unwrap_or(Path::new("")).as_os_str())).is_ok()
                && link.SetIconLocation(&HSTRING::from(icon), 0).is_ok()
                && link.SetDescription(&HSTRING::from(description)).is_ok();
            let Ok(file) = link.cast::<IPersistFile>() else { return false };
            ok && file.Save(&HSTRING::from(at.as_os_str()), true).is_ok()
        }
    }

    /// Run COM work on its own thread (its own apartment).
    fn com<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        std::thread::spawn(move || unsafe {
            let inited = CoInitializeEx(None, COINIT_APARTMENTTHREADED).is_ok();
            let r = f();
            if inited {
                CoUninitialize();
            }
            r
        })
        .join()
        .ok()
    }

    /// Rename Sentinel's shortcuts to "Calculator" (with the system
    /// calculator's icon). Returns every folder now holding a disguised one.
    pub fn disguise(already: &[PathBuf]) -> Vec<PathBuf> {
        if !enabled() {
            return already.to_vec();
        }
        let already = already.to_vec();
        com(move || {
            let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            let icon = format!("{windir}\\System32\\calc.exe");
            let mut out = already.clone();
            for dir in folders() {
                let real = dir.join(REAL);
                if real.exists() && make(&dir.join(FAKE), &icon, "Calculator") {
                    let _ = std::fs::remove_file(&real);
                    if !out.contains(&dir) {
                        out.push(dir);
                    }
                }
            }
            out
        })
        .unwrap_or_default()
    }

    /// Put the real shortcuts back where I renamed them.
    pub fn restore(renamed: &[PathBuf]) {
        if !enabled() {
            return;
        }
        let renamed = renamed.to_vec();
        com(move || {
            let Ok(exe) = std::env::current_exe() else { return };
            let icon = exe.to_string_lossy().into_owned();
            for dir in renamed {
                let fake = dir.join(FAKE);
                if fake.exists() && make(&dir.join(REAL), &icon, "The Sentinel Protocol") {
                    let _ = std::fs::remove_file(&fake);
                }
            }
        });
    }
}

#[cfg(not(windows))]
mod shortcuts {
    use std::path::PathBuf;
    pub fn disguise(already: &[PathBuf]) -> Vec<PathBuf> {
        already.to_vec()
    }
    pub fn restore(_: &[PathBuf]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_hash_is_salted_and_checked() {
        let salt = [1u8; 16];
        assert_eq!(digest(&salt, "1234"), digest(&salt, "1234"));
        assert_ne!(digest(&salt, "1234"), digest(&salt, "1235"));
        assert_ne!(digest(&salt, "1234"), digest(&[2u8; 16], "1234"));
    }
}
