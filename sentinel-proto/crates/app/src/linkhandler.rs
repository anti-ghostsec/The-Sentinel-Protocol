//! Opening `sentinel://` links on a computer.
//!
//! Off unless switched on in Settings: being the system's handler for
//! `sentinel://` means an entry in the system's settings that names this
//! app, which someone looking through the computer can find (the calculator
//! disguise doesn't hide it).
//!
//! When it's on, a tapped link starts this program with the link as its
//! argument. The link is left in a file in the app's data folder; if
//! Sentinel is already open, the new process then exits and the open one
//! picks the link up, and otherwise this one starts normally and picks it
//! up itself. Either way the page shows the link and asks before acting.

use std::path::PathBuf;

fn data_dir() -> Option<PathBuf> {
    sentinel_net::data_root(&crate::core::role()).ok()
}

fn pending_path() -> Option<PathBuf> {
    Some(data_dir()?.join("opened-link"))
}

fn acceptable(link: &str) -> bool {
    link.starts_with("sentinel://") && link.len() < 1024 && !link.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// At start: keep a link given as the first argument, and stop here if
/// Sentinel is already running (it will show the link).
pub fn at_start() {
    let Some(dir) = data_dir() else { return };
    let _ = std::fs::create_dir_all(&dir);
    let link = std::env::args().nth(1).filter(|a| acceptable(a));
    if let (Some(link), Some(p)) = (&link, pending_path()) {
        let _ = std::fs::write(p, link);
    }
    // Held for as long as this process lives: how a second one knows.
    let Ok(lock) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("instance.lock")) else { return };
    match lock.try_lock() {
        Ok(()) => std::mem::forget(lock),
        Err(_) if link.is_some() => std::process::exit(0),
        Err(_) => {}
    }
}

/// The link Sentinel was opened with, once.
pub fn take() -> Option<String> {
    let p = pending_path()?;
    let link = std::fs::read_to_string(&p).ok()?;
    let _ = std::fs::remove_file(&p);
    Some(link.trim().to_owned()).filter(|l| acceptable(l))
}

/// The program a link should start: the AppImage itself when running from
/// one (the path inside it changes every start).
fn program() -> Option<String> {
    let p = std::env::var_os("APPIMAGE").map(PathBuf::from).or_else(|| std::env::current_exe().ok())?;
    let s = p.to_str()?.to_owned();
    // Nothing that would need escaping in a .desktop file or a registry
    // command (Windows paths have backslashes, which are fine there).
    let risky: &[char] = if cfg!(windows) { &['"', '%', '\n'] } else { &['"', '`', '$', '\\', '%', '\n'] };
    (!s.contains(risky)).then_some(s)
}

#[cfg(all(unix, not(target_os = "macos")))]
mod os {
    use super::*;

    fn desktop_file() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
        Some(base.join("applications").join("sentinel-link.desktop"))
    }

    pub fn registered() -> bool {
        desktop_file().is_some_and(|f| f.exists())
    }

    pub fn register() -> Result<(), String> {
        let exe = program().ok_or("Sentinel is in a folder whose name can't be used for this.")?;
        let file = desktop_file().ok_or("No home folder to register in.")?;
        let dir = file.parent().ok_or("No home folder to register in.")?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let entry = format!("[Desktop Entry]\nType=Application\nName=The Sentinel Protocol\nExec=\"{exe}\" %u\nMimeType=x-scheme-handler/sentinel;\nNoDisplay=true\nTerminal=false\n");
        std::fs::write(&file, entry).map_err(|e| e.to_string())?;
        // Best effort: most desktops also pick the file up by themselves.
        let _ = std::process::Command::new("xdg-mime").args(["default", "sentinel-link.desktop", "x-scheme-handler/sentinel"]).status();
        let _ = std::process::Command::new("update-desktop-database").arg(dir).status();
        Ok(())
    }

    pub fn unregister() -> Result<(), String> {
        let file = desktop_file().ok_or("No home folder.")?;
        if file.exists() {
            std::fs::remove_file(&file).map_err(|e| e.to_string())?;
        }
        if let Some(dir) = file.parent() {
            let _ = std::process::Command::new("update-desktop-database").arg(dir).status();
        }
        Ok(())
    }
}

#[cfg(windows)]
mod os {
    use super::*;
    use std::os::windows::process::CommandExt;

    const KEY: &str = r"HKCU\Software\Classes\sentinel";
    const NO_WINDOW: u32 = 0x0800_0000;

    fn reg(args: &[&str]) -> bool {
        std::process::Command::new("reg").args(args).creation_flags(NO_WINDOW).output().is_ok_and(|o| o.status.success())
    }

    pub fn registered() -> bool {
        reg(&["query", &format!(r"{KEY}\shell\open\command")])
    }

    pub fn register() -> Result<(), String> {
        let exe = program().ok_or("Sentinel is in a folder whose name can't be used for this.")?;
        let command = format!("\"{exe}\" \"%1\"");
        let ok = reg(&["add", KEY, "/ve", "/d", "URL:Sentinel", "/f"])
            && reg(&["add", KEY, "/v", "URL Protocol", "/d", "", "/f"])
            && reg(&["add", &format!(r"{KEY}\shell\open\command"), "/ve", "/d", &command, "/f"]);
        if ok {
            Ok(())
        } else {
            let _ = unregister();
            Err("Windows didn't accept the setting.".into())
        }
    }

    pub fn unregister() -> Result<(), String> {
        if !registered() || reg(&["delete", KEY, "/f"]) {
            Ok(())
        } else {
            Err("Windows didn't remove the setting.".into())
        }
    }
}

#[cfg(target_os = "macos")]
mod os {
    pub fn registered() -> bool {
        false
    }
    pub fn register() -> Result<(), String> {
        Err("Not available on this system yet.".into())
    }
    pub fn unregister() -> Result<(), String> {
        Ok(())
    }
}

pub use os::{register, registered, unregister};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_sentinel_links_are_kept() {
        assert!(acceptable("sentinel://follow/abc@def#ghi"));
        assert!(!acceptable("https://example.com"));
        assert!(!acceptable("sentinel://follow/a b"));
        assert!(!acceptable("sentinel://follow/a\nb"));
        assert!(!acceptable(&format!("sentinel://{}", "a".repeat(2000))));
        assert!(!acceptable("--some-flag"));
    }
}
