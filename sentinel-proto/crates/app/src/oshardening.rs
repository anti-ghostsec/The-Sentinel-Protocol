//! Operating-system level protections (Windows).
//!
//! - **Screen security**: the window is excluded from screen capture, so
//!   screenshots, screen recording, screen-sharing apps and Windows Recall
//!   (which silently screenshots everything on Copilot+ PCs) see a blank
//!   window instead of decrypted messages. On by default; can be turned off.
//! - **Secret clipboard**: follow links and room invites contain keys.
//!   They are copied with the formats Windows honours to keep an item out
//!   of clipboard history and cloud clipboard sync, and the clipboard is
//!   cleared after a minute if it still holds the secret.
//! - **Crash dumps**: the WebView's crash reports (which may contain
//!   decrypted content) are deleted at startup.

/// Stop the WebView from saving anything typed: no form autofill entries
/// and no password saving in its profile on disk (a seized disk would
/// otherwise keep names, bios or search text typed into the app).
pub fn disable_webview_autofill(window: &tauri::WebviewWindow) {
    #[cfg(windows)]
    {
        let _ = window.with_webview(|wv| unsafe {
            use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings4;
            use windows::core::Interface;
            let Ok(core) = wv.controller().CoreWebView2() else { return };
            let Ok(settings) = core.Settings() else { return };
            if let Ok(s4) = settings.cast::<ICoreWebView2Settings4>() {
                let _ = s4.SetIsGeneralAutofillEnabled(false);
                let _ = s4.SetIsPasswordAutosaveEnabled(false);
            }
        });
    }
    #[cfg(not(windows))]
    let _ = window;
}

/// Exclude (or include) the window from screen capture.
pub fn set_screen_security(hwnd: isize, on: bool) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE};
        SetWindowDisplayAffinity(hwnd as _, if on { WDA_EXCLUDEFROMCAPTURE } else { WDA_NONE });
    }
    #[cfg(not(windows))]
    let _ = (hwnd, on);
}

#[cfg(windows)]
mod clip {
    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    const CF_UNICODETEXT: u32 = 13;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn put(format: u32, bytes: &[u8]) -> bool {
        let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1));
        if h.is_null() {
            return false;
        }
        let p = GlobalLock(h) as *mut u8;
        if p.is_null() {
            GlobalFree(h);
            return false;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        GlobalUnlock(h);
        if SetClipboardData(format, h as HANDLE).is_null() {
            GlobalFree(h);
            return false;
        }
        true
    }

    /// Copy text marked as sensitive. Returns the clipboard sequence number
    /// after the write (to know later whether it was replaced).
    pub fn copy_secret(text: &str) -> Option<u32> {
        unsafe {
            for _ in 0..10 {
                if OpenClipboard(std::ptr::null_mut()) != 0 {
                    EmptyClipboard();
                    let w = wide(text);
                    let ok = put(CF_UNICODETEXT, std::slice::from_raw_parts(w.as_ptr() as *const u8, w.len() * 2));
                    // Keep out of clipboard history and cloud clipboard, and
                    // ask clipboard monitors to ignore it.
                    let zero = 0u32.to_le_bytes();
                    for (name, data) in [
                        ("ExcludeClipboardContentFromMonitorProcessing", &[][..]),
                        ("CanIncludeInClipboardHistory", &zero[..]),
                        ("CanUploadToCloudClipboard", &zero[..]),
                    ] {
                        let f = RegisterClipboardFormatW(wide(name).as_ptr());
                        if f != 0 {
                            put(f, data);
                        }
                    }
                    CloseClipboard();
                    return ok.then(|| GetClipboardSequenceNumber());
                }
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            None
        }
    }

    /// Clear the clipboard if nothing replaced our item since `seq`.
    pub fn clear_if_unchanged(seq: u32) {
        unsafe {
            if GetClipboardSequenceNumber() == seq && OpenClipboard(std::ptr::null_mut()) != 0 {
                EmptyClipboard();
                CloseClipboard();
            }
        }
    }
}

/// Copy a secret (link with a key) and clear it again after `secs`.
pub fn copy_secret(text: String, secs: u64) -> bool {
    #[cfg(windows)]
    {
        let Some(seq) = clip::copy_secret(&text) else { return false };
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            clip::clear_if_unchanged(seq);
        });
        true
    }
    #[cfg(not(windows))]
    {
        use tauri_plugin_clipboard_manager::ClipboardExt;
        let Some(app) = crate::dialog::app() else { return false };
        if app.clipboard().write_text(text.clone()).is_err() {
            return false;
        }
        // Cleared after `secs` unless something else was copied since.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            if app.clipboard().read_text().ok().as_deref() == Some(text.as_str()) {
                let _ = app.clipboard().write_text(String::new());
            }
        });
        true
    }
}

fn webview_root() -> Option<std::path::PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|b| std::path::PathBuf::from(b).join("protocol.sentinel.app"))
}

/// Panic wipe: mark the WebView folder for deletion at the next start.
/// Wipe the WebView's data, and any files a wipe couldn't delete yet
/// (still held open), at the next start before anything opens them.
pub fn schedule_webview_wipe(leftover_files: &[std::path::PathBuf]) {
    if let Some(r) = webview_root() {
        let list: String = leftover_files.iter().map(|p| format!("{}\n", p.display())).collect();
        let _ = std::fs::write(r.join("wipe"), list);
    }
}

/// At startup (before the WebView exists): finish a pending panic wipe.
pub fn finish_webview_wipe() {
    if let Some(r) = webview_root() {
        if r.join("wipe").exists() {
            let _ = std::fs::remove_dir_all(r.join("EBWebView"));
            // Files left by the wipe (only under Sentinel's own data folder).
            let base = std::env::var_os("LOCALAPPDATA").map(|b| std::path::PathBuf::from(b).join("sentinel-proto"));
            for line in std::fs::read_to_string(r.join("wipe")).unwrap_or_default().lines() {
                let p = std::path::PathBuf::from(line);
                if base.as_ref().is_some_and(|b| p.starts_with(b)) {
                    let _ = std::fs::remove_file(&p);
                }
            }
            let _ = std::fs::remove_file(r.join("wipe"));
        }
    }
}

/// Delete WebView crash reports (they can hold decrypted page content).
pub fn remove_webview_crash_dumps() {
    if let Some(base) = std::env::var_os("LOCALAPPDATA") {
        let root = std::path::PathBuf::from(base).join("protocol.sentinel.app").join("EBWebView");
        for sub in ["Crashpad", "Crash Reports"] {
            let _ = std::fs::remove_dir_all(root.join(sub));
        }
    }
}

/// WebView2 policies in the registry that change how Sentinel's browser
/// engine runs (extra arguments such as a remote-control port, another
/// engine, another data folder): anything set for this program, or for
/// every program. Returns where each one is, for the warning.
#[cfg(windows)]
#[cfg_attr(feature = "test-hooks", allow(dead_code))]
pub fn webview_policy_tampering() -> Vec<String> {
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    let exe = std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase())).unwrap_or_default();
    let mut found = Vec::new();
    for (root, root_name) in [(HKEY_CURRENT_USER, "HKEY_CURRENT_USER"), (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE")] {
        for policy in ["AdditionalBrowserArguments", "BrowserExecutableFolder", "UserDataFolder", "ReleaseChannelPreference", "ReleaseChannels", "ChannelSearchKind"] {
            let path = format!(r"SOFTWARE\Policies\Microsoft\Edge\WebView2\{policy}");
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let mut key: HKEY = std::ptr::null_mut();
            // SAFETY: valid null-terminated path and out-pointer.
            if unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
                continue;
            }
            let mut i = 0;
            loop {
                let mut name = [0u16; 512];
                let mut len = name.len() as u32;
                // SAFETY: buffer and length describe `name`; the rest unused.
                let r = unsafe { RegEnumValueW(key, i, name.as_mut_ptr(), &mut len, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
                if r != 0 {
                    break;
                }
                let value = String::from_utf16_lossy(&name[..len as usize]).to_lowercase();
                if value == "*" || value == exe || value.ends_with(&format!(r"\{exe}")) {
                    found.push(format!(r#"{root_name}\{path} (value "{}")"#, String::from_utf16_lossy(&name[..len as usize])));
                }
                i += 1;
            }
            // SAFETY: key was opened above.
            unsafe { RegCloseKey(key) };
        }
    }
    found
}
