//! Native open/save dialogs, configured to leave as little trace as possible.
//!
//! Windows normally records files chosen in common dialogs (Recent items,
//! jump lists, per-app "last folder"). These dialogs set
//! `FOS_DONTADDTORECENT`, use a private client GUID and call
//! `ClearClientData` afterwards so the dialog's remembered state for this
//! app is wiped. Dropping files onto the window avoids dialogs entirely.

use std::path::PathBuf;

/// The app handle, for the system pickers on other systems.
#[cfg(not(windows))]
static APP: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

pub fn init(app: &tauri::AppHandle) {
    #[cfg(not(windows))]
    {
        let _ = APP.set(app.clone());
    }
    #[cfg(windows)]
    let _ = app;
}

#[cfg(not(windows))]
pub(crate) fn app() -> Option<&'static tauri::AppHandle> {
    APP.get()
}

#[cfg(target_os = "android")]
fn other_pick(_title: &'static str, many: bool) -> Vec<PathBuf> {
    crate::android::pick(many)
}

#[cfg(target_os = "android")]
fn other_save(_title: &'static str, name: String) -> Option<PathBuf> {
    crate::android::save(name)
}

#[cfg(not(any(windows, target_os = "android")))]
fn other_pick(title: &'static str, many: bool) -> Vec<PathBuf> {
    use tauri_plugin_dialog::DialogExt;
    let Some(app) = APP.get() else { return Vec::new() };
    let d = app.dialog().file().set_title(title);
    let got = if many { d.blocking_pick_files().unwrap_or_default() } else { d.blocking_pick_file().into_iter().collect() };
    got.into_iter().filter_map(|f| f.into_path().ok()).collect()
}

#[cfg(not(any(windows, target_os = "android")))]
fn other_save(title: &'static str, name: String) -> Option<PathBuf> {
    use tauri_plugin_dialog::DialogExt;
    APP.get()?.dialog().file().set_title(title).set_file_name(name).blocking_save_file()?.into_path().ok()
}

#[cfg(windows)]
mod imp {
    use std::path::PathBuf;

    use windows::core::{GUID, HSTRING, PWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
        COINIT_DISABLE_OLE1DDE,
    };
    use windows::Win32::UI::Shell::{
        FileOpenDialog, FileSaveDialog, IFileDialog, IFileOpenDialog, IFileSaveDialog, IShellItem, FOS_ALLOWMULTISELECT,
        FOS_DONTADDTORECENT, FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR, FOS_OVERWRITEPROMPT, FOS_PATHMUSTEXIST,
        FOLDERID_Downloads, KF_FLAG_DEFAULT, SHGetKnownFolderItem, SIGDN_FILESYSPATH,
    };

    /// Private dialog-state identity for Sentinel (state is cleared after use).
    const CLIENT: GUID = GUID::from_u128(0x6a0f_3c1e_5b2d_4e8a_9c71_d4e2_0b6f_a913);

    fn path_of(item: &IShellItem) -> Option<PathBuf> {
        unsafe {
            let p: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
            let s = p.to_string().ok();
            CoTaskMemFree(Some(p.0 as _));
            s.map(PathBuf::from)
        }
    }

    fn prepare(d: &IFileDialog, title: &str, extra: windows::Win32::UI::Shell::FILEOPENDIALOGOPTIONS) -> windows::core::Result<()> {
        unsafe {
            let o = d.GetOptions()?;
            d.SetOptions(o | extra | FOS_DONTADDTORECENT | FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR)?;
            d.SetClientGuid(&CLIENT)?;
            d.SetTitle(&HSTRING::from(title))?;
        }
        Ok(())
    }

    struct Com;
    impl Com {
        fn init() -> Option<Com> {
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).ok().ok().map(|_| Com) }
        }
    }
    impl Drop for Com {
        fn drop(&mut self) {
            unsafe { CoUninitialize() }
        }
    }

    pub fn open(owner: isize, title: &str) -> Vec<PathBuf> {
        let Some(_com) = Com::init() else { return Vec::new() };
        unsafe {
            let Ok(d) = CoCreateInstance::<_, IFileOpenDialog>(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) else { return Vec::new() };
            if prepare(&d.clone().into(), title, FOS_ALLOWMULTISELECT | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST).is_err() {
                return Vec::new();
            }
            let shown = d.Show(Some(HWND(owner as _)));
            let mut out = Vec::new();
            if shown.is_ok() {
                if let Ok(items) = d.GetResults() {
                    for i in 0..items.GetCount().unwrap_or(0) {
                        if let Some(p) = items.GetItemAt(i).ok().as_ref().and_then(path_of) {
                            out.push(p);
                        }
                    }
                }
            }
            let _ = d.ClearClientData();
            out
        }
    }

    pub fn save(owner: isize, title: &str, name: &str) -> Option<PathBuf> {
        let _com = Com::init()?;
        unsafe {
            let d = CoCreateInstance::<_, IFileSaveDialog>(&FileSaveDialog, None, CLSCTX_INPROC_SERVER).ok()?;
            prepare(&d.clone().into(), title, FOS_OVERWRITEPROMPT | FOS_PATHMUSTEXIST).ok()?;
            // Start in Downloads: Documents/Desktop are often synced to the
            // cloud (OneDrive "known folder move"), which would upload the file.
            if let Ok(dl) = SHGetKnownFolderItem::<IShellItem>(&FOLDERID_Downloads, KF_FLAG_DEFAULT, None) {
                let _ = d.SetFolder(&dl);
            }
            let _ = d.SetFileName(&HSTRING::from(name));
            let shown = d.Show(Some(HWND(owner as _)));
            let out = if shown.is_ok() { d.GetResult().ok().as_ref().and_then(path_of) } else { None };
            let _ = d.ClearClientData();
            out
        }
    }
}

/// If `path` is inside a folder that a cloud service syncs, the service's
/// name. Saving there would upload the file to that company.
pub fn cloud_synced(path: &std::path::Path) -> Option<&'static str> {
    let p = path.to_string_lossy().to_lowercase().replace('/', "\\");
    // Folders the sync clients announce through environment variables.
    for var in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
        if let Some(root) = std::env::var_os(var) {
            let root = root.to_string_lossy().to_lowercase();
            if !root.is_empty() && p.starts_with(&root) {
                return Some("OneDrive");
            }
        }
    }
    for (needle, name) in [
        ("\\onedrive", "OneDrive"),
        ("\\dropbox", "Dropbox"),
        ("\\google drive", "Google Drive"),
        ("\\my drive\\", "Google Drive"),
        ("\\icloud drive", "iCloud"),
        ("\\iclouddrive", "iCloud"),
        ("\\box\\", "Box"),
        ("\\mega\\", "MEGA"),
        ("\\pcloud", "pCloud"),
        ("\\nextcloud", "Nextcloud"),
        ("\\sync\\", "Sync.com"),
    ] {
        if p.contains(needle) {
            return Some(name);
        }
    }
    None
}

/// Show the open dialog on a dedicated COM thread; `owner` is the window
/// handle (0 = none). Returns the chosen files (empty if cancelled).
pub async fn pick_files(owner: isize) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || imp::open(owner, "Attach to post")).await.unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        let _ = owner;
        tokio::task::spawn_blocking(|| other_pick("Attach to post", true)).await.unwrap_or_default()
    }
}

/// One file, with its own dialog title (key files, backups).
pub async fn pick_one(owner: isize, title: &'static str) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || imp::open(owner, title)).await.unwrap_or_default().into_iter().next()
    }
    #[cfg(not(windows))]
    {
        let _ = owner;
        tokio::task::spawn_blocking(move || other_pick(title, false)).await.unwrap_or_default().into_iter().next()
    }
}

/// Save with a dialog title of our choosing.
pub async fn save_titled(owner: isize, title: &'static str, name: String) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || imp::save(owner, title, &name)).await.ok().flatten()
    }
    #[cfg(not(windows))]
    {
        let _ = owner;
        tokio::task::spawn_blocking(move || other_save(title, name)).await.ok().flatten()
    }
}

pub async fn save_file(owner: isize, name: String) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || imp::save(owner, "Save", &name)).await.ok().flatten()
    }
    #[cfg(not(windows))]
    {
        let _ = owner;
        tokio::task::spawn_blocking(move || other_save("Save", name)).await.ok().flatten()
    }
}

/// After writing a file to a path from a save dialog: on phones, move it to
/// the place the person chose (it was written to the app's private cache).
pub fn finish_save(path: &std::path::Path) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    return crate::android::finish_save(path);
    #[cfg(not(target_os = "android"))]
    {
        let _ = path;
        Ok(())
    }
}
