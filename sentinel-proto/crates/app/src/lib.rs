//! Sentinel app (Tauri: Windows, Linux, Android). The window is a local UI
//! only: it has no network access of its own (strict CSP, browser background
//! services disabled); every network operation happens in Rust, over Tor.

#[cfg(target_os = "android")]
mod android;
mod core;
mod dialog;
mod disguise;
mod hostproc;
mod torproc;
mod oshardening;

use std::sync::Arc;

use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};

use crate::core::{Core, PostView, StatusView};

type Res<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[tauri::command]
fn status(core: State<'_, Arc<Core>>) -> StatusView {
    core.status()
}

#[tauri::command]
fn create_account(core: State<'_, Arc<Core>>, name: String, pass: String, mode: String) -> Res<()> {
    let pass = zeroize::Zeroizing::new(pass);
    core.create_account(&name, &pass, &mode).map_err(err)
}

#[tauri::command]
fn unlock(window: WebviewWindow, core: State<'_, Arc<Core>>, pass: String) -> Res<()> {
    let pass = zeroize::Zeroizing::new(pass);
    core.unlock(&pass).map_err(err)?;
    // Apply the saved screen-security choice (on until we know otherwise).
    oshardening::set_screen_security(owner(&window), core.screen_security());
    Ok(())
}

/// Copy a Sentinel link (it contains a key) without clipboard history or
/// cloud sync, clearing it after a minute.
#[tauri::command]
fn copy_secret(text: String) -> bool {
    text.starts_with("sentinel://") && text.len() < 1024 && oshardening::copy_secret(text, 60)
}

#[tauri::command]
fn lock(core: State<'_, Arc<Core>>) {
    core.lock()
}

#[tauri::command]
async fn connect(app: AppHandle, core: State<'_, Arc<Core>>) -> Res<()> {
    let core = Arc::clone(&core);
    core.connect(app).await.map_err(err)
}

#[tauri::command]
fn publish(
    app: AppHandle,
    core: State<'_, Arc<Core>>,
    text: String,
    topics: Vec<String>,
    discoverable: bool,
    approved_only: Option<bool>,
    attachments: Vec<String>,
) -> Res<PostView> {
    core.publish(app, &text, &topics, discoverable, approved_only.unwrap_or(false), &attachments).map_err(err)
}

/// Attach a file: raw bytes in the request body (no base64/JSON round trip).
#[tauri::command]
async fn attach_media(core: State<'_, Arc<Core>>, request: tauri::ipc::Request<'_>) -> Res<crate::core::media_app::Attached> {
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err("expected file bytes".into());
    };
    let bytes = bytes.clone();
    let core = Arc::clone(&core);
    core.attach(bytes).await.map_err(err)
}

#[tauri::command]
fn discard_attachment(core: State<'_, Arc<Core>>, id: String) {
    core.discard_attachment(&id)
}

/// Native window handle for dialogs (0 if unavailable).
fn owner(window: &WebviewWindow) -> isize {
    #[cfg(windows)]
    {
        window.hwnd().map(|h| h.0 as isize).unwrap_or(0)
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        0
    }
}

/// Pick files with the native dialog (no recent-files trace) and attach them.
#[tauri::command]
async fn attach_files(window: WebviewWindow, core: State<'_, Arc<Core>>) -> Res<Vec<Result<crate::core::media_app::Attached, String>>> {
    let core = Arc::clone(&core);
    let mut out = Vec::new();
    for path in dialog::pick_files(owner(&window)).await.into_iter().take(4) {
        out.push(core.attach_path(path).await.map_err(err));
    }
    Ok(out)
}

#[tauri::command]
fn rename_attachment(core: State<'_, Arc<Core>>, id: String, name: String) -> Res<String> {
    core.rename_attachment(&id, &name).map_err(err)
}

#[tauri::command]
fn attachment_bytes(core: State<'_, Arc<Core>>, id: String) -> Result<tauri::ipc::Response, String> {
    core.attachment_bytes(&id).map(tauri::ipc::Response::new).map_err(err)
}

/// Decrypted media for display, returned as raw bytes (an ArrayBuffer in JS).
#[tauri::command]
async fn media_bytes(core: State<'_, Arc<Core>>, post_id: String, index: usize) -> Result<tauri::ipc::Response, String> {
    let core = Arc::clone(&core);
    let bytes = core.media_bytes(&post_id, index).await.map_err(err)?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveResult {
    started: bool,
    /// Cloud service that syncs the chosen folder; the download waits for
    /// an explicit confirmation.
    cloud: Option<String>,
}

/// Chosen paths waiting for the user to confirm a cloud-synced folder.
static PENDING_SAVES: std::sync::Mutex<Vec<(String, usize, std::path::PathBuf)>> = std::sync::Mutex::new(Vec::new());

/// Save a file from a post: native save dialog, then a background download.
/// A folder synced to a cloud service needs `confirm_save` first.
#[tauri::command]
async fn save_media(app: AppHandle, window: WebviewWindow, core: State<'_, Arc<Core>>, post_id: String, index: usize) -> Res<SaveResult> {
    let core = Arc::clone(&core);
    let name = core.media_name(&post_id, index).map_err(err)?;
    let Some(path) = dialog::save_file(owner(&window), name).await else { return Ok(SaveResult { started: false, cloud: None }) };
    if let Some(cloud) = dialog::cloud_synced(&path) {
        let mut p = PENDING_SAVES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        p.retain(|(id, i, _)| !(id == &post_id && *i == index));
        p.push((post_id, index, path));
        return Ok(SaveResult { started: false, cloud: Some(cloud.into()) });
    }
    core.save_media(app, post_id, index, path).await.map_err(err)?;
    Ok(SaveResult { started: true, cloud: None })
}

/// The user accepted saving into a cloud-synced folder (or cancelled).
#[tauri::command]
async fn confirm_save(app: AppHandle, core: State<'_, Arc<Core>>, post_id: String, index: usize, go: bool) -> Res<bool> {
    let found = {
        let mut p = PENDING_SAVES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let pos = p.iter().position(|(id, i, _)| id == &post_id && *i == index);
        pos.map(|k| p.remove(k))
    };
    let Some((post_id, index, path)) = found else { return Ok(false) };
    if !go {
        return Ok(false);
    }
    let core = Arc::clone(&core);
    core.save_media(app, post_id, index, path).await.map_err(err)?;
    Ok(true)
}

/* ---------- profile and identity ---------- */

fn shape(s: &str) -> Res<sentinel_core::media::Shape> {
    match s {
        "avatar" => Ok(sentinel_core::media::Shape::Avatar),
        "banner" => Ok(sentinel_core::media::Shape::Banner),
        _ => Err("unknown picture".into()),
    }
}

#[tauri::command]
fn my_profile(core: State<'_, Arc<Core>>) -> Res<crate::core::profile::ProfileView> {
    core.my_profile().map_err(err)
}

#[tauri::command]
fn user_profile(core: State<'_, Arc<Core>>, author: String) -> Res<crate::core::profile::ProfileView> {
    core.user_profile(&author).map_err(err)
}

#[tauri::command]
async fn set_emergency(core: State<'_, Arc<Core>>, current: String, emergency: String, name: String) -> Res<bool> {
    let core = Arc::clone(&core);
    tauri::async_runtime::spawn_blocking(move || core.set_emergency(&current, &emergency, &name)).await.map_err(|e| e.to_string())?.map_err(err)
}

#[tauri::command]
fn circle_view(core: State<'_, Arc<Core>>) -> Res<crate::core::circle::CircleView> {
    core.circle_view().map_err(err)
}

#[tauri::command]
fn request_circle(app: AppHandle, core: State<'_, Arc<Core>>, author: String) -> Res<()> {
    core.request_circle(app, &author).map_err(err)
}

#[tauri::command]
fn approve_circle(app: AppHandle, core: State<'_, Arc<Core>>, author: String) -> Res<()> {
    core.approve_circle(app, &author).map_err(err)
}

#[tauri::command]
fn decline_circle(core: State<'_, Arc<Core>>, author: String) -> Res<()> {
    core.decline_circle(&author).map_err(err)
}

#[tauri::command]
fn remove_circle(app: AppHandle, core: State<'_, Arc<Core>>, author: String) -> Res<usize> {
    core.remove_circle(app, &author).map_err(err)
}

#[tauri::command]
fn set_muted(core: State<'_, Arc<Core>>, author: String, on: bool) -> Res<()> {
    core.set_muted(&author, on).map_err(err)?;
    sync_hide(&core, &author, false, on);
    Ok(())
}

/// Tell my other devices (best effort).
fn sync_hide(core: &Core, author: &str, block: bool, on: bool) {
    if let Some(a) = sentinel_core::social::author_from_text(author) {
        let _ = core.sync_to_devices(sentinel_core::dm::DeviceSync::Hide { author: a, block, on });
    }
}

#[tauri::command]
fn set_blocked(core: State<'_, Arc<Core>>, author: String, on: bool) -> Res<()> {
    core.set_blocked(&author, on).map_err(err)?;
    sync_hide(&core, &author, true, on);
    Ok(())
}

#[tauri::command]
fn hidden_people(core: State<'_, Arc<Core>>) -> Res<Vec<crate::core::profile::HiddenView>> {
    core.hidden_people().map_err(err)
}

#[tauri::command]
fn update_profile(core: State<'_, Arc<Core>>, name: String, bio: String) -> Res<()> {
    core.update_profile(&name, &bio).map_err(err)
}

/// Choose a picture with the native dialog; it is cropped and re-encoded.
#[tauri::command]
async fn pick_profile_image(window: WebviewWindow, core: State<'_, Arc<Core>>, which: String) -> Res<bool> {
    let sh = shape(&which)?;
    let core = Arc::clone(&core);
    let Some(path) = dialog::pick_files(owner(&window)).await.into_iter().next() else { return Ok(false) };
    core.set_profile_image(path, sh).await.map_err(err)?;
    Ok(true)
}

#[tauri::command]
fn remove_profile_image(core: State<'_, Arc<Core>>, which: String) -> Res<()> {
    core.remove_profile_image(shape(&which)?).map_err(err)
}

/// Decrypted profile picture ("me" or an account key).
#[tauri::command]
async fn profile_image(core: State<'_, Arc<Core>>, author: String, which: String) -> Result<tauri::ipc::Response, String> {
    shape(&which)?;
    let core = Arc::clone(&core);
    let bytes = core.media_bytes(&format!("{which}:{author}"), 0).await.map_err(err)?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[tauri::command]
fn safety_number(core: State<'_, Arc<Core>>, author: String) -> Res<String> {
    core.safety_number(&author).map_err(err)
}

/// A strong random passphrase (7 diceware words, ~90 bits).
#[tauri::command]
fn generate_passphrase() -> String {
    sentinel_core::identity::generate_passphrase(7).to_string()
}

#[tauri::command]
fn passphrase_strength(pass: String) -> u32 {
    let pass = zeroize::Zeroizing::new(pass);
    sentinel_core::identity::estimate_bits(&pass)
}

/// Choose a key file with the native dialog (nothing about it is saved).
#[tauri::command]
async fn choose_keyfile(window: WebviewWindow, core: State<'_, Arc<Core>>) -> Res<Option<String>> {
    let Some(path) = dialog::pick_one(owner(&window), "Choose your key file").await else { return Ok(None) };
    core.choose_keyfile(&path).map(Some).map_err(err)
}

/// Make a new key file of random bytes and choose it.
#[tauri::command]
async fn make_keyfile(window: WebviewWindow, core: State<'_, Arc<Core>>) -> Res<Option<String>> {
    let Some(path) = dialog::save_titled(owner(&window), "Save your new key file", "untitled.bin".into()).await else { return Ok(None) };
    let r = core.make_keyfile(&path).map_err(err)?;
    dialog::finish_save(&path).map_err(err)?;
    Ok(Some(r))
}

/// Tests only: choose a key file by path, without the dialog. Refused in
/// release builds.
#[tauri::command]
fn test_choose_keyfile(core: State<'_, Arc<Core>>, path: String) -> Res<String> {
    if !cfg!(debug_assertions) {
        return Err("not available".into());
    }
    core.choose_keyfile(std::path::Path::new(&path)).map_err(err)
}

#[tauri::command]
fn forget_keyfile_choice(core: State<'_, Arc<Core>>) {
    core.forget_keyfile_choice()
}

#[tauri::command]
fn set_keyfile(core: State<'_, Arc<Core>>, current: String, remove: bool) -> Res<bool> {
    let current = zeroize::Zeroizing::new(current);
    core.set_keyfile(&current, remove).map_err(err)
}

#[tauri::command]
fn change_passphrase(core: State<'_, Arc<Core>>, old: String, new: String) -> Res<()> {
    let (old, new) = (zeroize::Zeroizing::new(old), zeroize::Zeroizing::new(new));
    core.change_passphrase(&old, &new).map_err(err)
}

/// Save an encrypted backup. Cloud-synced folders are refused unless
/// `allow_cloud` (the backup can be attacked offline wherever it is stored).
#[tauri::command]
async fn export_backup(window: WebviewWindow, core: State<'_, Arc<Core>>, allow_cloud: bool) -> Res<SaveResult> {
    let Some(path) = dialog::save_file(owner(&window), "sentinel-backup.bin".into()).await else {
        return Ok(SaveResult { started: false, cloud: None });
    };
    if let Some(c) = dialog::cloud_synced(&path) {
        if !allow_cloud {
            return Ok(SaveResult { started: false, cloud: Some(c.into()) });
        }
    }
    core.export_backup(&path).map_err(err)?;
    dialog::finish_save(&path).map_err(err)?;
    Ok(SaveResult { started: true, cloud: None })
}

#[tauri::command]
async fn import_backup(window: WebviewWindow, core: State<'_, Arc<Core>>) -> Res<bool> {
    let Some(path) = dialog::pick_files(owner(&window)).await.into_iter().next() else { return Ok(false) };
    core.import_backup(&path).map_err(err)?;
    Ok(true)
}

/// Erase this account from the device, then quit. Needs the word DELETE.
#[tauri::command]
fn panic_wipe(app: AppHandle, core: State<'_, Arc<Core>>, confirm: String) -> Res<()> {
    if confirm != "DELETE" {
        return Err("Type DELETE to confirm.".into());
    }
    core.panic_wipe().map_err(err)?;
    oshardening::remove_webview_crash_dumps();
    app.exit(0);
    Ok(())
}

#[tauri::command]
fn connection(core: State<'_, Arc<Core>>) -> Res<crate::core::ConnectionView> {
    core.connection().map_err(err)
}

#[tauri::command]
fn set_connection(core: State<'_, Arc<Core>>, mode: String, builtin: String, custom: Option<Vec<String>>) -> Res<()> {
    core.set_connection(&mode, &builtin, custom).map_err(err)
}

#[tauri::command]
fn storage_health(core: State<'_, Arc<Core>>) -> Res<crate::core::audit::StorageHealth> {
    core.storage_health().map_err(err)
}

/// Run one storage check now (result: true = the Archive proved it).
#[tauri::command]
async fn check_storage(core: State<'_, Arc<Core>>) -> Res<bool> {
    let core = Arc::clone(&core);
    core.audit_once(true).await.map_err(err)
}

#[tauri::command]
fn wallet(core: State<'_, Arc<Core>>) -> Res<crate::core::wallet::WalletView> {
    core.wallet().map_err(err)
}

/// Import credits a Pillar earned (a file from `pillar --take-credits`).
#[tauri::command]
async fn import_credits(window: WebviewWindow, core: State<'_, Arc<Core>>) -> Res<Option<usize>> {
    let Some(path) = dialog::pick_one(owner(&window), "Choose your Pillar's credits file").await else { return Ok(None) };
    let core = Arc::clone(&core);
    core.import_credits(&path).await.map(Some).map_err(err)
}

/// Delete messages of one conversation (`ids` empty = all); `theirs`:
/// also ask the other person's app to delete them.
#[tauri::command]
fn delete_dm_messages(app: AppHandle, core: State<'_, Arc<Core>>, author: String, ids: Vec<String>, theirs: bool) -> Res<usize> {
    core.delete_dm_messages(app, &author, ids, theirs).map_err(err)
}

/// Delete messages of one room on my devices (`ids` empty = all).
#[tauri::command]
fn delete_room_messages(app: AppHandle, core: State<'_, Arc<Core>>, id: String, ids: Vec<String>) -> Res<usize> {
    core.delete_room_messages(app, &id, ids).map_err(err)
}

/// Delete every message in every conversation and room.
#[tauri::command]
fn delete_all_messages(app: AppHandle, core: State<'_, Arc<Core>>) -> Res<usize> {
    core.delete_all_messages(app).map_err(err)
}

/// Send credits inside a private message.
#[tauri::command]
fn send_credits(app: AppHandle, core: State<'_, Arc<Core>>, author: String, amount: usize) -> Res<()> {
    core.send_credits(app, &author, amount).map_err(err)
}

#[tauri::command]
async fn pin_quote(core: State<'_, Arc<Core>>, post_id: String, index: usize, months: u32) -> Res<u64> {
    let core = Arc::clone(&core);
    core.pin_quote(&post_id, index, months).await.map_err(err)
}

#[tauri::command]
async fn pin_media(core: State<'_, Arc<Core>>, post_id: String, index: usize, months: u32) -> Res<u64> {
    let core = Arc::clone(&core);
    core.pin_media(&post_id, index, months).await.map_err(err)
}

#[tauri::command]
async fn set_archive(app: AppHandle, core: State<'_, Arc<Core>>, gb: u32) -> Res<()> {
    let core = Arc::clone(&core);
    core.set_archive(app, gb).await.map_err(err)
}

#[tauri::command]
fn set_self_seed(core: State<'_, Arc<Core>>, on: bool) -> Res<()> {
    core.set_self_seed(on).map_err(err)
}

#[tauri::command]
fn cancel_transfer(core: State<'_, Arc<Core>>, key: String) {
    core.cancel_transfer(&key)
}

#[tauri::command]
fn discard_draft(app: AppHandle, core: State<'_, Arc<Core>>, id: String) -> Res<()> {
    core.discard_draft(&id).map_err(err)?;
    let _ = app.emit("timeline", ());
    Ok(())
}

/// Local-only media URL scheme for streaming large audio/video:
/// `smedia://<token>/<post>/<index>` (served as http://smedia.localhost on
/// Windows). Decrypted ranges are produced in memory per request; nothing
/// is cached (no-store).
async fn stream_response(core: Arc<Core>, req: tauri::http::Request<Vec<u8>>) -> tauri::http::Response<Vec<u8>> {
    use tauri::http::Response;
    let status = |code: u16| Response::builder().status(code).header("Cache-Control", "no-store").body(Vec::new()).unwrap();
    let parts: Vec<String> = req.uri().path().trim_start_matches('/').split('/').map(str::to_owned).collect();
    if parts.len() != 3 || !constant_time_eq(parts[0].as_bytes(), core.stream_token.as_bytes()) {
        return status(403);
    }
    let Ok(index) = parts[2].parse::<usize>() else { return status(400) };
    let range = req.headers().get("range").and_then(|v| v.to_str().ok()).map(str::to_owned);
    match core.stream_range(&parts[1], index, range.as_deref()).await {
        Ok((body, start, end, size, mime)) => Response::builder()
            .status(206)
            .header("Content-Type", mime)
            .header("Accept-Ranges", "bytes")
            .header("Content-Range", format!("bytes {start}-{end}/{size}"))
            .header("Cache-Control", "no-store")
            .body(body)
            .unwrap_or_else(|_| status(500)),
        Err(_) => status(404),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[tauri::command]
fn discovered(core: State<'_, Arc<Core>>) -> Res<Vec<PostView>> {
    core.discovered().map_err(err)
}

#[tauri::command]
async fn discover_now(core: State<'_, Arc<Core>>) -> Res<usize> {
    let core = Arc::clone(&core);
    core.discover().await.map_err(err)
}

#[tauri::command]
fn add_topic(core: State<'_, Arc<Core>>, topic: String) -> Res<String> {
    core.add_topic(&topic).map_err(err)
}

#[tauri::command]
fn remove_topic(core: State<'_, Arc<Core>>, topic: String) -> Res<()> {
    core.remove_topic(&topic).map_err(err)
}

#[tauri::command]
fn conversations(core: State<'_, Arc<Core>>) -> Res<Vec<crate::core::dms::ConversationView>> {
    core.conversations().map_err(err)
}

#[tauri::command]
fn thread(core: State<'_, Arc<Core>>, author: String) -> Res<Vec<crate::core::dms::MessageView>> {
    core.thread(&author).map_err(err)
}

#[tauri::command]
fn send_dm(app: AppHandle, core: State<'_, Arc<Core>>, author: String, text: String) -> Res<()> {
    core.send_dm(app, &author, &text).map_err(err)
}

#[tauri::command]
async fn check_messages(core: State<'_, Arc<Core>>) -> Res<usize> {
    let core = Arc::clone(&core);
    core.poll_inbox().await.map_err(err)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_room(app: AppHandle, core: State<'_, Arc<Core>>, name: String, visibility: String, access: String, price: Option<u32>, description: Option<String>, topics: Option<Vec<String>>, approval: Option<bool>) -> Res<String> {
    core.create_room_priced(app, &name, &visibility, &access, price.unwrap_or(0), &description.unwrap_or_default(), &topics.unwrap_or_default(), approval.unwrap_or(false)).map_err(err)
}

#[tauri::command]
fn ask_to_join(app: AppHandle, core: State<'_, Arc<Core>>, link: String, note: Option<String>) -> Res<String> {
    core.ask_to_join(app, &link, &note.unwrap_or_default()).map_err(err)
}

/// Room name in an ask-to-join link (shown before asking).
#[tauri::command]
fn parse_ask_link(link: String) -> Option<String> {
    sentinel_core::room::AskLink::parse(&link).map(|a| a.name)
}

#[tauri::command]
fn join_requests(core: State<'_, Arc<Core>>, id: String) -> Res<Vec<crate::core::rooms::RequestView>> {
    core.join_requests(&id).map_err(err)
}

#[tauri::command]
fn answer_request(app: AppHandle, core: State<'_, Arc<Core>>, id: String, request: String, approve: bool) -> Res<()> {
    core.answer_request(app, &id, &request, approve).map_err(err)
}

/// Release key holders: make a key on a USB stick. Returns (public line,
/// saved on a removable drive).
#[tauri::command]
async fn release_key_create(window: WebviewWindow) -> Res<Option<(String, bool)>> {
    let Some(path) = dialog::save_titled(owner(&window), "Save your release key (on a USB stick)", "release-key.secret".into()).await else { return Ok(None) };
    let line = crate::core::release::create_key(&path).map_err(err)?;
    let removable = crate::core::release::removable(&path);
    dialog::finish_save(&path).map_err(err)?;
    Ok(Some((line, removable)))
}

/// Pick an update file and look inside it (nothing changes).
#[tauri::command]
async fn release_pick_bundle(window: WebviewWindow) -> Res<Option<(String, crate::core::release::BundleView)>> {
    let Some(path) = dialog::pick_one(owner(&window), "Choose the update file").await else { return Ok(None) };
    let v = crate::core::release::inspect(&path, None).map_err(err)?;
    Ok(Some((path.display().to_string(), v)))
}

/// Sign the update file (with the key file picked now) or revoke it.
#[tauri::command]
async fn release_sign(window: WebviewWindow, bundle: String, revoke: bool) -> Res<Option<String>> {
    let Some(key) = dialog::pick_one(owner(&window), "Choose your release key file").await else { return Ok(None) };
    let path = std::path::PathBuf::from(bundle);
    if revoke {
        let (out, n, need, valid) = crate::core::release::revoke(&path, &key).map_err(err)?;
        return Ok(Some(if valid {
            format!("Revocation ready ({n} of {need} signatures): {out}. Put it in a Pillar's update folder; it spreads from there.")
        } else {
            format!("Signed ({n} of {need} signatures needed). Pass {out} to the next key holder.")
        }));
    }
    let v = crate::core::release::sign(&path, &key).map_err(err)?;
    Ok(Some(if v.valid {
        format!("Signed. Version {} now has {} of {} signatures needed and apps will accept it. Hand it out or put it in a Pillar's update folder.", v.version, v.signatures, v.needed)
    } else {
        format!("Signed. Version {} has {} of {} signatures needed: pass the file to the next key holder.", v.version, v.signatures, v.needed)
    }))
}

#[tauri::command]
fn recovery_status(core: State<'_, Arc<Core>>) -> Res<crate::core::recover::RecoveryView> {
    core.recovery_status().map_err(err)
}

#[tauri::command]
fn recovery_words(core: State<'_, Arc<Core>>) -> Res<Vec<String>> {
    core.recovery_words().map_err(err)
}

#[tauri::command]
fn recovery_confirm(core: State<'_, Arc<Core>>) -> Res<()> {
    core.recovery_confirm().map_err(err)
}

#[tauri::command]
fn recovery_create(core: State<'_, Arc<Core>>) -> Res<()> {
    core.recovery_create().map_err(err)
}

#[tauri::command]
async fn move_account(core: State<'_, Arc<Core>>, words: String, taken: bool) -> Res<()> {
    let core = Arc::clone(&core);
    let words = zeroize::Zeroizing::new(words);
    core.move_account(&words, taken).await.map_err(err)
}

#[tauri::command]
async fn recover_account(core: State<'_, Arc<Core>>, words: String, name: String, pass: String, mode: String) -> Res<()> {
    let core = Arc::clone(&core);
    let (words, pass) = (zeroize::Zeroizing::new(words), zeroize::Zeroizing::new(pass));
    tauri::async_runtime::spawn_blocking(move || core.recover_account(&words, &name, &pass, &mode)).await.map_err(err)?.map_err(err)
}

/// Updates: what's installed and what's waiting.
#[tauri::command]
fn update_status(core: State<'_, Arc<Core>>) -> crate::core::updates::UpdateView {
    core.update_view()
}

#[tauri::command]
async fn check_updates(app: AppHandle, core: State<'_, Arc<Core>>) -> Res<bool> {
    let core = Arc::clone(&core);
    core.check_updates(&app).await.map_err(err)
}

/// An update handed over as a file (checked before anything else happens).
#[tauri::command]
async fn update_from_file(window: WebviewWindow, core: State<'_, Arc<Core>>) -> Res<Option<crate::core::updates::ReadyView>> {
    let Some(path) = dialog::pick_one(owner(&window), "Choose the update file").await else { return Ok(None) };
    let core = Arc::clone(&core);
    tauri::async_runtime::spawn_blocking(move || core.take_update_file(&path)).await.map_err(err)?.map(Some).map_err(err)
}

#[tauri::command]
async fn install_update(app: AppHandle, core: State<'_, Arc<Core>>) -> Res<()> {
    let core = Arc::clone(&core);
    tauri::async_runtime::spawn_blocking(move || core.install_update(&app)).await.map_err(err)?.map_err(err)
}

/// Is the calculator disguise on?
#[tauri::command]
fn disguise_state() -> bool {
    disguise::active()
}

/// The calculator's "=" with the code typed: true opens the unlock screen.
#[tauri::command]
fn disguise_check(code: String) -> bool {
    code.len() <= 12 && disguise::check(&code)
}

/// Turn the disguise on (with a code) or off. Only while unlocked.
#[tauri::command]
fn set_disguise(app: AppHandle, core: State<'_, Arc<Core>>, code: Option<String>) -> Res<()> {
    if !core.status().unlocked {
        return Err("Unlock first.".into());
    }
    disguise::set(code.as_deref()).map_err(err)?;
    if let Some(w) = app.get_webview_window("main") {
        disguise::apply_window(&w);
    }
    Ok(())
}

#[tauri::command]
fn leave_room(core: State<'_, Arc<Core>>, id: String) -> Res<()> {
    core.leave_room(&id).map_err(err)
}

#[tauri::command]
fn set_moderator(core: State<'_, Arc<Core>>, id: String, author: String, on: bool) -> Res<()> {
    core.set_moderator(&id, &author, on).map_err(err)
}

#[tauri::command]
fn discovered_rooms(core: State<'_, Arc<Core>>) -> Res<Vec<crate::core::DiscoveredRoomView>> {
    core.discovered_rooms().map_err(err)
}

#[tauri::command]
async fn buy_room(app: AppHandle, core: State<'_, Arc<Core>>, link: String) -> Res<()> {
    let core = Arc::clone(&core);
    core.buy_room(app, &link).await.map_err(err)
}

/// Price and name in a buy link (shown before paying).
#[tauri::command]
fn parse_buy_link(link: String) -> Option<(String, String, u32)> {
    sentinel_core::room::BuyLink::parse(&link).map(|b| (b.name, b.kind, b.price))
}

#[tauri::command]
fn room_members(core: State<'_, Arc<Core>>, id: String) -> Res<Vec<(String, String, bool, bool)>> {
    core.room_members(&id).map_err(err)
}

#[tauri::command]
fn remove_member(core: State<'_, Arc<Core>>, id: String, author: String) -> Res<()> {
    core.remove_member(&id, &author).map_err(err)
}

#[tauri::command]
fn hide_room_message(core: State<'_, Arc<Core>>, id: String, msg_id: String) -> Res<()> {
    core.hide_room_message(&id, &msg_id).map_err(err)
}

#[tauri::command]
fn join_room(app: AppHandle, core: State<'_, Arc<Core>>, link: String) -> Res<String> {
    let id = core.join_room(app, &link).map_err(err)?;
    if sentinel_core::room::RoomLink::parse(&link).is_some() {
        let _ = core.sync_to_devices(sentinel_core::dm::DeviceSync::Room { link });
    }
    Ok(id)
}

#[tauri::command]
fn rooms(core: State<'_, Arc<Core>>) -> Res<Vec<crate::core::rooms::RoomView>> {
    core.rooms().map_err(err)
}

#[tauri::command]
fn room_messages(core: State<'_, Arc<Core>>, id: String) -> Res<Vec<crate::core::rooms::RoomMsgView>> {
    core.room_messages(&id).map_err(err)
}

#[tauri::command]
fn room_link(core: State<'_, Arc<Core>>, id: String) -> Res<String> {
    core.room_link(&id).map_err(err)
}

/// Sentinel Apps: the ones that come with Sentinel.
#[tauri::command]
fn app_catalog(core: State<'_, Arc<Core>>) -> Vec<crate::core::apps::CatalogItem> {
    core.app_catalog()
}

/// Sentinel Apps: choose an app file from its author and check it.
#[tauri::command]
async fn choose_app_file(window: WebviewWindow, core: State<'_, Arc<Core>>) -> Res<Option<crate::core::apps::CatalogItem>> {
    let Some(path) = dialog::pick_one(owner(&window), "Choose a Sentinel app file").await else { return Ok(None) };
    core.inspect_app_file(&path).map(Some).map_err(err)
}

/// Tests only: check an app file by path, without the dialog.
#[tauri::command]
fn test_choose_app_file(core: State<'_, Arc<Core>>, path: String) -> Res<crate::core::apps::CatalogItem> {
    if !cfg!(debug_assertions) {
        return Err("not available".into());
    }
    core.inspect_app_file(std::path::Path::new(&path)).map_err(err)
}

#[tauri::command]
fn room_apps(core: State<'_, Arc<Core>>, id: String) -> Res<Vec<crate::core::apps::AppView>> {
    core.room_apps(&id).map_err(err)
}

#[tauri::command]
fn add_app(app: AppHandle, core: State<'_, Arc<Core>>, id: String, app_id: String) -> Res<()> {
    core.add_app(app, &id, &app_id).map_err(err)
}

#[tauri::command]
fn remove_app(app: AppHandle, core: State<'_, Arc<Core>>, id: String, app_id: String) -> Res<()> {
    core.remove_app(app, &id, &app_id).map_err(err)
}

#[tauri::command]
fn app_action(app: AppHandle, core: State<'_, Arc<Core>>, id: String, app_id: String, action: String, arg: u64, inputs: Vec<(String, String)>) -> Res<()> {
    core.app_action(app, &id, &app_id, &action, arg, inputs).map_err(err)
}

#[tauri::command]
fn send_room(app: AppHandle, core: State<'_, Arc<Core>>, id: String, text: String) -> Res<()> {
    core.send_room(app, &id, &text).map_err(err)
}

#[tauri::command]
async fn refresh_rooms(core: State<'_, Arc<Core>>) -> Res<usize> {
    let core = Arc::clone(&core);
    core.poll_rooms().await.map_err(err)
}

#[tauri::command]
async fn set_hosting(app: AppHandle, core: State<'_, Arc<Core>>, on: bool) -> Res<()> {
    let core = Arc::clone(&core);
    core.set_hosting(app, on).await.map_err(err)
}

#[tauri::command]
fn set_hide_count(core: State<'_, Arc<Core>>, hide: bool) -> Res<()> {
    core.set_hide_count(hide).map_err(err)
}

#[tauri::command]
fn timeline(core: State<'_, Arc<Core>>) -> Res<Vec<PostView>> {
    core.timeline().map_err(err)
}

#[tauri::command]
fn toggle_like(core: State<'_, Arc<Core>>, id: String) -> Res<()> {
    core.toggle_like(&id).map_err(err)
}

#[tauri::command]
fn follow(app: AppHandle, core: State<'_, Arc<Core>>, link: String) -> Res<()> {
    core.follow(app, &link).map_err(err)?;
    let _ = core.sync_to_devices(sentinel_core::dm::DeviceSync::Follow { link });
    Ok(())
}

#[tauri::command]
fn unfollow(core: State<'_, Arc<Core>>, author: String) -> Res<()> {
    core.unfollow(&author).map_err(err)?;
    if let Some(a) = sentinel_core::social::author_from_text(&author) {
        let _ = core.sync_to_devices(sentinel_core::dm::DeviceSync::Unfollow { author: a });
    }
    Ok(())
}

#[tauri::command]
fn devices(core: State<'_, Arc<Core>>) -> Res<Vec<crate::core::devices::DeviceView>> {
    core.devices().map_err(err)
}

#[tauri::command]
fn remove_device(core: State<'_, Arc<Core>>, id: String) -> Res<()> {
    core.remove_device(&id).map_err(err)
}

#[tauri::command]
fn link_view(core: State<'_, Arc<Core>>) -> Res<crate::core::devices::LinkView> {
    core.link_view().map_err(err)
}

#[tauri::command]
fn link_start(core: State<'_, Arc<Core>>) -> Res<String> {
    core.link_start().map_err(err)
}

#[tauri::command]
fn link_cancel(core: State<'_, Arc<Core>>) -> Res<()> {
    core.link_cancel().map_err(err)
}

#[tauri::command]
async fn link_approve(core: State<'_, Arc<Core>>, index: usize) -> Res<()> {
    let core = Arc::clone(&core);
    core.link_approve(index).await.map_err(err)
}

/// New device: ask to join an account (makes this device's own key file
/// with `pass`). Returns the check code to compare.
#[tauri::command]
async fn link_join(core: State<'_, Arc<Core>>, code: String, device: String, pass: String, mode: String) -> Res<String> {
    let core = Arc::clone(&core);
    let pass = zeroize::Zeroizing::new(pass);
    tauri::async_runtime::spawn_blocking(move || core.link_join(&code, &device, &pass, &mode)).await.map_err(err)?.map_err(err)
}

#[tauri::command]
fn link_join_cancel(core: State<'_, Arc<Core>>) -> Res<()> {
    core.link_join_cancel().map_err(err)
}

#[tauri::command]
async fn refresh(core: State<'_, Arc<Core>>) -> Res<usize> {
    let core = Arc::clone(&core);
    core.refresh().await.map_err(err)
}

/// The connection log (memory only; addresses blanked out by Tor).
#[tauri::command]
fn connection_log() -> String {
    sentinel_net::connection_log()
}

/// Copy the connection log (kept out of clipboard history, cleared after
/// 2 minutes).
#[tauri::command]
fn copy_connection_log() -> bool {
    oshardening::copy_secret(sentinel_net::connection_log(), 120)
}

#[tauri::command]
fn add_pillar_hint(core: State<'_, Arc<Core>>, onion: String) -> Res<()> {
    core.add_pillar_hint(&onion).map_err(err)
}

#[tauri::command]
async fn set_pillar(core: State<'_, Arc<Core>>, onion: String) -> Res<()> {
    core.set_pillar(&onion).map_err(err)
}

#[tauri::command]
fn set_privacy(window: WebviewWindow, core: State<'_, Arc<Core>>, key: String, on: bool) -> Res<()> {
    core.set_privacy(&key, on).map_err(err)?;
    if key == "screenSecurity" {
        oshardening::set_screen_security(owner(&window), on);
    }
    Ok(())
}

/// Opt this executable out of Windows Error Reporting. A crash dump can hold
/// anything in memory (including an unlocked key) and WER may queue it for
/// upload to Microsoft, violating I10 (no telemetry / crash reports).
#[cfg(windows)]
fn disable_crash_reporting() {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    };
    use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }
    if let Ok(exe) = std::env::current_exe() {
        let wide: Vec<u16> = exe.as_os_str().encode_wide_nul();
        // FALSE = current user only (no admin rights needed).
        unsafe {
            WerAddExcludedApplication(wide.as_ptr(), 0);
        }
    }
}

#[cfg(windows)]
trait EncodeWideNul {
    fn encode_wide_nul(&self) -> Vec<u16>;
}
#[cfg(windows)]
impl EncodeWideNul for std::ffi::OsStr {
    fn encode_wide_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

/// The system file pickers and clipboard, where Sentinel doesn't have its own.
fn platform_plugins(b: tauri::Builder<tauri::Wry>) -> tauri::Builder<tauri::Wry> {
    #[cfg(not(windows))]
    let b = b.plugin(tauri_plugin_dialog::init()).plugin(tauri_plugin_clipboard_manager::init());
    #[cfg(target_os = "android")]
    let b = b.plugin(android::init());
    b
}

/// Start the app (desktop: from `main`; Android: the system calls it).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(windows)]
    disable_crash_reporting();

    // Started by the app to run the user's Pillar in its own process.
    if std::env::args().nth(1).as_deref() == Some(hostproc::HOST_ARG) {
        hostproc::child_main();
    }
    // Started by the app to run the account's Tor client in its own process.
    if std::env::args().nth(1).as_deref() == Some(torproc::TOR_ARG) {
        torproc::child_main();
    }
    // The connection log (memory only), for "why won't it connect?".
    sentinel_net::enable_memory_log();
    // The browser engine reads settings from these environment variables:
    // anyone with a moment at this computer could set them permanently to
    // open a remote-control port into Sentinel or load a tampered engine.
    // Release builds ignore them (test builds keep them for automated tests).
    // The same settings can be planted as Windows policies. Refuse to open
    // rather than run under them (the person sees exactly where they are).
    #[cfg(all(windows, not(feature = "test-hooks")))]
    {
        let found = oshardening::webview_policy_tampering();
        if !found.is_empty() {
            let text = format!(
                "Sentinel won't open: a Windows policy on this computer changes how its browser engine runs. That could be used to watch or control Sentinel.\n\nIf you didn't set this up, someone else may have. Remove it (or ask someone you trust to), then open Sentinel again:\n\n{}",
                found.join("\n")
            );
            let w: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let t: Vec<u16> = "Sentinel".encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: null-terminated strings; no owner window.
            unsafe { windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(std::ptr::null_mut(), w.as_ptr(), t.as_ptr(), windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONWARNING) };
            std::process::exit(1);
        }
    }
    #[cfg(not(feature = "test-hooks"))]
    for var in [
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
        "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
        "WEBVIEW2_USER_DATA_FOLDER",
        "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
        "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
    ] {
        std::env::remove_var(var);
    }

    crate::core::updates::cleanup_old();
    oshardening::finish_webview_wipe();
    oshardening::remove_webview_crash_dumps();
    // Build the credit proof circuit while the app starts (about a second
    // and a half), so the first payment doesn't wait for it. Not on phones:
    // it takes a few hundred MB, built per payment there instead.
    #[cfg(not(target_os = "android"))]
    std::thread::spawn(sentinel_core::pqcash::warm_up);
    // Diagnostics only when asked for: write panic messages (never state)
    // to the file named by SENTINEL_PANIC_LOG. Off by default.
    if let Some(path) = std::env::var_os("SENTINEL_PANIC_LOG") {
        std::panic::set_hook(Box::new(move |info| {
            let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
            let msg = info.payload().downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| info.payload().downcast_ref::<String>().cloned()).unwrap_or_default();
            let _ = std::fs::write(&path, format!("panic at {loc}: {msg}\n"));
        }));
    }
    platform_plugins(tauri::Builder::default())
        .manage(Arc::new(Core::default()))
        .setup(|app| {
            // Screen security from the first frame: no screenshots, screen
            // recording or Windows Recall of the window.
            dialog::init(app.handle());
            if let Ok(r) = app.path().resource_dir() {
                crate::core::ffmpeg::set_resource_dir(r);
            }
            // Phones: everything lives in the app's private storage.
            #[cfg(mobile)]
            if let Ok(d) = app.path().app_data_dir() {
                let _ = std::fs::create_dir_all(&d);
                std::env::set_var("XDG_DATA_HOME", &d);
                std::env::set_var("HOME", &d);
            }
            if let Some(w) = app.get_webview_window("main") {
                oshardening::set_screen_security(owner(&w), true);
                oshardening::disable_webview_autofill(&w);
                disguise::apply_window(&w);
            }
            std::thread::spawn(disguise::reapply_shortcuts);
            Ok(())
        })
        .register_asynchronous_uri_scheme_protocol("smedia", |ctx, req, responder| {
            let core = Arc::clone(ctx.app_handle().state::<Arc<Core>>().inner());
            tauri::async_runtime::spawn(async move {
                responder.respond(stream_response(core, req).await);
            });
        })
        // Files dropped on the window are attached directly: no dialog, so no
        // trace in the system's recent-files lists.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event {
                let app = window.app_handle().clone();
                let core = Arc::clone(app.state::<Arc<Core>>().inner());
                let paths = paths.clone();
                tauri::async_runtime::spawn(async move {
                    for p in paths.into_iter().take(4) {
                        let r = core.attach_path(p).await.map_err(err);
                        let _ = app.emit("attached", r);
                    }
                });
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            create_account,
            unlock,
            lock,
            connect,
            publish,
            timeline,
            toggle_like,
            follow,
            refresh,
            set_pillar,
            app_catalog,
            choose_app_file,
            test_choose_app_file,
            room_apps,
            add_app,
            remove_app,
            app_action,
            add_pillar_hint,
            connection_log,
            copy_connection_log,
            set_privacy,
            discovered,
            discover_now,
            discovered_rooms,
            add_topic,
            remove_topic,
            set_hide_count,
            set_hosting,
            conversations,
            thread,
            send_dm,
            check_messages,
            create_room,
            join_room,
            rooms,
            room_messages,
            room_link,
            send_room,
            refresh_rooms,
            attach_media,
            attach_files,
            rename_attachment,
            attachment_bytes,
            discard_attachment,
            media_bytes,
            save_media,
            confirm_save,
            copy_secret,
            my_profile,
            user_profile,
            set_emergency,
            circle_view,
            request_circle,
            approve_circle,
            decline_circle,
            remove_circle,
            set_muted,
            set_blocked,
            hidden_people,
            update_profile,
            pick_profile_image,
            remove_profile_image,
            profile_image,
            safety_number,
            generate_passphrase,
            passphrase_strength,
            change_passphrase,
            export_backup,
            import_backup,
            panic_wipe,
            connection,
            set_connection,
            storage_health,
            check_storage,
            wallet,
            send_credits,
            delete_dm_messages,
            delete_room_messages,
            delete_all_messages,
            import_credits,
            pin_quote,
            pin_media,
            buy_room,
            parse_buy_link,
            room_members,
            remove_member,
            ask_to_join,
            parse_ask_link,
            join_requests,
            answer_request,
            set_moderator,
            leave_room,
            disguise_state,
            update_status,
            recovery_status,
            unfollow,
            devices,
            remove_device,
            link_view,
            link_start,
            link_cancel,
            link_approve,
            link_join,
            link_join_cancel,
            release_key_create,
            release_pick_bundle,
            release_sign,
            recovery_words,
            recovery_confirm,
            recovery_create,
            move_account,
            recover_account,
            check_updates,
            update_from_file,
            install_update,
            choose_keyfile,
            make_keyfile,
            forget_keyfile_choice,
            test_choose_keyfile,
            set_keyfile,
            disguise_check,
            set_disguise,
            hide_room_message,
            set_archive,
            set_self_seed,
            cancel_transfer,
            discard_draft
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sentinel");
}
