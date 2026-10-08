//! Sentinel Apps in rooms (spec §19): adding and removing apps (the room's
//! admin, through the authority log), working out each app's state from
//! the room's messages in the agreed order, drawing its screens, and
//! sending members' commands as room messages.
//!
//! The rules themselves run in `sentinel_core::apps`' sandbox. Everything
//! here only moves bytes in and out of it.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{bail, Context, Result};
use sentinel_core::apps::{self, App, OrderKey, Part, Program, Snapshot, Viewer};
use sentinel_core::apps::place;
use sentinel_core::room::{self, AppCall, RoomBlob};
use sentinel_core::room_auth::{Action, AppRef};
use sentinel_core::social;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use super::rooms::{admin_entry, Queued, RoomMsg, RoomState};
use super::Core;

const B64: data_encoding::Encoding = data_encoding::BASE64;

fn hex(b: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    data_encoding::HEXLOWER.decode(s.as_bytes()).ok()?.try_into().ok()
}

/// A room's apps, as this member keeps them.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct RoomApps {
    /// Apps in the room (from the authority log).
    #[serde(default)]
    pub list: Vec<AppRef>,
    /// Packages of apps that aren't built in (base64), by app id.
    #[serde(default)]
    code: HashMap<String, String>,
    /// Pieces of packages still arriving.
    #[serde(default)]
    parts: HashMap<String, (u16, BTreeMap<u16, String>)>,
    /// The newest snapshot the admin signed, per app.
    #[serde(default)]
    snaps: HashMap<String, Snapshot>,
    /// Admin: the day snapshots were last posted, the member count when the
    /// code was last posted, and the snapshot counter.
    #[serde(default)]
    day: u64,
    #[serde(default)]
    code_members: usize,
    /// Admin: the member count when the last snapshot was posted.
    #[serde(default)]
    snap_members: usize,
    #[serde(default)]
    version: u64,
}

impl RoomApps {
    /// The list from the authority log (anything else about removed apps
    /// is forgotten).
    pub fn set_list(&mut self, apps: Vec<AppRef>) {
        let mut list: Vec<AppRef> = Vec::new();
        for a in apps {
            if list.len() < apps::MAX_APPS && !list.iter().any(|x| x.id == a.id) {
                list.push(AppRef { id: a.id, name: a.name.chars().take(40).collect() });
            }
        }
        let keep: Vec<String> = list.iter().map(|a| hex(&a.id)).collect();
        self.code.retain(|k, _| keep.contains(k));
        self.parts.retain(|k, _| keep.contains(k));
        self.snaps.retain(|k, _| keep.contains(k));
        self.list = list;
    }

    fn has(&self, id: &[u8; 32]) -> bool {
        self.list.iter().any(|a| a.id == *id)
    }

    pub fn accept_snapshot(&mut self, room_id: &[u8; 32], signed: &[u8]) {
        let Some(s) = apps::verify_snapshot(room_id, signed) else { return };
        if !self.has(&s.app) {
            return;
        }
        let k = hex(&s.app);
        if self.snaps.get(&k).is_some_and(|old| old.version >= s.version) {
            return;
        }
        self.snaps.insert(k, s);
    }

    pub fn accept_code(&mut self, room_id: &[u8; 32], signed: &[u8]) {
        let Some(p) = apps::verify_code(room_id, signed) else { return };
        let k = hex(&p.app);
        if !self.has(&p.app) || builtin(&p.app).is_some() || self.code.contains_key(&k) {
            return;
        }
        let entry = self.parts.entry(k.clone()).or_insert((p.total, BTreeMap::new()));
        if entry.0 != p.total {
            *entry = (p.total, BTreeMap::new());
        }
        entry.1.insert(p.part, B64.encode(&p.bytes));
        if entry.1.len() == p.total as usize {
            let mut pkg = Vec::new();
            for v in entry.1.values() {
                pkg.extend(B64.decode(v.as_bytes()).unwrap_or_default());
            }
            self.parts.remove(&k);
            if apps::app_id(&pkg) == p.app && apps::open(&pkg).is_ok() {
                self.code.insert(k, B64.encode(&pkg));
            }
        }
    }

    fn package(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some((pkg, _)) = builtin(id) {
            return Some(pkg.clone());
        }
        B64.decode(self.code.get(&hex(id))?.as_bytes()).ok()
    }
}

fn builtins() -> &'static Vec<(Vec<u8>, App)> {
    static B: OnceLock<Vec<(Vec<u8>, App)>> = OnceLock::new();
    B.get_or_init(apps::builtins)
}

fn builtin(id: &[u8; 32]) -> Option<&'static (Vec<u8>, App)> {
    builtins().iter().find(|(_, a)| a.id == *id)
}

/// Compiled programs (code only, nothing private).
fn program(id: &[u8; 32], package: &[u8]) -> Result<Arc<Program>> {
    static P: OnceLock<Mutex<HashMap<[u8; 32], Arc<Program>>>> = OnceLock::new();
    let cache = P.get_or_init(Default::default);
    if let Some(p) = cache.lock().expect("lock").get(id) {
        return Ok(p.clone());
    }
    let app = apps::open(package)?;
    let p = Arc::new(Program::load(&app.wasm)?);
    cache.lock().expect("lock").insert(*id, p.clone());
    Ok(p)
}

/// Worked-out states, so new commands don't replay everything (memory
/// only; emptied when the app locks).
struct Cached {
    snap: Option<u64>,
    keys: Vec<OrderKey>,
    state: Vec<u8>,
}

fn states() -> &'static Mutex<HashMap<([u8; 32], [u8; 32]), Cached>> {
    static S: OnceLock<Mutex<HashMap<([u8; 32], [u8; 32]), Cached>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// Forget worked-out states (on lock).
pub fn forget_states() {
    states().lock().expect("lock").clear();
}

fn order_key(m: &RoomMsg) -> OrderKey {
    (m.lamport, m.minute, m.session.clone(), m.index)
}

/// Does this command count? (Hidden messages and banned members' messages
/// don't, for anyone — mine included, so I agree with everyone else.)
fn counts(x: &RoomState, m: &RoomMsg) -> bool {
    !x.redacted.iter().any(|(s, i)| *s == m.session && *i == m.index) && !x.inbound.get(&m.session).and_then(|e| e.member).is_some_and(|k| x.banned.contains(&k))
}

/// An app's commands in this room that count, in agreed order.
fn commands<'a>(x: &'a RoomState, app: &AppRef) -> Vec<(OrderKey, &'a RoomMsg)> {
    let mut cmds: Vec<(OrderKey, &RoomMsg)> = x.messages.iter().filter(|m| m.app.as_ref().is_some_and(|c| c.app == app.id) && !m.session.is_empty() && counts(x, m)).map(|m| (order_key(m), m)).collect();
    cmds.sort_by(|a, b| a.0.cmp(&b.0));
    cmds
}

fn apply_all(x: &RoomState, app: &AppRef, prog: &Program, mut state: Vec<u8>, cmds: &[(OrderKey, &RoomMsg)]) -> Vec<u8> {
    for (_, m) in cmds {
        let c = m.app.as_ref().expect("filtered");
        let ctx = apps::Ctx { who: apps::who(&x.room_id, &app.id, &m.author), minute: m.minute };
        if let Ok(next) = prog.apply(&state, &c.cmd, &ctx) {
            state = next;
        }
    }
    state
}

/// An app's state: the newest snapshot (or its start), then every command
/// the snapshot doesn't place, in the room's agreed order.
fn work_out(x: &RoomState, app: &AppRef) -> Result<(Arc<Program>, Vec<u8>)> {
    let pkg = x.apps.package(&app.id).context("This app is still arriving. Try again in a little while.")?;
    let prog = program(&app.id, &pkg)?;
    let snap = x.apps.snaps.get(&hex(&app.id));
    let cmds: Vec<(OrderKey, &RoomMsg)> = commands(x, app).into_iter().filter(|(_, m)| snap.is_none_or(|s| place(&s.cut, &m.session, m.index).is_none())).collect();
    let version = snap.map(|s| s.version);
    let mut cache = states().lock().expect("lock");
    let (state, done) = match cache.get(&(x.room_id, app.id)) {
        Some(c) if c.snap == version && c.keys.len() <= cmds.len() && c.keys.iter().zip(&cmds).all(|(a, b)| *a == b.0) => (c.state.clone(), c.keys.len()),
        _ => (match snap {
            Some(s) => s.state.clone(),
            None => prog.init()?,
        }, 0),
    };
    let state = apply_all(x, app, &prog, state, &cmds[done..]);
    cache.insert((x.room_id, app.id), Cached { snap: version, keys: cmds.iter().map(|c| c.0.clone()).collect(), state: state.clone() });
    Ok((prog, state))
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CatalogItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: u32,
    pub builtin: bool,
    /// Short fingerprint of the author's key (apps from files).
    pub author: String,
    pub can: Vec<String>,
    pub cannot: Vec<String>,
}

fn catalog_item(a: &App) -> CatalogItem {
    let (can, cannot) = apps::permission_lines(&a.manifest);
    CatalogItem {
        id: hex(&a.id),
        name: a.manifest.name.clone(),
        description: a.manifest.description.clone(),
        version: a.manifest.version,
        builtin: a.builtin,
        author: if a.builtin { "Built into Sentinel".into() } else { data_encoding::HEXUPPER.encode(&blake3::hash(&a.author).as_bytes()[..6]).as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ") },
        can,
        cannot,
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppView {
    pub id: String,
    pub name: String,
    pub builtin: bool,
    pub author: String,
    pub description: String,
    pub can: Vec<String>,
    pub cannot: Vec<String>,
    pub parts: Vec<Part>,
    pub error: Option<String>,
}

/// An app file someone chose, waiting to be added (memory only).
fn pending() -> &'static Mutex<Option<Vec<u8>>> {
    static P: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
    P.get_or_init(Default::default)
}

/// Show members by name, not by their app nickname.
fn name_members(parts: Vec<Part>, names: &HashMap<String, String>) -> Vec<Part> {
    parts
        .into_iter()
        .map(|p| match p {
            Part::Member(w) => Part::Member(names.get(&w).cloned().unwrap_or_else(|| "A member".into())),
            Part::Row(c) => Part::Row(name_members(c, names)),
            Part::Card(c) => Part::Card(name_members(c, names)),
            other => other,
        })
        .collect()
}

impl Core {
    /// Apps that come with Sentinel.
    pub fn app_catalog(&self) -> Vec<CatalogItem> {
        builtins().iter().map(|(_, a)| catalog_item(a)).collect()
    }

    /// Check an app file (from its author) before adding it to a room.
    pub fn inspect_app_file(&self, path: &std::path::Path) -> Result<CatalogItem> {
        let len = std::fs::metadata(path)?.len();
        if len as usize > apps::MAX_PACKAGE {
            bail!("That file is too large to be a Sentinel app.");
        }
        let bytes = std::fs::read(path)?;
        let app = apps::open(&bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
        *pending().lock().expect("lock") = Some(bytes);
        Ok(catalog_item(&app))
    }

    pub fn room_apps(&self, id: &str) -> Result<Vec<AppView>> {
        let (key, store) = self.unlocked()?;
        let x = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?;
        let me = social::author_text(&key.verifying_key().to_bytes());
        let mut out = Vec::new();
        for app in &x.apps.list {
            let mut names: HashMap<String, String> = x.members.values().map(|m| (apps::who(&x.room_id, &app.id, &m.author), m.name.clone())).collect();
            names.insert(apps::who(&x.room_id, &app.id, &me), "You".into());
            let info = x.apps.package(&app.id).and_then(|p| apps::open(&p).ok()).map(|mut a| {
                a.builtin = builtin(&app.id).is_some();
                catalog_item(&a)
            });
            let (parts, error) = match work_out(x, app) {
                Ok((prog, state)) => match prog.view(&state, &Viewer { who: apps::who(&x.room_id, &app.id, &me) }) {
                    Ok(p) => (name_members(p, &names), None),
                    Err(e) => (Vec::new(), Some(format!("This app couldn't show its screen ({e})."))),
                },
                Err(e) => (Vec::new(), Some(e.to_string())),
            };
            let info = info.unwrap_or(CatalogItem { id: hex(&app.id), name: app.name.clone(), description: String::new(), version: 0, builtin: false, author: String::new(), can: Vec::new(), cannot: Vec::new() });
            out.push(AppView { id: info.id, name: app.name.clone(), builtin: info.builtin, author: info.author, description: info.description, can: info.can, cannot: info.cannot, parts, error });
        }
        Ok(out)
    }

    /// Room admin: add an app (built in, or the file just checked).
    pub fn add_app(self: &Arc<Self>, handle: AppHandle, id: &str, app_id: &str) -> Result<()> {
        let app_id = unhex(app_id).context("unknown app")?;
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?;
        if r.admin.is_none() {
            bail!("Only the person who made the room can add apps.");
        }
        if r.apps.has(&app_id) {
            bail!("This room already has that app.");
        }
        if r.apps.list.len() >= apps::MAX_APPS {
            bail!("A room can have at most {} apps.", apps::MAX_APPS);
        }
        let (package, app) = match builtin(&app_id) {
            Some((p, a)) => (p.clone(), a.clone()),
            None => {
                let p = pending().lock().expect("lock").clone().filter(|p| apps::app_id(p) == app_id).context("Choose the app file again.")?;
                let a = apps::open(&p).map_err(|e| anyhow::anyhow!("{e}"))?;
                (p, a)
            }
        };
        self.update(|s| {
            let Some(x) = s.rooms.iter_mut().find(|x| hex(&x.room_id) == id) else { return };
            x.apps.list.push(AppRef { id: app_id, name: app.manifest.name.chars().take(40).collect() });
            let list = x.apps.list.clone();
            if let Some(b) = admin_entry(x, Action::Apps { apps: list }) {
                x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
            }
            if !app.builtin {
                x.apps.code.insert(hex(&app_id), B64.encode(&package));
                queue_code(x, &package);
            }
        })?;
        *pending().lock().expect("lock") = None;
        self.flush_soon(handle, r.room_id);
        Ok(())
    }

    /// Room admin: take an app out of the room.
    pub fn remove_app(self: &Arc<Self>, handle: AppHandle, id: &str, app_id: &str) -> Result<()> {
        let app_id = unhex(app_id).context("unknown app")?;
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?;
        if r.admin.is_none() {
            bail!("Only the person who made the room can remove apps.");
        }
        self.update(|s| {
            let Some(x) = s.rooms.iter_mut().find(|x| hex(&x.room_id) == id) else { return };
            let list: Vec<AppRef> = x.apps.list.iter().filter(|a| a.id != app_id).cloned().collect();
            x.apps.set_list(list.clone());
            if let Some(b) = admin_entry(x, Action::Apps { apps: list }) {
                x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
            }
        })?;
        self.flush_soon(handle, r.room_id);
        Ok(())
    }

    /// A member pressed a button in an app: checked here first (so a
    /// refused command isn't sent), then sent as a room message.
    pub fn app_action(self: &Arc<Self>, handle: AppHandle, id: &str, app_id: &str, action: &str, arg: u64, inputs: Vec<(String, String)>) -> Result<()> {
        let app_id = unhex(app_id).context("unknown app")?;
        let (key, store) = self.unlocked()?;
        let x = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?;
        if x.waiting {
            bail!("You can use the room's apps once you've been let in.");
        }
        let app = x.apps.list.iter().find(|a| a.id == app_id).context("This app isn't in the room any more.")?;
        let cmd = apps::command(action, arg, inputs).context("That's too long.")?;
        let (prog, state) = work_out(x, app)?;
        let me = social::author_text(&key.verifying_key().to_bytes());
        let ctx = apps::Ctx { who: apps::who(&x.room_id, &app_id, &me), minute: social::coarse_minute() };
        if prog.apply(&state, &cmd, &ctx).is_err() {
            bail!("The app didn't accept that. Check what you typed and try again.");
        }
        self.send_room_payload(handle, id, String::new(), Some(AppCall { app: app_id, cmd }))
    }

    /// Room admin, once a day: a signed snapshot of each app's state (so
    /// late joiners agree with everyone), and the code of apps that aren't
    /// built in again when new members have arrived.
    pub(super) fn app_upkeep(&self, room_id: &[u8; 32]) -> Result<()> {
        let (_, store) = self.unlocked()?;
        let Some(x) = store.rooms.iter().find(|r| r.room_id == *room_id) else { return Ok(()) };
        let Some(admin) = x.admin else { return Ok(()) };
        if x.apps.list.is_empty() || x.waiting {
            return Ok(());
        }
        let today = sentinel_core::dm::today();
        let mut snaps = Vec::new();
        // Daily, and whenever someone new arrives (they can't read earlier
        // messages, so they start from this).
        if x.apps.day != today || x.members.len() != x.apps.snap_members {
            let held: Vec<(String, u32)> = x.messages.iter().filter(|m| !m.session.is_empty()).map(|m| (m.session.clone(), m.index)).collect();
            for (n, app) in x.apps.list.iter().enumerate() {
                let Some(pkg) = x.apps.package(&app.id) else { continue };
                let Ok(prog) = program(&app.id, &pkg) else { continue };
                let prev = x.apps.snaps.get(&hex(&app.id));
                let old_cut = prev.map(|s| s.cut.clone()).unwrap_or_default();
                let start = match prev {
                    Some(s) => s.state.clone(),
                    None => match prog.init() {
                        Ok(s) => s,
                        Err(_) => continue,
                    },
                };
                let cut = apps::extend_cut(&old_cut, &held);
                // Exactly the commands the new cut adds.
                let add: Vec<(OrderKey, &RoomMsg)> = commands(x, app).into_iter().filter(|(_, m)| place(&old_cut, &m.session, m.index).is_none() && place(&cut, &m.session, m.index) == Some(true)).collect();
                let state = apply_all(x, app, &prog, start, &add);
                snaps.push(Snapshot { room_id: *room_id, app: app.id, version: x.apps.version + 1 + n as u64, cut, state });
            }
        }
        let repost_code = x.members.len() != x.apps.code_members;
        if snaps.is_empty() && !repost_code {
            return Ok(());
        }
        self.update(|s| {
            let Some(x) = s.rooms.iter_mut().find(|r| r.room_id == *room_id) else { return };
            if !snaps.is_empty() {
                x.apps.day = today;
                x.apps.snap_members = x.members.len();
                x.apps.version += snaps.len() as u64 + 1;
            }
            for snap in snaps {
                let signed = apps::sign_snapshot(&admin, &snap);
                x.apps.snaps.insert(hex(&snap.app), snap);
                x.queue.push(Queued { sealed: room::seal_blob(&x.secret, &RoomBlob::AppState { signed }), nonce: 0, secret: Some(x.secret) });
            }
            if repost_code {
                for app in x.apps.list.clone() {
                    if builtin(&app.id).is_none() {
                        if let Some(p) = x.apps.package(&app.id) {
                            queue_code(x, &p);
                        }
                    }
                }
                x.apps.code_members = x.members.len();
            }
        })
    }

    fn flush_soon(self: &Arc<Self>, handle: AppHandle, room_id: [u8; 32]) {
        let core = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let _ = core.flush_room_queue(&room_id).await;
            let _ = handle.emit("rooms", ());
        });
    }
}

/// Admin: queue an app's package for the room, in signed pieces.
fn queue_code(x: &mut RoomState, package: &[u8]) {
    let Some(admin) = x.admin else { return };
    for signed in apps::sign_code(&admin, &x.room_id, package) {
        x.queue.push(Queued { sealed: room::seal_blob(&x.secret, &RoomBlob::AppCode { signed }), nonce: 0, secret: Some(x.secret) });
    }
}
