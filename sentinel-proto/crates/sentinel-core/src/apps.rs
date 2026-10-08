//! Sentinel Apps (spec §19): small programs that add features to a room —
//! contracts without a blockchain.
//!
//! - **Package**: a manifest (name, version, description, permissions) and
//!   WebAssembly code, signed by its author. Its identity is the hash of the
//!   whole package, so everyone in a room runs exactly the same code.
//! - **Sandbox**: the code runs in an interpreter (wasmi) with Wasm's
//!   deterministic profile, a hard limit on computation (fuel) and memory,
//!   and **no imports at all**: no network, files, clock or randomness. A
//!   fresh instance runs every call, so nothing carries over between calls
//!   except the state everyone agrees on.
//! - **Agreement**: commands are room messages. Every member applies them
//!   in the room's agreed order (Lamport counter, then minute, session,
//!   index), starting from the latest *snapshot* the room's admin signed
//!   (or the app's starting state), so all members reach the same state —
//!   late joiners included. A snapshot names exactly which commands it
//!   holds (per sender stream, every message up to an index), so a
//!   command that arrives late is applied after it, never lost.
//! - **Screens**: apps describe screens with a fixed set of parts
//!   ([`Part`]); Sentinel draws them, always framed with the app's name.
//! - **Pseudonyms**: an app sees members only as a room-and-app-only
//!   pseudonym, never their account.

use serde::{Deserialize, Serialize};
use wasmi::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

pub use sentinel_app_sdk::{Cmd, Ctx, Part, Viewer};

/// Largest package (code and manifest).
pub const MAX_PACKAGE: usize = 384 * 1024;
/// Largest state an app may keep (it must fit in a signed snapshot).
pub const MAX_STATE: usize = 48 * 1024;
/// Largest command a member can send.
pub const MAX_CMD: usize = 2048;
/// Largest screen description.
const MAX_VIEW: usize = 64 * 1024;
/// Computation per call (wasmi fuel units, roughly one per instruction).
const FUEL: u64 = 30_000_000;
/// Memory per call.
const MEMORY: usize = 16 << 20;
/// Most apps in one room.
pub const MAX_APPS: usize = 8;
/// Code is carried to members in pieces this big (room blobs are ≤ 64 KB).
pub const CODE_PART: usize = 24 * 1024;

/// What an app may do, beyond keeping its own state in its room and
/// showing screens (which every app can).
pub const KNOWN_PERMISSIONS: &[&str] = &[];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub name: String,
    pub version: u32,
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Package {
    manifest: Manifest,
    #[serde(with = "serde_bytes_compat")]
    wasm: Vec<u8>,
    author: [u8; 32],
    #[serde(with = "serde_bytes_compat")]
    sig: Vec<u8>,
}

/// Byte strings as CBOR bytes (not arrays of numbers).
pub(crate) mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Ok(ciborium::Value::deserialize(d)?.into_bytes().map_err(|_| serde::de::Error::custom("expected bytes"))?)
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AppError {
    #[error("this isn't a Sentinel app")]
    NotAnApp,
    #[error("the app's signature doesn't match its contents")]
    BadSignature,
    #[error("the app is too large")]
    TooLarge,
    #[error("the app needs a permission this version of Sentinel doesn't have: {0}")]
    UnknownPermission(String),
    #[error("the app's code isn't allowed: {0}")]
    BadCode(String),
    #[error("the app stopped: {0}")]
    Trap(String),
    #[error("the app refused that")]
    Refused,
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

fn signed_message(manifest: &Manifest, wasm: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("sentinel/v1/app-package");
    let m = cbor(manifest);
    h.update(&(m.len() as u64).to_le_bytes());
    h.update(&m);
    h.update(wasm);
    *h.finalize().as_bytes()
}

/// Make a signed package (app authors; `sentinel-cli app-pack`).
pub fn pack(author_seed: &[u8; 32], manifest: Manifest, wasm: Vec<u8>) -> Result<Vec<u8>, AppError> {
    use ed25519_dalek::Signer;
    let k = ed25519_dalek::SigningKey::from_bytes(author_seed);
    let sig = k.sign(&signed_message(&manifest, &wasm)).to_bytes().to_vec();
    let bytes = cbor(&Package { manifest, wasm, author: k.verifying_key().to_bytes(), sig });
    open(&bytes)?;
    Ok(bytes)
}

/// A checked package.
#[derive(Clone, Debug)]
pub struct App {
    pub id: [u8; 32],
    pub manifest: Manifest,
    pub author: [u8; 32],
    pub wasm: Vec<u8>,
    pub builtin: bool,
}

/// An app's identity: the hash of its whole package.
pub fn app_id(package: &[u8]) -> [u8; 32] {
    blake3::derive_key("sentinel/v1/app-id", package)
}

/// Check a package: signature, size, permissions and code (no imports,
/// the right exports, valid for the sandbox).
pub fn open(package: &[u8]) -> Result<App, AppError> {
    if package.len() > MAX_PACKAGE {
        return Err(AppError::TooLarge);
    }
    let p: Package = ciborium::from_reader(package).map_err(|_| AppError::NotAnApp)?;
    let m = &p.manifest;
    if m.name.trim().is_empty() || m.name.chars().count() > 40 || m.description.chars().count() > 300 {
        return Err(AppError::NotAnApp);
    }
    if let Some(unknown) = m.permissions.iter().find(|x| !KNOWN_PERMISSIONS.contains(&x.as_str())) {
        return Err(AppError::UnknownPermission(unknown.chars().take(40).collect()));
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&p.author).map_err(|_| AppError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_slice(&p.sig).map_err(|_| AppError::BadSignature)?;
    key.verify_strict(&signed_message(m, &p.wasm), &sig).map_err(|_| AppError::BadSignature)?;
    Program::load(&p.wasm)?;
    Ok(App { id: app_id(package), manifest: p.manifest, author: p.author, wasm: p.wasm, builtin: false })
}

/// Apps that ship inside Sentinel. Their packages are made the same way on
/// every device (deterministic signatures with a fixed, public key), so
/// they have the same identity everywhere; they're trusted because they
/// were compiled in, not because of that key.
pub fn builtins() -> Vec<(Vec<u8>, App)> {
    let seed = blake3::derive_key("sentinel/v1/builtin-apps", b"");
    let poll = Manifest {
        name: "Polls".into(),
        version: 1,
        description: "Ask the room a question with up to four answers. Everyone can vote and change their vote until the person who asked closes it.".into(),
        permissions: Vec::new(),
    };
    [(poll, include_bytes!("../apps/poll-1.wasm").as_slice())]
        .into_iter()
        .filter_map(|(m, w)| {
            let pkg = pack(&seed, m, w.to_vec()).ok()?;
            let mut app = open(&pkg).ok()?;
            app.builtin = true;
            Some((pkg, app))
        })
        .collect()
}

/// Plain-language list of what an app can and can't do, for the install
/// screen.
pub fn permission_lines(_m: &Manifest) -> (Vec<String>, Vec<String>) {
    let can = vec!["Keep its own information in this room, which every member's device keeps the same".to_string(), "Show screens inside this room, framed with its name".to_string()];
    let cannot = vec![
        "Connect to anything: no internet, no servers, no Pillars".to_string(),
        "See your account, keys, files, contacts or other rooms".to_string(),
        "See who you are outside this room (it only sees a nickname made for this room)".to_string(),
        "Spend your credits or send messages".to_string(),
    ];
    (can, cannot)
}

/// Compiled code, ready to run.
pub struct Program {
    engine: Engine,
    module: Module,
}

struct Limits(StoreLimits);

impl Program {
    pub fn load(wasm: &[u8]) -> Result<Self, AppError> {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, wasm).map_err(|e| AppError::BadCode(e.to_string().chars().take(120).collect()))?;
        if module.imports().next().is_some() {
            return Err(AppError::BadCode("it asks for outside functions".into()));
        }
        let exports: Vec<String> = module.exports().map(|e| e.name().to_owned()).collect();
        for need in ["memory", "sentinel_alloc", "sentinel_call"] {
            if !exports.iter().any(|e| e == need) {
                return Err(AppError::BadCode(format!("missing {need}")));
            }
        }
        Ok(Program { engine, module })
    }

    /// One call in a fresh instance. `Ok(None)`: the app refused.
    fn call(&self, op: i32, input: &[u8], max_out: usize) -> Result<Option<Vec<u8>>, AppError> {
        let trap = |e: wasmi::Error| AppError::Trap(e.to_string().chars().take(120).collect());
        let limits = StoreLimitsBuilder::new().memory_size(MEMORY).instances(1).memories(1).tables(1).table_elements(10_000).build();
        let mut store = Store::new(&self.engine, Limits(limits));
        store.limiter(|l| &mut l.0);
        store.set_fuel(FUEL).map_err(trap)?;
        let linker = Linker::<Limits>::new(&self.engine);
        let instance = linker.instantiate_and_start(&mut store, &self.module).map_err(trap)?;
        let memory = instance.get_memory(&store, "memory").ok_or(AppError::BadCode("no memory".into()))?;
        let alloc = instance.get_typed_func::<i32, i32>(&store, "sentinel_alloc").map_err(trap)?;
        let run = instance.get_typed_func::<(i32, i32, i32), i64>(&store, "sentinel_call").map_err(trap)?;
        let len = i32::try_from(input.len()).map_err(|_| AppError::TooLarge)?;
        let ptr = alloc.call(&mut store, len).map_err(trap)?;
        memory.write(&mut store, ptr as u32 as usize, input).map_err(|e| AppError::Trap(e.to_string()))?;
        let r = run.call(&mut store, (op, ptr, len)).map_err(trap)?;
        if r < 0 {
            return Ok(None);
        }
        let (out_ptr, out_len) = ((r >> 32) as u32 as usize, (r & 0xffff_ffff) as usize);
        if out_len > max_out {
            return Err(AppError::TooLarge);
        }
        let mut out = vec![0u8; out_len];
        memory.read(&store, out_ptr, &mut out).map_err(|e| AppError::Trap(e.to_string()))?;
        Ok(Some(out))
    }

    pub fn init(&self) -> Result<Vec<u8>, AppError> {
        self.call(sentinel_app_sdk::OP_INIT, &[], MAX_STATE)?.ok_or(AppError::Refused)
    }

    /// The new state, or an error (refused or failed: the state stays).
    pub fn apply(&self, state: &[u8], cmd: &[u8], ctx: &Ctx) -> Result<Vec<u8>, AppError> {
        let mut input = Vec::with_capacity(state.len() + cmd.len() + 64);
        sentinel_app_sdk::frame(&mut input, state);
        sentinel_app_sdk::frame(&mut input, cmd);
        sentinel_app_sdk::frame(&mut input, &cbor(ctx));
        self.call(sentinel_app_sdk::OP_APPLY, &input, MAX_STATE)?.ok_or(AppError::Refused)
    }

    /// The screen for `viewer`, checked and trimmed to Sentinel's limits.
    pub fn view(&self, state: &[u8], viewer: &Viewer) -> Result<Vec<Part>, AppError> {
        let mut input = Vec::new();
        sentinel_app_sdk::frame(&mut input, state);
        sentinel_app_sdk::frame(&mut input, &cbor(viewer));
        let out = self.call(sentinel_app_sdk::OP_VIEW, &input, MAX_VIEW)?.ok_or(AppError::Refused)?;
        let parts: Vec<Part> = ciborium::from_reader(out.as_slice()).map_err(|_| AppError::BadCode("unreadable screen".into()))?;
        let mut budget = 400usize;
        Ok(tidy(parts, 0, &mut budget))
    }
}

/// Limit a screen: depth, number of parts, text lengths.
fn tidy(parts: Vec<Part>, depth: usize, budget: &mut usize) -> Vec<Part> {
    let t = |s: String, n: usize| -> String { s.chars().filter(|c| !c.is_control() || *c == '\n').take(n).collect() };
    let mut out = Vec::new();
    for p in parts {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        out.push(match p {
            Part::Title(s) => Part::Title(t(s, 200)),
            Part::Text(s) => Part::Text(t(s, 2000)),
            Part::Muted(s) => Part::Muted(t(s, 500)),
            Part::Member(s) => Part::Member(t(s, 32)),
            Part::Input { id, label, max } => Part::Input { id: t(id, 32), label: t(label, 80), max: max.clamp(1, 1000) },
            Part::Button { label, action, arg, primary } => Part::Button { label: t(label, 80), action: t(action, 32), arg, primary },
            Part::Bar { label, value, total, mine } => Part::Bar { label: t(label, 120), value: value.min(total.max(value)), total, mine },
            Part::Row(c) if depth < 4 => Part::Row(tidy(c, depth + 1, budget)),
            Part::Card(c) if depth < 4 => Part::Card(tidy(c, depth + 1, budget)),
            Part::Row(_) | Part::Card(_) => continue,
            Part::Divider => Part::Divider,
        });
    }
    out
}

/// A command as sent in a room message (checked for size and shape).
pub fn command(action: &str, arg: u64, inputs: Vec<(String, String)>) -> Option<Vec<u8>> {
    if action.is_empty() || action.len() > 32 || inputs.len() > 16 {
        return None;
    }
    let inputs = inputs.into_iter().map(|(k, v)| (k.chars().take(32).collect(), v.chars().take(1000).collect())).collect();
    let bytes = cbor(&Cmd { action: action.to_owned(), arg, inputs });
    (bytes.len() <= MAX_CMD).then_some(bytes)
}

/// A member's pseudonym inside one app in one room.
pub fn who(room_id: &[u8; 32], app: &[u8; 32], author: &str) -> String {
    let mut h = blake3::Hasher::new_derive_key("sentinel/v1/app-member");
    h.update(room_id);
    h.update(app);
    h.update(author.as_bytes());
    data_encoding::HEXLOWER.encode(&h.finalize().as_bytes()[..8])
}

/// A command's place in the room's agreed order.
pub type OrderKey = (u64, u64, String, u32);

/// Per sender stream (Megolm session): the range of message indexes a
/// snapshot holds. For each command, a snapshot says one of three things
/// (see [`place`]), and every member treats it the same way.
pub type Cut = Vec<(String, u32, u32)>;

/// Where message `index` of `session` stands against a snapshot:
/// `Some(true)` it's in the snapshot's state; `Some(false)` it came before
/// anything the snapshot holds from that stream and is left out by
/// everyone; `None` it comes after (applied on top, in agreed order).
pub fn place(cut: &Cut, session: &str, index: u32) -> Option<bool> {
    let (_, from, to) = cut.iter().find(|(s, _, _)| s == session)?;
    if index < *from {
        Some(false)
    } else if index <= *to {
        Some(true)
    } else {
        None
    }
}

/// Admin: the new cut from the messages I hold (session, index). Each
/// stream only grows through an unbroken run of indexes, so a message I'm
/// missing is never counted as included; it's applied after, once it comes.
pub fn extend_cut(old: &Cut, held: &[(String, u32)]) -> Cut {
    let mut by: std::collections::BTreeMap<&str, Vec<u32>> = std::collections::BTreeMap::new();
    for (s, i) in held {
        by.entry(s.as_str()).or_default().push(*i);
    }
    let mut out: Cut = old.clone();
    for (s, mut idx) in by {
        idx.sort_unstable();
        idx.dedup();
        match out.iter_mut().find(|(x, _, _)| x == s) {
            Some(e) => {
                let after = e.2;
                for i in idx.into_iter().filter(|i| *i > after) {
                    if i != e.2 + 1 {
                        break;
                    }
                    e.2 = i;
                }
            }
            None => {
                let (from, mut to) = (idx[0], idx[0]);
                for &i in &idx[1..] {
                    if i != to + 1 {
                        break;
                    }
                    to = i;
                }
                out.push((s.to_owned(), from, to));
            }
        }
    }
    out
}

/// The admin's signed record of an app's state up to a point in the order.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Snapshot {
    pub room_id: [u8; 32],
    pub app: [u8; 32],
    /// Raised by each snapshot; the highest wins.
    pub version: u64,
    /// Exactly which commands are in `state` (see [`place`]).
    pub cut: Cut,
    #[serde(with = "serde_bytes_compat")]
    pub state: Vec<u8>,
}

pub const SNAPSHOT_KIND: &str = "room-app-state";

pub fn sign_snapshot(admin_seed: &[u8; 32], s: &Snapshot) -> Vec<u8> {
    let k = ed25519_dalek::SigningKey::from_bytes(admin_seed);
    crate::object::Envelope::sign(&k, SNAPSHOT_KIND, cbor(s)).encode().expect("snapshot encodes")
}

/// A snapshot signed by this room's admin key.
pub fn verify_snapshot(room_id: &[u8; 32], signed: &[u8]) -> Option<Snapshot> {
    let env = crate::object::Envelope::decode_verified(signed).ok()?;
    if env.kind != SNAPSHOT_KIND || crate::room::room_id_for(&env.author) != *room_id {
        return None;
    }
    let s: Snapshot = ciborium::from_reader(env.body.as_slice()).ok()?;
    (s.room_id == *room_id && s.state.len() <= MAX_STATE).then_some(s)
}

/// Apply commands (already in agreed order) to a state. Refused or failed
/// commands leave it unchanged, the same on every device.
pub fn replay<'a>(program: &Program, mut state: Vec<u8>, cmds: impl IntoIterator<Item = (&'a [u8], Ctx)>) -> Vec<u8> {
    for (cmd, ctx) in cmds {
        if let Ok(next) = program.apply(&state, cmd, &ctx) {
            state = next;
        }
    }
    state
}

/// A piece of a package, as the admin posts it to the room.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CodePart {
    pub room_id: [u8; 32],
    pub app: [u8; 32],
    pub part: u16,
    pub total: u16,
    #[serde(with = "serde_bytes_compat")]
    pub bytes: Vec<u8>,
}

pub const CODE_KIND: &str = "room-app-code";

/// Admin: the package in signed pieces for the room.
pub fn sign_code(admin_seed: &[u8; 32], room_id: &[u8; 32], package: &[u8]) -> Vec<Vec<u8>> {
    let k = ed25519_dalek::SigningKey::from_bytes(admin_seed);
    let app = app_id(package);
    let chunks: Vec<&[u8]> = package.chunks(CODE_PART).collect();
    let total = chunks.len() as u16;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            let p = CodePart { room_id: *room_id, app, part: i as u16, total, bytes: c.to_vec() };
            crate::object::Envelope::sign(&k, CODE_KIND, cbor(&p)).encode().expect("code part encodes")
        })
        .collect()
}

/// A piece of a package signed by this room's admin key.
pub fn verify_code(room_id: &[u8; 32], signed: &[u8]) -> Option<CodePart> {
    let env = crate::object::Envelope::decode_verified(signed).ok()?;
    if env.kind != CODE_KIND || crate::room::room_id_for(&env.author) != *room_id {
        return None;
    }
    let p: CodePart = ciborium::from_reader(env.body.as_slice()).ok()?;
    let most = MAX_PACKAGE.div_ceil(CODE_PART) as u16;
    (p.room_id == *room_id && p.total > 0 && p.total <= most && p.part < p.total && p.bytes.len() <= CODE_PART).then_some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll() -> (Vec<u8>, App) {
        builtins().into_iter().find(|(_, a)| a.manifest.name == "Polls").expect("poll is built in")
    }

    fn ask(q: &str, a: &str, b: &str) -> Vec<u8> {
        command("ask", 0, vec![("question".into(), q.into()), ("option1".into(), a.into()), ("option2".into(), b.into())]).unwrap()
    }

    fn ctx(who: &str) -> Ctx {
        Ctx { who: who.into(), minute: 1 }
    }

    #[test]
    fn builtins_have_the_same_identity_everywhere() {
        let (p1, a1) = poll();
        let (p2, a2) = poll();
        assert_eq!(p1, p2);
        assert_eq!(a1.id, a2.id);
        assert_eq!(app_id(&p1), a1.id);
        assert!(a1.builtin);
    }

    #[test]
    fn everyone_reaches_the_same_state() {
        let (_, app) = poll();
        let prog = Program::load(&app.wasm).unwrap();
        let start = prog.init().unwrap();
        let cmds = [(ask("Lunch?", "Pizza", "Soup"), ctx("a")), (command("vote", 1, vec![]).unwrap(), ctx("b")), (command("vote", 0, vec![]).unwrap(), ctx("c")), (command("vote", 0, vec![]).unwrap(), ctx("b"))];
        let run = |p: &Program| replay(p, start.clone(), cmds.iter().map(|(c, x)| (c.as_slice(), x.clone())));
        // Two devices (two separate compilations) agree byte for byte.
        let other = Program::load(&app.wasm).unwrap();
        assert_eq!(run(&prog), run(&other));
        let view = prog.view(&run(&prog), &Viewer { who: "b".into() }).unwrap();
        let bars: Vec<(String, u32, bool)> = view
            .iter()
            .flat_map(|p| if let Part::Card(c) = p { c.clone() } else { vec![] })
            .filter_map(|p| if let Part::Bar { label, value, mine, .. } = p { Some((label, value, mine)) } else { None })
            .collect();
        // b changed their vote to Pizza; c voted Pizza.
        assert_eq!(bars, vec![("Pizza".into(), 2, true), ("Soup".into(), 0, false)]);
    }

    #[test]
    fn refused_and_broken_commands_change_nothing() {
        let (_, app) = poll();
        let prog = Program::load(&app.wasm).unwrap();
        let s = replay(&prog, prog.init().unwrap(), [(ask("Q", "x", "y").as_slice(), ctx("a"))]);
        // Only the asker can close; nonsense is refused; garbage too.
        assert_eq!(prog.apply(&s, &command("close", 0, vec![]).unwrap(), &ctx("b")), Err(AppError::Refused));
        assert_eq!(prog.apply(&s, &command("fly", 0, vec![]).unwrap(), &ctx("a")), Err(AppError::Refused));
        assert!(prog.apply(&s, b"\xff\x00garbage", &ctx("a")).is_err());
        assert_eq!(replay(&prog, s.clone(), [(b"junk".as_slice(), ctx("a"))]), s);
        assert!(prog.apply(&s, &command("close", 0, vec![]).unwrap(), &ctx("a")).is_ok());
    }

    #[test]
    fn packages_are_checked() {
        let seed = [7u8; 32];
        let (_, app) = poll();
        let m = app.manifest.clone();
        let pkg = pack(&seed, m.clone(), app.wasm.clone()).unwrap();
        let opened = open(&pkg).unwrap();
        assert!(!opened.builtin);
        // Tampering breaks the signature.
        let mut bad: Package = ciborium::from_reader(pkg.as_slice()).unwrap();
        bad.manifest.name = "Pills".into();
        assert_eq!(open(&cbor(&bad)).unwrap_err(), AppError::BadSignature);
        // Unknown permissions are refused.
        let mut m2 = m.clone();
        m2.permissions = vec!["internet".into()];
        assert!(matches!(pack(&seed, m2, app.wasm.clone()), Err(AppError::UnknownPermission(_))));
        // Not Wasm, or Wasm that imports anything, is refused.
        assert!(matches!(pack(&seed, m.clone(), b"hello".to_vec()), Err(AppError::BadCode(_))));
        // (module (import "env" "net" (func)) (memory (export "memory") 1))
        let importing = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x02, 0x0b, 0x01, 0x03, b'e', b'n', b'v', 0x03, b'n', b'e', b't', 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x0a, 0x01, 0x06, b'm', b'e', b'm', b'o', b'r', b'y', 0x02, 0x00,
        ];
        assert_eq!(pack(&seed, m, importing.to_vec()).unwrap_err(), AppError::BadCode("it asks for outside functions".into()));
    }

    #[test]
    fn endless_loops_are_stopped() {
        // (module (memory (export "memory") 1)
        //   (func (export "sentinel_alloc") (param i32) (result i32) i32.const 0)
        //   (func (export "sentinel_call") (param i32 i32 i32) (result i64) (loop (br 0)) i64.const 0))
        let wasm = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
            0x01, 0x0d, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x03, 0x7f, 0x7f, 0x7f, 0x01, 0x7e, // types
            0x03, 0x03, 0x02, 0x00, 0x01, // functions
            0x05, 0x03, 0x01, 0x00, 0x01, // memory
            0x07, 0x2b, 0x03, 0x06, b'm', b'e', b'm', b'o', b'r', b'y', 0x02, 0x00, 0x0e, b's', b'e', b'n', b't', b'i', b'n', b'e', b'l', b'_', b'a', b'l', b'l', b'o', b'c', 0x00, 0x00, 0x0d, b's', b'e', b'n', b't', b'i', b'n', b'e', b'l', b'_', b'c', b'a', b'l', b'l', 0x00, 0x01, // exports
            0x0a, 0x10, 0x02, 0x04, 0x00, 0x41, 0x00, 0x0b, 0x09, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x42, 0x00, 0x0b, // code
        ];
        let prog = Program::load(&wasm).unwrap();
        assert!(matches!(prog.init(), Err(AppError::Trap(_))));
    }

    #[test]
    fn snapshots_are_signed_by_the_admin() {
        let (room, _, admin) = crate::room::new_room_with_admin();
        let s = Snapshot { room_id: room, app: [1; 32], version: 2, cut: vec![("s".into(), 0, 3)], state: vec![1, 2, 3] };
        let signed = sign_snapshot(&admin, &s);
        assert_eq!(verify_snapshot(&room, &signed), Some(s.clone()));
        assert!(verify_snapshot(&room, &sign_snapshot(&[9; 32], &s)).is_none());
        let (other, _, _) = crate::room::new_room_with_admin();
        assert!(verify_snapshot(&other, &signed).is_none());
    }

    #[test]
    fn cuts_never_cover_what_is_missing() {
        let h = |v: &[(&str, u32)]| v.iter().map(|(s, i)| (s.to_string(), *i)).collect::<Vec<_>>();
        // A new stream: from its first message I hold, through the unbroken run.
        let c = extend_cut(&vec![], &h(&[("a", 4), ("a", 5), ("a", 7), ("b", 0), ("b", 1)]));
        assert_eq!(place(&c, "a", 3), Some(false));
        assert_eq!(place(&c, "a", 5), Some(true));
        assert_eq!(place(&c, "a", 6), None);
        assert_eq!(place(&c, "a", 7), None, "after a gap: applied on top");
        assert_eq!(place(&c, "b", 1), Some(true));
        assert_eq!(place(&c, "z", 0), None, "a stream the snapshot never saw");
        // 6 arrives: the run continues through 7.
        let c2 = extend_cut(&c, &h(&[("a", 4), ("a", 5), ("a", 6), ("a", 7)]));
        assert_eq!(place(&c2, "a", 7), Some(true));
        assert_eq!(place(&c2, "a", 8), None);
        // Never goes backwards.
        assert_eq!(place(&extend_cut(&c2, &[]), "a", 7), Some(true));
    }

    #[test]
    fn pseudonyms_differ_per_room_and_app() {
        let a = who(&[1; 32], &[2; 32], "alice");
        assert_eq!(a, who(&[1; 32], &[2; 32], "alice"));
        assert_ne!(a, who(&[3; 32], &[2; 32], "alice"));
        assert_ne!(a, who(&[1; 32], &[4; 32], "alice"));
        assert_eq!(a.len(), 16);
    }
}
