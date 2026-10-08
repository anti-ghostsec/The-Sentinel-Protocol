//! Sentinel Apps (spec §19): the boundary between Sentinel and an app.
//!
//! An app is a WebAssembly module with **no imports at all**: it can't reach
//! the network, files, clocks, randomness or anything else. It exports three
//! things, which [`export_app!`] writes for you:
//!
//! - `memory`;
//! - `sentinel_alloc(len) -> ptr`, so Sentinel can hand it input;
//! - `sentinel_call(op, ptr, len) -> (ptr << 32 | len)` or `-1` (refused).
//!
//! The three operations are pure functions:
//!
//! - **init** → the starting state;
//! - **apply** (state, command, context) → the new state, or refused. Every
//!   member runs this on the same commands in the room's agreed order, so
//!   everyone reaches the same state;
//! - **view** (state, viewer) → a screen made of [`Part`]s, which Sentinel
//!   draws itself (apps never ship their own page or scripts).
//!
//! State is the app's own bytes (usually CBOR). Members are identified only
//! by a room-and-app-only pseudonym (`who`), never by their account.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const OP_INIT: i32 = 0;
pub const OP_APPLY: i32 = 1;
pub const OP_VIEW: i32 = 2;

/// A member pressed a button. `inputs` holds what they typed in the
/// screen's input boxes, by id.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Cmd {
    pub action: String,
    #[serde(default)]
    pub arg: u64,
    #[serde(default)]
    pub inputs: Vec<(String, String)>,
}

impl Cmd {
    /// What was typed in input `id` (trimmed; empty if none).
    pub fn input(&self, id: &str) -> &str {
        self.inputs.iter().find(|(k, _)| k == id).map(|(_, v)| v.trim()).unwrap_or("")
    }
}

/// Facts every member agrees on about a command.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Ctx {
    /// The sender's pseudonym in this room and app.
    pub who: String,
    /// The minute the sender stamped on it (Unix minutes).
    pub minute: u64,
}

/// Who is looking at the screen (views may differ per person; state never).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Viewer {
    pub who: String,
}

/// The parts a screen is made of. Sentinel draws them in its own style,
/// always inside a frame naming the app.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Part {
    Title(String),
    Text(String),
    /// Smaller, quieter text.
    Muted(String),
    /// A member, by pseudonym: Sentinel shows their name.
    Member(String),
    /// A text box; its contents go with the next button pressed.
    Input { id: String, label: String, max: u32 },
    Button { label: String, action: String, arg: u64, primary: bool },
    /// A result bar (e.g. votes): value out of total.
    Bar { label: String, value: u32, total: u32, mine: bool },
    /// Side by side.
    Row(Vec<Part>),
    /// A boxed group.
    Card(Vec<Part>),
    Divider,
}

/// What an app implements.
pub trait App {
    fn init() -> Vec<u8>;
    /// `None` refuses the command (the state stays as it was).
    fn apply(state: &[u8], cmd: &Cmd, ctx: &Ctx) -> Option<Vec<u8>>;
    fn view(state: &[u8], viewer: &Viewer) -> Vec<Part>;
}

pub fn to_cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

pub fn from_cbor<T: DeserializeOwned>(b: &[u8]) -> Option<T> {
    ciborium::from_reader(b).ok()
}

/// Inputs are passed as length-prefixed parts (u32 little-endian).
pub fn frame(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_le_bytes());
    out.extend_from_slice(part);
}

pub fn unframe(mut input: &[u8], n: usize) -> Option<Vec<&[u8]>> {
    let mut parts = Vec::with_capacity(n);
    for _ in 0..n {
        let len = u32::from_le_bytes(input.get(..4)?.try_into().ok()?) as usize;
        parts.push(input.get(4..4 + len)?);
        input = &input[4 + len..];
    }
    input.is_empty().then_some(parts)
}

#[doc(hidden)]
pub fn dispatch<A: App>(op: i32, input: &[u8]) -> Option<Vec<u8>> {
    match op {
        OP_INIT => Some(A::init()),
        OP_APPLY => {
            let p = unframe(input, 3)?;
            A::apply(p[0], &from_cbor(p[1])?, &from_cbor(p[2])?)
        }
        OP_VIEW => {
            let p = unframe(input, 2)?;
            Some(to_cbor(&A::view(p[0], &from_cbor(p[1])?)))
        }
        _ => None,
    }
}

/// Export an [`App`] as a Sentinel App module.
#[macro_export]
macro_rules! export_app {
    ($app:ty) => {
        #[no_mangle]
        pub extern "C" fn sentinel_alloc(len: i32) -> i32 {
            let mut v = ::std::vec::Vec::<u8>::with_capacity(len.max(0) as usize);
            let p = v.as_mut_ptr();
            ::std::mem::forget(v);
            p as i32
        }

        /// # Safety
        /// Called by Sentinel with a buffer it filled via `sentinel_alloc`.
        #[no_mangle]
        pub unsafe extern "C" fn sentinel_call(op: i32, ptr: i32, len: i32) -> i64 {
            let input = ::std::slice::from_raw_parts(ptr as usize as *const u8, len.max(0) as usize);
            match $crate::dispatch::<$app>(op, input) {
                Some(out) => {
                    let out = out.into_boxed_slice();
                    let l = out.len() as i64;
                    let p = ::std::boxed::Box::into_raw(out) as *mut u8 as usize as i64;
                    (p << 32) | l
                }
                None => -1,
            }
        }
    };
}
