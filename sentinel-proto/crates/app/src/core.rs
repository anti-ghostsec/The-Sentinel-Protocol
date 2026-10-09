//! App backend: identity, encrypted local store, Tor, posting and following.
//!
//! Privacy properties:
//! - The signing key exists in memory only while unlocked; `lock` drops it
//!   (ed25519-dalek zeroizes on drop).
//! - Everything except the passphrase-sealed identity file lives in one
//!   store encrypted with a key derived from the identity (spec §18), so a
//!   seized device reveals nothing without the passphrase — including who you
//!   follow and which Pillar you use.
//! - All networking is Tor-only via `sentinel_net` (no other path exists).
//! - Timeline refresh runs on a fixed schedule, not when the user acts, and
//!   each followed account is fetched on its own isolated circuit (I13).

pub mod apps;
pub mod audit;
pub mod circle;
pub mod deletion;
pub mod directory;
pub mod moderation;

/// What a report can be about, with the words shown in the app (the keys
/// are `sentinel_core::social::REPORT_CATEGORIES`, in the same order).
pub const REPORT_CATEGORY_NAMES: &[(&str, &str)] = &[
    ("child-abuse", "Sexual content involving a child"),
    ("intimate-images", "Intimate images shared without consent"),
    ("violence", "Threats or violence"),
    ("doxxing", "Someone's private details (doxxing)"),
    ("spam", "Spam or scams"),
    ("other-illegal", "Something else that's illegal or dangerous"),
];
pub mod dms;
pub mod ffmpeg;
pub mod local;
pub mod mailbox;
pub mod media_app;
pub mod profile;
pub mod rooms;
pub mod devices;
pub mod recover;
pub mod release;
pub mod updates;
pub mod wallet;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sentinel_core::cell::{read_message, write_message};
use sentinel_core::object::{Address, Envelope};
use sentinel_core::social::{self, FollowLink};
use sentinel_core::wire::{self, Request, Response};
use sentinel_core::identity;
use sentinel_net::pool::Pool;
use sentinel_net::transport::{check_onion, Io, Net};
use tauri::{AppHandle, Emitter};
use zeroize::Zeroizing;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Fixed refresh schedule (privacy: independent of user activity).
const REFRESH_EVERY: Duration = Duration::from_secs(90);

/// Data role for this app instance. `SENTINEL_PROFILE=<name>` selects a
/// separate local profile (own identity, store and Tor state) — used for
/// testing several accounts on one machine.
pub fn role() -> String {
    // Test builds only: in the app people get, a setting left on the
    // computer can't point Sentinel at a different (decoy) account.
    if !cfg!(feature = "test-hooks") {
        return "app".into();
    }
    match std::env::var("SENTINEL_PROFILE") {
        Ok(p) if !p.is_empty() && p.len() <= 16 && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) => {
            format!("app-{p}")
        }
        _ => "app".into(),
    }
}

fn data_dir() -> Result<PathBuf> {
    sentinel_net::data_root(&role())
}
fn identity_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("identity.key"))
}
fn store_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("store.bin"))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Privacy {
    #[serde(default = "yes")]
    pub disappearing: bool,
    #[serde(default, alias = "high_risk")]
    pub high_risk: bool,
    /// Keep the window out of screenshots, screen recording and Recall.
    #[serde(default = "yes")]
    pub screen_security: bool,
    /// Lock after a while without use (15 min; 5 in High-risk mode).
    #[serde(default = "yes")]
    pub auto_lock: bool,
    /// Send messages through two mixing Pillars with random delays (always
    /// on in High-risk mode).
    #[serde(default)]
    pub mix: bool,
}

fn yes() -> bool {
    true
}

impl Default for Privacy {
    fn default() -> Self {
        Privacy { disappearing: true, high_risk: false, screen_security: true, auto_lock: true, mix: false }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Followed {
    pub author: String,
    pub pillar: String,
    pub name: Option<String>,
    /// 0 until their history has been read (author buckets are then read
    /// from the start once).
    pub cursor: u64,
    pub profile_minute: u64,
    /// Their feed key (from their follow link). Without it only their
    /// discoverable posts can be read.
    #[serde(default)]
    pub feed_key: Option<[u8; 32]>,
    /// Their latest contact card (lets us message them).
    #[serde(default)]
    pub card: Option<sentinel_core::social::ContactCard>,
    /// Keys for their approved-followers posts (newest last).
    #[serde(default)]
    pub circle_keys: Vec<[u8; 32]>,
    /// "" | "requested" | "approved"
    #[serde(default)]
    pub circle_state: String,
    #[serde(default)]
    pub bio: String,
    #[serde(default)]
    pub avatar: Option<sentinel_core::media::MediaRef>,
    #[serde(default)]
    pub banner: Option<sentinel_core::media::MediaRef>,
    /// Their recovery key (first one seen; only it can move the account).
    #[serde(default)]
    pub recovery: Option<sentinel_core::recovery::RecoveryPin>,
    /// Generation of their account key I follow (raised by each move).
    #[serde(default)]
    pub recovery_gen: u32,
    /// Earlier keys of this account, and whether it moved since I last looked.
    #[serde(default)]
    pub moved_from: Vec<String>,
    #[serde(default)]
    pub moved_notice: bool,
    /// Their ML-DSA-65 key (first one seen, or from a verified move): from
    /// then on, only their objects with a valid post-quantum signature count.
    #[serde(default)]
    pub pq_key: Option<Vec<u8>>,
    /// Messaging cards of each of their devices (newest per device).
    #[serde(default)]
    pub cards: Vec<sentinel_core::social::ContactCard>,
}

/// Merge a card into a device list: newest per device (Olm identity),
/// devices not heard from in 90 days dropped, at most 8.
pub(crate) fn merge_card(list: &mut Vec<sentinel_core::social::ContactCard>, c: sentinel_core::social::ContactCard) {
    match list.iter_mut().find(|x| x.olm_identity == c.olm_identity) {
        Some(old) if c.minute >= old.minute => *old = c,
        Some(_) => {}
        None => list.push(c),
    }
    let now = social::coarse_minute();
    list.retain(|x| now.saturating_sub(x.minute) < 90 * 24 * 60);
    list.sort_by(|a, b| b.minute.cmp(&a.minute));
    list.truncate(8);
}

/// Keys and state for end-to-end encrypted messaging (all inside the
/// encrypted store; the Olm account and sessions are additionally pickled
/// with their own key).
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DmState {
    pub account: String,
    /// Olm sessions keyed by the peer's Olm identity (hex).
    pub sessions: std::collections::HashMap<String, String>,
    pub inbox_secret: [u8; 32],
    /// Secret behind my daily inbox fetch tokens (only I hold it).
    #[serde(alias = "inbox_key")]
    pub fetch_secret: [u8; 32],
    /// Last fetched position per inbox ID (hex).
    pub cursors: std::collections::HashMap<String, u64>,
    pub card_minute: u64,
    pub card_pillar: Option<String>,
    /// Which Sentinel account owns each Olm session (peer Olm identity hex
    /// -> author), learned when a session is authenticated.
    #[serde(default)]
    pub owners: std::collections::HashMap<String, String>,
    /// The card this device published last (handed to a new device).
    #[serde(default)]
    pub last_card: Option<sentinel_core::social::ContactCard>,
}

/// Disappearing messages: days until deletion.
pub const DISAPPEAR_DAYS: u16 = 7;

#[derive(Clone, Serialize, Deserialize)]
pub struct Message {
    pub mine: bool,
    pub text: String,
    pub minute: u64,
    pub sent: bool,
    /// Sealed blob kept until it is delivered (mine only).
    #[serde(default)]
    pub blob: Option<Vec<u8>>,
    /// Disappearing timer set by the sender.
    #[serde(default)]
    pub expire_days: Option<u16>,
    /// Copies still to deliver, one per device (theirs and my other ones).
    #[serde(default)]
    pub out: Vec<Outgoing>,
}

/// A sealed copy of a message for one device (by its Olm identity).
#[derive(Clone, Serialize, Deserialize)]
pub struct Outgoing {
    pub olm: [u8; 32],
    pub blob: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub author: String,
    pub name: String,
    /// Peer card learned from their first message (if not followed).
    pub card: Option<sentinel_core::social::ContactCard>,
    pub messages: Vec<Message>,
    /// Whether we already sent them our signed card.
    pub introduced: bool,
    /// Cards of each of their devices learned from their messages.
    #[serde(default)]
    pub cards: Vec<sentinel_core::social::ContactCard>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredPost {
    pub id: String,
    pub author: String,
    pub text: String,
    pub minute: u64,
    pub mine: bool,
    pub sent: bool,
    /// Encoded envelope kept until a Pillar confirms storage.
    pub raw: Option<Vec<u8>>,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub discoverable: bool,
    #[serde(default)]
    pub media: Vec<sentinel_core::media::MediaRef>,
    /// Encrypted media chunks (addresses) still to upload before the post.
    #[serde(default)]
    pub pending_chunks: Vec<String>,
    /// Sealed for approved followers only.
    #[serde(default)]
    pub approved_only: bool,
    /// Set while large attachments are still uploading (post not sealed yet).
    #[serde(default)]
    pub draft: Option<media_app::Draft>,
    /// High-risk mode: don't send before this Unix time (random delay, so
    /// network activity doesn't reveal when the post was written).
    #[serde(default)]
    pub not_before: u64,
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Random send delay for High-risk mode: 2-20 minutes.
pub(crate) fn high_risk_delay() -> u64 {
    unix_now() + 120 + u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % 1080
}

/// A public room found in Discover.
#[derive(Clone, Serialize, Deserialize)]
pub struct DiscoveredRoom {
    pub room_id: String,
    pub name: String,
    pub description: String,
    pub topics: Vec<String>,
    pub access: String,
    pub price: u32,
    pub link: String,
    pub minute: u64,
    /// The listing's address and the Pillar it was found on (for reports).
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub pillar: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredRoomView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub topics: Vec<String>,
    pub access: String,
    pub price: u32,
    pub link: String,
    pub joined: bool,
    /// Joining needs approval (the link is an ask link).
    pub approval: bool,
    /// I asked and wait for an answer.
    pub waiting: bool,
}

/// A post found through discovery (not from someone we follow).
#[derive(Clone, Serialize, Deserialize)]
pub struct DiscoveredPost {
    pub id: String,
    pub author: String,
    pub text: String,
    pub minute: u64,
    pub topics: Vec<String>,
    #[serde(default)]
    pub media: Vec<sentinel_core::media::MediaRef>,
    /// Pillar it was found on (lets the reader follow the author).
    pub pillar: String,
    /// Found via a subscribed topic (vs. undirected exploration).
    pub topical: bool,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Store {
    /// My current identity seed, once the account has moved to a new key
    /// (otherwise the key file's key is the identity).
    #[serde(default)]
    pub identity: Option<[u8; 32]>,
    /// My recovery key pin (published in my profile) and the generation of
    /// my current identity. `None` generation: an older account whose key
    /// isn't derived from recovery words (its first move goes to 1).
    #[serde(default)]
    pub recovery_pin: Option<sentinel_core::recovery::RecoveryPin>,
    #[serde(default)]
    pub recovery_gen: Option<u32>,
    /// The recovery words' secret, kept only until I confirm I wrote them down.
    #[serde(default)]
    pub recovery_pending: Option<[u8; 32]>,
    /// Recovered from words: look for later moves once connected.
    #[serde(default)]
    pub recovery_catch_up: bool,
    /// My other devices' messaging cards (they get copies of what I send).
    #[serde(default)]
    pub my_devices: Vec<sentinel_core::social::ContactCard>,
    /// Names I gave my devices (Olm identity hex -> name).
    #[serde(default)]
    pub device_names: std::collections::HashMap<String, String>,
    /// Sync messages for my other devices, waiting to be delivered.
    #[serde(default)]
    pub device_outbox: Vec<Outgoing>,
    /// Sync messages from my other devices, applied on the next pass.
    #[serde(default)]
    pub incoming_sync: Vec<sentinel_core::dm::DeviceSync>,
    /// Linking a new device: my offer (this device) or my request (new device).
    #[serde(default)]
    pub link_offer: Option<devices::LinkOffer>,
    #[serde(default)]
    pub link_join: Option<devices::LinkJoin>,
    /// Reading my own posts and cards (once I have more than one device).
    #[serde(default)]
    pub self_cursor: u64,
    pub name: String,
    /// "tor" or "bridges".
    pub mode: String,
    pub bridges_set: String,
    pub pillar: Option<String>,
    pub following: Vec<Followed>,
    pub posts: Vec<StoredPost>,
    pub liked: Vec<String>,
    pub privacy: Privacy,
    pub profile_published: bool,
    /// Discovery topics this user reads (local only, never sent).
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub discovered: Vec<DiscoveredPost>,
    /// Public rooms found in Discover.
    #[serde(default)]
    pub discovered_rooms: Vec<DiscoveredRoom>,
    /// Public posts and listings I reported (never shown to me again).
    #[serde(default)]
    pub reported: Vec<String>,
    /// Remembered "discoverable" choice for new posts.
    #[serde(default)]
    pub discover_default: bool,
    #[serde(default)]
    pub hide_count: bool,
    #[serde(default)]
    pub followers: Option<u64>,
    /// Backup Pillars that also receive my posts (chosen automatically).
    #[serde(default)]
    pub replicas: Vec<String>,
    /// Pillars learned from the directory (cache for automatic selection).
    #[serde(default)]
    pub known_pillars: Vec<String>,
    /// Which known Pillars answered lately (days only; see `directory`).
    #[serde(default)]
    pub pillar_health: std::collections::HashMap<String, directory::PillarHealth>,
    /// Pillars the credit issuers vouch for, and the day they were fetched.
    #[serde(default)]
    pub vouched_pillars: Vec<String>,
    #[serde(default)]
    pub vouched_day: u64,
    /// Whether this device runs a Pillar for the network.
    #[serde(default)]
    pub host: bool,
    /// Key that encrypts my posts, profile and contact card for followers;
    /// shared only inside my follow link.
    #[serde(default)]
    pub feed_key: Option<[u8; 32]>,
    #[serde(default)]
    pub dm: Option<DmState>,
    #[serde(default)]
    pub conversations: Vec<Conversation>,
    #[serde(default)]
    pub rooms: Vec<rooms::RoomState>,
    /// Archives (media storage nodes) learned from the directory.
    #[serde(default)]
    pub known_archives: Vec<String>,
    #[serde(default)]
    pub archives_minute: u64,
    /// Media storage this device offers when it runs a Pillar (GB, 0 = none).
    #[serde(default)]
    pub host_archive_gb: u32,
    /// My profile description and pictures.
    #[serde(default)]
    pub bio: String,
    #[serde(default)]
    pub avatar: Option<sentinel_core::media::MediaRef>,
    #[serde(default)]
    pub banner: Option<sentinel_core::media::MediaRef>,
    /// Profile picture chunks still to upload (hex addresses).
    #[serde(default)]
    pub profile_chunks: Vec<String>,
    /// Private bridge lines (used instead of the built-in set when present).
    #[serde(default)]
    pub custom_bridges: Vec<String>,
    /// Mailbox fetch positions ("pillar|bits|prefix" -> sequence number).
    #[serde(default)]
    pub mail_cursors: std::collections::HashMap<String, u64>,
    /// The last day every mailbox was read (after being away, the days
    /// missed are read too, back to the 7 days Pillars keep messages).
    #[serde(default)]
    pub mail_day: u64,
    /// Fingerprints of blobs already handled (-> day seen), so re-scans
    /// and replays never process a message twice. Kept 9 days.
    #[serde(default)]
    pub mail_seen: std::collections::HashMap<String, u64>,
    /// Single-use storage challenges for my uploads.
    #[serde(default)]
    pub audits: Vec<audit::Audit>,
    /// Proof-of-storage results per Archive.
    #[serde(default)]
    pub archive_health: std::collections::HashMap<String, audit::Health>,
    /// Single-mint tokens from older versions (moved into `parts` on unlock).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wallet: Vec<sentinel_core::credits::Token>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_rewards: Vec<sentinel_core::credits::Token>,
    /// My credit parts: (mint, anonymous token). See `wallet`.
    #[serde(default)]
    pub parts: Vec<(String, sentinel_core::credits::Token)>,
    /// Parts whose fate is unknown, re-checked each sync.
    #[serde(default)]
    pub pending_parts: Vec<(String, sentinel_core::credits::Token)>,
    /// My approved followers (spec §8.4).
    #[serde(default)]
    pub circle: circle::Circle,
    /// Accounts whose posts I don't want to see (kept on this device only).
    #[serde(default)]
    pub muted: Vec<String>,
    /// Accounts I've blocked: hidden everywhere, and their messages are
    /// dropped unread (kept on this device only; they aren't told).
    #[serde(default)]
    pub blocked: Vec<String>,
    /// Author buckets (spec §10.1): per Pillar, the depth I read buckets at
    /// and how far I've read.
    #[serde(default)]
    pub author_depth: std::collections::HashMap<String, u8>,
    #[serde(default)]
    pub author_cursor: std::collections::HashMap<String, u64>,
    /// Mint list override (empty = the seed Pillars; not exposed in the UI).
    #[serde(default)]
    pub mints: Vec<String>,
    /// Mint public keys as first seen (pinned).
    #[serde(default)]
    pub mint_keys: std::collections::HashMap<String, Vec<u8>>,
    /// Mints' quantum-safe checkpoint keys as first seen (pinned).
    #[serde(default)]
    pub pq_mint_keys: std::collections::HashMap<String, sentinel_core::pq::HybridPublic>,
    /// The latest checkpoints seen per mint (to catch one showing
    /// different lists to different people).
    #[serde(default)]
    pub pq_checkpoints: std::collections::HashMap<String, Vec<sentinel_core::pqcash::Checkpoint>>,
    /// Mints caught signing contradicting checkpoints: not used again.
    #[serde(default)]
    pub pq_cheaters: Vec<String>,
    /// Payments received in DMs, processed on the next sync.
    #[serde(default)]
    pub incoming_payments: Vec<IncomingPayment>,
    /// Credits I sent in messages, kept until it's clear they arrived (see
    /// `wallet::reclaim_unclaimed`).
    #[serde(default)]
    pub sent_credits: Vec<SentCredits>,
    /// Room invites granted to me: (sender, link). Honoured only from the
    /// creator I paid (see `purchases`).
    #[serde(default)]
    pub incoming_grants: Vec<(String, String)>,
    /// Rooms I paid for: room id (hex) -> creator I paid.
    #[serde(default)]
    pub purchases: std::collections::HashMap<String, String>,
    /// Also serve my uploads from my own hosted Archive (off by default;
    /// never in High-risk mode: it ties my node's uptime to my posts).
    #[serde(default)]
    pub self_seed: bool,
}

/// Credits I sent inside a message (a copy of the bearer parts).
#[derive(Clone, Serialize, Deserialize)]
pub struct SentCredits {
    pub to: String,
    pub minute: u64,
    pub text: String,
    pub parts: Vec<(String, sentinel_core::credits::Token)>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IncomingPayment {
    pub from: String,
    /// Credits still to redeem (after a partial redeem: only the parts
    /// whose mint couldn't be reached yet).
    #[serde(default)]
    pub bundles: Vec<sentinel_core::credits::Bundle>,
    pub purchase: Option<sentinel_core::dm::RoomPurchase>,
    /// Credits already redeemed in full.
    #[serde(default)]
    pub confirmed: usize,
    /// Bundle shapes were checked (partial leftovers aren't whole bundles).
    #[serde(default)]
    pub checked: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionView {
    /// tor | bridges
    pub mode: String,
    /// Built-in set in use (snowflake | obfs4).
    pub builtin: String,
    /// Number of private bridges saved (lines are never sent back to the page).
    pub custom: usize,
}

/// The account's keys while unlocked. `id` is who people know me as;
/// `root` is the key sealed in the key file, which encrypts everything
/// kept on this device. They're the same key until the account moves to a
/// new identity (recovery words): then the identity changes and the root
/// stays, so nothing on the device has to be re-encrypted.
#[derive(Clone)]
pub struct Keys {
    id: SigningKey,
    root: SigningKey,
}

impl std::ops::Deref for Keys {
    type Target = SigningKey;
    fn deref(&self) -> &SigningKey {
        &self.id
    }
}

impl Keys {
    fn new(root: SigningKey, store: &Store) -> Self {
        let id = store.identity.map(|s| SigningKey::from_bytes(&s)).unwrap_or_else(|| root.clone());
        Keys { id, root }
    }

    pub fn root(&self) -> &SigningKey {
        &self.root
    }
}

fn pickle_key(key: &Keys) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key("sentinel/v0/olm-pickle", &key.root.to_bytes()))
}

/// Make sure this store has a feed key and messaging keys (new accounts and
/// stores created before these features existed).
fn ensure_keys(key: &Keys, s: &mut Store) {
    if s.feed_key.is_none() {
        s.feed_key = Some(sentinel_core::random_bytes::<32>());
    }
    if s.dm.is_none() {
        let account = vodozemac::olm::Account::new();
        s.dm = Some(DmState {
            account: account.pickle().encrypt(&pickle_key(key)),
            inbox_secret: sentinel_core::random_bytes::<32>(),
            fetch_secret: sentinel_core::random_bytes::<32>(),
            ..Default::default()
        });
    }
}

fn store_key(key: &SigningKey) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key("sentinel/v0/local-store", &key.to_bytes()))
}

/// The store encrypted under the identity-derived key (file format).
fn seal_store(key: &Keys, store: &Store) -> Result<Vec<u8>> {
    let plain = Zeroizing::new(serde_json::to_vec(store)?);
    let k = store_key(&key.root);
    let nonce = sentinel_core::random_bytes::<24>();
    let ct = XChaCha20Poly1305::new(k.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), plain.as_slice())
        .map_err(|_| anyhow!("encrypting store"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

fn save_store(key: &Keys, store: &Store) -> Result<()> {
    let out = seal_store(key, store)?;
    let path = store_path()?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Open the store with the key-file root (before the identity is known).
fn load_store(root: &SigningKey) -> Result<Store> {
    let data = std::fs::read(store_path()?).context("reading store")?;
    if data.len() < 24 {
        bail!("store is corrupted");
    }
    let k = store_key(root);
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(k.as_ref().into())
            .decrypt(XNonce::from_slice(&data[..24]), &data[24..])
            .map_err(|_| anyhow!("store could not be decrypted"))?,
    );
    Ok(serde_json::from_slice(&plain)?)
}

#[derive(Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NetStatus {
    /// idle | connecting | ready | error
    pub state: String,
    pub frac: f32,
    pub text: String,
}

#[derive(Default)]
struct Inner {
    key: Option<Keys>,
    store: Option<Store>,
    net: Option<Net>,
    pool: Option<Arc<Pool>>,
    status: NetStatus,
    refresher: Option<tauri::async_runtime::JoinHandle<()>>,
    /// The Pillar this device runs for the network, if enabled.
    /// The Pillar this device hosts, running in its own process.
    hosted: Option<crate::hostproc::HostedPillar>,
    /// The account's Tor client, running in its own process.
    tor_proc: Option<crate::torproc::TorProcess>,
    /// Attachments waiting for a post (memory only, never on disk).
    attachments: std::collections::HashMap<String, media_app::Attachment>,
    host_state: String,
    host_error: Option<String>,
    /// Encrypted local chunk store (outbox + cache).
    local: Option<local::LocalChunks>,
    /// Open media fetch sessions (one per file).
    sessions: std::collections::HashMap<String, Arc<media_app::Session>>,
    /// Running downloads (cancel flags).
    transfers: std::collections::HashMap<String, Arc<std::sync::atomic::AtomicBool>>,
    uploader: Option<tauri::async_runtime::JoinHandle<()>>,
    cover: Option<tauri::async_runtime::JoinHandle<()>>,
    auditor: Option<tauri::async_runtime::JoinHandle<()>>,
    mail: mailbox::MailState,
    /// This account's key-file fingerprint, while unlocked (memory only).
    keyfile: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// A key file chosen on the unlock or new-account screen (fingerprint
    /// and file name), used by the next unlock or account creation.
    chosen_keyfile: Option<(zeroize::Zeroizing<[u8; 32]>, String)>,
    /// Mix keys of Pillars fetched this session.
    mix_keys: std::collections::HashMap<String, sentinel_core::mix::MixKey>,
    /// Update checks and downloads.
    update: updates::UpdateView,
    updater: Option<tauri::async_runtime::JoinHandle<()>>,
    /// Pillar addresses typed in while the first connection was stuck
    /// (tried first; memory only).
    pillar_hints: Vec<String>,
}

pub struct Core {
    inner: Mutex<Inner>,
    /// Random per-run secret in local media URLs (the player's only way in).
    pub stream_token: String,
}

impl Default for Core {
    fn default() -> Self {
        Core {
            inner: Mutex::new(Inner::default()),
            stream_token: data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<16>()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusView {
    pub initialized: bool,
    pub unlocked: bool,
    pub name: String,
    pub handle: String,
    pub mode: String,
    pub pillar: Option<String>,
    pub link: Option<String>,
    pub following: usize,
    pub net: NetStatus,
    pub privacy: Option<Privacy>,
    pub followers: Option<u64>,
    pub hide_count: bool,
    pub topics: Vec<String>,
    pub discover_default: bool,
    pub hosting: HostView,
    pub stream_token: String,
    pub has_avatar: bool,
    pub credits: usize,
    /// Credit parts still being swapped in.
    pub credits_pending: usize,
    /// This account needs a key file to unlock.
    pub keyfile: bool,
    /// Name of the key file chosen for the next unlock (if any).
    pub keyfile_chosen: Option<String>,
    /// This new device waits to be linked: the check code to compare.
    pub linking: Option<String>,
    /// windows | linux | android | …
    pub platform: String,
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct HostView {
    /// Enabled by the user.
    pub enabled: bool,
    /// off | starting | online | error
    pub state: String,
    pub used_mb: u64,
    pub served: u64,
    pub error: Option<String>,
    pub archive_gb: u32,
    pub chunks_mb: u64,
    pub self_seed: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PostView {
    /// Full author key text (for profile pages and pictures).
    pub author: String,
    /// The author has a profile picture (load via `profile_image`).
    pub avatar: bool,
    pub id: String,
    pub name: String,
    pub handle: String,
    pub text: String,
    pub minute: u64,
    pub mine: bool,
    pub sent: bool,
    pub liked: bool,
    pub topics: Vec<String>,
    /// Follow link for discovered authors not yet followed.
    pub follow_link: Option<String>,
    /// A public (discoverable) post: it can be reported to Pillars.
    pub public: bool,
    pub media: Vec<MediaView>,
    /// Upload progress for my posts with large attachments (0-1).
    pub progress: Option<f32>,
    pub upload_error: Option<String>,
}

/// What the UI needs to lay out embedded media (bytes are fetched separately).
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MediaView {
    pub kind: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub size: u64,
    pub name: Option<String>,
    /// Shown in the timeline (small media).
    pub inline: bool,
    /// Played through the local streaming URL (large audio/video).
    pub stream: bool,
    /// Metadata was removed by the sender's app.
    pub cleaned: bool,
    /// Still uploading (my drafts).
    pub pending: bool,
}

fn media_views(m: &[sentinel_core::media::MediaRef]) -> Vec<MediaView> {
    m.iter()
        // References that fail validation are never offered to the UI.
        .filter(|r| r.validate())
        .map(|r| MediaView {
            kind: r.kind.clone(),
            mime: r.mime.clone(),
            width: r.width,
            height: r.height,
            size: r.size,
            name: r.name.clone(),
            inline: r.inline(),
            stream: r.streamable() && !r.inline(),
            cleaned: r.cleaned,
            pending: false,
        })
        .collect()
}

/// Media of a post, including a draft's ready items and pending files.
fn post_media(p: &StoredPost) -> (Vec<MediaView>, Option<f32>, Option<String>) {
    let Some(d) = &p.draft else { return (media_views(&p.media), None, None) };
    let mut v = media_views(&d.ready);
    for j in &d.jobs {
        v.push(MediaView {
            kind: j.kind.clone(),
            mime: j.mime.clone(),
            width: j.width,
            height: j.height,
            size: j.len,
            name: Some(j.name.clone()),
            inline: false,
            stream: false,
            cleaned: j.cleaned,
            pending: true,
        });
    }
    let total: u64 = d.jobs.iter().map(|j| j.len.max(1)).sum();
    let done: f32 = d.jobs.iter().map(|j| j.progress() * j.len.max(1) as f32).sum();
    let err = d.jobs.iter().find_map(|j| j.error.clone());
    (v, Some(done / total.max(1) as f32), err)
}

/// Bridges to use: my private ones if I have any, else the built-in set.
fn bridges_for(store: &Store) -> Result<Vec<String>> {
    if !store.custom_bridges.is_empty() {
        return Ok(store.custom_bridges.clone());
    }
    sentinel_net::builtin_pt::builtin_bridges(&store.bridges_set)
}

fn handle_of(author: &str) -> String {
    author.chars().take(8).collect()
}

async fn request(stream: &mut Box<dyn Io>, req: &Request) -> Result<Response> {
    request_timeout(stream, req, REQUEST_TIMEOUT).await
}

/// `request` with a custom timeout (for requests the node must forward,
/// e.g. pin payments it redeems at the mint).
async fn request_timeout(stream: &mut Box<dyn Io>, req: &Request, t: Duration) -> Result<Response> {
    tokio::time::timeout(t, async {
        write_message(stream, &wire::encode(req)).await?;
        let bytes = read_message(stream).await?;
        wire::decode(&bytes).context("malformed response")
    })
    .await
    .context("request timed out")?
}

impl Core {
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        f(&mut self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    fn unlocked(&self) -> Result<(Keys, Store)> {
        self.with(|i| match (&i.key, &i.store) {
            (Some(k), Some(s)) => Ok((k.clone(), s.clone())),
            _ => Err(anyhow!("locked")),
        })
    }

    /// Mutate the store and persist it.
    fn update(&self, f: impl FnOnce(&mut Store)) -> Result<()> {
        self.with(|i| {
            let (Some(k), Some(s)) = (&i.key, &mut i.store) else { bail!("locked") };
            f(s);
            save_store(k, s)
        })
    }

    pub fn status(&self) -> StatusView {
        let initialized = identity_path().map(|p| p.exists()).unwrap_or(false);
        self.with(|i| {
            let me = i.key.as_ref().map(|k| social::author_text(&k.verifying_key().to_bytes()));
            let store = i.store.as_ref();
            let link = match (&i.key, store.and_then(|s| s.pillar.clone())) {
                (Some(k), Some(p)) => Some(
                    FollowLink { author: k.verifying_key().to_bytes(), pillar: p, feed_key: store.and_then(|s| s.feed_key) }
                        .to_text(),
                ),
                _ => None,
            };
            StatusView {
                initialized,
                unlocked: i.key.is_some(),
                name: store.map(|s| s.name.clone()).unwrap_or_default(),
                handle: me.as_deref().map(handle_of).unwrap_or_default(),
                mode: store.map(|s| s.mode.clone()).unwrap_or_default(),
                pillar: store.and_then(|s| s.pillar.clone()),
                link,
                following: store.map(|s| s.following.len()).unwrap_or(0),
                net: i.status.clone(),
                privacy: store.map(|s| s.privacy.clone()),
                followers: store.and_then(|s| s.followers),
                hide_count: store.map(|s| s.hide_count).unwrap_or(false),
                topics: store.map(|s| s.topics.clone()).unwrap_or_default(),
                discover_default: store.map(|s| s.discover_default).unwrap_or(false),
                hosting: HostView {
                    enabled: store.map(|s| s.host).unwrap_or(false),
                    state: if i.host_state.is_empty() { "off".into() } else { i.host_state.clone() },
                    used_mb: i.hosted.as_ref().map(|h| h.stats.used_bytes.load(std::sync::atomic::Ordering::Relaxed) / 1_000_000).unwrap_or(0),
                    served: i.hosted.as_ref().map(|h| h.stats.served.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0),
                    error: i.host_error.clone(),
                    archive_gb: store.map(|s| s.host_archive_gb).unwrap_or(0),
                    self_seed: store.is_some_and(|s| s.self_seed),
                    chunks_mb: i.hosted.as_ref().map(|h| h.stats.chunk_bytes.load(std::sync::atomic::Ordering::Relaxed) / 1_000_000).unwrap_or(0),
                },
                stream_token: self.stream_token.clone(),
                has_avatar: store.is_some_and(|s| s.avatar.is_some()),
                credits: store.map(wallet::balance).unwrap_or(0),
                credits_pending: store.map(|s| s.pending_parts.len()).unwrap_or(0),
                keyfile: i.keyfile.is_some(),
                keyfile_chosen: i.chosen_keyfile.as_ref().map(|(_, n)| n.clone()),
                linking: store.and_then(|s| s.link_join.as_ref().map(|j| j.check.clone())),
                platform: std::env::consts::OS.into(),
            }
        })
    }

    pub fn create_account(&self, name: &str, pass: &str, mode: &str) -> Result<()> {
        // Everything comes from new recovery words: the identity (generation
        // 0), the feed key and the recovery key.
        self.create_from(sentinel_core::recovery::RecoverySecret::generate(), name, pass, mode, false)
    }

    pub fn unlock(&self, pass: &str) -> Result<()> {
        let id_path = identity_path()?;
        let file = std::fs::read(&id_path).context("no account on this device")?;
        // The key file chosen on this screen, if any. A wrong or missing one
        // fails exactly like a wrong passphrase (nothing says one is needed).
        let keyfile = self.with(|i| i.chosen_keyfile.as_ref().map(|(d, _)| d.clone()));
        let root = match identity::open_any(&file, pass.as_bytes(), keyfile.as_deref()).map_err(|_| anyhow!("Wrong passphrase or key file."))? {
            identity::Opened::Real(k) => {
                identity::equalize_unlock_time();
                self.with(|i| {
                    i.keyfile = keyfile.clone();
                    i.chosen_keyfile = None;
                });
                k
            }
            // The emergency passphrase: wipe the real account and open an
            // empty one, exactly as if this were a normal unlock. The empty
            // account never uses a key file.
            identity::Opened::Emergency(decoy) => {
                self.with(|i| i.chosen_keyfile = None);
                self.panic_wipe()?;
                return self.create_account(&decoy.name, pass, if decoy.bridges { "bridges" } else { "tor" });
            }
        };
        // Older key files get the (empty) emergency slot, so every file
        // looks the same whether or not an emergency passphrase is set.
        if identity::needs_upgrade(&file) {
            if let Ok(sealed) = identity::reseal(&file, &root, pass.as_bytes(), keyfile.as_deref()) {
                let tmp = id_path.with_extension("tmp");
                if std::fs::write(&tmp, sealed).is_ok() {
                    let _ = std::fs::rename(&tmp, &id_path);
                }
            }
        }
        let mut store = load_store(&root)?;
        let key = Keys::new(root, &store);
        // Rooms joined but never given their details: re-scan their Pillar
        // (earlier blobs may have been skipped before the room was known).
        let stale: Vec<String> = store.rooms.iter().filter(|r| r.admin.is_none() && r.info_version == 0).map(|r| format!("{}|", r.pillar)).collect();
        let rescan = !stale.is_empty();
        store.mail_cursors.retain(|k, _| !stale.iter().any(|p| k.starts_with(p)));
        let missing_room_keys = store.rooms.iter().any(|r| r.member_secret.is_none());
        for r in store.rooms.iter_mut().filter(|r| r.member_secret.is_none()) {
            r.member_secret = Some(sentinel_core::random_bytes::<32>());
            r.needs_hello = true;
        }
        let migrated = wallet::migrate(&mut store);
        if store.feed_key.is_none() || store.dm.is_none() || missing_room_keys || rescan || migrated {
            ensure_keys(&key, &mut store);
            save_store(&key, &store)?;
        }
        let local = local::LocalChunks::open(&key)?;
        if store.privacy.high_risk {
            local.clear_cache();
        } else {
            local.trim_cache();
        }
        self.with(|i| {
            i.key = Some(key);
            i.store = Some(store);
            i.local = Some(local);
        });
        let _ = self.purge_expired();
        Ok(())
    }

    pub fn lock(&self) {
        self.with(|i| {
            if let Some(h) = i.refresher.take() {
                h.abort();
            }
            i.pool = None;
            i.net = None;
            i.tor_proc = None; // ends the Tor process (frees its files)
            i.store = None;
            i.key = None; // SigningKey zeroizes on drop
            apps::forget_states();
            i.status = NetStatus { state: "idle".into(), ..Default::default() };
            i.hosted = None; // stops the hosted Pillar
            i.host_state = String::new();
            if let Some(h) = i.uploader.take() {
                h.abort();
            }
            if let Some(h) = i.cover.take() {
                h.abort();
            }
            if let Some(h) = i.auditor.take() {
                h.abort();
            }
            if let Some(h) = i.updater.take() {
                h.abort();
            }
            for c in i.transfers.values() {
                c.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            i.transfers.clear();
            i.sessions.clear();
            // Sanitised attachments and the local chunk key go too.
            i.attachments.clear();
            i.local = None;
            i.keyfile = None;
            i.chosen_keyfile = None;
        });
    }

    fn set_status(&self, app: &AppHandle, state: &str, frac: f32, text: String) {
        let st = NetStatus { state: state.into(), frac, text };
        self.with(|i| i.status = st.clone());
        let _ = app.emit("net", st);
    }

    /// Start Tor (if not already), then the pool, profile, outbox and the
    /// fixed-schedule refresher.
    pub async fn connect(self: &Arc<Self>, app: AppHandle) -> Result<()> {
        if self.with(|i| i.net.is_some() || i.status.state == "connecting") {
            return Ok(());
        }
        let (_, store) = self.unlocked()?;
        let bridges = if store.mode == "bridges" {
            Some(bridges_for(&store)?)
        } else {
            sentinel_net::builtin_pt::remove_builtin_pt();
            None
        };
        self.set_status(&app, "connecting", 0.0, "Starting Tor on this device".into());
        let progress_app = app.clone();
        let progress_core = Arc::clone(self);
        // If Tor stops on its own later, say so (and drop the connection).
        let exit_core = Arc::clone(self);
        let exit_app = app.clone();
        let started = crate::torproc::spawn(
            &role(),
            bridges,
            move |frac, text| progress_core.set_status(&progress_app, "connecting", frac, text),
            move |id, err| {
                let gone = exit_core.with(|i| {
                    if i.tor_proc.as_ref().map(|t| t.id) != Some(id) {
                        return false;
                    }
                    i.tor_proc = None;
                    i.net = None;
                    i.pool = None;
                    true
                });
                if gone {
                    exit_core.set_status(&exit_app, "error", 0.0, format!("Tor stopped: {}", err.unwrap_or_else(|| "unexpectedly".into())));
                }
            },
        )
        .await;
        let net = match started {
            Ok((proc_, n)) => {
                self.with(|i| i.tor_proc = Some(proc_));
                n
            }
            Err(e) => {
                self.set_status(&app, "error", 0.0, format!("Couldn't connect: {e}"));
                return Err(e);
            }
        };
        self.with(|i| i.net = Some(net.clone()));
        // My Pillar may have gone away since last time: if it doesn't
        // answer, pick again (Pillars that worked lately, like the backup,
        // are tried first; a Pillar that was only slow stays in that race).
        if let Some(p) = self.unlocked().ok().and_then(|(_, s)| s.pillar) {
            self.set_status(&app, "connecting", 0.95, "Checking your Pillar".into());
            let probe = async {
                let mut s = net.connect_hedged(&p).await?;
                anyhow::Ok(matches!(request(&mut s, &Request::Ping).await?, Response::Pong))
            };
            let answered = matches!(tokio::time::timeout(Duration::from_secs(45), probe).await, Ok(Ok(true)));
            let today = directory::today();
            let _ = self.update(|s| {
                directory::record(s, &[(p.clone(), answered)], today);
                if !answered && s.pillar.as_ref() == Some(&p) {
                    sentinel_net::note(format!("Sentinel: my Pillar {}… didn't answer; picking another", &p[..6.min(p.len())]));
                    s.pillar = None;
                    s.replicas.retain(|r| *r != p);
                }
            });
        }
        // Pick Pillars automatically the first time (no addresses to paste),
        // or when mine is gone.
        if self.unlocked().map(|(_, s)| s.pillar.is_none()).unwrap_or(false) {
            // A Pillar can be briefly unreachable (just started, or its
            // onion address still being published): keep trying for a while.
            let mut last = None;
            for attempt in 0..6 {
                let text = match (&last, attempt) {
                    (_, 0) => "Finding Pillars".to_string(),
                    (Some(e), _) => format!("Finding Pillars (still trying, try {}) — last problem: {e:#}", attempt + 1),
                    (None, _) => "Finding Pillars (still trying)".to_string(),
                };
                self.set_status(&app, "connecting", 0.95, text);
                sentinel_net::note(format!("Sentinel: finding Pillars, try {}", attempt + 1));
                // A hard limit on the whole try, whatever happens inside it.
                let found = match tokio::time::timeout(Duration::from_secs(240), self.auto_select_pillars(&net)).await {
                    Ok(r) => r,
                    Err(_) => Err(anyhow!("finding Pillars took more than 4 minutes")),
                };
                if let Err(e) = &found {
                    sentinel_net::note(format!("Sentinel: try {} failed: {e:#}", attempt + 1));
                }
                match found {
                    Ok(rest) => {
                        last = None;
                        // Connected: a backup Pillar is looked for quietly
                        // in the background, never holding up the start.
                        let core = Arc::clone(self);
                        let net2 = net.clone();
                        tauri::async_runtime::spawn(async move {
                            core.find_backup(&net2, rest).await;
                            core.refresh_vouched(&net2).await;
                        });
                        break;
                    }
                    Err(e) => {
                        last = Some(e);
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
            if let Some(e) = last {
                self.set_status(&app, "error", 0.0, format!("Couldn't reach any Pillar: {e}"));
                self.with(|i| i.net = None);
                return Err(e);
            }
        }
        self.start_pool();
        self.set_status(&app, "ready", 1.0, "Connected privately".into());
        if self.unlocked().map(|(_, s)| s.host && !s.privacy.high_risk).unwrap_or(false) {
            let core = Arc::clone(self);
            let app2 = app.clone();
            tauri::async_runtime::spawn(async move {
                let _ = core.resume_hosting(&app2).await;
            });
        }

        let uploader = tauri::async_runtime::spawn(Arc::clone(self).run_uploader(app.clone()));
        let cover = tauri::async_runtime::spawn(Arc::clone(self).run_cover_traffic());
        let auditor = tauri::async_runtime::spawn(Arc::clone(self).run_auditor());
        let updater = tauri::async_runtime::spawn(Arc::clone(self).run_update_checks(app.clone()));
        {
            let core = Arc::clone(self);
            tauri::async_runtime::spawn(async move {
                let _ = core.catch_up_generation().await;
            });
        }
        let core = Arc::clone(self);
        let refresher = tauri::async_runtime::spawn(async move {
            loop {
                let t = tokio::time::Instant::now();
                sentinel_net::note("Sentinel: sync pass started");
                core.sync_once(&app).await;
                sentinel_net::note(format!("Sentinel: sync pass finished in {}s", t.elapsed().as_secs()));
                tokio::time::sleep(REFRESH_EVERY).await;
            }
        });
        self.with(|i| {
            i.refresher = Some(refresher);
            i.uploader = Some(uploader);
            i.cover = Some(cover);
            i.auditor = Some(auditor);
            if let Some(old) = i.updater.replace(updater) {
                old.abort();
            }
        });
        Ok(())
    }

    /// Deposit into a mailbox shard on `pillar`: directly, or mixed through
    /// two other Pillars with random delays when mixing is on (High-risk
    /// mode, or the setting). Mixed deposits count as sent once the first
    /// Pillar took them.
    pub(crate) async fn deposit(&self, net: &Net, pillar: &str, shard: u16, blob: Vec<u8>, nonce: u64) -> Result<()> {
        let started = tokio::time::Instant::now();
        let short = pillar.chars().take(6).collect::<String>();
        // A limit on the whole attempt: one that hangs (a Pillar restarting,
        // a circuit that stalls) fails and is retried on the next sync,
        // instead of holding the message for many minutes.
        let r = match tokio::time::timeout(Duration::from_secs(240), self.deposit_inner(net, pillar, shard, blob, nonce)).await {
            Ok(r) => r,
            Err(_) => Err(anyhow!("no answer within 4 minutes")),
        };
        match &r {
            Ok(true) => sentinel_net::note(format!("Sentinel: delivered to Pillar {short}… in {}s", started.elapsed().as_secs())),
            Ok(false) => sentinel_net::note(format!("Sentinel: message for Pillar {short}… handed on in {}s (it will be delivered when that Pillar answers)", started.elapsed().as_secs())),
            Err(e) => sentinel_net::note(format!("Sentinel: delivery to Pillar {short}… failed after {}s: {e:#}", started.elapsed().as_secs())),
        }
        r.map(|_| ())
    }

    /// Ok(true): delivered straight to its Pillar; Ok(false): handed to
    /// another Pillar (mixing, or the destination didn't answer).
    async fn deposit_inner(&self, net: &Net, pillar: &str, shard: u16, blob: Vec<u8>, nonce: u64) -> Result<bool> {
        let (_, store) = self.unlocked()?;
        if store.privacy.mix || store.privacy.high_risk {
            match self.mix_route(net, &store, pillar).await {
                Ok(route) if !route.is_empty() => {
                    let packet = sentinel_core::mix::wrap(&route, sentinel_core::mix::Step::Deliver { pillar: pillar.to_owned(), shard, blob, nonce }).context("message too large to mix")?;
                    let data = sentinel_core::mix::pow_data(&packet);
                    let pn = tokio::task::spawn_blocking(move || sentinel_core::pow::stamp(sentinel_core::mix::MIX_POW_DOMAIN, &data, sentinel_core::mix::MIX_POW_BITS)).await?;
                    let mut s = match net.connect_hedged(&route[0].0).await {
                        Ok(s) => s,
                        Err(e) => {
                            // Gone since its key was saved: pick another next time.
                            self.with(|i| i.mix_keys.remove(&route[0].0));
                            return Err(e);
                        }
                    };
                    return match request(&mut s, &Request::Mix { packet, nonce: pn }).await? {
                        Response::Pong => Ok(false),
                        other => bail!("not taken: {other:?}"),
                    };
                }
                // Not enough mixing Pillars known yet: wait rather than send unmixed.
                _ => bail!("waiting for mixing Pillars"),
            }
        }
        // Straight to the destination...
        let direct = tokio::time::timeout(Duration::from_secs(45), async {
            let mut s = net.connect_hedged(pillar).await?;
            match request(&mut s, &Request::Deposit { shard, blob: blob.clone(), nonce }).await? {
                Response::Pong => Ok(()),
                other => bail!("not delivered: {other:?}"),
            }
        })
        .await;
        if matches!(direct, Ok(Ok(()))) {
            return Ok(true);
        }
        // ...or, if it doesn't answer, handed to another Pillar that keeps
        // trying for days: the message leaves this device now, and I can go
        // offline (sealed: that Pillar can't read it or tell who sent it).
        let via = self.mix_route(net, &store, pillar).await?;
        let (onion, key) = &via[0];
        let packet = sentinel_core::mix::handoff(key, sentinel_core::mix::Step::Deliver { pillar: pillar.to_owned(), shard, blob, nonce }).context("message too large to hand over")?;
        let data = sentinel_core::mix::pow_data(&packet);
        let pn = tokio::task::spawn_blocking(move || sentinel_core::pow::stamp(sentinel_core::mix::MIX_POW_DOMAIN, &data, sentinel_core::mix::MIX_POW_BITS)).await?;
        let mut s = net.connect_hedged(onion).await?;
        match request(&mut s, &Request::Mix { packet, nonce: pn }).await? {
            Response::Pong => {
                sentinel_net::note(format!("Sentinel: Pillar {}… didn't answer; handed the message to Pillar {}… to deliver", &pillar[..6.min(pillar.len())], &onion[..6.min(onion.len())]));
                Ok(false)
            }
            other => bail!("not taken: {other:?}"),
        }
    }

    /// Two Pillars (other than the destination) and their mix keys, picked
    /// at random among the ones I know, those that answered lately first.
    /// Missing keys are fetched a few Pillars at a time, each with a time
    /// limit, so gone Pillars in the directory never hold a message up.
    async fn mix_route(&self, net: &Net, store: &Store, dest: &str) -> Result<Vec<(String, sentinel_core::mix::MixKey)>> {
        let today = directory::today();
        let pool: Vec<String> = directory::order(&[], &sentinel_net::seed_pillars(), &store.known_pillars, &store.vouched_pillars, &store.pillar_health, None, today)
            .into_iter()
            .filter(|p| p.as_str() != dest)
            .collect();
        let mut route: Vec<(String, sentinel_core::mix::MixKey)> = Vec::new();
        for p in &pool {
            if route.len() == 2 {
                break;
            }
            if let Some(k) = self.with(|i| i.mix_keys.get(p).cloned()) {
                route.push((p.clone(), k));
            }
        }
        let missing: Vec<String> = pool.into_iter().filter(|p| !route.iter().any(|(r, _)| r == p)).collect();
        let mut outcomes: Vec<(String, bool)> = Vec::new();
        for batch in missing.chunks(6) {
            if route.len() >= 2 {
                break;
            }
            let probes = batch.iter().map(|p| async move {
                let r = tokio::time::timeout(Duration::from_secs(45), async {
                    let mut s = net.connect_hedged(p).await?;
                    anyhow::Ok(match request(&mut s, &Request::MixKey).await? {
                        Response::Object(b) => sentinel_core::mix::MixKey::decode(&b),
                        _ => None,
                    })
                })
                .await;
                (p.clone(), r.ok().and_then(Result::ok).flatten())
            });
            for (p, k) in futures::future::join_all(probes).await {
                outcomes.push((p.clone(), k.is_some()));
                if let Some(k) = k {
                    self.with(|i| i.mix_keys.insert(p.clone(), k.clone()));
                    if route.len() < 2 {
                        route.push((p, k));
                    }
                }
            }
        }
        if !outcomes.is_empty() {
            let _ = self.update(|s| directory::record(s, &outcomes, today));
        }
        // One hop still separates the timing; none would not.
        if route.is_empty() {
            bail!("no mixing Pillar reachable");
        }
        Ok(route)
    }

    pub(crate) fn start_pool(&self) {
        self.with(|i| {
            if let (Some(net), Some(p)) = (&i.net, i.store.as_ref().and_then(|s| s.pillar.clone())) {
                i.pool = Some(Arc::new(Pool::spawn(net.clone(), p, 2)));
            }
        });
    }

    /// One sync pass: publish profile, flush the outbox, fetch followed accounts.
    async fn sync_once(self: &Arc<Self>, app: &AppHandle) {
        // A new device waiting to be linked: only its request and the answer.
        if self.unlocked().is_ok_and(|(_, s)| s.link_join.is_some()) {
            let _ = self.link_send_request().await;
            let _ = self.poll_mail().await;
            if self.unlocked().is_ok_and(|(_, s)| s.link_join.is_none()) {
                // Linked: work from the account's home Pillar from now on.
                self.start_pool();
                let _ = app.emit("status", ());
            }
            return;
        }
        let _ = self.apply_device_sync(app);
        if self.purge_expired().unwrap_or(false) {
            let _ = app.emit("messages", ());
            let _ = app.emit("rooms", ());
        }
        // Messages first: they're what people wait on. The steps don't
        // depend on each other, so they run at the same time (each on its
        // own circuits), and a slow one doesn't hold up the rest.
        let (sent, _, paid, mail) = tokio::join!(self.retry_dms(), self.room_maintenance(), self.process_payments(app), self.poll_mail());
        if sent.unwrap_or(0) > 0 {
            let _ = app.emit("messages", ());
        }
        if paid.unwrap_or(0) > 0 {
            let _ = app.emit("rooms", ());
            let _ = app.emit("status", ());
        }
        // One pass over my mailbox prefixes serves DMs and rooms alike.
        if let Ok((dms, rooms)) = mail {
            if dms > 0 {
                let _ = app.emit("messages", ());
            }
            if rooms > 0 {
                let _ = app.emit("rooms", ());
            }
        }
        let (_, _, flushed, refreshed, discovered, count, _, rewards) = tokio::join!(
            self.publish_profile(),
            self.publish_card(),
            self.flush_outbox(),
            self.refresh(),
            self.discover(),
            self.fetch_follower_count(),
            self.refresh_archives(),
            self.collect_rewards(),
        );
        if flushed > 0 || refreshed.unwrap_or(0) > 0 {
            let _ = app.emit("timeline", ());
        }
        if discovered.unwrap_or(0) > 0 {
            let _ = app.emit("discover", ());
        }
        if count.is_ok() || rewards.unwrap_or(0) > 0 {
            let _ = app.emit("status", ());
        }
    }

    /// High-risk cover traffic: dummy exchanges with my Pillar at random
    /// (exponentially distributed) intervals, mean ~20 s, with sizes drawn
    /// like real requests and replies. An observer of my connection sees a
    /// steady background instead of bursts that line up with what I do.
    async fn run_cover_traffic(self: Arc<Self>) {
        loop {
            let u = (u32::from_le_bytes(sentinel_core::random_bytes::<4>()) as f64 + 1.0) / (u32::MAX as f64 + 2.0);
            let wait = (-u.ln() * 20.0).clamp(1.0, 120.0);
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
            let active = self.with(|i| i.store.as_ref().is_some_and(|s| s.privacy.high_risk));
            let Some(pool) = self.with(|i| i.pool.clone()) else { continue };
            if !active {
                continue;
            }
            let r = sentinel_core::random_bytes::<4>();
            let pad_len = [0usize, 900, 3_000, 16_000, 60_000][r[0] as usize % 5] + (r[1] as usize * 7);
            let reply = [0u32, 2_000, 8_000, 64_000, 200_000][r[2] as usize % 5] + r[3] as u32 * 13;
            if let Ok(mut s) = pool.take().await {
                let _ = request(&mut s, &Request::Noise { pad: vec![0u8; pad_len], reply }).await;
            }
        }
    }

    /// Delete messages whose disappearing timer has run out: the sender's
    /// timer, or mine (7 days) for everything when the setting is on.
    /// Returns whether anything was deleted.
    pub fn purge_expired(&self) -> Result<bool> {
        let now = social::coarse_minute();
        let mut changed = false;
        self.update(|s| {
            let mine = s.privacy.disappearing.then_some(DISAPPEAR_DAYS);
            let expired = |minute: u64, days: Option<u16>| {
                let d = match (days, mine) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                d.is_some_and(|d| minute + d as u64 * 1440 < now)
            };
            for c in &mut s.conversations {
                let before = c.messages.len();
                c.messages.retain(|m| !expired(m.minute, m.expire_days) || (m.mine && !m.sent));
                changed |= c.messages.len() != before;
            }
            for r in &mut s.rooms {
                let before = r.messages.len();
                r.messages.retain(|m| !expired(m.minute, None) || (m.mine && !m.sent));
                changed |= r.messages.len() != before;
            }
        })?;
        Ok(changed)
    }

    /// Learn Archives from my Pillar's directory (every 6 hours).
    async fn refresh_archives(&self) -> Result<()> {
        let (_, store) = self.unlocked()?;
        if !store.known_archives.is_empty() && social::coarse_minute().saturating_sub(store.archives_minute) < 6 * 60 {
            return Ok(());
        }
        let pool = self.with(|i| i.pool.clone()).context("no Pillar configured")?;
        let mut s = pool.take().await?;
        if let Response::Pillars(list) = request(&mut s, &Request::Archives).await? {
            let list: Vec<String> = list.into_iter().filter_map(|a| social::valid_onion(&a)).take(50).collect();
            self.update(|st| {
                if !list.is_empty() {
                    st.known_archives = list;
                }
                st.archives_minute = social::coarse_minute();
            })?;
        }
        Ok(())
    }

    /// Fetch discovery shards (spec §10.4.2): the shards for subscribed
    /// topics, an equal number (min 2) of random cover shards, and the recent
    /// shard — each on its own isolated circuit. Filtering and ranking happen
    /// here on the device. Returns the number of new discovered posts.
    pub async fn discover(&self) -> Result<usize> {
        let (key, store) = self.unlocked()?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let pillar = store.pillar.clone().context("no Pillar configured")?;
        let me = social::author_text(&key.verifying_key().to_bytes());

        let mut real: Vec<u16> = Vec::new();
        for t in &store.topics {
            let s = social::topic_shard(t);
            if !real.contains(&s) {
                real.push(s);
            }
        }
        // Random cover shards so the node can't tell real interests apart.
        let mut cover: Vec<u16> = Vec::new();
        let want_cover = real.len().max(2);
        let mut guard = 0;
        while cover.len() < want_cover && guard < 1000 {
            guard += 1;
            let r = u16::from_le_bytes(sentinel_core::random_bytes::<2>()) % social::DISCOVERY_SHARDS;
            if !real.contains(&r) && !cover.contains(&r) {
                cover.push(r);
            }
        }
        // Shuffle request order so real and cover fetches interleave.
        let mut plan: Vec<(u16, bool)> =
            real.iter().map(|s| (*s, true)).chain(cover.iter().map(|s| (*s, false))).collect();
        plan.push((social::RECENT_SHARD, true));
        for i in (1..plan.len()).rev() {
            let j = (u32::from_le_bytes(sentinel_core::random_bytes::<4>()) as usize) % (i + 1);
            plan.swap(i, j);
        }

        let known: std::collections::HashSet<String> = store
            .discovered
            .iter()
            .map(|d| d.id.clone())
            .chain(store.posts.iter().map(|p| p.id.clone()))
            .chain(store.reported.iter().cloned())
            .collect();
        // Keys that can open discoverable posts: one per subscribed topic,
        // plus the explore key for undirected exploration.
        let mut reader_keys: Vec<[u8; 32]> =
            store.topics.iter().map(|t| social::reader_key_for_subscription(t)).collect();
        reader_keys.push(sentinel_core::seal::explore_key());
        let mut found: Vec<DiscoveredPost> = Vec::new();
        let mut found_rooms: Vec<DiscoveredRoom> = Vec::new();
        // Posts live on their authors' Pillars, so Discover also reads two
        // other Pillars each pass (ones that answered lately first): people
        // on different Pillars find each other. Cover buckets only on mine.
        let today = directory::today();
        let others: Vec<String> = directory::order(&[], &sentinel_net::seed_pillars(), &store.known_pillars, &store.vouched_pillars, &store.pillar_health, Some(&pillar), today)
            .into_iter()
            .filter(|p| *p != pillar)
            .take(2)
            .collect();
        let mut sources: Vec<(String, u16, bool)> = plan.iter().map(|(s, k)| (pillar.clone(), *s, *k)).collect();
        for o in &others {
            sources.extend(plan.iter().filter(|(_, k)| *k).map(|(s, _)| (o.clone(), *s, true)));
        }
        let fetches = sources.into_iter().map(|(src, shard, keep)| {
            let (net, known, reader_keys) = (net.clone(), &known, &reader_keys);
            async move {
                let r = tokio::time::timeout(std::time::Duration::from_secs(120), fetch_shard(&net, &src, shard, known, reader_keys)).await;
                (shard, keep, r.ok().and_then(Result::ok))
            }
        });
        for (shard, keep, got) in futures::future::join_all(fetches).await {
            let Some((posts, rooms)) = got else { continue };
            if !keep {
                continue; // cover traffic: fetched, then discarded
            }
            for r in rooms {
                let topical = r.topics.iter().any(|t| store.topics.iter().any(|mine| topic_matches(mine, t)));
                if (shard == social::RECENT_SHARD || topical) && !found_rooms.iter().any(|f| f.room_id == r.room_id) {
                    found_rooms.push(r);
                }
            }
            for p in posts {
                if p.author == me || found.iter().any(|f| f.id == p.id) {
                    continue;
                }
                let topical = p.topics.iter().any(|t| store.topics.iter().any(|mine| topic_matches(mine, t)));
                if shard != social::RECENT_SHARD && !topical {
                    continue; // another topic that happens to share this shard
                }
                found.push(DiscoveredPost { topical, ..p }); // keeps the Pillar it was found on
            }
        }
        let n = found.len();
        if n > 0 || !found_rooms.is_empty() {
            self.update(|s| {
                s.discovered.extend(found);
                s.discovered.sort_by(|a, b| b.minute.cmp(&a.minute));
                s.discovered.truncate(300);
                for r in found_rooms {
                    match s.discovered_rooms.iter_mut().find(|x| x.room_id == r.room_id) {
                        Some(x) if r.minute >= x.minute => *x = r,
                        Some(_) => {}
                        None => s.discovered_rooms.push(r),
                    }
                }
                s.discovered_rooms.sort_by(|a, b| b.minute.cmp(&a.minute));
                s.discovered_rooms.truncate(100);
            })?;
        }
        Ok(n)
    }

    /// Public rooms found in Discover (newest first).
    pub fn discovered_rooms(&self) -> Result<Vec<DiscoveredRoomView>> {
        let (_, store) = self.unlocked()?;
        Ok(store
            .discovered_rooms
            .iter()
            .map(|r| DiscoveredRoomView {
                id: r.room_id.clone(),
                name: r.name.clone(),
                description: r.description.clone(),
                topics: r.topics.clone(),
                access: r.access.clone(),
                price: r.price,
                link: r.link.clone(),
                joined: store.rooms.iter().any(|x| data_encoding::HEXLOWER.encode(&x.room_id) == r.room_id && !x.waiting),
                approval: sentinel_core::room::AskLink::parse(&r.link).is_some(),
                waiting: store.rooms.iter().any(|x| data_encoding::HEXLOWER.encode(&x.room_id) == r.room_id && x.waiting),
            })
            .collect())
    }

    /// Discovered posts, ranked locally: topical matches first, then
    /// freshness. Authors you already follow are left to the Home timeline.
    pub fn discovered(&self) -> Result<Vec<PostView>> {
        let (key, store) = self.unlocked()?;
        let me = social::author_text(&key.verifying_key().to_bytes());
        let now = social::coarse_minute();
        let mut items: Vec<(i64, PostView)> = store
            .discovered
            .iter()
            .filter(|d| d.author != me && !store.following.iter().any(|f| f.author == d.author))
            .filter(|d| !store.muted.contains(&d.author) && !store.blocked.contains(&d.author))
            .filter_map(|d| {
                let author = social::author_from_text(&d.author)?;
                let age_h = now.saturating_sub(d.minute) as i64 / 60;
                let score = if d.topical { 48 } else { 0 } - age_h;
                Some((
                    score,
                    PostView {
                        author: d.author.clone(),
                        avatar: false,
                        id: d.id.clone(),
                        name: handle_of(&d.author),
                        handle: handle_of(&d.author),
                        text: d.text.clone(),
                        minute: d.minute,
                        mine: false,
                        sent: true,
                        liked: store.liked.contains(&d.id),
                        topics: d.topics.clone(),
                        follow_link: Some(FollowLink { author, pillar: d.pillar.clone(), feed_key: None }.to_text()),
                        public: true,
                        media: media_views(&d.media),
                        progress: None,
                        upload_error: None,
                    },
                ))
            })
            .collect();
        items.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(items.into_iter().map(|(_, v)| v).collect())
    }

    pub fn add_topic(&self, raw: &str) -> Result<String> {
        let t = social::normalize_topic(raw).context("Topics use letters, numbers and dashes, like robotics or ai/llm.")?;
        self.update(|s| {
            if !s.topics.contains(&t) {
                s.topics.push(t.clone());
            }
        })?;
        Ok(t)
    }

    pub fn remove_topic(&self, topic: &str) -> Result<()> {
        self.update(|s| s.topics.retain(|t| t != topic))
    }

    /// Storage my hosted node offers others (GB; 0 = none). Takes effect
    /// when hosting restarts.
    /// Turn the Archive on (lending `gb`) or off (0). An Archive runs
    /// inside the Pillar, so this turns the Pillar on too. A running Pillar
    /// changes at once, without restarting.
    pub async fn set_archive(self: &Arc<Self>, app: AppHandle, gb: u32) -> Result<()> {
        if gb > 100_000 {
            bail!("That's more than 100 TB.");
        }
        let (_, store) = self.unlocked()?;
        if gb > 0 && store.privacy.high_risk {
            bail!("Archives are off in High-risk mode.");
        }
        self.update(|s| {
            s.host_archive_gb = gb;
            if gb == 0 {
                s.self_seed = false;
            } else {
                s.host = true;
            }
        })?;
        let running = self.with(|i| {
            if let Some(h) = &i.hosted {
                h.set_archive(gb);
                true
            } else {
                false
            }
        });
        if !running && gb > 0 {
            self.resume_hosting(&app).await?;
        }
        let _ = app.emit("status", ());
        Ok(())
    }

    /// Start the Pillar if the app is connected (otherwise it starts when
    /// it connects).
    async fn resume_hosting(self: &Arc<Self>, app: &AppHandle) -> Result<()> {
        if self.with(|i| i.net.is_some()) {
            self.start_hosting(app).await?;
        }
        Ok(())
    }

    pub fn set_self_seed(&self, on: bool) -> Result<()> {
        let (_, s) = self.unlocked()?;
        if on && s.privacy.high_risk {
            bail!("Self-seeding is off in High-risk mode.");
        }
        if on && (!s.host || s.host_archive_gb == 0) {
            bail!("Run a Pillar with Archive storage first.");
        }
        self.update(|s| s.self_seed = on)
    }

    pub fn set_hide_count(&self, hide: bool) -> Result<()> {
        self.update(|s| s.hide_count = hide)
    }

    /// Ask my own Pillar for my approximate follower count.
    async fn fetch_follower_count(&self) -> Result<()> {
        let (key, _) = self.unlocked()?;
        let pool = self.with(|i| i.pool.clone()).context("no Pillar configured")?;
        let mut s = pool.take().await?;
        let author = key.verifying_key().to_bytes();
        if let Response::Count(n) = request(&mut s, &Request::FollowerCount { author }).await? {
            self.update(|st| st.followers = Some(n))?;
        }
        Ok(())
    }

    /// Send an anonymous follow notice (spec §10.4.7) after a random delay,
    /// so the notice's timing doesn't line up with the follow action. Skipped
    /// in High-risk mode.
    fn send_follow_notice(&self, link: &FollowLink, follow: bool) {
        let Ok((key, store)) = self.unlocked() else { return };
        if store.privacy.high_risk {
            return;
        }
        let Some(net) = self.with(|i| i.net.clone()) else { return };
        let token = social::follow_token(&key, &link.author);
        let author = link.author;
        let pillar = link.pillar.clone();
        tauri::async_runtime::spawn(async move {
            let data = social::follow_pow_data(&author, &token, follow);
            let Ok(nonce) = tokio::task::spawn_blocking(move || {
                sentinel_core::pow::stamp(social::FOLLOW_POW_DOMAIN, &data, sentinel_core::pow::DEFAULT_BITS)
            })
            .await
            else {
                return;
            };
            let delay = u64::from(u16::from_le_bytes(sentinel_core::random_bytes::<2>())) % 45;
            tokio::time::sleep(Duration::from_secs(5 + delay)).await;
            if let Ok(mut s) = net.connect_hedged(&pillar).await {
                let _ = request(&mut s, &Request::FollowNotice { author, token, follow, nonce }).await;
            }
        });
    }

    async fn put(&self, bytes: Vec<u8>) -> Result<()> {
        let pool = self.with(|i| i.pool.clone()).context("no Pillar configured")?;
        // Copy to backup Pillars too (best effort, each on its own circuit),
        // so a post survives if the primary disappears.
        if let (Ok((_, store)), Some(net)) = (self.unlocked(), self.with(|i| i.net.clone())) {
            for replica in store.replicas {
                let (net, bytes) = (net.clone(), bytes.clone());
                tokio::spawn(async move {
                    if let Ok(mut s) = net.connect_hedged(&replica).await {
                        let _ = request(&mut s, &Request::Put(bytes)).await;
                    }
                });
            }
        }
        let mut s = pool.take().await?;
        match request(&mut s, &Request::Put(bytes)).await? {
            Response::Stored(_) => Ok(()),
            Response::Rejected(r) => bail!("Pillar rejected: {r}"),
            other => bail!("unexpected response: {other:?}"),
        }
    }

    /// Choose a Pillar automatically: try built-in seeds and cached
    /// directory entries in random order, a few at a time, and start with
    /// the first that answers, learning more of the directory along the way.
    /// Returns the candidates not tried yet (for [`Self::find_backup`]).
    /// Never picks this device's own hosted Pillar (that would let observers
    /// link the account to the Pillar's uptime).
    async fn auto_select_pillars(&self, net: &Net) -> Result<Vec<String>> {
        let (_, store) = self.unlocked()?;
        let own = self.with(|i| i.hosted.as_ref().map(|h| h.onion.clone()));
        let today = directory::today();
        // Typed-in addresses, then a mix of Pillars that worked lately,
        // vouched ones and seeds, then the rest (see `directory::order`).
        let mut candidates = directory::order(
            &self.with(|i| i.pillar_hints.clone()),
            &sentinel_net::seed_pillars(),
            &store.known_pillars,
            &store.vouched_pillars,
            &store.pillar_health,
            own.as_ref(),
            today,
        );
        let mut outcomes: Vec<(String, bool)> = Vec::new();

        // Probe a few candidates at once (each on its own circuit), so dead
        // entries in the directory don't make the first connection crawl.
        let mut chosen: Vec<String> = Vec::new();
        let mut learned: Vec<String> = Vec::new();
        // Why probes failed (shown on the connecting screen so a tester can say).
        let mut problems: Vec<String> = Vec::new();
        let mut i = 0;
        // One Pillar that answers is enough to start: the directory can list
        // Pillars that have since gone, and waiting for them only delays the
        // start (a backup is found in the background afterwards).
        while i < candidates.len() && chosen.is_empty() {
            let batch: Vec<String> = candidates[i..candidates.len().min(i + 6)].to_vec();
            i += batch.len();
            let probes = batch.iter().map(|c| async move {
                let started = tokio::time::Instant::now();
                sentinel_net::note(format!("Sentinel: trying Pillar {}…", &c[..6.min(c.len())]));
                let probe = async {
                    let mut s = net.connect_hedged(c).await?;
                    if !matches!(request(&mut s, &Request::Ping).await?, Response::Pong) {
                        bail!("not a Pillar");
                    }
                    if let Response::Pillars(list) = request(&mut s, &Request::Pillars).await? {
                        Ok(list)
                    } else {
                        Ok(Vec::new())
                    }
                };
                let r = tokio::time::timeout(Duration::from_secs(60), probe).await;
                let how = match &r {
                    Ok(Ok(_)) => "answered".to_string(),
                    Ok(Err(e)) => format!("failed: {e:#}"),
                    Err(_) => "no answer within 60 seconds".to_string(),
                };
                sentinel_net::note(format!("Sentinel: Pillar {}… {how} after {}s", &c[..6.min(c.len())], started.elapsed().as_secs()));
                (c.clone(), r)
            });
            for (c, r) in futures::future::join_all(probes).await {
                outcomes.push((c.clone(), matches!(r, Ok(Ok(_)))));
                let list = match r {
                    Ok(Ok(list)) => list,
                    Ok(Err(e)) => {
                        problems.push(format!("{e:#}").chars().take(160).collect());
                        continue;
                    }
                    Err(_) => {
                        problems.push("no answer within 60 seconds".into());
                        continue;
                    }
                };
                if chosen.len() < 2 {
                    chosen.push(c);
                }
                for p in list {
                    if check_onion(&p).is_ok() && !candidates.contains(&p) && Some(&p) != own.as_ref() {
                        learned.push(p.clone());
                        candidates.push(p);
                    }
                }
            }
        }
        if chosen.is_empty() {
            let _ = self.update(|s| directory::record(s, &outcomes, today));
            match problems.first() {
                Some(p) => bail!("no Pillars answered ({} tried; {p})", problems.len()),
                None => bail!("no Pillars answered"),
            }
        }
        self.update(|s| {
            s.pillar = Some(chosen[0].clone());
            s.replicas = chosen[1..].to_vec();
            for p in learned {
                if !s.known_pillars.contains(&p) {
                    s.known_pillars.push(p);
                }
            }
            s.known_pillars.truncate(200);
            s.profile_published = false;
            directory::record(s, &outcomes, today);
        })?;
        Ok(candidates.into_iter().skip(i).filter(|c| !chosen.contains(c)).collect())
    }

    /// After connecting: find one backup Pillar among `candidates` (a few at
    /// a time, each on its own circuit), for copies of posts and as a
    /// fallback. Pillars that don't answer are just skipped.
    async fn find_backup(&self, net: &Net, candidates: Vec<String>) {
        if self.unlocked().map(|(_, s)| !s.replicas.is_empty()).unwrap_or(true) {
            return;
        }
        for batch in candidates.chunks(6) {
            let probes = batch.iter().map(|c| async move {
                let ok = tokio::time::timeout(Duration::from_secs(60), async {
                    let mut s = net.connect_hedged(c).await?;
                    anyhow::Ok(matches!(request(&mut s, &Request::Ping).await?, Response::Pong))
                })
                .await;
                (c.clone(), matches!(ok, Ok(Ok(true))))
            });
            let results = futures::future::join_all(probes).await;
            let _ = self.update(|s| directory::record(s, &results, directory::today()));
            if let Some((c, _)) = results.into_iter().find(|(_, ok)| *ok) {
                sentinel_net::note(format!("Sentinel: backup Pillar {}… found", &c[..6.min(c.len())]));
                let _ = self.update(|s| {
                    if s.replicas.is_empty() && s.pillar.as_ref() != Some(&c) {
                        s.replicas.push(c.clone());
                    }
                });
                return;
            }
        }
    }

    /// Start (or restart) this device's Pillar on its own Tor client, with
    /// separate state and guards from the user's account.
    pub async fn start_hosting(self: &Arc<Self>, app: &AppHandle) -> Result<()> {
        if cfg!(any(target_os = "android", target_os = "ios")) {
            bail!("Phones can't run a Pillar.");
        }
        let (_, store) = self.unlocked()?;
        if store.privacy.high_risk {
            bail!("Running a Pillar is disabled in High-risk mode.");
        }
        // One start at a time (connecting and a settings switch can race).
        let claimed = self.with(|i| {
            if i.hosted.is_some() || i.host_state == "starting" {
                return false;
            }
            i.host_state = "starting".into();
            i.host_error = None;
            true
        });
        if !claimed {
            return Ok(());
        }
        let _ = app.emit("status", ());
        let result = async {
            let mut seeds = sentinel_net::seed_pillars();
            seeds.extend(store.pillar.iter().cloned());
            seeds.extend(store.replicas.iter().cloned());
            let cfg = crate::hostproc::HostConfig {
                role: format!("{}-host", role()),
                bridges: if store.mode == "bridges" { Some(bridges_for(&store)?) } else { None },
                seeds,
                archive_gb: store.host_archive_gb,
                mints: wallet::mints_of(&store),
                updates: updates::dir(),
            };
            // If the Pillar process stops on its own, say so.
            let core = Arc::clone(self);
            let app2 = app.clone();
            crate::hostproc::spawn(&cfg, move |id, err| {
                let stopped = core.with(|i| {
                    if i.hosted.as_ref().map(|h| h.id) != Some(id) {
                        return false;
                    }
                    i.hosted = None;
                    i.host_state = "error".into();
                    i.host_error = Some(err.unwrap_or_else(|| "Your Pillar stopped unexpectedly.".into()));
                    true
                });
                if stopped {
                    let _ = app2.emit("status", ());
                }
            })
            .await
        }
        .await;
        match result {
            Ok(p) => {
                // Settings may have changed while it was starting.
                let gb = self.unlocked().map(|(_, s)| s.host_archive_gb).unwrap_or(0);
                p.set_archive(gb);
                // Switched off (or locked) while it was starting: stop it.
                let wanted = self.unlocked().map(|(_, s)| s.host && !s.privacy.high_risk).unwrap_or(false);
                self.with(|i| {
                    if wanted {
                        i.hosted = Some(p);
                        i.host_state = "online".into();
                    } else {
                        i.host_state = "off".into();
                    }
                })
            }
            Err(e) => {
                self.with(|i| {
                    i.host_state = "error".into();
                    i.host_error = Some(e.to_string());
                });
                let _ = app.emit("status", ());
                return Err(e);
            }
        }
        let _ = app.emit("status", ());
        Ok(())
    }

    pub async fn set_hosting(self: &Arc<Self>, app: AppHandle, on: bool) -> Result<()> {
        let (_, store) = self.unlocked()?;
        if on && store.privacy.high_risk {
            bail!("Running a Pillar is disabled in High-risk mode.");
        }
        self.update(|s| {
            s.host = on;
            if !on {
                // The Archive lives inside the Pillar.
                s.host_archive_gb = 0;
                s.self_seed = false;
            }
        })?;
        if on {
            self.resume_hosting(&app).await?;
        } else {
            self.with(|i| {
                i.hosted = None;
                i.host_state = "off".into();
                i.host_error = None;
            });
        }
        let _ = app.emit("status", ());
        Ok(())
    }

    async fn publish_profile(&self) -> Result<()> {
        let (key, store) = self.unlocked()?;
        if store.profile_published || store.pillar.is_none() {
            return Ok(());
        }
        // Pictures first: the profile only points at stored chunks.
        if !store.profile_chunks.is_empty() {
            let hosts: Vec<String> = store.avatar.iter().chain(store.banner.iter()).flat_map(|m| m.archives.clone()).collect();
            let mut uniq: Vec<String> = Vec::new();
            for h in hosts {
                if !uniq.contains(&h) {
                    uniq.push(h);
                }
            }
            self.upload_profile_chunks(&store.profile_chunks, &uniq).await?;
        }
        let feed_key = store.feed_key.context("no feed key")?;
        let body = social::ProfileBody {
            name: store.name.clone(),
            bio: store.bio.clone(),
            avatar: store.avatar.clone(),
            banner: store.banner.clone(),
            recovery: store.recovery_pin,
            pq_key: Some(sentinel_core::pq::identity_dsa_public(&key)),
            ..Default::default()
        };
        let env = social::profile_envelope_full(&key, &feed_key, body).map_err(|e| anyhow!(e))?;
        self.put(env.encode()?).await?;
        self.update(|s| s.profile_published = true)
    }

    /// Upload any of my posts not yet confirmed (media chunks first). Returns
    /// how many posts were sent.
    async fn flush_outbox(&self) -> usize {
        let Ok((_, store)) = self.unlocked() else { return 0 };
        // Drafts (large uploads still running) have no envelope yet.
        let pending: Vec<(String, Vec<u8>, Vec<String>, Vec<String>)> = store
            .posts
            .iter()
            .filter(|p| p.mine && !p.sent && p.draft.is_none() && p.not_before <= unix_now())
            .filter_map(|p| {
                let mut hosts: Vec<String> = Vec::new();
                for h in p.media.iter().flat_map(|m| m.archives.iter()) {
                    if !hosts.contains(h) {
                        hosts.push(h.clone());
                    }
                }
                if hosts.is_empty() {
                    hosts.extend(store.pillar.iter().cloned());
                }
                Some((p.id.clone(), p.raw.clone()?, p.pending_chunks.clone(), hosts))
            })
            .collect();
        let mut sent = 0;
        for (id, raw, chunks, hosts) in pending {
            if !chunks.is_empty() && self.upload_chunks(&id, &chunks, &hosts).await.is_err() {
                continue; // retry on the next pass
            }
            if self.put(raw).await.is_ok() {
                sent += 1;
                let _ = self.update(|s| {
                    if let Some(p) = s.posts.iter_mut().find(|p| p.id == id) {
                        p.sent = true;
                        p.raw = None;
                    }
                });
            }
        }
        sent
    }

    pub fn publish(
        self: &Arc<Self>,
        app: AppHandle,
        text: &str,
        topics: &[String],
        discoverable: bool,
        approved_only: bool,
        attachments: &[String],
    ) -> Result<PostView> {
        let (key, store) = self.unlocked()?;
        // High-risk mode never offers posts to discovery (spec §10.4.1);
        // approved-followers posts are never discoverable.
        let discoverable = discoverable && !store.privacy.high_risk && !approved_only;
        // The key readers need: my link's feed key, or the approved
        // followers' key.
        let feed_key = if approved_only { self.circle_key()? } else { store.feed_key.context("no feed key")? };
        // Encrypt small media now (ciphertext kept only in the encrypted
        // outbox); large files become upload jobs.
        let (media, pending_chunks, jobs) = if attachments.is_empty() {
            (Vec::new(), Vec::new(), Vec::new())
        } else {
            self.take_attachments(attachments)?
        };
        if !jobs.is_empty() {
            return self.publish_draft(app, text, topics, discoverable, approved_only, media, pending_chunks, jobs);
        }
        let env = social::post_envelope_full(&key, &feed_key, text, topics, discoverable, media.clone())
            .map_err(|e| anyhow!(e))?;
        self.update(|s| s.discover_default = discoverable)?;
        let bytes = env.encode()?;
        let id = Address::of(&bytes).to_text();
        let body = match social::open_record(&env, &[feed_key]) {
            Some(social::Record::Post(p)) => p,
            _ => bail!("encoding post"),
        };
        let me = social::author_text(&key.verifying_key().to_bytes());
        let post = StoredPost {
            id: id.clone(),
            author: me.clone(),
            text: body.text,
            minute: body.minute,
            mine: true,
            sent: false,
            raw: Some(bytes),
            topics: body.topics.clone(),
            discoverable: body.discoverable,
            media,
            pending_chunks,
            approved_only,
            draft: None,
            // Discoverable posts (readable by anyone) also get a short random
            // delay, so arrival time is harder to tie to real-world events.
            not_before: if store.privacy.high_risk {
                high_risk_delay()
            } else if discoverable {
                unix_now() + 60 + u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % 240
            } else {
                0
            },
        };
        self.update(|s| s.posts.push(post.clone()))?;
        let core = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            if core.flush_outbox().await > 0 {
                let _ = app.emit("timeline", ());
            }
        });
        Ok(PostView {
            author: me.clone(),
            avatar: store.avatar.is_some(),
            id,
            name: store.name,
            handle: handle_of(&me),
            text: post.text,
            minute: post.minute,
            mine: true,
            sent: false,
            liked: false,
            topics: post.topics.clone(),
            follow_link: None,
            public: post.discoverable,
            media: media_views(&post.media),
            progress: None,
            upload_error: None,
        })
    }

    /// A post with large attachments: kept as a draft (text, ready media and
    /// upload jobs) until every chunk is stored, then sealed and sent.
    #[allow(clippy::too_many_arguments)]
    fn publish_draft(
        self: &Arc<Self>,
        app: AppHandle,
        text: &str,
        topics: &[String],
        discoverable: bool,
        approved_only: bool,
        ready: Vec<sentinel_core::media::MediaRef>,
        pending_chunks: Vec<String>,
        jobs: Vec<media_app::UploadJob>,
    ) -> Result<PostView> {
        let (key, store) = self.unlocked()?;
        let text = text.trim().to_owned();
        if text.chars().count() > social::MAX_POST_CHARS {
            bail!("post is too long");
        }
        // Validate topics now (the same rules the sealed post will apply).
        let mut norm = Vec::new();
        for t in topics {
            let t = social::normalize_topic(t).context("invalid topic")?;
            if !norm.contains(&t) {
                norm.push(t);
            }
        }
        if norm.len() > social::MAX_TOPICS {
            bail!("at most 3 topics");
        }
        let id = format!("draft-{}", data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<8>()));
        let me = social::author_text(&key.verifying_key().to_bytes());
        let post = StoredPost {
            id: id.clone(),
            author: me.clone(),
            text: text.clone(),
            minute: social::coarse_minute(),
            mine: true,
            sent: false,
            raw: None,
            topics: norm.clone(),
            discoverable,
            media: Vec::new(),
            pending_chunks,
            approved_only,
            draft: Some(media_app::Draft { text, topics: norm, discoverable, approved_only, ready, jobs }),
            not_before: 0,
        };
        self.update(|s| {
            s.discover_default = discoverable;
            s.posts.push(post.clone());
        })?;
        let _ = app.emit("timeline", ());
        let (media, progress, upload_error) = post_media(&post);
        Ok(PostView {
            author: me.clone(),
            avatar: store.avatar.is_some(),
            id,
            name: store.name,
            handle: handle_of(&me),
            text: post.text,
            minute: post.minute,
            mine: true,
            sent: false,
            liked: false,
            topics: post.topics,
            follow_link: None,
            public: post.discoverable,
            media,
            progress,
            upload_error,
        })
    }

    pub fn timeline(&self) -> Result<Vec<PostView>> {
        let (key, store) = self.unlocked()?;
        let me = social::author_text(&key.verifying_key().to_bytes());
        let hidden = |a: &String| store.muted.contains(a) || store.blocked.contains(a);
        let mut posts: Vec<PostView> = store
            .posts
            .iter()
            .filter(|p| p.author == me || !hidden(&p.author))
            .map(|p| {
                let name = if p.author == me {
                    store.name.clone()
                } else {
                    store
                        .following
                        .iter()
                        .find(|f| f.author == p.author)
                        .and_then(|f| f.name.clone())
                        .unwrap_or_else(|| handle_of(&p.author))
                };
                let (media, progress, upload_error) = post_media(p);
                PostView {
                    author: p.author.clone(),
                    avatar: if p.author == me { store.avatar.is_some() } else { store.following.iter().any(|f| f.author == p.author && f.avatar.is_some()) },
                    id: p.id.clone(),
                    name,
                    handle: handle_of(&p.author),
                    text: p.text.clone(),
                    minute: p.minute,
                    mine: p.mine,
                    sent: p.sent,
                    liked: store.liked.contains(&p.id),
                    topics: p.topics.clone(),
                    follow_link: None,
                    public: p.discoverable,
                    media,
                    progress,
                    upload_error,
                }
            })
            .collect();
        posts.sort_by(|a, b| b.minute.cmp(&a.minute));
        Ok(posts)
    }

    pub fn toggle_like(&self, id: &str) -> Result<()> {
        // Likes are private by default (spec §7): kept locally only.
        self.update(|s| {
            if let Some(pos) = s.liked.iter().position(|l| l == id) {
                s.liked.remove(pos);
            } else {
                s.liked.push(id.to_owned());
            }
        })
    }

    pub fn connection(&self) -> Result<ConnectionView> {
        let (_, s) = self.unlocked()?;
        Ok(ConnectionView { mode: s.mode.clone(), builtin: s.bridges_set.clone(), custom: s.custom_bridges.len() })
    }

    /// Change how Sentinel reaches Tor (takes effect at the next unlock).
    /// `custom`: None keeps my private bridges, Some(lines) replaces them.
    pub fn set_connection(&self, mode: &str, builtin: &str, custom: Option<Vec<String>>) -> Result<()> {
        if !matches!(mode, "tor" | "bridges") {
            bail!("unknown connection mode");
        }
        if !sentinel_net::builtin_pt::BUILTIN_SETS.contains(&builtin) {
            bail!("unknown built-in bridge set");
        }
        let mut lines = Vec::new();
        if let Some(c) = &custom {
            for l in c.iter().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                let l = l.strip_prefix("Bridge ").or_else(|| l.strip_prefix("bridge ")).unwrap_or(l).to_owned();
                sentinel_net::tor_config_with_bridges_check(&l).map_err(|_| anyhow!("Not a valid bridge line: {}", l.chars().take(40).collect::<String>()))?;
                if let Some(t) = sentinel_net::bridge_transport(&l) {
                    if !matches!(t.as_str(), "obfs4" | "webtunnel" | "snowflake" | "meek_lite") {
                        bail!("Unsupported bridge type: {t}");
                    }
                }
                lines.push(l);
            }
            if lines.len() > 50 {
                bail!("At most 50 bridges.");
            }
        }
        self.update(|s| {
            s.mode = mode.to_owned();
            s.bridges_set = builtin.to_owned();
            if custom.is_some() {
                s.custom_bridges = lines;
            }
        })
    }

    /// A Pillar address to try first while looking for Pillars (someone
    /// trusted runs it; the network's seeds may be down).
    pub fn add_pillar_hint(&self, onion: &str) -> Result<()> {
        let onion = check_onion(onion)?;
        self.with(|i| {
            if !i.pillar_hints.contains(&onion) {
                i.pillar_hints.push(onion);
            }
        });
        Ok(())
    }

    pub fn set_pillar(&self, onion: &str) -> Result<()> {
        let onion = check_onion(onion)?;
        self.update(|s| {
            s.pillar = Some(onion);
            s.profile_published = false;
        })?;
        self.start_pool();
        Ok(())
    }

    /// Screen security setting (on while locked or unknown).
    pub fn screen_security(&self) -> bool {
        self.with(|i| i.store.as_ref().is_none_or(|s| s.privacy.screen_security))
    }

    pub fn set_privacy(&self, key: &str, on: bool) -> Result<()> {
        let mut ok = true;
        self.update(|s| match key {
            "disappearing" => s.privacy.disappearing = on,
            "screenSecurity" => s.privacy.screen_security = on,
            "autoLock" => s.privacy.auto_lock = on,
            "mix" => s.privacy.mix = on,
            "highRisk" => {
                s.privacy.high_risk = on;
                if on {
                    s.host = false; // never host a Pillar in High-risk mode
                    s.self_seed = false;
                }
            }
            _ => ok = false,
        })?;
        if !ok {
            bail!("unknown setting");
        }
        if key == "highRisk" && on {
            self.with(|i| {
                i.hosted = None;
                i.host_state = "off".into();
                // Viewed media is no longer kept on disk in High-risk mode.
                if let Some(l) = &i.local {
                    l.clear_cache();
                }
            });
        }
        if key == "disappearing" && on {
            let _ = self.purge_expired();
        }
        Ok(())
    }

    /// Stop following someone (their posts stay until they expire). Their
    /// Pillar's anonymous follower count is told, like when following.
    pub fn unfollow(&self, author: &str) -> Result<()> {
        let (_, store) = self.unlocked()?;
        let f = store.following.iter().find(|f| f.author == author).cloned().context("You don't follow them.")?;
        self.update(|s| {
            s.following.retain(|x| x.author != author);
            s.posts.retain(|p| p.mine || p.author != author);
        })?;
        if let Some(a) = social::author_from_text(author) {
            self.send_follow_notice(&FollowLink { author: a, pillar: f.pillar, feed_key: f.feed_key }, false);
        }
        Ok(())
    }

    pub fn follow(self: &Arc<Self>, app: AppHandle, link: &str) -> Result<()> {
        let link = FollowLink::parse(link).context("That isn't a valid Sentinel follow link.")?;
        let (key, store) = self.unlocked()?;
        if link.author == key.verifying_key().to_bytes() {
            bail!("That's your own link.");
        }
        let author = social::author_text(&link.author);
        if let Some(existing) = store.following.iter().find(|f| f.author == author) {
            // Following again with a full link upgrades a key-less follow
            // (from Discover) so followers-only posts become readable.
            if existing.feed_key.is_none() && link.feed_key.is_some() {
                self.update(|s| {
                    if let Some(f) = s.following.iter_mut().find(|f| f.author == author) {
                        f.feed_key = link.feed_key;
                        f.cursor = 0; // re-read their history with the key
                    }
                })?;
            } else {
                bail!("You already follow them.");
            }
        } else {
            self.update(|s| {
                s.following.push(Followed {
                    author,
                    pillar: link.pillar.clone(),
                    name: None,
                    cursor: 0,
                    profile_minute: 0,
                    feed_key: link.feed_key,
                    card: None,
                    circle_keys: Vec::new(),
                    circle_state: String::new(),
                    bio: String::new(),
                    avatar: None,
                    banner: None,
                    recovery: None,
                    recovery_gen: 0,
                    moved_from: Vec::new(),
                    moved_notice: false,
                    pq_key: None,
                    cards: Vec::new(),
                })
            })?;
            self.send_follow_notice(&link, true);
        }
        let core = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            if core.refresh().await.unwrap_or(0) > 0 {
                let _ = app.emit("timeline", ());
            }
        });
        Ok(())
    }

    /// Fetch new posts, profiles and cards of everyone I follow.
    ///
    /// Private by design (spec §10.1): for each Pillar, I download whole
    /// **author buckets** (each shared by many accounts), never one
    /// account's list. A bucket is fetched on its own isolated circuit, in
    /// random order, with one random cover bucket when buckets are split.
    /// I choose the depth from my own bandwidth, never from anything the
    /// Pillar says: buckets split only when a round downloads too much.
    /// Returns the number of new posts.
    pub async fn refresh(&self) -> Result<usize> {
        let (_, store) = self.unlocked()?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let mut by_pillar: std::collections::HashMap<String, Vec<Followed>> = std::collections::HashMap::new();
        for f in store.following.iter().cloned() {
            by_pillar.entry(f.pillar.clone()).or_default().push(f);
        }
        // Several devices: also read my own posts and device cards.
        let (key, _) = self.unlocked()?;
        let me = social::author_text(&key.verifying_key().to_bytes());
        if let (false, Some(p)) = (store.my_devices.is_empty(), store.pillar.clone()) {
            by_pillar.entry(p.clone()).or_default().push(Followed {
                author: me.clone(),
                pillar: p,
                name: Some(store.name.clone()),
                cursor: store.self_cursor,
                profile_minute: 0,
                feed_key: store.feed_key,
                card: None,
                circle_keys: Vec::new(),
                circle_state: String::new(),
                bio: String::new(),
                avatar: None,
                banner: None,
                recovery: None,
                recovery_gen: 0,
                moved_from: Vec::new(),
                moved_notice: false,
                pq_key: Some(sentinel_core::pq::identity_dsa_public(&key)),
                cards: Vec::new(),
            });
        }
        let known: std::collections::HashSet<String> = store.posts.iter().map(|p| p.id.clone()).collect();
        let mut new_posts = 0;
        for (pillar, follows) in by_pillar {
            let bits = store.author_depth.get(&pillar).copied().unwrap_or(0).min(8);
            match read_author_buckets(&net, &pillar, bits, &store.author_cursor, &follows, &known).await {
                Ok(round) => {
                    new_posts += round.fetched.values().map(|a| a.posts.len()).sum::<usize>();
                    self.update(|s| {
                        for (k, v) in round.cursors {
                            s.author_cursor.insert(k, v);
                        }
                        if round.split && bits < 8 {
                            s.author_depth.insert(pillar.clone(), bits + 1);
                        }
                        for f in s.following.iter_mut().filter(|f| f.pillar == pillar && f.cursor == 0) {
                            if round.history_read.contains(&f.author) {
                                f.cursor = 1;
                            }
                        }
                        if round.history_read.contains(&me) {
                            s.self_cursor = 1;
                        }
                        let my_card = s.dm.as_ref().and_then(|d| d.last_card.as_ref().map(|c| c.olm_identity));
                        for (author, got) in round.fetched {
                            if author == me {
                                // My other devices: their cards, and posts made there.
                                for c in got.cards {
                                    if Some(c.olm_identity) != my_card {
                                        merge_card(&mut s.my_devices, c);
                                    }
                                }
                                for mut p in got.posts {
                                    if !s.posts.iter().any(|x| x.id == p.id) {
                                        p.mine = true;
                                        s.posts.push(p);
                                    }
                                }
                                continue;
                            }
                            apply_author_fetch(s, &author, got);
                        }
                    })?;
                }
                Err(e) => {
                    // Tried again on the next scheduled pass.
                    sentinel_net::note(format!("Sentinel: reading posts from Pillar {}… failed: {e:#}", &pillar[..6.min(pillar.len())]));
                    continue;
                }
            }
        }
        Ok(new_posts)
    }
}

/// Merge what was read for one followed account into the store.
fn apply_author_fetch(s: &mut Store, author: &str, mut got: AuthorFetch) {
    // Moves to a new key (checked against their pinned recovery key), in order.
    got.successions.sort_by_key(|x| x.gen);
    let mut author = author.to_owned();
    for m in std::mem::take(&mut got.successions) {
        let Some(entry) = s.following.iter_mut().find(|x| x.author == author) else { break };
        if m.gen <= entry.recovery_gen || social::author_from_text(&entry.author) != Some(m.old) {
            continue;
        }
        let new = social::author_text(&m.new);
        entry.moved_from.push(entry.author.clone());
        entry.author = new.clone();
        entry.recovery_gen = m.gen;
        entry.cursor = 0; // read the new key's history
        entry.card = None; // their new card comes under the new key
        entry.moved_notice = true;
        // Their new key's ML-DSA key came signed by their recovery key.
        entry.pq_key = m.new_pq.clone().filter(|k| k.len() == sentinel_core::pq::DSA_PUBLIC);
        // Their new feed key, if they passed it on (device lost). If not
        // (device taken), only their discoverable posts can be read until
        // they share a new follow link.
        entry.feed_key = entry.feed_key.and_then(|k| sentinel_core::recovery::open_feed(&m, &k));
        for c in s.conversations.iter_mut().filter(|c| c.author == author) {
            c.author = new.clone();
        }
        for p in s.posts.iter_mut().filter(|p| p.author == author) {
            p.author = new.clone();
        }
        author = new;
    }
    // Anything read under the old key in this round still belongs to them.
    for p in got.posts.iter_mut() {
        p.author = author.clone();
    }
    let author = author.as_str();
    for p in got.posts {
        if !s.posts.iter().any(|x| x.id == p.id) {
            s.posts.push(p);
        }
    }
    if let Some(entry) = s.following.iter_mut().find(|x| x.author == author) {
        for c in got.cards {
            merge_card(&mut entry.cards, c);
        }
        // The newest device card stays the default one.
        if let Some(c) = entry.cards.first() {
            if entry.card.as_ref().map_or(true, |old| c.minute >= old.minute) {
                entry.card = Some(c.clone());
            }
        }
        // The first recovery pin seen is kept: a thief with the account key
        // could publish a profile with their own, and it's ignored.
        if entry.recovery.is_none() {
            entry.recovery = got.profile.as_ref().and_then(|p| p.recovery);
        }
        if entry.pq_key.is_none() {
            entry.pq_key = got.profile.as_ref().and_then(|p| p.pq_key.clone()).filter(|k| k.len() == sentinel_core::pq::DSA_PUBLIC);
        }
        if let Some(pr) = got.profile {
            if pr.minute >= entry.profile_minute {
                entry.name = Some(pr.name);
                entry.profile_minute = pr.minute;
                entry.bio = pr.bio.chars().take(social::MAX_BIO_CHARS).collect();
                // Only well-formed small images are kept.
                entry.avatar = pr.avatar.filter(|m| m.validate() && m.inline() && m.kind == "image");
                entry.banner = pr.banner.filter(|m| m.validate() && m.inline() && m.kind == "image");
            }
        }
    }
}

#[derive(Default)]
struct AuthorFetch {
    posts: Vec<StoredPost>,
    profile: Option<social::ProfileBody>,
    cards: Vec<sentinel_core::social::ContactCard>,
    successions: Vec<sentinel_core::recovery::Succession>,
}

struct BucketRound {
    fetched: std::collections::HashMap<String, AuthorFetch>,
    /// New per-bucket positions ("pillar|bits|prefix" -> sequence).
    cursors: Vec<(String, u64)>,
    /// Accounts whose whole bucket history has now been read.
    history_read: Vec<String>,
    /// Too much for one round: read at a finer depth next time.
    split: bool,
}

/// Most bytes one refresh downloads from a Pillar before splitting buckets.
const BUCKET_ROUND_BYTES: usize = 8 * 1024 * 1024;
/// Positions are rounded down to this many objects when asking, so a
/// returning reader's position doesn't single them out.
const BUCKET_CURSOR_ROUND: u64 = 32;

fn bucket_key(pillar: &str, bits: u8, prefix: u8) -> String {
    format!("{pillar}|{bits}|{prefix}")
}

/// Where I am in a bucket. A finer bucket I haven't read yet starts where
/// its parent bucket had got to.
fn bucket_cursor(cursors: &std::collections::HashMap<String, u64>, pillar: &str, bits: u8, prefix: u8) -> u64 {
    let mut b = bits;
    let mut p = prefix;
    loop {
        if let Some(c) = cursors.get(&bucket_key(pillar, b, p)) {
            return *c;
        }
        if b == 0 {
            return 0;
        }
        b -= 1;
        p >>= 1;
    }
}

/// Read one Pillar's author buckets for the accounts I follow there.
async fn read_author_buckets(
    net: &Net,
    pillar: &str,
    bits: u8,
    cursors: &std::collections::HashMap<String, u64>,
    follows: &[Followed],
    known: &std::collections::HashSet<String>,
) -> Result<BucketRound> {
    let mut by_author: std::collections::HashMap<[u8; 32], &Followed> = std::collections::HashMap::new();
    for f in follows {
        if let Some(a) = social::author_from_text(&f.author) {
            by_author.insert(a, f);
        }
        // Their recovery key's bucket too: a move to a new key is filed there.
        if let Some(pin) = f.recovery {
            by_author.insert(pin.ed, f);
        }
    }
    // prefix -> (start position, accounts in it still needing history)
    let mut wanted: std::collections::BTreeMap<u8, (u64, Vec<String>)> = std::collections::BTreeMap::new();
    for (a, f) in &by_author {
        let p = social::bucket_prefix(social::author_bucket(a), bits);
        let e = wanted.entry(p).or_insert_with(|| (bucket_cursor(cursors, pillar, bits, p), Vec::new()));
        if f.cursor == 0 {
            e.0 = 0; // someone new here: read this bucket from the beginning, once
            e.1.push(f.author.clone());
        }
    }
    if bits > 0 {
        // One cover bucket, so the set of buckets I read isn't exact.
        let cover = (sentinel_core::random_bytes::<1>()[0] as u16 % (1u16 << bits)) as u8;
        // When a newly followed account's bucket is read from the start, the
        // cover bucket is too, so a full read doesn't single out a new follow.
        let fresh = by_author.values().any(|f| f.cursor == 0);
        let e = wanted.entry(cover).or_insert_with(|| (bucket_cursor(cursors, pillar, bits, cover), Vec::new()));
        if fresh {
            e.0 = 0;
        }
    }
    // Random order.
    let mut order: Vec<([u8; 4], u8)> = wanted.keys().map(|p| (sentinel_core::random_bytes::<4>(), *p)).collect();
    order.sort();

    let mut round = BucketRound { fetched: Default::default(), cursors: Vec::new(), history_read: Vec::new(), split: false };
    let mut total = 0usize;
    for (i, (_, prefix)) in order.into_iter().enumerate() {
        if total > BUCKET_ROUND_BYTES {
            round.split = true;
            break; // the rest waits for the next round (positions unchanged)
        }
        if i > 0 {
            // Spread the bucket fetches out a little.
            tokio::time::sleep(std::time::Duration::from_millis(500 + u64::from(sentinel_core::random_bytes::<1>()[0]) * 12)).await;
        }
        let (start, newcomers) = wanted.get(&prefix).cloned().unwrap_or_default();
        let mut s = net.connect_hedged(pillar).await?;
        let mut after = start - start % BUCKET_CURSOR_ROUND;
        let mut finished = false;
        for _page in 0..64 {
            let list = match request(&mut s, &Request::AuthorBucket { bits, prefix, after }).await? {
                Response::Blobs(l) => l,
                other => bail!("unexpected response: {other:?}"),
            };
            if list.is_empty() {
                finished = true;
                break;
            }
            for (seq, bytes) in list {
                if seq <= after {
                    continue;
                }
                after = seq;
                total += bytes.len();
                read_bucket_object(&bytes, &by_author, known, &mut round.fetched);
            }
            if total > BUCKET_ROUND_BYTES {
                round.split = true;
                break;
            }
        }
        // Progress is kept even when stopped early, so a busy bucket is
        // read across several rounds instead of starting over.
        round.cursors.push((bucket_key(pillar, bits, prefix), after.max(start)));
        // Read from the start: the saved position now carries their history
        // forward even if this round stopped early.
        if finished || start == 0 {
            round.history_read.extend(newcomers);
        }
    }
    Ok(round)
}

/// Keep an object from a bucket only if it verifies and belongs to someone
/// I follow there; decrypt with their keys.
fn read_bucket_object(
    bytes: &[u8],
    by_author: &std::collections::HashMap<[u8; 32], &Followed>,
    known: &std::collections::HashSet<String>,
    out: &mut std::collections::HashMap<String, AuthorFetch>,
) {
    let Ok(env) = Envelope::decode_verified(bytes) else { return };
    let Some(f) = by_author.get(&env.author) else { return };
    // Under their recovery key: only a move to a new key counts (sealed
    // with their feed key, signed by their pinned recovery key).
    if f.recovery.is_some_and(|pin| pin.ed == env.author) {
        if let Some(s) = f.recovery.as_ref().zip(f.feed_key.as_ref()).and_then(|(pin, fk)| sentinel_core::recovery::verify(&env, pin, fk)) {
            out.entry(f.author.clone()).or_default().successions.push(s);
        }
        return;
    }
    let addr = Address::of(bytes);
    let id = addr.to_text();
    let mut keys: Vec<[u8; 32]> = match f.feed_key {
        Some(k) => vec![k, sentinel_core::seal::explore_key()],
        None => vec![sentinel_core::seal::explore_key()],
    };
    keys.extend(f.circle_keys.iter().copied());
    let got = out.entry(f.author.clone()).or_default();
    // Once their ML-DSA key is pinned, only objects with a valid
    // post-quantum signature count (a quantum forger can't make one).
    let record = match f.pq_key.as_deref() {
        Some(pin) => social::open_record_pinned(&env, &keys, Some(pin)),
        None => {
            // Not pinned yet: a profile that names an ML-DSA key must carry a
            // valid signature by that same key before the key is pinned.
            let (kind, body, pq) = match sentinel_core::seal::open_full(&env, &keys) {
                Some(x) => x,
                None => return,
            };
            match social::open_record(&env, &keys) {
                Some(social::Record::Profile(mut pr)) => {
                    if let Some(k) = pr.pq_key.as_deref() {
                        if !sentinel_core::seal::verify_pq(&env.author, &kind, &body, &pq, k) {
                            pr.pq_key = None; // not self-consistent: don't pin
                        }
                    }
                    Some(social::Record::Profile(pr))
                }
                other => other,
            }
        }
    };
    match record {
        Some(social::Record::Post(p)) => {
            if known.contains(&id) || got.posts.iter().any(|x| x.id == id) {
                return;
            }
            got.posts.push(StoredPost {
                id,
                author: f.author.clone(),
                text: p.text,
                minute: p.minute,
                mine: false,
                sent: true,
                raw: None,
                topics: p.topics,
                discoverable: p.discoverable,
                media: p.media,
                pending_chunks: Vec::new(),
                approved_only: false,
                draft: None,
                not_before: 0,
            });
        }
        Some(social::Record::Profile(pr)) => {
            if got.profile.as_ref().map_or(true, |old| pr.minute >= old.minute) {
                got.profile = Some(pr);
            }
        }
        Some(social::Record::Card(c)) => merge_card(&mut got.cards, c),
        // Room listings and anything unreadable: not part of a timeline.
        Some(social::Record::RoomListing(_)) | None => {}
    }
}

/// True if a subscribed topic covers a post topic: `ai` matches `ai/llm`.
fn topic_matches(subscribed: &str, post: &str) -> bool {
    post == subscribed || post.starts_with(&format!("{subscribed}/"))
}

/// Fetch up to 30 of the newest posts from one discovery shard, verifying
/// every object's address, signature and that it really is discoverable.
async fn fetch_shard(
    net: &Net,
    pillar: &str,
    shard: u16,
    known: &std::collections::HashSet<String>,
    keys: &[[u8; 32]],
) -> Result<(Vec<DiscoveredPost>, Vec<DiscoveredRoom>)> {
    let mut s = net.connect_hedged(pillar).await?;
    let index = match request(&mut s, &Request::Shard { shard, after: u64::MAX }).await? {
        Response::Index(ix) => ix,
        other => bail!("unexpected response: {other:?}"),
    };
    let mut out = Vec::new();
    let mut rooms = Vec::new();
    for (_, addr) in index.into_iter().rev().take(30) {
        if known.contains(&addr.to_text()) {
            continue;
        }
        let bytes = match request(&mut s, &Request::Get(addr)).await? {
            Response::Object(b) => b,
            _ => continue,
        };
        if Address::of(&bytes) != addr {
            continue;
        }
        let Ok(env) = Envelope::decode_verified(&bytes) else { continue };
        let p = match social::open_record(&env, keys) {
            Some(social::Record::Post(p)) => p,
            Some(social::Record::RoomListing(l)) => {
                // The join link must be for the room whose admin key signed
                // the listing: nobody can list someone else's room.
                let id = sentinel_core::room::room_id_for(&env.author);
                let linked = sentinel_core::room::RoomLink::parse(&l.link).map(|x| x.room_id).or_else(|| sentinel_core::room::BuyLink::parse(&l.link).map(|b| b.room_id))
                    .or_else(|| sentinel_core::room::AskLink::parse(&l.link).map(|a| a.room_id));
                if linked == Some(id) && matches!(l.access.as_str(), "free" | "pass" | "membership") {
                    rooms.push(DiscoveredRoom {
                        room_id: data_encoding::HEXLOWER.encode(&id),
                        name: l.name.chars().take(60).collect(),
                        description: l.description.chars().take(social::MAX_ROOM_DESCRIPTION).collect(),
                        topics: l.topics.into_iter().take(social::MAX_TOPICS).collect(),
                        access: l.access,
                        price: l.price,
                        link: l.link,
                        minute: l.minute,
                        address: addr.to_text(),
                        pillar: pillar.to_owned(),
                    });
                }
                continue;
            }
            _ => continue,
        };
        if !p.discoverable {
            continue;
        }
        out.push(DiscoveredPost {
            id: addr.to_text(),
            author: social::author_text(&env.author),
            text: p.text,
            minute: p.minute,
            topics: p.topics,
            pillar: pillar.to_owned(),
            media: p.media,
            topical: false,
        });
    }
    Ok((out, rooms))
}

#[cfg(test)]
mod tests {
    use super::topic_matches;

    #[test]
    fn topic_matching() {
        assert!(topic_matches("ai", "ai/llm"));
        assert!(topic_matches("ai/llm", "ai/llm"));
        assert!(!topic_matches("ai", "aid"));
        assert!(!topic_matches("ai/llm", "ai"));
    }
}

pub(crate) fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = (u32::from_le_bytes(sentinel_core::random_bytes::<4>()) as usize) % (i + 1);
        v.swap(i, j);
    }
}
