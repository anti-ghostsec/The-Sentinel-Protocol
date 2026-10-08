//! Rooms v1 (spec §6.2.6–6.2.7): small rooms with Megolm sender keys,
//! sealed blobs in rotating room boxes, invite links.
//!
//! - Room boxes rotate daily and members read only today's and yesterday's,
//!   so each member **re-announces** their sender key (at its current
//!   ratchet position — older messages stay unreadable to newcomers) on the
//!   first message of each day, and the creator re-posts the room details
//!   daily. Late joiners can therefore read from the day they join.
//! - Room details are signed by a room-only admin key (never an identity).
//! - Outgoing blobs wait in a queue until a Pillar accepts them, so nothing
//!   is lost if Tor or the Pillar is briefly unreachable.
//! - Admin actions form the **room authority log** (`room_auth`): a daily
//!   checkpoint (details, bans, hidden messages), bans, hidden messages, and
//!   rekeys with epoch cuts (no back-dated messages). Members apply entries
//!   in order, and messages are shown in one agreed order.
//! - **Moderators** (named by the admin, by room-only key) hide messages and
//!   ban members with their own room-only key; the admin's app turns their
//!   bans into full removals.
//! - **Approval rooms**: the shared link is an *ask* link. Requests are
//!   sealed with the room's ask key (admin and moderators only); an
//!   approval sends the room secret sealed to the requester's room-only key,
//!   into a reply box only they read.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use sentinel_core::room::{self, AskLink, JoinRequest, RoomBlob, RoomLink, RoomPayload};
use sentinel_core::room_auth::{self, Action, ModAction, Moderator};
use sentinel_core::social;
use sentinel_core::wire::{Request, Response};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use vodozemac::megolm::{GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle};

use super::{handle_of, pickle_key, request, Core};

#[derive(Clone, Serialize, Deserialize)]
pub struct InboundEntry {
    pub pickle: String,
    pub author: String,
    pub name: String,
    /// The sender proved this identity to me (deniable hello MAC).
    #[serde(default)]
    pub verified: bool,
    /// Their room-only key (from the hello), for bans.
    #[serde(default)]
    pub member: Option<[u8; 32]>,
}

/// A member's room-only key and who they say they are.
#[derive(Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    pub author: String,
    pub name: String,
    /// This member proved the identity to me (deniable MAC). Only verified
    /// members are handed new room keys.
    #[serde(default)]
    pub verified: bool,
    /// Their room-only ML-KEM key (new room keys are sealed to it post-quantum).
    #[serde(default)]
    pub kem: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RoomMsg {
    pub author: String,
    pub name: String,
    pub text: String,
    pub minute: u64,
    pub mine: bool,
    pub sent: bool,
    /// Matches a queued blob to this message (mine only).
    #[serde(default)]
    pub nonce: u64,
    #[serde(default = "yes")]
    pub verified: bool,
    /// Megolm session and index (a message's identity in the room), the
    /// epoch it arrived in, and its Lamport counter (agreed order).
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub index: u32,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub lamport: u64,
    /// A Sentinel App command (not shown as a message).
    #[serde(default)]
    pub app: Option<room::AppCall>,
}

fn yes() -> bool {
    true
}

/// A sealed blob waiting to be deposited (`nonce` != 0 marks a message).
#[derive(Clone, Serialize, Deserialize)]
pub struct Queued {
    pub sealed: Vec<u8>,
    pub nonce: u64,
    /// The room secret it was sealed with (its box). A rekey can happen
    /// while it waits; it must still go where readers of that secret look.
    #[serde(default)]
    pub secret: Option<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RoomState {
    pub room_id: [u8; 32],
    pub secret: [u8; 32],
    pub pillar: String,
    pub name: String,
    /// public | private
    pub visibility: String,
    /// free | pass | membership
    pub access: String,
    pub outbound: Option<String>,
    pub outbound_id: Option<String>,
    #[serde(default)]
    pub announced: bool,
    #[serde(default)]
    pub info_sent: bool,
    pub inbound: HashMap<String, InboundEntry>,
    pub cursors: HashMap<String, u64>,
    pub seen: HashSet<String>,
    pub messages: Vec<RoomMsg>,
    /// Room admin key seed (creator only).
    #[serde(default)]
    pub admin: Option<[u8; 32]>,
    #[serde(default)]
    pub info_version: u64,
    /// Day the creator last posted the room details.
    #[serde(default)]
    pub info_day: u64,
    /// Day I last announced my sender key.
    #[serde(default)]
    pub announced_day: u64,
    #[serde(default)]
    pub queue: Vec<Queued>,
    /// My room-only X25519 secret (members MAC their hellos to it).
    #[serde(default)]
    pub member_secret: Option<[u8; 32]>,
    /// Members' room-only keys (hex) -> who they claim to be.
    #[serde(default)]
    pub members: HashMap<String, MemberInfo>,
    /// Member keys my last hello covered.
    #[serde(default)]
    pub hello_covers: Vec<[u8; 32]>,
    /// A member appeared that my last hello didn't cover.
    #[serde(default)]
    pub needs_hello: bool,
    /// Paid rooms: price in credits.
    #[serde(default)]
    pub price: u32,
    /// Creator: who paid, until when (Unix time; u64::MAX = pass).
    #[serde(default)]
    pub paid: HashMap<String, u64>,
    /// Secret generation (raised by each rekey).
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub last_rekey_day: u64,
    /// Creator: the latest rekey, re-posted in the old box for a week so
    /// members who were offline still get it: (sealed blob, old secret,
    /// last day to post).
    #[serde(default)]
    pub rekey_repost: Option<(Vec<u8>, [u8; 32], u64)>,
    /// Public rooms: shown in Discover with this description and topics.
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub topics: Vec<String>,
    /// Day the Discover listing was last published (creator).
    #[serde(default)]
    pub listing_day: u64,
    /// Day the rekey was last re-posted (its own marker: tying it to the
    /// daily room details let a message the same day suppress it).
    #[serde(default)]
    pub repost_day: u64,
    /// Members I removed (never included in a rekey again).
    #[serde(default)]
    pub removed: Vec<String>,
    /// The room authority log as I've applied it.
    #[serde(default)]
    pub auth: room_auth::Log,
    /// Banned room-only keys (from the authority log).
    #[serde(default)]
    pub banned: Vec<[u8; 32]>,
    /// Hidden messages (session, index).
    #[serde(default)]
    pub redacted: Vec<(String, u32)>,
    /// My Lamport counter.
    #[serde(default)]
    pub lamport: u64,
    /// Highest message index seen per session (the admin's cut).
    #[serde(default)]
    pub seen_max: HashMap<String, u32>,
    /// Moderators named by the admin (authority log).
    #[serde(default)]
    pub mods: Vec<Moderator>,
    /// My moderator key seed, if I'm a moderator.
    #[serde(default)]
    pub my_mod: Option<[u8; 32]>,
    /// Joining needs approval from the admin or a moderator.
    #[serde(default)]
    pub approval: bool,
    /// The ask key (admin and moderators of approval rooms).
    #[serde(default)]
    pub ask: Option<[u8; 32]>,
    /// Join requests waiting for an answer (admin and moderators).
    #[serde(default)]
    pub requests: Vec<JoinRequest>,
    /// I asked to join and wait for an answer (`secret` is my reply box
    /// until then).
    #[serde(default)]
    pub waiting: bool,
    #[serde(default)]
    pub declined: bool,
    /// Admin: members a moderator banned, to remove fully.
    #[serde(default)]
    pub pending_bans: Vec<[u8; 32]>,
    /// Moderator actions already applied (no replays).
    #[serde(default)]
    pub mod_seen: Vec<[u8; 16]>,
    /// The room's Sentinel Apps.
    #[serde(default)]
    pub apps: super::apps::RoomApps,
}

/// Most join requests kept waiting.
const MAX_REQUESTS: usize = 200;

/// Largest forward jump accepted in a message's order counter.
const MAX_LAMPORT_JUMP: u64 = 1_000_000;

/// Membership period.
const MONTH_SECS: u64 = 30 * 86_400;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RoomView {
    pub id: String,
    pub name: String,
    pub visibility: String,
    pub access: String,
    pub price: u32,
    pub admin: bool,
    pub members: usize,
    pub last: Option<String>,
    pub minute: u64,
    /// The room's admin key signed conflicting changes (stolen or misused).
    pub fork: bool,
    /// I'm a moderator here.
    pub moderator: bool,
    pub approval: bool,
    /// I asked to join and wait for an answer / was turned down.
    pub waiting: bool,
    pub declined: bool,
    /// Join requests waiting (admin and moderators).
    pub requests: usize,
    /// Key period and authority-log position (for diagnostics).
    pub epoch: u64,
    pub auth_seq: u64,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RequestView {
    pub id: String,
    pub name: String,
    /// The handle they *say* is theirs (proven once they're in).
    pub handle: String,
    pub note: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RoomMsgView {
    /// The sender's account (opens their profile).
    pub author: String,
    pub name: String,
    pub handle: String,
    pub text: String,
    pub minute: u64,
    pub mine: bool,
    pub sent: bool,
    /// Sender identity proven to me (false = claimed only).
    pub verified: bool,
    /// "session:index" (for the admin's Hide).
    pub id: String,
}

/// The member key part of a member-map entry ("<key hex>:<identity>").
fn member_key(k: &str) -> Option<[u8; 32]> {
    let h = k.split(':').next()?;
    data_encoding::HEXLOWER.decode(h.as_bytes()).ok()?.try_into().ok()
}

fn hex(b: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

fn new_state(room_id: [u8; 32], secret: [u8; 32], pillar: String, name: String, admin: Option<[u8; 32]>) -> RoomState {
    RoomState {
        room_id,
        secret,
        pillar,
        name,
        visibility: "private".into(),
        access: "free".into(),
        outbound: None,
        outbound_id: None,
        announced: false,
        info_sent: false,
        inbound: HashMap::new(),
        cursors: HashMap::new(),
        seen: HashSet::new(),
        messages: Vec::new(),
        admin,
        info_version: 0,
        info_day: 0,
        announced_day: 0,
        queue: Vec::new(),
        member_secret: Some(sentinel_core::random_bytes::<32>()),
        members: HashMap::new(),
        hello_covers: Vec::new(),
        // Say hello on joining, so members can verify me before I post.
        needs_hello: true,
        price: 0,
        paid: HashMap::new(),
        epoch: 0,
        last_rekey_day: 0,
        rekey_repost: None,
        repost_day: 0,
        description: String::new(),
        topics: Vec::new(),
        listing_day: 0,
        removed: Vec::new(),
        auth: room_auth::Log::default(),
        banned: Vec::new(),
        redacted: Vec::new(),
        lamport: 0,
        seen_max: HashMap::new(),
        mods: Vec::new(),
        my_mod: None,
        approval: false,
        ask: None,
        requests: Vec::new(),
        waiting: false,
        declined: false,
        pending_bans: Vec::new(),
        mod_seen: Vec::new(),
        apps: Default::default(),
    }
}

/// Apply the moderator list and approval setting from the authority log.
fn apply_mods(x: &mut RoomState, mods: Vec<Moderator>, approval: bool) {
    let mods: Vec<Moderator> = mods.into_iter().take(room_auth::MAX_MODS).collect();
    x.approval = approval;
    if x.admin.is_none() {
        match room_auth::my_moderator(&x.room_id, &mods, &x.member_secret.unwrap_or_default()) {
            Some((seed, ask)) => {
                x.my_mod = Some(seed);
                if x.ask != ask {
                    x.requests.clear(); // a new ask key: old requests are gone
                }
                x.ask = ask;
            }
            None => {
                x.my_mod = None;
                x.ask = None;
                x.requests.clear();
            }
        }
    }
    x.mods = mods;
}

/// A moderator action, sealed for a box.
fn mod_blob(box_secret: &[u8; 32], seed: &[u8; 32], room_id: &[u8; 32], action: ModAction) -> Vec<u8> {
    room::seal_blob(box_secret, &RoomBlob::Mod { signed: room_auth::sign_mod(seed, room_id, action) })
}

/// Admin: a new ask key (an ex-moderator knew the old one), resealed to
/// the remaining moderators. The old ask link stops working.
fn rotate_ask(x: &mut RoomState) {
    if !x.approval {
        return;
    }
    let ask = sentinel_core::random_bytes::<32>();
    x.ask = Some(ask);
    x.requests.clear();
    let room_id = x.room_id;
    for m in x.mods.iter_mut() {
        room_auth::reseal_ask(&room_id, m, Some(&ask));
    }
    x.listing_day = 0; // the Discover listing carries the new link
}

/// Admin: sign the next authority entry, apply it to my own copy, and
/// return it sealed for the room box.
pub(super) fn admin_entry(x: &mut RoomState, action: Action) -> Option<Vec<u8>> {
    let admin = x.admin?;
    let entry = room_auth::Entry { room_id: x.room_id, seq: x.auth.seq + 1, prev: x.auth.head, action };
    let (signed, _) = room_auth::sign(&admin, &entry);
    x.auth.offer(&x.room_id, &signed);
    Some(room::seal_blob(&x.secret, &room_auth::blob(signed)))
}

/// Is this message hidden for me (banned sender, hidden by the admin)?
fn hidden(x: &RoomState, m: &RoomMsg) -> bool {
    if m.mine {
        return false;
    }
    x.redacted.iter().any(|(s, i)| *s == m.session && *i == m.index)
        || x.inbound.get(&m.session).and_then(|e| e.member).is_some_and(|k| x.banned.contains(&k))
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn create_room_priced(self: &Arc<Self>, app: AppHandle, name: &str, visibility: &str, access: &str, price: u32, description: &str, topics: &[String], approval: bool) -> Result<String> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 60 {
            bail!("Room names must be 1–60 characters.");
        }
        if !matches!(visibility, "public" | "private") {
            bail!("unknown visibility");
        }
        let description = description.trim().to_owned();
        let mut norm: Vec<String> = Vec::new();
        if visibility == "public" {
            if description.chars().count() > social::MAX_ROOM_DESCRIPTION {
                bail!("The description can be at most 300 characters.");
            }
            for t in topics {
                let t = social::normalize_topic(t).context("Topics are words like robotics or ai/llm.")?;
                if !norm.contains(&t) {
                    norm.push(t);
                }
            }
            if norm.is_empty() || norm.len() > social::MAX_TOPICS {
                bail!("A public room needs 1–3 topics, so people can find it in Discover.");
            }
        }
        match access {
            "free" => {}
            "pass" | "membership" => {
                if !(1..=1000).contains(&price) {
                    bail!("Set a price between 1 and 1000 credits.");
                }
                if self.status().link.is_none() {
                    bail!("Connect first (buyers pay you through your follow link).");
                }
            }
            _ => bail!("unknown access type"),
        }
        if approval && access != "free" {
            bail!("Paid rooms already decide who gets in; approval is for free rooms.");
        }
        let (_, store) = self.unlocked()?;
        let pillar = store.pillar.clone().context("Connect first.")?;
        let (room_id, secret, admin) = room::new_room_with_admin();
        let mut state = new_state(room_id, secret, pillar, name.to_owned(), Some(admin));
        state.visibility = visibility.into();
        state.access = access.into();
        state.info_version = 1;
        state.price = if access == "free" { 0 } else { price };
        state.description = description;
        state.topics = norm;
        state.last_rekey_day = sentinel_core::dm::today();
        state.approval = approval;
        state.ask = approval.then(sentinel_core::random_bytes::<32>);
        self.update(|s| s.rooms.push(state))?;
        let id = hex(&room_id);
        let core = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let _ = core.poll_rooms().await;
            let _ = app.emit("rooms", ());
        });
        Ok(id)
    }

    pub fn join_room(self: &Arc<Self>, app: AppHandle, link: &str) -> Result<String> {
        if AskLink::parse(link).is_some() {
            return self.ask_to_join(app, link, "");
        }
        let l = RoomLink::parse(link).context("That isn't a valid room invite link.")?;
        let (_, store) = self.unlocked()?;
        let id = hex(&l.room_id);
        if store.rooms.iter().any(|r| r.room_id == l.room_id) {
            bail!("You're already in this room.");
        }
        let pillar = l.pillar.clone();
        self.update(|s| s.rooms.push(new_state(l.room_id, l.secret, l.pillar, "Joining…".into(), None)))?;
        self.rescan_pillar(&pillar);
        let core = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let _ = core.poll_rooms().await;
            let _ = app.emit("rooms", ());
        });
        Ok(id)
    }

    /// Ask to join an approval room. The admin and moderators see my name,
    /// handle and note; nobody else does. Until they answer, the room's
    /// `secret` is my reply box.
    pub fn ask_to_join(self: &Arc<Self>, app: AppHandle, link: &str, note: &str) -> Result<String> {
        let l = AskLink::parse(link).context("That isn't a valid ask-to-join link.")?;
        let note = note.trim();
        if note.chars().count() > room::MAX_REQUEST_NOTE {
            bail!("Keep the note under {} characters.", room::MAX_REQUEST_NOTE);
        }
        let (key, store) = self.unlocked()?;
        if store.rooms.iter().any(|r| r.room_id == l.room_id) {
            bail!("You're already in this room, or waiting for an answer.");
        }
        let reply = sentinel_core::random_bytes::<32>();
        let mut st = new_state(l.room_id, reply, l.pillar.clone(), l.name.clone(), None);
        st.waiting = true;
        st.needs_hello = false;
        st.approval = true;
        let req = JoinRequest {
            room_id: l.room_id,
            from: key.verifying_key().to_bytes(),
            name: store.name.chars().take(40).collect(),
            note: note.to_owned(),
            member_pub: room::member_pub(&st.member_secret.unwrap_or_default()),
            reply,
            member_kem: Some(room::member_kem_public(&st.member_secret.unwrap_or_default())),
        };
        st.queue.push(Queued { sealed: room::seal_blob(&l.ask, &RoomBlob::Ask(req)), nonce: 0, secret: Some(l.ask) });
        let id = hex(&l.room_id);
        self.update(|s| s.rooms.push(st))?;
        let core = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let _ = core.poll_rooms().await;
            let _ = app.emit("rooms", ());
        });
        Ok(id)
    }

    /// Forget a room on this device: its keys and messages. Members aren't
    /// told and keep what I posted. (Also cancels a request to join.)
    pub fn leave_room(&self, id: &str) -> Result<()> {
        self.update(|s| s.rooms.retain(|r| hex(&r.room_id) != id))
    }

    /// Admin and moderators: join requests waiting for an answer.
    pub fn join_requests(&self, id: &str) -> Result<Vec<RequestView>> {
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?;
        Ok(r.requests
            .iter()
            .map(|q| RequestView { id: hex(&q.id()), name: q.name.clone(), handle: handle_of(&social::author_text(&q.from)), note: q.note.clone() })
            .collect())
    }

    /// Admin and moderators: let someone in (the room secret, sealed to the
    /// key they sent) or turn them down. Other moderators are told it was
    /// handled.
    pub fn answer_request(self: &Arc<Self>, app: AppHandle, id: &str, request: &str, approve: bool) -> Result<()> {
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?.clone();
        let signer = r.admin.or(r.my_mod).context("Only the room's admin and moderators can answer requests.")?;
        let ask = r.ask.context("This room doesn't take requests.")?;
        let req = r.requests.iter().find(|q| hex(&q.id()) == request).cloned().context("That request was already answered.")?;
        let ans = room::answer(&r.room_id, &req, approve.then_some(&r.secret), r.epoch);
        let handled = mod_blob(&ask, &signer, &r.room_id, ModAction::Handled { request: req.id() });
        self.update(|s| {
            if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == r.room_id) {
                x.requests.retain(|q| q.reply != req.reply);
                x.queue.push(Queued { sealed: room::seal_blob(&req.reply, &ans), nonce: 0, secret: Some(req.reply) });
                x.queue.push(Queued { sealed: handled, nonce: 0, secret: Some(ask) });
            }
        })?;
        let core = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let _ = core.flush_room_queue(&r.room_id).await;
            let _ = app.emit("rooms", ());
        });
        Ok(())
    }

    /// Admin: make a member a moderator, or take it away. Taking it away in
    /// an approval room also changes the ask key (they knew the old one), so
    /// the old ask link stops working.
    pub fn set_moderator(&self, id: &str, author: &str, on: bool) -> Result<()> {
        let mut err = None;
        self.update(|s| {
            let Some(x) = s.rooms.iter_mut().find(|x| hex(&x.room_id) == id) else { return };
            if x.admin.is_none() {
                err = Some("Only the room's creator can choose moderators.");
                return;
            }
            // Only keys whose owner proved who they are to me.
            let keys: Vec<[u8; 32]> = x.members.iter().filter(|(_, m)| m.author == author && m.verified).filter_map(|(k, _)| member_key(k)).collect();
            if keys.is_empty() {
                err = Some("They need to have said hello in the room first (so their key is known).");
                return;
            }
            if on {
                for k in keys {
                    if x.mods.len() >= room_auth::MAX_MODS {
                        err = Some("A room can have at most 20 moderators.");
                        return;
                    }
                    if !x.mods.iter().any(|m| m.member == k) && !x.banned.contains(&k) {
                        let kem = x.members.iter().find(|(mk, _)| member_key(mk) == Some(k)).and_then(|(_, m)| m.kem.clone());
                        let m = room_auth::new_moderator(&x.room_id, &k, kem.as_deref(), x.ask.as_ref());
                        x.mods.push(m);
                    }
                }
            } else {
                x.mods.retain(|m| !keys.contains(&m.member));
                rotate_ask(x);
            }
            let action = Action::Moderators { mods: x.mods.clone(), approval: x.approval };
            if let Some(b) = admin_entry(x, action) {
                x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
            }
        })?;
        match err {
            Some(e) => bail!(e),
            None => Ok(()),
        }
    }

    /// Members as I see them: (identity, name, removed, moderator).
    pub fn room_members(&self, id: &str) -> Result<Vec<(String, String, bool, bool)>> {
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?;
        let mut out: Vec<(String, String, bool, bool)> = Vec::new();
        for (k, m) in &r.members {
            let is_mod = member_key(k).is_some_and(|k| r.mods.iter().any(|x| x.member == k));
            match out.iter_mut().find(|(a, _, _, _)| *a == m.author) {
                Some(e) => e.3 |= is_mod,
                None => out.push((m.author.clone(), m.name.clone(), r.removed.contains(&m.author), is_mod)),
            }
        }
        Ok(out)
    }

    pub fn rooms(&self) -> Result<Vec<RoomView>> {
        let (_, store) = self.unlocked()?;
        let mut out: Vec<RoomView> = store
            .rooms
            .iter()
            .map(|r| {
                let mut authors: HashSet<&str> = r.inbound.values().map(|e| e.author.as_str()).collect();
                if r.outbound_id.is_some() {
                    authors.insert("me");
                }
                RoomView {
                    id: hex(&r.room_id),
                    name: r.name.clone(),
                    visibility: r.visibility.clone(),
                    access: r.access.clone(),
                    price: r.price,
                    admin: r.admin.is_some(),
                    members: authors.len().max(1),
                    last: r.messages.iter().rev().find(|m| m.app.is_none() && !hidden(r, m)).map(|m| format!("{}: {}", m.name, m.text)),
                    minute: r.messages.last().map(|m| m.minute).unwrap_or(0),
                    fork: r.auth.fork,
                    moderator: r.my_mod.is_some(),
                    approval: r.approval,
                    waiting: r.waiting,
                    declined: r.declined,
                    requests: r.requests.len(),
                    epoch: r.epoch,
                    auth_seq: r.auth.seq,
                }
            })
            .collect();
        out.sort_by(|a, b| b.minute.cmp(&a.minute));
        Ok(out)
    }

    pub fn room_messages(&self, id: &str) -> Result<Vec<RoomMsgView>> {
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?;
        Ok(r.messages
            .iter()
            .filter(|m| m.app.is_none() && !store.blocked.contains(&m.author) && !hidden(r, m))
            .map(|m| RoomMsgView {
                author: m.author.clone(),
                name: m.name.clone(),
                handle: handle_of(&m.author),
                text: m.text.clone(),
                minute: m.minute,
                mine: m.mine,
                sent: m.sent,
                verified: m.verified,
                id: format!("{}:{}", m.session, m.index),
            })
            .collect())
    }

    /// The link to share: an invite (free rooms) or, for my paid rooms, a
    /// buy link (never the secret).
    pub fn room_link(&self, id: &str) -> Result<String> {
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?;
        if r.waiting {
            bail!("You're still waiting to be let in.");
        }
        // Approval rooms: an ask link (never the secret), from the admin
        // and moderators only.
        if r.approval && r.access == "free" {
            let ask = r.ask.context("This room needs approval to join: only its admin and moderators can share the link.")?;
            return Ok(AskLink { room_id: r.room_id, pillar: r.pillar.clone(), ask, name: r.name.clone() }.to_text());
        }
        if r.admin.is_some() && r.access != "free" {
            let creator = self.status().link.context("Connect first.")?;
            return Ok(room::BuyLink { room_id: r.room_id, kind: r.access.clone(), price: r.price, creator, name: r.name.clone() }.to_text());
        }
        if r.access != "free" {
            bail!("Only the creator can invite people to a paid room.");
        }
        Ok(RoomLink { room_id: r.room_id, pillar: r.pillar.clone(), secret: r.secret }.to_text())
    }

    /// Pay for a room from a buy link: follow the creator if needed (to
    /// reach them), then send the credits in an encrypted DM. Their app
    /// confirms with the invite, which joins me automatically.
    pub async fn buy_room(self: &Arc<Self>, app: AppHandle, link: &str) -> Result<()> {
        let b = room::BuyLink::parse(link).context("That isn't a valid room link.")?;
        let creator = social::FollowLink::parse(&b.creator).context("bad creator link")?;
        let author = social::author_text(&creator.author);
        let (_, store) = self.unlocked()?;
        if store.rooms.iter().any(|r| r.room_id == b.room_id) && b.kind == "pass" {
            bail!("You're already in this room.");
        }
        let have = super::wallet::balance(&store);
        if have < b.price as usize {
            bail!("This room costs {} credits; you have {}.", b.price, have);
        }
        if !store.following.iter().any(|f| f.author == author) {
            self.follow(app.clone(), &b.creator)?;
        }
        // Their contact card arrives with their posts.
        for _ in 0..6 {
            if self.unlocked()?.1.following.iter().any(|f| f.author == author && f.card.is_some()) {
                break;
            }
            let _ = self.refresh().await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        let tokens = self.take_bundles(b.price as usize)?;
        // Remember whom I paid: only their grant for this room is honoured.
        self.update(|s| {
            s.purchases.insert(hex(&b.room_id), author.clone());
        })?;
        let text = format!("Paying {} credits for {}: {}", b.price, if b.kind == "pass" { "a pass to" } else { "a month in" }, b.name);
        if let Err(e) = self.send_dm_with(app, &author, &text, tokens.clone(), Some(sentinel_core::dm::RoomPurchase { room_id: b.room_id }), None) {
            self.refund(tokens);
            return Err(e);
        }
        Ok(())
    }

    /// Creator: handle payments; everyone: join rooms I was granted.
    pub(super) async fn process_payments(self: &Arc<Self>, app: &AppHandle) -> Result<usize> {
        let mut pays = Vec::new();
        let mut grants = Vec::new();
        self.update(|s| {
            pays = std::mem::take(&mut s.incoming_payments);
            grants = std::mem::take(&mut s.incoming_grants);
        })?;
        let mut n = 0;
        for mut p in pays {
            // Whole credits only: parts from a majority of distinct mints.
            if !p.checked {
                let mints = super::wallet::mints_of(&self.unlocked()?.1);
                let t = sentinel_core::credits::threshold(mints.len());
                p.bundles.retain(|b| b.valid_shape(&mints, t));
                p.checked = true;
            }
            // Redeem first: the parts become mine and can't be spent again.
            let parts: Vec<(String, sentinel_core::credits::Token)> = p.bundles.iter().flat_map(|b| b.parts.clone()).collect();
            let fates = self.redeem(&parts, false).await;
            let mut at = 0;
            let mut waiting = Vec::new();
            for b in std::mem::take(&mut p.bundles) {
                let f = &fates[at..at + b.parts.len()];
                at += b.parts.len();
                if f.contains(&super::wallet::Fate::Spent) {
                    continue; // invalid or already spent: doesn't count
                }
                let left: Vec<_> = b.parts.into_iter().zip(f).filter(|(_, f)| **f == super::wallet::Fate::Unknown).map(|(x, _)| x).collect();
                if left.is_empty() {
                    p.confirmed += 1;
                } else {
                    waiting.push(sentinel_core::credits::Bundle { parts: left });
                }
            }
            // A mint couldn't be reached: keep the rest and retry later
            // (never tell a buyer "invalid" because of a network hiccup).
            if !waiting.is_empty() {
                p.bundles = waiting;
                self.update(|s| s.incoming_payments.push(p.clone()))?;
                continue;
            }
            let got = p.confirmed;
            let Some(pur) = p.purchase else { continue };
            let (_, store) = self.unlocked()?;
            let Some(r) = store.rooms.iter().find(|r| r.room_id == pur.room_id && r.admin.is_some() && r.access != "free").cloned() else { continue };
            if got >= r.price as usize && !r.removed.contains(&p.from) {
                let until = if r.access == "pass" { u64::MAX } else { super::unix_now() + MONTH_SECS };
                self.update(|s| {
                    if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == r.room_id) {
                        let e = x.paid.entry(p.from.clone()).or_insert(0);
                        *e = (*e).max(until);
                    }
                })?;
                let invite = RoomLink { room_id: r.room_id, pillar: r.pillar.clone(), secret: r.secret }.to_text();
                let _ = self.send_dm_with(app.clone(), &p.from, &format!("Welcome to {}!", r.name), Vec::new(), None, Some(invite));
                n += 1;
            } else {
                let _ = self.send_dm(app.clone(), &p.from, &format!("Your payment for {} wasn't valid (already spent or too little). Nothing was granted.", r.name));
            }
        }
        for (from, g) in grants {
            let Some(l) = RoomLink::parse(&g) else { continue };
            let (_, store) = self.unlocked()?;
            // Only grants from the creator I paid for that room. Anything else
            // could pull me into a room someone else controls (and my hello
            // would show them who I am).
            if store.purchases.get(&hex(&l.room_id)) != Some(&from) {
                continue;
            }
            match store.rooms.iter().find(|r| r.room_id == l.room_id) {
                // Renewal after a rekey: take the current secret.
                Some(r) if r.secret != l.secret => {
                    self.update(|s| {
                        if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == l.room_id) {
                            x.secret = l.secret;
                            x.pillar = l.pillar.clone();
                            x.needs_hello = true;
                            x.cursors.clear();
                        }
                    })?;
                    self.rescan_pillar(&l.pillar);
                }
                Some(_) => {}
                None => {
                    let _ = self.join_room(app.clone(), &g);
                }
            }
            n += 1;
        }
        Ok(n)
    }

    /// Creator: remove a member (they keep what they saw; they can't read
    /// anything new).
    pub fn remove_member(&self, id: &str, author: &str) -> Result<()> {
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?;
        if r.admin.is_none() {
            // A moderator bans every key they announced; members refuse
            // them at once and the admin's app removes them fully.
            let seed = r.my_mod.context("Only the room's admin and moderators can remove people.")?;
            let keys: Vec<[u8; 32]> = r.members.iter().filter(|(_, m)| m.author == author).filter_map(|(k, _)| member_key(k)).collect();
            if keys.iter().any(|k| r.mods.iter().any(|m| m.member == *k)) {
                bail!("Moderators can't remove each other; ask the room's creator.");
            }
            return self.update(|s| {
                if let Some(x) = s.rooms.iter_mut().find(|x| hex(&x.room_id) == id) {
                    for k in keys {
                        x.queue.push(Queued { sealed: mod_blob(&x.secret, &seed, &x.room_id, ModAction::Ban { member: k }), nonce: 0, secret: Some(x.secret) });
                        if !x.banned.contains(&k) {
                            x.banned.push(k);
                        }
                    }
                }
            });
        }
        self.update(|s| {
            if let Some(x) = s.rooms.iter_mut().find(|x| hex(&x.room_id) == id && x.admin.is_some()) {
                if !x.removed.contains(&author.to_owned()) {
                    x.removed.push(author.to_owned());
                }
                x.paid.remove(author);
                let gone: Vec<[u8; 32]> = x.members.iter().filter(|(_, m)| m.author == author).filter_map(|(k, _)| member_key(k)).collect();
                // A removed moderator stops being one.
                if x.mods.iter().any(|m| gone.contains(&m.member)) {
                    x.mods.retain(|m| !gone.contains(&m.member));
                    rotate_ask(x);
                    let action = Action::Moderators { mods: x.mods.clone(), approval: x.approval };
                    if let Some(b) = admin_entry(x, action) {
                        x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
                    }
                }
                // Ban every room-only key they announced (authority log), so
                // their hellos and messages are refused by everyone.
                let keys: Vec<[u8; 32]> = x.members.iter().filter(|(_, m)| m.author == author).filter_map(|(k, _)| member_key(k)).collect();
                for k in keys {
                    if !x.banned.contains(&k) {
                        if let Some(b) = admin_entry(x, Action::Ban { member: k }) {
                            x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
                        }
                        x.banned.push(k);
                    }
                }
            }
        })?;
        self.rekey_room(id)
    }

    /// Admin: hide a message for everyone in the room.
    pub fn hide_room_message(&self, id: &str, msg_id: &str) -> Result<()> {
        let (session, index) = msg_id.rsplit_once(':').context("bad message")?;
        let index: u32 = index.parse().context("bad message")?;
        let session = session.to_owned();
        let mut ok = false;
        self.update(|s| {
            if let Some(x) = s.rooms.iter_mut().find(|x| hex(&x.room_id) == id) {
                if x.admin.is_some() {
                    if let Some(b) = admin_entry(x, Action::Redact { session_id: session.clone(), index }) {
                        x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
                        x.redacted.push((session.clone(), index));
                        ok = true;
                    }
                } else if let Some(seed) = x.my_mod {
                    let b = mod_blob(&x.secret, &seed, &x.room_id, ModAction::Hide { session_id: session.clone(), index });
                    x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
                    x.redacted.push((session.clone(), index));
                    ok = true;
                }
            }
        })?;
        if !ok {
            bail!("Only the room's admin and moderators can hide messages.");
        }
        Ok(())
    }

    /// Creator: new room secret for everyone still entitled.
    fn rekey_room(&self, id: &str) -> Result<()> {
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?.clone();
        let admin = r.admin.context("Only the creator can do this.")?;
        let now = super::unix_now();
        let keep: Vec<([u8; 32], Option<Vec<u8>>)> = r
            .members
            .iter()
            // Only identities proven to me: anyone with the room secret could
            // post a hello *claiming* to be a paid member.
            .filter(|(_, m)| m.verified)
            .filter(|(_, m)| !r.removed.contains(&m.author))
            .filter(|(_, m)| r.access != "membership" || r.paid.get(&m.author).is_some_and(|u| *u > now))
            .filter_map(|(k, m)| member_key(k).map(|k| (k, m.kem.clone())))
            .collect();
        let _ = admin;
        let new_secret = sentinel_core::random_bytes::<32>();
        let epoch = r.epoch + 1;
        // The cut: the last message of each stream I've seen in this epoch.
        // Anything later in the old epoch is dropped by everyone (a removed
        // member can't back-date messages).
        let mut cut: room_auth::Cut = r.seen_max.iter().map(|(s, i)| (s.clone(), *i)).collect();
        if let (Some(sid), Some(mine)) = (&r.outbound_id, r.messages.iter().filter(|m| m.mine && m.epoch == r.epoch).map(|m| m.index).max()) {
            cut.push((sid.clone(), mine));
        }
        let action = room_auth::rekey_action(&r.room_id, epoch, &new_secret, &keep, cut);
        let today = sentinel_core::dm::today();
        self.update(|s| {
            if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == r.room_id) {
                let Some(blob) = admin_entry(x, action) else { return };
                // Send it right away, ahead of any new-epoch messages, into
                // the old box (where the remaining members still look); then
                // re-post it daily for a week for anyone who was offline.
                x.queue.push(Queued { sealed: blob.clone(), nonce: 0, secret: Some(x.secret) });
                x.rekey_repost = Some((blob, x.secret, today + 7));
                x.repost_day = today;
                x.seen_max.clear();
                x.secret = new_secret;
                x.epoch = epoch;
                x.last_rekey_day = today;
                x.needs_hello = true;
                x.info_day = 0; // re-post details in the new boxes
                x.cursors.clear();
                // Fresh sender key: removed members hold the old one's keys.
                x.outbound = None;
                x.outbound_id = None;
            }
        })
    }

    /// Creator: put this public room's listing in Discover. Signed with the
    /// room's own admin key (not my account), refreshed every 30 days.
    async fn publish_listing(&self, r: &RoomState) -> Result<()> {
        let admin = r.admin.context("not the creator")?;
        let link = self.room_link(&hex(&r.room_id))?;
        let listing = social::RoomListing {
            name: r.name.clone(),
            description: r.description.clone(),
            topics: r.topics.clone(),
            access: r.access.clone(),
            price: r.price,
            link,
            minute: 0,
        };
        let env = social::room_listing_envelope(&SigningKey::from_bytes(&admin), &listing).map_err(|e| anyhow::anyhow!(e))?;
        let bytes = env.encode()?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let mut s = net.connect_hedged(&r.pillar).await?;
        match request(&mut s, &Request::Put(bytes)).await? {
            Response::Stored(_) => Ok(()),
            other => bail!("listing not stored: {other:?}"),
        }
    }

    /// Deposit an already sealed blob into today's room box.
    pub(super) async fn deposit_sealed(&self, pillar: &str, secret: &[u8; 32], sealed: Vec<u8>) -> Result<()> {
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let (bx, _) = room::room_box(secret, sentinel_core::dm::today());
        let shard = sentinel_core::dm::shard_of(&bx);
        let data = sentinel_core::dm::deposit_pow_data(shard, &sealed);
        let bits = sentinel_core::dm::deposit_bits(sealed.len());
        let nonce = tokio::task::spawn_blocking(move || sentinel_core::pow::stamp(sentinel_core::dm::DEPOSIT_POW_DOMAIN, &data, bits)).await?;
        self.deposit(&net, pillar, shard, sealed, nonce).await
    }

    /// Deliver a room's queued blobs in order; stop at the first failure.
    pub(super) async fn flush_room_queue(&self, room_id: &[u8; 32]) -> Result<usize> {
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| r.room_id == *room_id).context("no such room")?.clone();
        // Without mixing, one room's queued items share one connection to
        // the room's Pillar: a new onion connection costs 5–20 seconds each,
        // which made a new room's first message wait a minute or more. The
        // Pillar can tell these sealed items came from one device (as their
        // timing mostly shows anyway), never what they say, who sent them or
        // which room they belong to. With mixing, each goes through the mix.
        let direct = !(store.privacy.mix || store.privacy.high_risk);
        let mut conn: Option<Box<dyn super::Io>> = None;
        let mut delivered = 0;
        for q in r.queue {
            let secret = q.secret.unwrap_or(r.secret);
            if direct {
                let net = self.with(|i| i.net.clone()).context("not connected")?;
                let (bx, _) = room::room_box(&secret, sentinel_core::dm::today());
                let shard = sentinel_core::dm::shard_of(&bx);
                let data = sentinel_core::dm::deposit_pow_data(shard, &q.sealed);
                let bits = sentinel_core::dm::deposit_bits(q.sealed.len());
                let nonce = tokio::task::spawn_blocking(move || sentinel_core::pow::stamp(sentinel_core::dm::DEPOSIT_POW_DOMAIN, &data, bits)).await?;
                let started = tokio::time::Instant::now();
                if conn.is_none() {
                    conn = Some(net.connect_hedged(&r.pillar).await?);
                }
                let s = conn.as_mut().expect("just opened");
                match request(s, &Request::Deposit { shard, blob: q.sealed.clone(), nonce }).await {
                    Ok(Response::Pong) => sentinel_net::note(format!("Sentinel: room item delivered in {}s", started.elapsed().as_secs())),
                    Ok(other) => bail!("not delivered: {other:?}"),
                    Err(e) => {
                        sentinel_net::note(format!("Sentinel: room item failed: {e:#}"));
                        return Err(e);
                    }
                }
            } else {
                self.deposit_sealed(&r.pillar, &secret, q.sealed.clone()).await?;
            }
            delivered += 1;
            self.update(|s| {
                if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) {
                    x.queue.retain(|y| y.sealed != q.sealed);
                    if q.nonce != 0 {
                        if let Some(m) = x.messages.iter_mut().find(|m| m.mine && m.nonce == q.nonce) {
                            m.sent = true;
                        }
                    }
                }
            })?;
        }
        Ok(delivered)
    }

    /// Creator: post the signed room details once a day (late joiners only
    /// read recent boxes).
    fn queue_room_info(&self, room_id: &[u8; 32]) -> Result<()> {
        let today = sentinel_core::dm::today();
        self.update(|s| {
            let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) else { return };
            let Some(admin) = x.admin else { return };
            if x.info_day == today {
                return;
            }
            let _ = admin;
            // A checkpoint: the full room state, so late joiners and members
            // back from a long absence catch up without the whole history.
            let cp = Action::Checkpoint {
                name: x.name.clone(),
                visibility: x.visibility.clone(),
                access: x.access.clone(),
                epoch: x.epoch,
                banned: x.banned.clone(),
                redacted: x.redacted.iter().rev().take(200).cloned().collect(),
                mods: x.mods.clone(),
                approval: x.approval,
                apps: x.apps.list.clone(),
            };
            if let Some(b) = admin_entry(x, cp) {
                x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
            }
            x.info_day = today;
        })
    }

    /// Encrypt with my Megolm session (announcing it first if needed) and send.
    pub fn send_room(self: &Arc<Self>, app: AppHandle, id: &str, text: &str) -> Result<()> {
        let text = text.trim().to_owned();
        if text.is_empty() || text.chars().count() > 4000 {
            bail!("Messages must be 1–4000 characters.");
        }
        self.send_room_payload(app, id, text, None)
    }

    /// Send a message, or (with `call`) a Sentinel App command.
    pub(super) fn send_room_payload(self: &Arc<Self>, app: AppHandle, id: &str, text: String, call: Option<room::AppCall>) -> Result<()> {
        let (key, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| hex(&r.room_id) == id).context("no such room")?.clone();
        if r.waiting {
            bail!("You can post once you've been let in.");
        }
        let mut session = match r.outbound.as_deref().and_then(|p| load_group(&key, p)) {
            Some(s) => s,
            None => GroupSession::new(room::megolm_config()),
        };
        let today = sentinel_core::dm::today();
        // Hello (at the current ratchet index) on the first message of each
        // day, or when new members appeared, so they can read and verify me.
        let announce = (r.announced_day != today || r.needs_hello).then(|| self.make_hello(&key, &r, &session, &store.name));
        let lamport = r.lamport.saturating_add(1);
        let index = session.message_index();
        let payload = RoomPayload { text: text.clone(), minute: social::coarse_minute(), from: Some(key.verifying_key().to_bytes()), lamport, app: call.clone() };
        let msg = room::seal_blob(&r.secret, &room::encrypt_message(&mut session, &payload));
        let pickled = session.pickle().encrypt(&pickle_key(&key));
        let sid = session.session_id();
        let me = social::author_text(&key.verifying_key().to_bytes());
        let minute = payload.minute;
        let nonce = u64::from_le_bytes(sentinel_core::random_bytes::<8>()) | 1;
        self.update(|s| {
            let name = s.name.clone();
            if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == r.room_id) {
                x.outbound = Some(pickled);
                x.outbound_id = Some(sid.clone());
                if let Some((a, covers)) = announce {
                    x.queue.push(Queued { sealed: a, nonce: 0, secret: Some(r.secret) });
                    x.announced_day = today;
                    x.announced = true;
                    x.hello_covers = covers;
                    x.needs_hello = false;
                }
                x.queue.push(Queued { sealed: msg, nonce, secret: Some(r.secret) });
                x.lamport = x.lamport.max(lamport);
                let epoch = x.epoch;
                x.messages.push(RoomMsg { author: me.clone(), name, text, minute, mine: true, sent: false, nonce, verified: true, session: sid.clone(), index, epoch, lamport, app: call });
            }
        })?;
        let _ = self.queue_room_info(&r.room_id);
        let core = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let _ = core.flush_room_queue(&r.room_id).await;
            let _ = app.emit("rooms", ());
        });
        Ok(())
    }

    /// A sealed hello for my session, MACed to every member I know.
    fn make_hello(&self, key: &super::Keys, r: &RoomState, session: &GroupSession, name: &str) -> (Vec<u8>, Vec<[u8; 32]>) {
        let mut members: Vec<[u8; 32]> = r.members.keys().filter_map(|k| member_key(k)).collect();
        members.sort();
        members.dedup();
        let secret = r.member_secret.unwrap_or_default();
        (room::seal_blob(&r.secret, &room::hello(key, &r.room_id, name, &secret, session, &members)), members)
    }

    /// Queue a hello if one is due (joined, new members, new day), without
    /// waiting for me to send a message.
    fn queue_hello_if_needed(&self, room_id: &[u8; 32]) -> Result<()> {
        let (key, store) = self.unlocked()?;
        let Some(r) = store.rooms.iter().find(|r| r.room_id == *room_id).cloned() else { return Ok(()) };
        if !r.needs_hello || r.waiting {
            return Ok(());
        }
        let session = match r.outbound.as_deref().and_then(|p| load_group(&key, p)) {
            Some(s) => s,
            None => GroupSession::new(room::megolm_config()),
        };
        let (blob, covers) = self.make_hello(&key, &r, &session, &store.name);
        let pickled = session.pickle().encrypt(&pickle_key(&key));
        let sid = session.session_id();
        let today = sentinel_core::dm::today();
        self.update(|s| {
            if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) {
                x.outbound = Some(pickled);
                x.outbound_id = Some(sid);
                x.queue.push(Queued { sealed: blob, nonce: 0, secret: Some(r.secret) });
                x.hello_covers = covers;
                x.needs_hello = false;
                x.announced_day = today;
                x.announced = true;
            }
        })
    }

    /// Room upkeep: post room details (creator), hellos when due, and
    /// deliver queued blobs.
    pub async fn room_maintenance(&self) -> Result<()> {
        let (_, store) = self.unlocked()?;
        let today = sentinel_core::dm::today();
        for r in store.rooms {
            if r.waiting {
                let _ = self.flush_room_queue(&r.room_id).await; // my request
                continue;
            }
            // Members a moderator banned: remove them fully (new keys).
            if r.admin.is_some() && !r.pending_bans.is_empty() {
                for k in &r.pending_bans {
                    match r.members.iter().find(|(m, _)| member_key(m) == Some(*k)) {
                        Some((_, m)) if !r.removed.contains(&m.author) => {
                            let _ = self.remove_member(&hex(&r.room_id), &m.author);
                        }
                        Some(_) => {}
                        None => {
                            // A key I never saw a hello from: just ban it.
                            self.update(|s| {
                                if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == r.room_id) {
                                    if !x.banned.contains(k) {
                                        if let Some(b) = admin_entry(x, Action::Ban { member: *k }) {
                                            x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
                                        }
                                        x.banned.push(*k);
                                    }
                                }
                            })?;
                        }
                    }
                }
                self.update(|s| {
                    if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == r.room_id) {
                        x.pending_bans.retain(|k| !r.pending_bans.contains(k));
                    }
                })?;
            }
            // Memberships: new secret every 30 days, only for paid-up members.
            if r.admin.is_some() && r.access == "membership" && today >= r.last_rekey_day + 30 {
                let _ = self.rekey_room(&hex(&r.room_id));
            }
            // Keep re-posting the latest rekey in the old boxes for a week.
            if let Some((blob, old, until)) = self.unlocked()?.1.rooms.iter().find(|x| x.room_id == r.room_id).and_then(|x| x.rekey_repost.clone()) {
                if today <= until && r.repost_day != today && self.deposit_sealed(&r.pillar, &old, blob).await.is_ok() {
                    self.update(|s| {
                        if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == r.room_id) {
                            x.repost_day = today;
                        }
                    })?;
                }
            }
            if r.admin.is_some() && r.visibility == "public" && (r.listing_day == 0 || today >= r.listing_day + 30) && self.publish_listing(&r).await.is_ok() {
                self.update(|s| {
                    if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == r.room_id) {
                        x.listing_day = today;
                    }
                })?;
            }
            let _ = self.app_upkeep(&r.room_id);
            let _ = self.queue_room_info(&r.room_id);
            let _ = self.queue_hello_if_needed(&r.room_id);
            let _ = self.flush_room_queue(&r.room_id).await;
        }
        Ok(())
    }

    /// Upkeep, then fetch new room messages. Returns how many arrived.
    pub async fn poll_rooms(&self) -> Result<usize> {
        self.room_maintenance().await?;
        Ok(self.poll_mail().await?.1)
    }

    pub(super) fn apply_room_blob(&self, key: &super::Keys, room_id: &[u8; 32], secret: &[u8; 32], bytes: &[u8]) -> Result<bool> {
        let Some(blob) = room::open_blob(secret, bytes) else { return Ok(false) };
        let me = social::author_text(&key.verifying_key().to_bytes());
        match blob {
            RoomBlob::Info { signed } => {
                // Only the room's admin key can set the details.
                let Some(info) = room::accept_info(room_id, &signed) else { return Ok(false) };
                if !matches!(info.visibility.as_str(), "public" | "private") || !matches!(info.access.as_str(), "free" | "pass" | "membership") {
                    return Ok(false);
                }
                self.update(|s| {
                    if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) {
                        if info.version >= x.info_version {
                            x.name = info.name.chars().take(60).collect();
                            x.visibility = info.visibility;
                            x.access = info.access;
                            x.info_version = info.version;
                        }
                    }
                })?;
                Ok(false)
            }
            RoomBlob::Rekey { signed } => {
                let (_, store) = self.unlocked()?;
                let Some(r) = store.rooms.iter().find(|x| x.room_id == *room_id) else { return Ok(false) };
                let Some((epoch, new_secret)) = room::accept_rekey(room_id, &signed, &r.member_secret.unwrap_or_default()) else { return Ok(false) };
                if epoch > r.epoch {
                    self.update(|s| {
                        if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) {
                            x.secret = new_secret;
                            x.epoch = epoch;
                            x.needs_hello = true;
                            x.cursors.clear();
                            // Fresh sender key for the new epoch.
                            x.outbound = None;
                            x.outbound_id = None;
                        }
                    })?;
                    self.rescan_pillar(&r.pillar);
                }
                Ok(false)
            }
            RoomBlob::Authority { signed } => {
                let mut rescan = None;
                self.update(|s| {
                    let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) else { return };
                    for e in x.auth.offer(room_id, &signed) {
                        match e.action {
                            Action::Moderators { mods, approval } => {
                                if x.admin.is_none() {
                                    apply_mods(x, mods, approval);
                                }
                            }
                            Action::Checkpoint { name, visibility, access, banned, redacted, mods, approval, apps, .. } => {
                                if matches!(visibility.as_str(), "public" | "private") && matches!(access.as_str(), "free" | "pass" | "membership") {
                                    x.name = name.chars().take(60).collect();
                                    x.visibility = visibility;
                                    x.access = access;
                                }
                                if x.admin.is_none() {
                                    x.apps.set_list(apps);
                                    apply_mods(x, mods, approval);
                                    x.banned = banned;
                                    for r in redacted {
                                        if !x.redacted.contains(&r) {
                                            x.redacted.push(r);
                                        }
                                    }
                                }
                            }
                            Action::Apps { apps } => {
                                if x.admin.is_none() {
                                    x.apps.set_list(apps);
                                }
                            }
                            Action::Details { name, visibility, access } => {
                                if matches!(visibility.as_str(), "public" | "private") && matches!(access.as_str(), "free" | "pass" | "membership") {
                                    x.name = name.chars().take(60).collect();
                                    x.visibility = visibility;
                                    x.access = access;
                                }
                            }
                            Action::Ban { member } => {
                                if !x.banned.contains(&member) {
                                    x.banned.push(member);
                                }
                            }
                            Action::Unban { member } => x.banned.retain(|m| *m != member),
                            Action::Redact { session_id, index } => {
                                if !x.redacted.iter().any(|(s, i)| *s == session_id && *i == index) {
                                    x.redacted.push((session_id, index));
                                }
                            }
                            Action::Rekey { epoch, entries, cut } => {
                                if x.admin.is_some() || epoch <= x.epoch {
                                    continue;
                                }
                                // Drop old-epoch messages beyond the cut (no back-dating).
                                let old = x.epoch;
                                x.messages.retain(|m| m.mine || m.epoch != old || m.session.is_empty() || !room_auth::beyond_cut(&cut, &m.session, m.index));
                                if let Some(new_secret) = room_auth::open_rekey(room_id, &entries, &x.member_secret.unwrap_or_default()) {
                                    x.secret = new_secret;
                                    x.epoch = epoch;
                                    x.needs_hello = true;
                                    x.cursors.clear();
                                    x.outbound = None;
                                    x.outbound_id = None;
                                    x.seen_max.clear();
                                    rescan = Some(x.pillar.clone());
                                }
                            }
                        }
                    }
                })?;
                if let Some(p) = rescan {
                    self.rescan_pillar(&p);
                }
                Ok(false)
            }
            RoomBlob::Mod { signed } => {
                self.update(|s| {
                    let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) else { return };
                    let Some((_, e)) = room_auth::verify_mod(room_id, &x.mods, &signed) else { return };
                    if x.mod_seen.contains(&e.id) {
                        return;
                    }
                    x.mod_seen.push(e.id);
                    if x.mod_seen.len() > 4096 {
                        x.mod_seen.remove(0);
                    }
                    let in_room = *secret == x.secret;
                    match e.action {
                        ModAction::Hide { session_id, index } if in_room => {
                            if !x.redacted.iter().any(|(s, i)| *s == session_id && *i == index) {
                                x.redacted.push((session_id, index));
                            }
                        }
                        ModAction::Ban { member } if in_room => {
                            // Moderators can't ban each other.
                            if x.mods.iter().any(|m| m.member == member) {
                                return;
                            }
                            if x.admin.is_some() {
                                let mine = x.member_secret.map(|m| room::member_pub(&m));
                                if mine == Some(member) {
                                    // A moderator banned the creator: undo it for everyone.
                                    if let Some(b) = admin_entry(x, Action::Unban { member }) {
                                        x.queue.push(Queued { sealed: b, nonce: 0, secret: Some(x.secret) });
                                    }
                                } else if !x.pending_bans.contains(&member) && !x.banned.contains(&member) {
                                    x.pending_bans.push(member); // removed fully in upkeep
                                }
                            } else if !x.banned.contains(&member) {
                                x.banned.push(member);
                            }
                        }
                        ModAction::Handled { request } if Some(*secret) == x.ask => x.requests.retain(|q| q.id() != request),
                        _ => {}
                    }
                })?;
                Ok(false)
            }
            RoomBlob::Ask(req) => {
                self.update(|s| {
                    let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) else { return };
                    let approver = x.admin.is_some() || x.my_mod.is_some();
                    if !approver || x.ask != Some(*secret) || req.room_id != *room_id || !req.valid() {
                        return;
                    }
                    if x.removed.contains(&social::author_text(&req.from)) || x.requests.iter().any(|q| q.reply == req.reply) || x.requests.len() >= MAX_REQUESTS {
                        return;
                    }
                    x.requests.push(req);
                })?;
                Ok(false)
            }
            RoomBlob::Answer { room_id: rid, sealed, epoch } => {
                let mut rescan = None;
                self.update(|s| {
                    let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) else { return };
                    if !x.waiting || *secret != x.secret || rid != *room_id {
                        return;
                    }
                    match sealed {
                        Some(b) => {
                            if let Some(room_secret) = room::open_answer(room_id, &b, &x.member_secret.unwrap_or_default()) {
                                x.secret = room_secret;
                                x.epoch = epoch;
                                x.waiting = false;
                                x.declined = false;
                                x.needs_hello = true;
                                x.cursors.clear();
                                rescan = Some(x.pillar.clone());
                            }
                        }
                        None => x.declined = true,
                    }
                })?;
                if let Some(p) = rescan {
                    self.rescan_pillar(&p);
                }
                Ok(false)
            }
            RoomBlob::AppState { signed } => {
                self.update(|s| {
                    if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) {
                        x.apps.accept_snapshot(room_id, &signed);
                    }
                })?;
                Ok(false)
            }
            RoomBlob::AppCode { signed } => {
                self.update(|s| {
                    if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) {
                        x.apps.accept_code(room_id, &signed);
                    }
                })?;
                Ok(false)
            }
            RoomBlob::Hello(h) => {
                let (_, store) = self.unlocked()?;
                let Some(r) = store.rooms.iter().find(|x| x.room_id == *room_id) else { return Ok(false) };
                if r.banned.contains(&h.member_pub) {
                    return Ok(false); // banned by the room's admin
                }
                let my_secret = r.member_secret.unwrap_or_default();
                let Some((inbound, verified)) = room::accept_hello(room_id, &h, &my_secret) else { return Ok(false) };
                let author = social::author_text(&h.from);
                if author == me || h.member_pub == room::member_pub(&my_secret) {
                    return Ok(false); // my own hello
                }
                let sid = inbound.session_id();
                let pickle = inbound.pickle().encrypt(&pickle_key(key));
                let name: String = h.name.chars().take(40).collect();
                self.update(|s| {
                    if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) {
                        // Keyed by (member key, identity): nobody can claim
                        // someone else's key away from them.
                        let key = format!("{}:{}", hex(&h.member_pub), author);
                        let entry = x.members.entry(key).or_insert(MemberInfo { author: author.clone(), name: name.clone(), verified: false, kem: None });
                        if h.member_kem.is_some() {
                            entry.kem = h.member_kem.clone();
                        }
                        entry.name = name.clone();
                        entry.verified |= verified;
                        if !x.hello_covers.contains(&h.member_pub) && x.members.len() <= 500 {
                            x.needs_hello = true; // let them verify me too
                        }
                        // A session belongs to the first identity that claimed
                        // it; a later valid MAC from that identity verifies it.
                        let e = x.inbound.entry(sid).or_insert(InboundEntry { pickle, author: author.clone(), name: name.clone(), verified, member: Some(h.member_pub) });
                        if e.author == author {
                            e.name = name.clone();
                            e.verified |= verified;
                        }
                        if verified {
                            for m in x.messages.iter_mut().filter(|m| m.author == author) {
                                m.verified = true;
                                m.name = name.clone();
                            }
                        }
                    }
                })?;
                Ok(false)
            }
            RoomBlob::Message { session_id, ciphertext } => {
                let (_, store) = self.unlocked()?;
                let Some(r) = store.rooms.iter().find(|x| x.room_id == *room_id) else { return Ok(false) };
                if r.outbound_id.as_deref() == Some(session_id.as_str()) {
                    return Ok(false); // my own message, already shown
                }
                let Some(entry) = r.inbound.get(&session_id).cloned() else { return Ok(false) };
                if entry.member.is_some_and(|k| r.banned.contains(&k)) {
                    return Ok(false); // banned by the room's admin
                }
                let Some(mut inbound) = load_inbound(key, &entry.pickle) else { return Ok(false) };
                let Some((payload, idx)) = room::decrypt_message(&mut inbound, &ciphertext) else { return Ok(false) };
                let seen_key = format!("{session_id}:{idx}");
                if r.seen.contains(&seen_key) {
                    return Ok(false); // replayed message
                }
                // Trust the identity inside the signed message over the
                // announcement; if they disagree, show only the real handle.
                let (author, name, verified) = match payload.from.map(|f| social::author_text(&f)) {
                    Some(a) if a != entry.author => (a.clone(), handle_of(&a), false),
                    _ => (entry.author.clone(), entry.name.clone(), entry.verified),
                };
                if author == me {
                    return Ok(false);
                }
                let pickle = inbound.pickle().encrypt(&pickle_key(key));
                self.update(|s| {
                    if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == *room_id) {
                        if let Some(e) = x.inbound.get_mut(&session_id) {
                            e.pickle = pickle;
                        }
                        x.seen.insert(seen_key);
                        let top = x.seen_max.entry(session_id.clone()).or_insert(0);
                        *top = (*top).max(idx);
                        // A counter can only jump so far ahead: an honest room never
                        // gets near this, and a member sending a huge one can't push
                        // everyone's counter to the limit and break the order.
                        let lamport = payload.lamport.min(x.lamport.saturating_add(MAX_LAMPORT_JUMP));
                        x.lamport = x.lamport.max(lamport);
                        let epoch = x.epoch;
                        x.messages.push(RoomMsg {
                            author,
                            name,
                            text: payload.text,
                            minute: payload.minute,
                            mine: false,
                            sent: true,
                            nonce: 0,
                            verified,
                            session: session_id.clone(),
                            index: idx,
                            epoch,
                            lamport,
                            app: payload.app,
                        });
                        // One agreed order for every member: (counter, then
                        // time for older messages without one, session, index).
                        x.messages.sort_by(|a, b| (a.lamport, a.minute, &a.session, a.index).cmp(&(b.lamport, b.minute, &b.session, b.index)));
                    }
                })?;
                Ok(true)
            }
        }
    }
}

fn load_group(key: &super::Keys, p: &str) -> Option<GroupSession> {
    GroupSessionPickle::from_encrypted(p, &pickle_key(key)).ok().map(GroupSession::from_pickle)
}

fn load_inbound(key: &super::Keys, p: &str) -> Option<InboundGroupSession> {
    InboundGroupSessionPickle::from_encrypted(p, &pickle_key(key)).ok().map(InboundGroupSession::from_pickle)
}
