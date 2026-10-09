//! Rooms v1 (spec §6.2.6): small rooms with Megolm sender keys.
//!
//! - A room has a random `room_id` and a 32-byte **room secret**. The invite
//!   link carries the secret. Admin actions (details, rekeys with epoch
//!   cuts, bans, hidden messages) form the room authority log (`room_auth`).
//! - Each member sends with their own Megolm outbound session (vodozemac)
//!   and shares it in a **hello**. Hellos are *deniable*: instead of an
//!   identity signature, each carries a MAC for every member it knows, keyed
//!   by Diffie-Hellman between the sender's identity key and that member's
//!   room-only key. A member can verify who sent a session; a seized room
//!   database proves nothing to outsiders, because any member could have
//!   computed the same MACs.
//! - Room details (name, visibility, access) are signed by a **room admin
//!   key** that exists only for this room and is held by its creator; the
//!   room ID is derived from that key, so members can verify who may change
//!   the details without anyone's identity being involved.
//! - All blobs are sealed with a key derived from the room secret and stored
//!   under a **rotating room box ID** that is the hash of a fetch token only
//!   members can compute. A Pillar can't tell which room a blob is for, who
//!   sent it, or who is in the room.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use vodozemac::megolm::{GroupSession, InboundGroupSession, MegolmMessage, SessionConfig, SessionKey};

use crate::object::Envelope;

const PAD: usize = 512;

pub fn megolm_config() -> SessionConfig {
    SessionConfig::version_1()
}

/// `sentinel://room/<room_id>@<pillar-host>#<secret>`.
#[derive(Clone, Debug, PartialEq)]
pub struct RoomLink {
    pub room_id: [u8; 32],
    pub pillar: String,
    pub secret: [u8; 32],
}

fn b32(b: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(b).to_lowercase()
}

fn from_b32(s: &str) -> Option<[u8; 32]> {
    data_encoding::BASE32_NOPAD.decode(s.trim().to_uppercase().as_bytes()).ok()?.try_into().ok()
}

impl RoomLink {
    pub fn to_text(&self) -> String {
        format!("sentinel://room/{}@{}#{}", b32(&self.room_id), self.pillar.trim_end_matches(".onion"), b32(&self.secret))
    }

    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.trim().strip_prefix("sentinel://room/")?;
        let (rest, secret) = rest.split_once('#')?;
        let (id, host) = rest.split_once('@')?;
        let host = host.trim_end_matches(".onion").to_ascii_lowercase();
        if host.len() != 56 || !host.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)) {
            return None;
        }
        Some(RoomLink { room_id: from_b32(id)?, pillar: format!("{host}.onion"), secret: from_b32(secret)? })
    }
}

fn kdf(label: &str, secret: &[u8; 32], day: Option<u64>) -> [u8; 32] {
    let mut m = secret.to_vec();
    if let Some(d) = day {
        m.extend_from_slice(&d.to_le_bytes());
    }
    blake3::derive_key(label, &m)
}

/// Daily room box: `(id, fetch_token)`; id = H(token), like DM inboxes.
pub fn room_box(secret: &[u8; 32], day: u64) -> ([u8; 32], [u8; 32]) {
    let token = kdf("sentinel/v0/room-fetch-token", secret, Some(day));
    (crate::dm::inbox_id_from_token(&token), token)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RoomBlob {
    /// A member's Megolm session with deniable per-member MACs.
    Hello(Hello),
    /// A Megolm-encrypted message.
    Message { session_id: String, ciphertext: Vec<u8> },
    /// Room details, signed by the room admin key (see `RoomInfo`).
    Info { signed: Vec<u8> },
    /// New room secret for the members still in the room, signed by the
    /// admin key (removals, monthly memberships).
    Rekey { signed: Vec<u8> },
    /// An entry of the room authority log (see `room_auth`).
    Authority { signed: Vec<u8> },
    /// A moderator's action (or the admin's note that a request was
    /// handled), signed with their room-only key (see `room_auth::ModEntry`).
    Mod { signed: Vec<u8> },
    /// A request to join an approval room. Sealed with the room's *ask*
    /// key and left in the ask box, which only the admin and moderators read.
    Ask(JoinRequest),
    /// The answer to a request, left in the requester's reply box: the room
    /// secret sealed to the room-only key they sent, or nothing (declined).
    Answer { room_id: [u8; 32], sealed: Option<Vec<u8>>, epoch: u64 },
    /// A Sentinel App's state, signed by the admin key (see
    /// `apps::Snapshot`): members start from the newest one.
    AppState {
        #[serde(with = "crate::apps::serde_bytes_compat")]
        signed: Vec<u8>,
    },
    /// A piece of an app's package (apps that aren't built in), signed by
    /// the admin key. Members check the whole against the app's identity
    /// in the authority log.
    AppCode {
        #[serde(with = "crate::apps::serde_bytes_compat")]
        signed: Vec<u8>,
    },
    /// A member's report about a message, sealed separately to the room's
    /// admin and each moderator: only they can read it (other members see a
    /// blob they can't open, and so does the Pillar).
    Report { sealed: Vec<Vec<u8>> },
}

/// A report about one room message (see `RoomBlob::Report`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomReport {
    pub session_id: String,
    pub index: u32,
    /// What's wrong (one of `crate::social::REPORT_CATEGORIES`).
    pub category: String,
    /// The reporter's note (optional, short).
    pub note: String,
    /// The message as the reporter saw it.
    pub text: String,
    pub minute: u64,
}

const REPORT_CONTEXT: &str = "sentinel/v1/room-report";

/// Seal a report to one admin or moderator (their room-only keys).
pub fn seal_report(to: &[u8; 32], to_kem: &[u8], room_id: &[u8; 32], r: &RoomReport) -> Option<Vec<u8>> {
    crate::pq::seal(REPORT_CONTEXT, room_id, to, Some(to_kem), &cbor(r))
}

/// Open a report sealed to me, if it is.
pub fn open_report(member_secret: &[u8; 32], room_id: &[u8; 32], sealed: &[u8]) -> Option<RoomReport> {
    let plain = crate::pq::open(REPORT_CONTEXT, room_id, member_secret, Some(&member_kem_seed(member_secret)), sealed)?;
    let r: RoomReport = ciborium::from_reader(plain.as_slice()).ok()?;
    (r.text.chars().count() <= 5000 && r.note.chars().count() <= 500 && r.category.len() <= 40).then_some(r)
}

/// A request to join (approval rooms).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct JoinRequest {
    pub room_id: [u8; 32],
    /// Who they *say* they are. Not proven here (a signature would be
    /// lasting proof that they asked); once in, their hello proves it.
    pub from: [u8; 32],
    pub name: String,
    pub note: String,
    /// The room-only key they'll use as a member (the answer is sealed to it).
    pub member_pub: [u8; 32],
    /// Their reply box secret (random, used once).
    pub reply: [u8; 32],
    /// Their room-only ML-KEM key (the answer is sealed post-quantum).
    #[serde(default)]
    pub member_kem: Option<Vec<u8>>,
}

pub const MAX_REQUEST_NOTE: usize = 280;

impl JoinRequest {
    /// Short ID moderators use to tell each other a request was handled
    /// (never the reply secret itself: the ask box is readable by anyone
    /// holding the ask link).
    pub fn id(&self) -> [u8; 32] {
        blake3::derive_key("sentinel/v0/room-request-id", &self.reply)
    }

    pub fn valid(&self) -> bool {
        self.name.chars().count() <= 40 && self.note.chars().count() <= MAX_REQUEST_NOTE
    }
}

/// An approved request: the room secret sealed to the requester.
pub fn answer(room_id: &[u8; 32], req: &JoinRequest, secret: Option<&[u8; 32]>, epoch: u64) -> RoomBlob {
    RoomBlob::Answer { room_id: *room_id, sealed: secret.map(|s| seal_secret_to(&req.member_pub, req.member_kem.as_deref(), s, room_id)), epoch }
}

/// Requester: the room secret from an answer, if approved.
pub fn open_answer(room_id: &[u8; 32], sealed: &[u8], my_member_secret: &[u8; 32]) -> Option<[u8; 32]> {
    open_secret(my_member_secret, sealed, room_id)
}

/// `sentinel://ask/<room_id>@<pillar-host>#<ask key>/<name>`: asks to join
/// an approval room. It never carries the room secret.
#[derive(Clone, Debug, PartialEq)]
pub struct AskLink {
    pub room_id: [u8; 32],
    pub pillar: String,
    pub ask: [u8; 32],
    pub name: String,
}

impl AskLink {
    pub fn to_text(&self) -> String {
        format!("sentinel://ask/{}@{}#{}/{}", b32(&self.room_id), self.pillar.trim_end_matches(".onion"), b32(&self.ask), b32(self.name.as_bytes()))
    }

    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.trim().strip_prefix("sentinel://ask/")?;
        let (rest, tail) = rest.split_once('#')?;
        let (ask, name) = tail.split_once('/')?;
        let (id, host) = rest.split_once('@')?;
        let host = host.trim_end_matches(".onion").to_ascii_lowercase();
        if host.len() != 56 || !host.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)) {
            return None;
        }
        let name = data_encoding::BASE32_NOPAD.decode(name.to_uppercase().as_bytes()).ok().and_then(|v| String::from_utf8(v).ok())?;
        Some(AskLink { room_id: from_b32(id)?, pillar: format!("{host}.onion"), ask: from_b32(ask)?, name: name.chars().take(60).collect() })
    }
}

pub const KIND_ROOM_REKEY: &str = "room-rekey";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RekeyBody {
    pub room_id: [u8; 32],
    pub epoch: u64,
    /// (member's room-only key, new secret sealed to it).
    pub entries: Vec<([u8; 32], Vec<u8>)>,
}

/// A member's post-quantum (ML-KEM) key seed, derived from their room-only key.
pub fn member_kem_seed(member_secret: &[u8; 32]) -> zeroize::Zeroizing<[u8; 64]> {
    crate::pq::kem_seed_from("sentinel/v0/room-member-kem", member_secret, 0)
}

pub fn member_kem_public(member_secret: &[u8; 32]) -> Vec<u8> {
    crate::pq::kem_public(&member_kem_seed(member_secret))
}

/// Classical sealed secrets are exactly this long; hybrid ones are longer.
const CLASSICAL_SEALED: usize = 32 + 24 + 32 + 16;
const PQ_CONTEXT: &str = "sentinel/v0/room-secret-pq";

/// Seal a 32-byte secret to a member: hybrid (X25519 + ML-KEM-768) when
/// their ML-KEM key is known, classical otherwise (older apps).
pub(crate) fn seal_secret_to(to: &[u8; 32], to_kem: Option<&[u8]>, secret: &[u8; 32], room_id: &[u8; 32]) -> Vec<u8> {
    match to_kem.filter(|k| k.len() == crate::pq::KEM_PUBLIC) {
        Some(k) => crate::pq::seal(PQ_CONTEXT, room_id, to, Some(k), secret).unwrap_or_else(|| seal_secret(to, secret, room_id)),
        None => seal_secret(to, secret, room_id),
    }
}

pub(crate) fn seal_secret(to: &[u8; 32], secret: &[u8; 32], room_id: &[u8; 32]) -> Vec<u8> {
    let eph = x25519_dalek::StaticSecret::from(crate::random_bytes::<32>());
    let eph_pub = x25519_dalek::PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(*to));
    let mut m = shared.as_bytes().to_vec();
    m.extend_from_slice(eph_pub.as_bytes());
    m.extend_from_slice(room_id);
    let key = blake3::derive_key("sentinel/v0/room-rekey", &m);
    let nonce = crate::random_bytes::<24>();
    let mut out = eph_pub.as_bytes().to_vec();
    out.extend_from_slice(&nonce);
    out.extend(XChaCha20Poly1305::new((&key).into()).encrypt(XNonce::from_slice(&nonce), secret.as_slice()).expect("encrypt"));
    out
}

pub(crate) fn open_secret(member_secret: &[u8; 32], b: &[u8], room_id: &[u8; 32]) -> Option<[u8; 32]> {
    if b.len() != CLASSICAL_SEALED {
        let plain = crate::pq::open(PQ_CONTEXT, room_id, member_secret, Some(&member_kem_seed(member_secret)), b)?;
        return plain.as_slice().try_into().ok();
    }
    let eph_pub: [u8; 32] = b[..32].try_into().ok()?;
    let shared = x25519_dalek::StaticSecret::from(*member_secret).diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub));
    let mut m = shared.as_bytes().to_vec();
    m.extend_from_slice(&eph_pub);
    m.extend_from_slice(room_id);
    let key = blake3::derive_key("sentinel/v0/room-rekey", &m);
    let s = XChaCha20Poly1305::new((&key).into()).decrypt(XNonce::from_slice(&b[32..56]), &b[56..]).ok()?;
    s.try_into().ok()
}

/// Admin: hand `new_secret` to these members (their room-only keys).
pub fn rekey(admin_seed: &[u8; 32], room_id: &[u8; 32], epoch: u64, new_secret: &[u8; 32], members: &[[u8; 32]]) -> RoomBlob {
    let entries = members.iter().map(|m| (*m, seal_secret(m, new_secret, room_id))).collect();
    let body = RekeyBody { room_id: *room_id, epoch, entries };
    let k = ed25519_dalek::SigningKey::from_bytes(admin_seed);
    RoomBlob::Rekey { signed: Envelope::sign(&k, KIND_ROOM_REKEY, cbor(&body)).encode().expect("rekey encodes") }
}

/// Member: (epoch, new secret) if the admin included me.
pub fn accept_rekey(room_id: &[u8; 32], signed: &[u8], my_member_secret: &[u8; 32]) -> Option<(u64, [u8; 32])> {
    let env = Envelope::decode_verified(signed).ok()?;
    if env.kind != KIND_ROOM_REKEY || room_id_for(&env.author) != *room_id {
        return None;
    }
    let body: RekeyBody = ciborium::from_reader(env.body.as_slice()).ok()?;
    if body.room_id != *room_id {
        return None;
    }
    let mine = member_pub(my_member_secret);
    let (_, sealed) = body.entries.iter().find(|(m, _)| *m == mine)?;
    Some((body.epoch, open_secret(my_member_secret, sealed, room_id)?))
}

/// Link to buy access to a paid room: the creator's follow link (to pay
/// them by DM), the price and kind. The room secret is never in it.
#[derive(Clone, Debug, PartialEq)]
pub struct BuyLink {
    pub room_id: [u8; 32],
    /// pass | membership
    pub kind: String,
    pub price: u32,
    pub creator: String,
    pub name: String,
}

impl BuyLink {
    pub fn to_text(&self) -> String {
        format!(
            "sentinel://buy/{}/{}/{}/{}/{}",
            b32(&self.room_id),
            self.kind,
            self.price,
            b32(self.creator.as_bytes()),
            b32(self.name.as_bytes())
        )
    }

    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.trim().strip_prefix("sentinel://buy/")?;
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() != 5 || !matches!(parts[1], "pass" | "membership") {
            return None;
        }
        let dec = |x: &str| data_encoding::BASE32_NOPAD.decode(x.to_uppercase().as_bytes()).ok().and_then(|v| String::from_utf8(v).ok());
        let creator = dec(parts[3])?;
        crate::social::FollowLink::parse(&creator)?;
        let name: String = dec(parts[4])?.chars().take(60).collect();
        Some(BuyLink { room_id: from_b32(parts[0])?, kind: parts[1].into(), price: parts[2].parse().ok().filter(|p| (1..=1000).contains(p))?, creator, name })
    }
}

pub const KIND_ROOM_INFO: &str = "room-info";

/// Room details. Signed with the room admin key, whose public half derives
/// the room ID.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomInfo {
    pub room_id: [u8; 32],
    pub name: String,
    pub visibility: String,
    pub access: String,
    /// Increases with every change; the highest version wins.
    pub version: u64,
}

/// Room ID for an admin public key.
pub fn room_id_for(admin_pub: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("sentinel/v0/room-id", admin_pub)
}

/// New room: (room_id, room secret, admin key seed).
pub fn new_room_with_admin() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let admin = crate::random_bytes::<32>();
    let pubk = ed25519_dalek::SigningKey::from_bytes(&admin).verifying_key().to_bytes();
    (room_id_for(&pubk), crate::random_bytes::<32>(), admin)
}

pub fn sign_info(admin_seed: &[u8; 32], info: &RoomInfo) -> RoomBlob {
    let k = ed25519_dalek::SigningKey::from_bytes(admin_seed);
    RoomBlob::Info { signed: Envelope::sign(&k, KIND_ROOM_INFO, cbor(info)).encode().expect("info encodes") }
}

/// Verify room details: signed by the key the room ID was derived from.
pub fn accept_info(room_id: &[u8; 32], signed: &[u8]) -> Option<RoomInfo> {
    let env = Envelope::decode_verified(signed).ok()?;
    if env.kind != KIND_ROOM_INFO || room_id_for(&env.author) != *room_id {
        return None;
    }
    let info: RoomInfo = ciborium::from_reader(env.body.as_slice()).ok()?;
    (info.room_id == *room_id).then_some(info)
}

/// Member hello (see module docs).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Hello {
    pub room_id: [u8; 32],
    /// Claimed identity (verified per member by `macs`).
    pub from: [u8; 32],
    pub name: String,
    /// The sender's room-only X25519 key (members MAC to it).
    pub member_pub: [u8; 32],
    /// Megolm session export (from the current ratchet index).
    pub session_key: Vec<u8>,
    /// `(recipient member_pub, MAC)` for every member the sender knows.
    pub macs: Vec<([u8; 32], [u8; 32])>,
    /// The sender's room-only ML-KEM key, so new room keys can be sealed to
    /// them post-quantum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_kem: Option<Vec<u8>>,
}

fn hello_body(h: &Hello) -> Vec<u8> {
    let mut c = h.clone();
    c.macs.clear();
    cbor(&c)
}

fn hello_mac_key(shared: &[u8; 32], room_id: &[u8; 32], from: &[u8; 32], to: &[u8; 32]) -> [u8; 32] {
    let mut m = shared.to_vec();
    m.extend_from_slice(room_id);
    m.extend_from_slice(from);
    m.extend_from_slice(to);
    blake3::derive_key("sentinel/v0/room-hello-mac", &m)
}

/// Public half of a room-only member key.
pub fn member_pub(member_secret: &[u8; 32]) -> [u8; 32] {
    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*member_secret)).as_bytes()
}

/// Build a hello for `members` (their room-only public keys).
pub fn hello(
    identity: &ed25519_dalek::SigningKey,
    room_id: &[u8; 32],
    name: &str,
    member_secret: &[u8; 32],
    session: &GroupSession,
    members: &[[u8; 32]],
) -> RoomBlob {
    let from = identity.verifying_key().to_bytes();
    let mut h = Hello {
        room_id: *room_id,
        from,
        name: name.to_owned(),
        member_pub: member_pub(member_secret),
        session_key: session.session_key().to_bytes(),
        macs: Vec::new(),
        member_kem: Some(member_kem_public(member_secret)),
    };
    let body = hello_body(&h);
    let id_secret = x25519_dalek::StaticSecret::from(identity.to_scalar_bytes());
    for m in members.iter().filter(|m| **m != h.member_pub).take(500) {
        let shared = id_secret.diffie_hellman(&x25519_dalek::PublicKey::from(*m));
        let key = hello_mac_key(shared.as_bytes(), room_id, &from, m);
        h.macs.push((*m, *blake3::keyed_hash(&key, &body).as_bytes()));
    }
    RoomBlob::Hello(h)
}

/// Read a hello: the inbound session and whether its identity is verified
/// *for me* (a MAC to my member key checked out).
pub fn accept_hello(room_id: &[u8; 32], h: &Hello, my_member_secret: &[u8; 32]) -> Option<(InboundGroupSession, bool)> {
    if h.room_id != *room_id || h.name.chars().count() > 40 || h.macs.len() > 500 || h.member_kem.as_ref().is_some_and(|k| k.len() != crate::pq::KEM_PUBLIC) {
        return None;
    }
    let key = SessionKey::from_bytes(&h.session_key).ok()?;
    let inbound = InboundGroupSession::new(&key, megolm_config());
    let mine = member_pub(my_member_secret);
    let verified = h.macs.iter().find(|(to, _)| *to == mine).is_some_and(|(_, mac)| {
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&h.from) else { return false };
        let shared = x25519_dalek::StaticSecret::from(*my_member_secret)
            .diffie_hellman(&x25519_dalek::PublicKey::from(vk.to_montgomery().to_bytes()));
        let k = hello_mac_key(shared.as_bytes(), room_id, &h.from, &mine);
        blake3::keyed_hash(&k, &hello_body(h)) == blake3::Hash::from(*mac)
    });
    Some((inbound, verified))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomPayload {
    pub text: String,
    pub minute: u64,
    /// Sender identity, inside the Megolm-signed payload: only the real
    /// session holder can set it, so a member who re-announces someone
    /// else's session can't claim their messages.
    #[serde(default)]
    pub from: Option<[u8; 32]>,
    /// Lamport counter: everyone sorts by (counter, session, index), so all
    /// members agree on the order of messages.
    #[serde(default)]
    pub lamport: u64,
    /// A command for a Sentinel App in this room (`text` is then empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppCall>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AppCall {
    pub app: [u8; 32],
    #[serde(with = "crate::apps::serde_bytes_compat")]
    pub cmd: Vec<u8>,
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

/// Seal a blob for the room box (padded; only members can open).
pub fn seal_blob(secret: &[u8; 32], blob: &RoomBlob) -> Vec<u8> {
    let mut plain = cbor(blob);
    let target = plain.len().div_ceil(PAD) * PAD + PAD;
    let len = (plain.len() as u32).to_le_bytes();
    plain.resize(target - 4, 0);
    plain.extend_from_slice(&len);
    let key = kdf("sentinel/v0/room-seal", secret, None);
    let nonce = crate::random_bytes::<24>();
    let ct = XChaCha20Poly1305::new((&key).into()).encrypt(XNonce::from_slice(&nonce), plain.as_slice()).expect("encrypt");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    out
}

pub fn open_blob(secret: &[u8; 32], bytes: &[u8]) -> Option<RoomBlob> {
    if bytes.len() < 24 + 16 + 4 {
        return None;
    }
    let key = kdf("sentinel/v0/room-seal", secret, None);
    let plain = XChaCha20Poly1305::new((&key).into()).decrypt(XNonce::from_slice(&bytes[..24]), &bytes[24..]).ok()?;
    let len = u32::from_le_bytes(plain[plain.len() - 4..].try_into().ok()?) as usize;
    ciborium::from_reader(plain.get(..len)?).ok()
}

pub fn encrypt_message(session: &mut GroupSession, payload: &RoomPayload) -> RoomBlob {
    let msg = session.encrypt(cbor(payload));
    RoomBlob::Message { session_id: session.session_id(), ciphertext: msg.to_bytes() }
}

/// Decrypt; returns (payload, message index) — the index lets callers
/// reject replays of the same message.
pub fn decrypt_message(session: &mut InboundGroupSession, ciphertext: &[u8]) -> Option<(RoomPayload, u32)> {
    let msg = MegolmMessage::from_bytes(ciphertext).ok()?;
    let d = session.decrypt(&msg).ok()?;
    Some((ciborium::from_reader(d.plaintext.as_slice()).ok()?, d.message_index))
}

pub fn new_room() -> ([u8; 32], [u8; 32]) {
    let (id, secret, _) = new_room_with_admin();
    (id, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_reports_open_only_for_the_admin_and_moderators() {
        let room_id = [3u8; 32];
        let admin = crate::random_bytes::<32>();
        let other = crate::random_bytes::<32>();
        let r = RoomReport { session_id: "s".into(), index: 4, category: "violence".into(), note: "".into(), text: "bad".into(), minute: 1 };
        let sealed = seal_report(&member_pub(&admin), &member_kem_public(&admin), &room_id, &r).unwrap();
        assert_eq!(open_report(&admin, &room_id, &sealed), Some(r));
        assert!(open_report(&other, &room_id, &sealed).is_none(), "another member can't read it");
        assert!(open_report(&admin, &[4u8; 32], &sealed).is_none(), "another room");
    }

    #[test]
    fn two_members_talk_deniably_and_outsiders_cant() {
        let (room_id, secret) = new_room();
        let alice = crate::identity::generate();
        let bob_member = crate::random_bytes::<32>();
        let eve_member = crate::random_bytes::<32>();
        let mut a_out = GroupSession::new(megolm_config());

        // Alice says hello to the members she knows (Bob) and sends.
        let a_member = crate::random_bytes::<32>();
        let h = seal_blob(&secret, &hello(&alice, &room_id, "Alice", &a_member, &a_out, &[member_pub(&bob_member)]));
        let msg = seal_blob(&secret, &encrypt_message(&mut a_out, &RoomPayload { text: "hello room".into(), minute: 5, from: None, lamport: 0, app: None }));
        assert!(!msg.windows(10).any(|w| w == b"hello room"));

        let Some(RoomBlob::Hello(hb)) = open_blob(&secret, &h) else { panic!() };
        // Bob verifies Alice; Eve (a member Alice didn't know yet) can't.
        let (mut inbound, verified) = accept_hello(&room_id, &hb, &bob_member).unwrap();
        assert!(verified);
        assert!(!accept_hello(&room_id, &hb, &eve_member).unwrap().1);
        // Forged identity claim fails verification.
        let mut forged = hb.clone();
        forged.from = crate::identity::generate().verifying_key().to_bytes();
        assert!(!accept_hello(&room_id, &forged, &bob_member).unwrap().1);
        // Deniable: Bob can compute the MAC himself (no signature exists).
        let shared = x25519_dalek::StaticSecret::from(bob_member)
            .diffie_hellman(&x25519_dalek::PublicKey::from(alice.verifying_key().to_montgomery().to_bytes()));
        let k = hello_mac_key(shared.as_bytes(), &room_id, &hb.from, &member_pub(&bob_member));
        assert_eq!(*blake3::keyed_hash(&k, &hello_body(&hb)).as_bytes(), hb.macs[0].1);

        let Some(RoomBlob::Message { session_id, ciphertext }) = open_blob(&secret, &msg) else { panic!() };
        assert_eq!(session_id, inbound.session_id());
        let (p, idx) = decrypt_message(&mut inbound, &ciphertext).unwrap();
        assert_eq!(p.text, "hello room");
        assert_eq!(idx, 0);
        assert!(open_blob(&crate::random_bytes::<32>(), &msg).is_none());
        // A hello can't be replayed into another room.
        assert!(accept_hello(&crate::random_bytes::<32>(), &hb, &bob_member).is_none());
    }

    #[test]
    fn only_the_admin_key_can_set_room_details() {
        let (room_id, _, admin) = new_room_with_admin();
        let info = RoomInfo { room_id, name: "Night Shift".into(), visibility: "private".into(), access: "free".into(), version: 1 };
        let RoomBlob::Info { signed } = sign_info(&admin, &info) else { panic!() };
        assert_eq!(accept_info(&room_id, &signed), Some(info.clone()));
        // A member (anyone with the secret) signing their own details fails.
        let RoomBlob::Info { signed: forged } = sign_info(&crate::random_bytes::<32>(), &info) else { panic!() };
        assert!(accept_info(&room_id, &forged).is_none());
        // Details for another room don't apply here.
        assert!(accept_info(&crate::random_bytes::<32>(), &signed).is_none());
    }

    #[test]
    fn rekey_reaches_only_included_members() {
        let (room_id, _, admin) = new_room_with_admin();
        let (a, b) = (crate::random_bytes::<32>(), crate::random_bytes::<32>());
        let new_secret = crate::random_bytes::<32>();
        let RoomBlob::Rekey { signed } = rekey(&admin, &room_id, 2, &new_secret, &[member_pub(&a)]) else { panic!() };
        assert_eq!(accept_rekey(&room_id, &signed, &a), Some((2, new_secret)));
        assert!(accept_rekey(&room_id, &signed, &b).is_none()); // removed
        // Only the admin key can rekey.
        let RoomBlob::Rekey { signed: forged } = rekey(&crate::random_bytes::<32>(), &room_id, 3, &new_secret, &[member_pub(&a)]) else { panic!() };
        assert!(accept_rekey(&room_id, &forged, &a).is_none());
    }

    #[test]
    fn buy_link_roundtrip() {
        let creator = crate::social::FollowLink { author: [3; 32], pillar: format!("{}.onion", "c".repeat(56)), feed_key: Some([4; 32]) }.to_text();
        let l = BuyLink { room_id: [9; 32], kind: "membership".into(), price: 5, creator, name: "Night Shift".into() };
        assert_eq!(BuyLink::parse(&l.to_text()), Some(l));
        assert!(BuyLink::parse("sentinel://buy/x/free/1/a/b").is_none());
    }

    #[test]
    fn ask_links_and_answers() {
        let (room_id, secret) = new_room();
        let l = AskLink { room_id, pillar: format!("{}.onion", "d".repeat(56)), ask: [5; 32], name: "Quiet Garden".into() };
        assert_eq!(AskLink::parse(&l.to_text()), Some(l.clone()));
        assert!(!l.to_text().contains(&b32(&secret)), "an ask link never holds the room secret");
        let member = crate::random_bytes::<32>();
        let req = JoinRequest { room_id, from: [1; 32], name: "Ana".into(), note: "hi".into(), member_pub: member_pub(&member), reply: [8; 32], member_kem: Some(member_kem_public(&member)) };
        let RoomBlob::Answer { sealed: Some(sealed), .. } = answer(&room_id, &req, Some(&secret), 3) else { panic!() };
        assert_eq!(open_answer(&room_id, &sealed, &member), Some(secret));
        assert!(open_answer(&room_id, &sealed, &crate::random_bytes::<32>()).is_none());
        assert_ne!(req.id(), req.reply);
        assert!(sealed.len() > CLASSICAL_SEALED, "sealed post-quantum");
        // An older requester without an ML-KEM key still gets a classical answer.
        let old = JoinRequest { member_kem: None, ..req };
        let RoomBlob::Answer { sealed: Some(c), .. } = answer(&room_id, &old, Some(&secret), 3) else { panic!() };
        assert_eq!(c.len(), CLASSICAL_SEALED);
        assert_eq!(open_answer(&room_id, &c, &member), Some(secret));
    }

    #[test]
    fn room_link_roundtrip_and_boxes_rotate() {
        let (room_id, secret) = new_room();
        let link = RoomLink { room_id, pillar: format!("{}.onion", "b".repeat(56)), secret };
        assert_eq!(RoomLink::parse(&link.to_text()), Some(link));
        assert!(RoomLink::parse("sentinel://room/xyz@evil.com#abc").is_none());
        assert_ne!(room_box(&secret, 1).0, room_box(&secret, 2).0);
        let (id, token) = room_box(&secret, 7);
        assert_eq!(crate::dm::inbox_id_from_token(&token), id);
    }
}
