//! Direct messages (spec §6.3, §10.2): Olm Double Ratchet via vodozemac
//! (Matrix's audited implementation) + sealed-sender inbox delivery.
//!
//! - Sessions: X3DH-style setup from the recipient's contact card
//!   (one-time / fallback prekeys), then the Double Ratchet (forward secrecy
//!   and post-compromise security).
//! - Deniable: messages are authenticated by the ratchet's MACs, never by
//!   long-term signatures. The *first* message carries the sender's contact
//!   card with a **deniable MAC**: a key from Diffie-Hellman between the
//!   sender's identity key and the recipient's inbox key. Only the two of
//!   them can compute it, so it convinces the recipient — and proves nothing
//!   to anyone else, because the recipient could have made it.
//! - Sealed sender: each Olm message is encrypted again to the recipient's
//!   inbox X25519 key with a fresh ephemeral key and deposited under a
//!   rotating inbox ID. The Pillar sees neither sender nor recipient.
//!
//! - Post-quantum: the sealed-sender layer around every Olm message is a
//!   hybrid (X25519 + ML-KEM-768) when the recipient's card has an ML-KEM
//!   key, so a recording of today's traffic can't be read by tomorrow's
//!   quantum computer without also breaking ML-KEM. The inbox ML-KEM key is
//!   derived from the inbox secret per 30-day period and rotates with it.
//!   (Olm inside is still classical; it adds forward secrecy.)

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::social::ContactCard;

/// One-time prekeys kept published in a contact card.
pub const ONE_TIME_KEYS: usize = 20;
/// Maximum deposited blob size.
pub const MAX_BLOB: usize = 64 * 1024;
/// Proof-of-work for inbox deposits (anti-spam without identity).
pub const DEPOSIT_POW_DOMAIN: &str = "sentinel/v0/deposit-pow";
pub const DEPOSIT_POW_BITS: u32 = 14;
/// Pad sealed payloads to multiples of this.
const PAD: usize = 512;

pub fn session_config() -> SessionConfig {
    SessionConfig::version_1()
}

/// Day number for inbox rotation.
pub fn today() -> u64 {
    crate::social::coarse_minute() / (60 * 24)
}

/// Days of future inbox IDs published in a card / reply info.
pub const INBOX_DAYS_AHEAD: u64 = 30;

/// Daily fetch token: only the inbox owner can compute it.
pub fn fetch_token(fetch_secret: &[u8; 32], day: u64) -> [u8; 32] {
    let mut m = fetch_secret.to_vec();
    m.extend_from_slice(&day.to_le_bytes());
    blake3::derive_key("sentinel/v0/inbox-fetch-token", &m)
}

/// Inbox ID = H(fetch token). Senders know IDs (from the card) but can't
/// derive the token, so Pillars can require the token to list an inbox.
pub fn inbox_id_from_token(token: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("sentinel/v0/inbox-id", token)
}

pub fn inbox_id(fetch_secret: &[u8; 32], day: u64) -> [u8; 32] {
    inbox_id_from_token(&fetch_token(fetch_secret, day))
}

/// My inbox IDs from yesterday through `INBOX_DAYS_AHEAD` days ahead.
pub fn upcoming_inbox_ids(fetch_secret: &[u8; 32]) -> Vec<(u64, [u8; 32])> {
    let t = today();
    (t.saturating_sub(1)..=t + INBOX_DAYS_AHEAD).map(|d| (d, inbox_id(fetch_secret, d))).collect()
}

/// Which of a contact's published inbox IDs to deliver to today.
pub fn deliver_to(ids: &[(u64, [u8; 32])]) -> Option<[u8; 32]> {
    let t = today();
    ids.iter().find(|(d, _)| *d == t).or_else(|| ids.iter().filter(|(d, _)| *d + 1 >= t && *d <= t).max_by_key(|(d, _)| *d)).map(|(_, id)| *id)
}

/// Delivery details sent inside every message so the other side always has
/// fresh inbox IDs for replies.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReplyInfo {
    pub pillar: String,
    pub inbox_pub: [u8; 32],
    pub inbox_ids: Vec<(u64, [u8; 32])>,
    /// This period's inbox ML-KEM key (it rotates every 30 days).
    #[serde(default)]
    pub inbox_kem: Option<Vec<u8>>,
}

/* ---- Mailbox shards (spec §10.2, threat #48) ----
 *
 * Deposits are filed under a 16-bit *shard* of the recipient's rotating
 * inbox ID (or a room box ID), never the ID itself. Readers fetch every
 * deposit whose shard starts with a short prefix and try to decrypt each one
 * (sealed sender: someone else's blob fails at once). The Pillar learns only
 * that someone fetched a prefix shared by many people, so it can't tell
 * when a particular person is online or count their messages. The prefix
 * length ("depth") is set by the Pillar from its traffic: 0 on a small
 * network, so everyone fetches everything.
 */

/// The 16-bit shard of an inbox or room-box ID.
pub fn shard_of(id: &[u8; 32]) -> u16 {
    u16::from_be_bytes([id[0], id[1]])
}

/// The first `bits` bits of a shard (0 bits = everything).
pub fn prefix_of(shard: u16, bits: u8) -> u16 {
    if bits == 0 { 0 } else { shard >> (16 - bits.min(16) as u32) }
}

pub fn prefix_matches(shard: u16, bits: u8, prefix: u16) -> bool {
    prefix_of(shard, bits) == prefix
}

/// Deposit proof-of-work grows with size (a shard flooded with big junk
/// blobs costs the flooder, not just the readers).
pub fn deposit_bits(len: usize) -> u32 {
    let units = len.div_ceil(8192).max(1);
    DEPOSIT_POW_BITS + (usize::BITS - 1 - units.leading_zeros())
}

pub fn deposit_pow_data(shard: u16, blob: &[u8]) -> Vec<u8> {
    let mut d = shard.to_be_bytes().to_vec();
    d.extend_from_slice(blake3::hash(blob).as_bytes());
    d
}

/// The payload inside an Olm message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DmPayload {
    /// Sender's Sentinel identity (author key).
    pub from: [u8; 32],
    pub name: String,
    pub text: String,
    pub minute: u64,
    /// First messages: the sender's contact card (so the recipient can reply).
    #[serde(default)]
    pub card: Option<ContactCard>,
    /// Deniable MAC binding `from` to `card` for this recipient.
    #[serde(default)]
    pub card_mac: Option<[u8; 32]>,
    /// Fresh delivery details for replies (every message).
    #[serde(default)]
    pub reply: Option<ReplyInfo>,
    /// Disappearing-message timer: both sides delete the message this many
    /// days after it was sent.
    #[serde(default)]
    pub expire_days: Option<u16>,
    /// Credits sent with this message (the recipient swaps them at once).
    #[serde(default)]
    pub credits: Vec<crate::credits::Bundle>,
    /// Buying access to one of the recipient's rooms with `credits`.
    #[serde(default)]
    pub purchase: Option<RoomPurchase>,
    /// A room invite granted in return (sent by the room's creator).
    #[serde(default)]
    pub grant: Option<String>,
    /// Approved followers (spec §8.4): a request, or the key for the
    /// sender's approved-followers posts.
    #[serde(default)]
    pub circle: Option<CircleMsg>,
    /// Between my own devices only (sender and recipient are the same
    /// account): keep the other device up to date.
    #[serde(default)]
    pub sync: Option<DeviceSync>,
    /// Asking the recipient's app to delete messages of this conversation
    /// (`text` is then empty and nothing is shown).
    #[serde(default)]
    pub delete: Option<DeleteRequest>,
}

/// Messages to delete: all of a conversation, or these ones (by
/// `message_key`: both sides compute the same key for a message).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DeleteRequest {
    pub all: bool,
    #[serde(default)]
    pub keys: Vec<(u64, [u8; 8])>,
}

/// A message's key on both sides: its minute and a hash of its text.
pub fn message_key(minute: u64, text: &str) -> (u64, [u8; 8]) {
    let h = blake3::derive_key("sentinel/v1/message-key", text.as_bytes());
    (minute, h[..8].try_into().expect("8"))
}

/// What one of my devices tells my others (inside an end-to-end encrypted
/// message to themselves).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DeviceSync {
    /// I sent this message's text to `peer` (shown on my other devices).
    Sent { peer: [u8; 32] },
    /// `peer` sent me this message's text (they may not know all my devices).
    Received { peer: [u8; 32], name: String },
    /// I followed someone (their follow link) or stopped.
    Follow { link: String },
    Unfollow { author: [u8; 32] },
    /// I joined a room (its invite link).
    Room { link: String },
    /// I muted or blocked someone (or undid it).
    Hide { author: [u8; 32], block: bool, on: bool },
    /// I deleted messages: of a conversation (`peer`), of a room (`room`),
    /// or everything (neither). `keys` empty = all of them.
    Delete {
        peer: Option<[u8; 32]>,
        room: Option<[u8; 32]>,
        #[serde(default)]
        keys: Vec<(u64, [u8; 8])>,
        #[serde(default)]
        room_keys: Vec<(String, u32)>,
    },
}

/// Approved followers messages.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CircleMsg {
    /// "Please approve me as a follower."
    Request,
    /// The current key for the sender's approved-followers posts.
    Grant { epoch: u32, key: [u8; 32] },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomPurchase {
    pub room_id: [u8; 32],
}

/// What travels inside the sealed-sender layer.
#[derive(Serialize, Deserialize)]
struct Wire {
    sender_identity: [u8; 32],
    olm_type: u8,
    olm: Vec<u8>,
    pad: Vec<u8>,
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

fn card_mac_key(shared: &[u8; 32], sender: &[u8; 32], recipient_inbox: &[u8; 32]) -> [u8; 32] {
    let mut m = shared.to_vec();
    m.extend_from_slice(sender);
    m.extend_from_slice(recipient_inbox);
    blake3::derive_key("sentinel/v0/deniable-card-mac", &m)
}

/// Deniable authentication of my card for one recipient: MAC under
/// DH(my identity key as X25519, their inbox key). The recipient can compute
/// the same value, so it is no evidence to a third party.
pub fn card_mac(author: &ed25519_dalek::SigningKey, recipient_inbox: &[u8; 32], card: &ContactCard) -> [u8; 32] {
    let secret = StaticSecret::from(author.to_scalar_bytes());
    let shared = secret.diffie_hellman(&PublicKey::from(*recipient_inbox));
    let key = card_mac_key(shared.as_bytes(), &author.verifying_key().to_bytes(), recipient_inbox);
    *blake3::keyed_hash(&key, &cbor(card)).as_bytes()
}

/// Recipient side of `card_mac`.
pub fn check_card_mac(inbox_secret: &[u8; 32], sender: &[u8; 32], card: &ContactCard, mac: &[u8; 32]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(sender) else { return false };
    let secret = StaticSecret::from(*inbox_secret);
    let my_pub = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(vk.to_montgomery().to_bytes()));
    let key = card_mac_key(shared.as_bytes(), sender, my_pub.as_bytes());
    let want = blake3::keyed_hash(&key, &cbor(card));
    // Constant time (blake3::Hash implements it).
    want == blake3::Hash::from(*mac)
}

/// Fill the account with prekeys and describe it as a contact card.
/// The 30-day period an inbox ML-KEM key belongs to.
pub fn kem_period(day: u64) -> u64 {
    day / 30
}

/// Periods of inbox ML-KEM keys still opened (a card can be a while old).
const KEM_PERIODS_KEPT: u64 = 4;

pub fn inbox_kem_seed(inbox_secret: &[u8; 32], period: u64) -> zeroize::Zeroizing<[u8; 64]> {
    crate::pq::kem_seed_from("sentinel/v0/inbox-kem", inbox_secret, period)
}

/// This period's inbox ML-KEM key (for my card).
pub fn inbox_kem_public(inbox_secret: &[u8; 32]) -> Vec<u8> {
    crate::pq::kem_public(&inbox_kem_seed(inbox_secret, kem_period(today())))
}

pub fn make_card(account: &mut Account, inbox_pub: [u8; 32], inbox_kem: Option<Vec<u8>>, fetch_secret: [u8; 32], pillar: String) -> ContactCard {
    let have = account.one_time_keys().len();
    if have < ONE_TIME_KEYS {
        account.generate_one_time_keys(ONE_TIME_KEYS - have);
    }
    if account.fallback_key().is_empty() {
        account.generate_fallback_key();
    }
    let card = ContactCard {
        olm_identity: account.curve25519_key().to_bytes(),
        one_time_keys: account.one_time_keys().values().map(|k| k.to_bytes()).collect(),
        fallback_key: account.fallback_key().values().next().map(|k| k.to_bytes()),
        inbox_pub,
        inbox_ids: upcoming_inbox_ids(&fetch_secret),
        pillar,
        minute: crate::social::coarse_minute(),
        inbox_kem,
    };
    account.mark_keys_as_published();
    card
}

/// Start a session to `card` using a random one-time key (or the fallback).
pub fn outbound_session(account: &Account, card: &ContactCard) -> Option<Session> {
    let identity = Curve25519PublicKey::from_bytes(card.olm_identity);
    let otk = if card.one_time_keys.is_empty() {
        card.fallback_key?
    } else {
        let i = (u32::from_le_bytes(crate::random_bytes::<4>()) as usize) % card.one_time_keys.len();
        card.one_time_keys[i]
    };
    account.create_outbound_session(session_config(), identity, Curve25519PublicKey::from_bytes(otk)).ok()
}

/// Encrypt a payload with an Olm session and seal it for the recipient's
/// inbox. Returns the blob to deposit.
pub fn encrypt(account: &Account, session: &mut Session, payload: &DmPayload, card: &ContactCard) -> Option<Vec<u8>> {
    let msg = session.encrypt(cbor(payload)).ok()?;
    let (t, bytes) = msg.to_parts();
    let mut wire = Wire { sender_identity: account.curve25519_key().to_bytes(), olm_type: t as u8, olm: bytes, pad: Vec::new() };
    let len = cbor(&wire).len();
    wire.pad = vec![0; (len.div_ceil(PAD) * PAD).saturating_sub(len + 3)];
    match card.inbox_kem.as_deref().filter(|k| k.len() == crate::pq::KEM_PUBLIC) {
        Some(k) => crate::pq::seal(PQ_SEAL, &card.inbox_pub, &card.inbox_pub, Some(k), &cbor(&wire)),
        None => Some(seal_to(&card.inbox_pub, &cbor(&wire))),
    }
}

const PQ_SEAL: &str = "sentinel/v0/sealed-sender-pq";

/// Sealed box to an X25519 key: ephemeral DH + XChaCha20-Poly1305.
fn seal_to(recipient: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let eph = StaticSecret::from(crate::random_bytes::<32>());
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient));
    let key = sealed_key(shared.as_bytes(), eph_pub.as_bytes(), recipient);
    let nonce = crate::random_bytes::<24>();
    let ct = XChaCha20Poly1305::new((&key).into()).encrypt(XNonce::from_slice(&nonce), plaintext).expect("encrypt");
    let mut out = eph_pub.as_bytes().to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn sealed_key(shared: &[u8; 32], eph_pub: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
    let mut m = shared.to_vec();
    m.extend_from_slice(eph_pub);
    m.extend_from_slice(recipient);
    blake3::derive_key("sentinel/v0/sealed-sender", &m)
}

/// Remove the sealed-sender layer: (sender's Olm identity, Olm message).
pub fn unseal(inbox_secret: &[u8; 32], blob: &[u8]) -> Option<([u8; 32], OlmMessage)> {
    if blob.len() < 32 + 24 + 16 || blob.len() > MAX_BLOB {
        return None;
    }
    let secret = StaticSecret::from(*inbox_secret);
    let my_pub = PublicKey::from(&secret);
    // Hybrid (post-quantum) first: this period's key and a few earlier ones.
    let hybrid = blob.get(32..34).map(|n| u16::from_le_bytes([n[0], n[1]]) as usize) == Some(crate::pq::KEM_CT);
    let plain: zeroize::Zeroizing<Vec<u8>> = if hybrid {
        let now = kem_period(today());
        (0..KEM_PERIODS_KEPT)
            .filter_map(|back| now.checked_sub(back))
            .find_map(|p| crate::pq::open(PQ_SEAL, my_pub.as_bytes(), inbox_secret, Some(&inbox_kem_seed(inbox_secret, p)), blob))?
    } else {
        let eph_pub: [u8; 32] = blob[..32].try_into().ok()?;
        let shared = secret.diffie_hellman(&PublicKey::from(eph_pub));
        let key = sealed_key(shared.as_bytes(), &eph_pub, my_pub.as_bytes());
        zeroize::Zeroizing::new(XChaCha20Poly1305::new((&key).into()).decrypt(XNonce::from_slice(&blob[32..56]), &blob[56..]).ok()?)
    };
    let wire: Wire = ciborium::from_reader(plain.as_slice()).ok()?;
    let msg = OlmMessage::from_parts(wire.olm_type as usize, &wire.olm).ok()?;
    Some((wire.sender_identity, msg))
}

pub fn inbox_public(inbox_secret: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*inbox_secret)).as_bytes()
}

/// Decrypt an incoming Olm message, creating a session from a prekey
/// message if needed. Returns (session, payload).
pub fn decrypt(
    account: &mut Account,
    existing: Option<Session>,
    sender_identity: [u8; 32],
    msg: &OlmMessage,
) -> Option<(Session, DmPayload)> {
    let sender = Curve25519PublicKey::from_bytes(sender_identity);
    if let Some(mut s) = existing {
        if let Ok(plain) = s.decrypt(msg) {
            return Some((s, ciborium::from_reader(plain.as_slice()).ok()?));
        }
    }
    match msg {
        OlmMessage::PreKey(pk) => {
            let r = account.create_inbound_session(session_config(), sender, pk).ok()?;
            Some((r.session, ciborium::from_reader(r.plaintext.as_slice()).ok()?))
        }
        OlmMessage::Normal(_) => None,
    }
}

/// Check a first message's card: the deniable MAC proves (to me only) that
/// `from` wrote it, and the card's Olm identity must be the one that
/// established the session.
pub fn authenticate_first(payload: &DmPayload, sender_identity: [u8; 32], inbox_secret: &[u8; 32]) -> Option<ContactCard> {
    let card = payload.card.clone()?;
    let mac = payload.card_mac?;
    (check_card_mac(inbox_secret, &payload.from, &card, &mac) && card.olm_identity == sender_identity).then_some(card)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first(from: &ed25519_dalek::SigningKey, text: &str, card: &ContactCard, to_inbox: &[u8; 32]) -> DmPayload {
        DmPayload {
            from: from.verifying_key().to_bytes(),
            name: "Alice".into(),
            text: text.into(),
            minute: 1,
            card: Some(card.clone()),
            card_mac: Some(card_mac(from, to_inbox, card)),
            reply: None,
            expire_days: None,
            credits: Vec::new(),
            purchase: None,
            grant: None,
            circle: None,
            sync: None,
            delete: None,
        }
    }

    fn party(pillar: &str) -> (ed25519_dalek::SigningKey, Account, [u8; 32], ContactCard) {
        let key = crate::identity::generate();
        let mut acc = Account::new();
        let inbox_secret = crate::random_bytes::<32>();
        let card = make_card(&mut acc, inbox_public(&inbox_secret), Some(inbox_kem_public(&inbox_secret)), crate::random_bytes::<32>(), pillar.into());
        (key, acc, inbox_secret, card)
    }

    #[test]
    fn alice_and_bob_talk_through_sealed_sender() {
        let (a_key, a_acc, _a_inbox, a_card) = party("a.onion");
        let (_b_key, mut b_acc, b_inbox, b_card) = party("b.onion");

        // Alice -> Bob (first message carries her signed card).
        let mut a_sess = outbound_session(&a_acc, &b_card).unwrap();
        let first = first(&a_key, "hi bob", &a_card, &b_card.inbox_pub);
        let blob = encrypt(&a_acc, &mut a_sess, &first, &b_card).unwrap();
        assert!(!blob.windows(6).any(|w| w == b"hi bob")); // Pillar sees ciphertext only

        // Post-quantum hybrid sealing (the card has an ML-KEM key).
        assert_eq!(u16::from_le_bytes([blob[32], blob[33]]) as usize, crate::pq::KEM_CT);
        let (sender, msg) = unseal(&b_inbox, &blob).unwrap();
        let (mut b_sess, got) = decrypt(&mut b_acc, None, sender, &msg).unwrap();
        assert_eq!(got.text, "hi bob");
        let a_card_seen = authenticate_first(&got, sender, &b_inbox).expect("sender authenticated");
        // Deniable: Bob alone can produce the same MAC (it isn't a signature).
        let bob_forgery = {
            let secret = StaticSecret::from(b_inbox);
            let shared = secret.diffie_hellman(&PublicKey::from(a_key.verifying_key().to_montgomery().to_bytes()));
            let key = card_mac_key(shared.as_bytes(), &a_key.verifying_key().to_bytes(), &b_card.inbox_pub);
            *blake3::keyed_hash(&key, &cbor(&a_card)).as_bytes()
        };
        assert_eq!(Some(bob_forgery), got.card_mac);

        // Bob replies using the card from Alice's first message.
        let reply = DmPayload { from: [0; 32], name: "Bob".into(), text: "hey alice".into(), minute: 2, card: None, card_mac: None, reply: None, expire_days: None, credits: Vec::new(), purchase: None, grant: None, circle: None, sync: None, delete: None };
        let blob2 = encrypt(&b_acc, &mut b_sess, &reply, &a_card_seen).unwrap();
        // Alice can't unseal with the wrong inbox secret...
        assert!(unseal(&b_inbox, &blob2).is_none());
    }

    #[test]
    fn cards_without_an_ml_kem_key_still_work() {
        let (a_key, a_acc, _, a_card) = party("a.onion");
        let (_, mut b_acc, b_inbox, mut b_card) = party("b.onion");
        b_card.inbox_kem = None; // an older app
        let mut sess = outbound_session(&a_acc, &b_card).unwrap();
        let blob = encrypt(&a_acc, &mut sess, &first(&a_key, "hi", &a_card, &b_card.inbox_pub), &b_card).unwrap();
        let (sender, msg) = unseal(&b_inbox, &blob).unwrap();
        assert_eq!(decrypt(&mut b_acc, None, sender, &msg).unwrap().1.text, "hi");
    }

    #[test]
    fn forged_first_message_is_rejected() {
        let (a_key, a_acc, _, a_card) = party("a.onion");
        let (_, mut b_acc, b_inbox, b_card) = party("b.onion");
        let (mallory_key, _, _, _) = party("m.onion");
        // Mallory MACs Alice's card with her own key but claims to be Alice.
        let mut sess = outbound_session(&a_acc, &b_card).unwrap();
        let mut forged = first(&mallory_key, "send money", &a_card, &b_card.inbox_pub);
        forged.from = a_key.verifying_key().to_bytes();
        let blob = encrypt(&a_acc, &mut sess, &forged, &b_card).unwrap();
        let (sender, msg) = unseal(&b_inbox, &blob).unwrap();
        let (_, got) = decrypt(&mut b_acc, None, sender, &msg).unwrap();
        assert!(authenticate_first(&got, sender, &b_inbox).is_none());
    }

    #[test]
    fn shards_and_prefixes() {
        let id = [0xAB, 0xCD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let s = shard_of(&id);
        assert_eq!(s, 0xABCD);
        assert!(prefix_matches(s, 0, 0)); // depth 0: everything
        assert_eq!(prefix_of(s, 4), 0xA);
        assert!(prefix_matches(s, 8, 0xAB) && !prefix_matches(s, 8, 0xAC));
        assert_eq!(deposit_bits(1000), DEPOSIT_POW_BITS);
        assert_eq!(deposit_bits(64 * 1024), DEPOSIT_POW_BITS + 3);
    }

    #[test]
    fn inbox_ids_rotate_daily() {
        let k = crate::random_bytes::<32>();
        assert_ne!(inbox_id(&k, 100), inbox_id(&k, 101));
        assert_eq!(inbox_id(&k, 100), inbox_id(&k, 100));
    }
}

#[cfg(test)]
mod inbox_capability_tests {
    use super::*;

    #[test]
    fn only_the_owner_can_derive_the_fetch_token() {
        let secret = crate::random_bytes::<32>();
        let ids = upcoming_inbox_ids(&secret);
        let today_id = deliver_to(&ids).unwrap();
        // The owner's token hashes to the published ID...
        assert_eq!(inbox_id_from_token(&fetch_token(&secret, today())), today_id);
        // ...and knowing the ID (as a contact does) doesn't give the token.
        assert_ne!(inbox_id_from_token(&today_id), today_id);
        assert_eq!(ids.len() as u64, INBOX_DAYS_AHEAD + 2);
    }
}
