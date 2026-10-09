//! Room authority log (spec §6.2.1–6.2.4).
//!
//! Every admin action in a room is an **entry** in one chain: numbered, and
//! pointing at the hash of the entry before it, signed with the room's admin
//! key (the key the room ID is derived from, held only by the creator). Each
//! member keeps the chain and applies entries strictly in order, so every
//! member ends up with the same room state.
//!
//! - **Forks are visible.** If two different entries ever carry the same
//!   number, the admin key signed conflicting histories (stolen or misused).
//!   Members mark the room so the app can warn.
//! - **Resync points.** A *checkpoint* (full room state) or a *rekey* can be
//!   applied across a gap, so a member who missed entries while offline (or
//!   joined late) catches up without the whole history. Other entries wait
//!   until the gap is filled.
//! - **Epoch cuts (no back-dating).** A rekey carries a *cut*: for each
//!   member's message stream (Megolm session), the last message the admin had
//!   seen in the old epoch. Old-epoch messages beyond the cut are dropped by
//!   everyone, so a removed member can't slip in messages "from before" the
//!   removal. Honest late messages are re-sent in the new epoch.
//! - **Agreed order.** Messages carry a Lamport counter; every member sorts
//!   by (counter, session, index), so all members see the same order. Sentinel
//!   Apps (spec §19) build on this.
//!
//! - **Moderators.** The admin names moderators in the log by their
//!   room-only member key (never their account) and hands each a room-only
//!   *moderator key*, sealed to them. Moderators sign hides and bans with
//!   it; members apply them at once, and the admin's app turns a ban into a
//!   full removal (new keys). Only the admin can name moderators or rekey.
//! - **Approval rooms.** The admin and moderators hold the room's *ask key*
//!   (sealed to each moderator here); join requests are sealed with it.
//!
//! Formal analysis of these rules is still required (spec §20).

use serde::{Deserialize, Serialize};

use crate::object::Envelope;
use crate::room::{room_id_for, RoomBlob};

pub const KIND: &str = "room-authority";
/// Entry hashes remembered for fork detection.
const KEEP_SEEN: usize = 4096;
/// Entries held while waiting for a gap to fill.
const MAX_PENDING: usize = 64;

/// (Megolm session id, last message index) per member stream.
pub type Cut = Vec<(String, u32)>;

/// A moderator, as named by the admin.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Moderator {
    /// Their room-only member key.
    pub member: [u8; 32],
    /// Their room-only moderator signing key (public half).
    pub key: [u8; 32],
    /// The signing key's seed, sealed to their member key.
    pub seed: Vec<u8>,
    /// The room's ask key (approval rooms), sealed to their member key.
    #[serde(default)]
    pub ask: Vec<u8>,
    /// Their room-only ML-KEM key (seals above are post-quantum when known).
    #[serde(default)]
    pub kem: Option<Vec<u8>>,
}

/// Admin: name a moderator (a fresh room-only signing key, sealed to them).
pub fn new_moderator(room_id: &[u8; 32], member: &[u8; 32], kem: Option<&[u8]>, ask: Option<&[u8; 32]>) -> Moderator {
    let seed = crate::random_bytes::<32>();
    let key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let mut m = Moderator { member: *member, key, seed: crate::room::seal_secret_to(member, kem, &seed, room_id), ask: Vec::new(), kem: kem.map(<[u8]>::to_vec) };
    reseal_ask(room_id, &mut m, ask);
    m
}

/// Admin: give a moderator the (new) ask key, or take it away.
pub fn reseal_ask(room_id: &[u8; 32], m: &mut Moderator, ask: Option<&[u8; 32]>) {
    m.ask = ask.map(|a| crate::room::seal_secret_to(&m.member, m.kem.as_deref(), a, room_id)).unwrap_or_default();
}

/// Member: my moderator seed and the ask key, if I'm on the list.
pub fn my_moderator(room_id: &[u8; 32], mods: &[Moderator], my_member_secret: &[u8; 32]) -> Option<([u8; 32], Option<[u8; 32]>)> {
    let mine = crate::room::member_pub(my_member_secret);
    let m = mods.iter().find(|m| m.member == mine)?;
    let seed = crate::room::open_secret(my_member_secret, &m.seed, room_id)?;
    // The seed must match the key everyone else checks against.
    if ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes() != m.key {
        return None;
    }
    let ask = (!m.ask.is_empty()).then(|| crate::room::open_secret(my_member_secret, &m.ask, room_id)).flatten();
    Some((seed, ask))
}

pub const MOD_KIND: &str = "room-mod";
/// Most moderators a room can have.
pub const MAX_MODS: usize = 20;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ModAction {
    /// Hide one message for everyone.
    Hide { session_id: String, index: u32 },
    /// Refuse a member's room-only key (the admin then removes them fully).
    Ban { member: [u8; 32] },
    /// A join request was answered (sent to the ask box, so other
    /// moderators drop it from their list).
    Handled { request: [u8; 32] },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ModEntry {
    pub room_id: [u8; 32],
    /// Random: each action applies once (no replays).
    pub id: [u8; 16],
    pub action: ModAction,
}

/// A moderator (or the admin, with the admin seed) signs an action.
pub fn sign_mod(seed: &[u8; 32], room_id: &[u8; 32], action: ModAction) -> Vec<u8> {
    let k = ed25519_dalek::SigningKey::from_bytes(seed);
    let e = ModEntry { room_id: *room_id, id: crate::random_bytes::<16>(), action };
    Envelope::sign(&k, MOD_KIND, cbor(&e)).encode().expect("mod entry encodes")
}

/// Check a moderator action: for this room and signed by the admin key or
/// one of `mods`. Returns (signer, entry).
pub fn verify_mod(room_id: &[u8; 32], mods: &[Moderator], signed: &[u8]) -> Option<([u8; 32], ModEntry)> {
    let env = Envelope::decode_verified(signed).ok()?;
    if env.kind != MOD_KIND {
        return None;
    }
    let admin = room_id_for(&env.author) == *room_id;
    if !admin && !mods.iter().any(|m| m.key == env.author) {
        return None;
    }
    let e: ModEntry = ciborium::from_reader(env.body.as_slice()).ok()?;
    (e.room_id == *room_id).then_some((env.author, e))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Action {
    /// The full room state; also a resync point.
    Checkpoint {
        name: String,
        visibility: String,
        access: String,
        epoch: u64,
        banned: Vec<[u8; 32]>,
        redacted: Vec<(String, u32)>,
        #[serde(default)]
        mods: Vec<Moderator>,
        /// Joining needs approval from the admin or a moderator.
        #[serde(default)]
        approval: bool,
        /// The room's Sentinel Apps.
        #[serde(default)]
        apps: Vec<AppRef>,
        /// The admin's room-only member key, so members can seal reports
        /// to them (see `room::RoomReport`).
        #[serde(default)]
        admin_member: Option<[u8; 32]>,
    },
    Details { name: String, visibility: String, access: String },
    /// New room secret sealed to each remaining member, plus the cut.
    Rekey { epoch: u64, entries: Vec<([u8; 32], Vec<u8>)>, cut: Cut },
    /// A member's room-only key: their hellos and messages are refused.
    Ban { member: [u8; 32] },
    Unban { member: [u8; 32] },
    /// Hide one message for everyone.
    Redact { session_id: String, index: u32 },
    /// The full moderator list (replaces the previous one) and whether
    /// joining needs approval.
    Moderators { mods: Vec<Moderator>, approval: bool },
    /// The full list of the room's Sentinel Apps (replaces the previous one).
    Apps { apps: Vec<AppRef> },
}

/// A Sentinel App added to a room: its identity (the hash of its package)
/// and name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AppRef {
    pub id: [u8; 32],
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub room_id: [u8; 32],
    pub seq: u64,
    pub prev: [u8; 32],
    pub action: Action,
}

impl Entry {
    fn resync(&self) -> bool {
        matches!(self.action, Action::Checkpoint { .. } | Action::Rekey { .. })
    }
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

/// Hash that the next entry points at.
pub fn hash(signed: &[u8]) -> [u8; 32] {
    blake3::derive_key("sentinel/v1/room-authority", signed)
}

/// Admin: sign the next entry. Returns (signed bytes, its hash).
pub fn sign(admin_seed: &[u8; 32], entry: &Entry) -> (Vec<u8>, [u8; 32]) {
    let k = ed25519_dalek::SigningKey::from_bytes(admin_seed);
    let signed = Envelope::sign(&k, KIND, cbor(entry)).encode().expect("entry encodes");
    let h = hash(&signed);
    (signed, h)
}

pub fn blob(signed: Vec<u8>) -> RoomBlob {
    RoomBlob::Authority { signed }
}

/// Check an entry: signed by this room's admin key and for this room.
pub fn verify(room_id: &[u8; 32], signed: &[u8]) -> Option<(Entry, [u8; 32])> {
    let env = Envelope::decode_verified(signed).ok()?;
    if env.kind != KIND || room_id_for(&env.author) != *room_id {
        return None;
    }
    let e: Entry = ciborium::from_reader(env.body.as_slice()).ok()?;
    (e.room_id == *room_id && e.seq > 0).then(|| (e, hash(signed)))
}

/// Admin: a rekey action for these members' room-only keys.
/// `members`: (room-only key, ML-KEM key if known).
pub fn rekey_action(room_id: &[u8; 32], epoch: u64, new_secret: &[u8; 32], members: &[([u8; 32], Option<Vec<u8>>)], cut: Cut) -> Action {
    let entries = members.iter().map(|(m, k)| (*m, crate::room::seal_secret_to(m, k.as_deref(), new_secret, room_id))).collect();
    Action::Rekey { epoch, entries, cut }
}

/// Member: my new secret from a rekey, if I'm included.
pub fn open_rekey(room_id: &[u8; 32], entries: &[([u8; 32], Vec<u8>)], my_member_secret: &[u8; 32]) -> Option<[u8; 32]> {
    let mine = crate::room::member_pub(my_member_secret);
    let (_, sealed) = entries.iter().find(|(m, _)| *m == mine)?;
    crate::room::open_secret(my_member_secret, sealed, room_id)
}

/// Is message `index` of `session` beyond the cut (to be dropped)?
pub fn beyond_cut(cut: &Cut, session: &str, index: u32) -> bool {
    match cut.iter().find(|(s, _)| s == session) {
        Some((_, last)) => index > *last,
        None => true,
    }
}

/// A member's copy of the chain.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Log {
    pub seq: u64,
    pub head: [u8; 32],
    /// (seq, hash) of entries seen, for fork detection.
    pub seen: Vec<(u64, [u8; 32])>,
    /// Entries waiting for a gap to fill.
    pub pending: Vec<Vec<u8>>,
    /// The admin key signed conflicting entries.
    pub fork: bool,
}

impl Log {
    fn note(&mut self, seq: u64, h: [u8; 32]) {
        self.seen.push((seq, h));
        if self.seen.len() > KEEP_SEEN {
            self.seen.remove(0);
        }
    }

    fn try_apply(&mut self, e: &Entry, h: [u8; 32]) -> bool {
        let next = e.seq == self.seq + 1 && e.prev == self.head;
        // A resync only bridges a real gap; the very next number must point
        // at my head (anything else there is a second history).
        if next || (e.resync() && e.seq > self.seq + 1) {
            self.seq = e.seq;
            self.head = h;
            self.note(e.seq, h);
            true
        } else {
            false
        }
    }

    /// Offer an entry; returns the entries that now apply, in order.
    pub fn offer(&mut self, room_id: &[u8; 32], signed: &[u8]) -> Vec<Entry> {
        let Some((e, h)) = verify(room_id, signed) else { return Vec::new() };
        if let Some((_, old)) = self.seen.iter().find(|(s, _)| *s == e.seq) {
            if *old != h {
                self.fork = true;
            }
            return Vec::new();
        }
        if e.seq <= self.seq {
            return Vec::new(); // older than what I have (and not remembered)
        }
        let mut out = Vec::new();
        if self.try_apply(&e, h) {
            out.push(e);
        } else if e.seq == self.seq + 1 {
            // Right number, wrong parent: a second history.
            self.fork = true;
            return out;
        } else {
            if !self.pending.iter().any(|p| p.as_slice() == signed) && self.pending.len() < MAX_PENDING {
                self.pending.push(signed.to_vec());
            }
            return out;
        }
        // Waiting entries that now fit.
        loop {
            let mut applied = false;
            let pending = std::mem::take(&mut self.pending);
            for p in pending {
                match verify(room_id, &p) {
                    Some((pe, ph)) if pe.seq > self.seq => {
                        if !applied && self.try_apply(&pe, ph) {
                            out.push(pe);
                            applied = true;
                        } else {
                            self.pending.push(p);
                        }
                    }
                    _ => {}
                }
            }
            if !applied {
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::room::{member_pub, new_room_with_admin};

    fn entry(room_id: [u8; 32], seq: u64, prev: [u8; 32], action: Action) -> Entry {
        Entry { room_id, seq, prev, action }
    }

    fn details(n: &str) -> Action {
        Action::Details { name: n.into(), visibility: "private".into(), access: "free".into() }
    }

    #[test]
    fn chain_applies_in_order_and_waits_for_gaps() {
        let (room, _, admin) = new_room_with_admin();
        let (s1, h1) = sign(&admin, &entry(room, 1, [0; 32], details("one")));
        let (s2, h2) = sign(&admin, &entry(room, 2, h1, details("two")));
        let (s3, _) = sign(&admin, &entry(room, 3, h2, Action::Ban { member: [7; 32] }));
        let mut log = Log::default();
        // Out of order: 3 and 2 wait, 1 releases them in order.
        assert!(log.offer(&room, &s3).is_empty());
        assert!(log.offer(&room, &s2).is_empty());
        let got = log.offer(&room, &s1);
        assert_eq!(got.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(log.seq, 3);
        assert!(!log.fork);
        // Replays do nothing.
        assert!(log.offer(&room, &s2).is_empty());
    }

    #[test]
    fn only_the_admin_key_writes_and_forks_are_flagged() {
        let (room, _, admin) = new_room_with_admin();
        let (s1, h1) = sign(&admin, &entry(room, 1, [0; 32], details("one")));
        let mut log = Log::default();
        log.offer(&room, &s1);
        // A member (or anyone) signing an entry: refused.
        let (forged, _) = sign(&crate::random_bytes::<32>(), &entry(room, 2, h1, Action::Ban { member: [1; 32] }));
        assert!(log.offer(&room, &forged).is_empty());
        assert_eq!(log.seq, 1);
        // The admin key signing two different entry 2s: a fork.
        let (a2, _) = sign(&admin, &entry(room, 2, h1, details("a")));
        let (b2, _) = sign(&admin, &entry(room, 2, h1, details("b")));
        assert_eq!(log.offer(&room, &a2).len(), 1);
        assert!(log.offer(&room, &b2).is_empty());
        assert!(log.fork);
        // A checkpoint with the next number but another parent is a fork too.
        let mut log2 = Log::default();
        log2.offer(&room, &s1);
        let cp = Action::Checkpoint { name: "x".into(), visibility: "private".into(), access: "free".into(), epoch: 0, banned: vec![], redacted: vec![], mods: vec![], approval: false, apps: vec![], admin_member: None };
        let (bad, _) = sign(&admin, &entry(room, 2, [9; 32], cp));
        assert!(log2.offer(&room, &bad).is_empty());
        assert!(log2.fork);
        // An entry for another room doesn't apply.
        let (other_room, _, _) = new_room_with_admin();
        assert!(verify(&other_room, &a2).is_none());
    }

    #[test]
    fn checkpoints_and_rekeys_resync_across_gaps() {
        let (room, _, admin) = new_room_with_admin();
        let mut log = Log::default();
        let cp = Action::Checkpoint { name: "n".into(), visibility: "private".into(), access: "free".into(), epoch: 0, banned: vec![], redacted: vec![], mods: vec![], approval: false, apps: vec![], admin_member: None };
        let (s9, h9) = sign(&admin, &entry(room, 9, [5; 32], cp));
        // A late joiner starts from a checkpoint.
        assert_eq!(log.offer(&room, &s9).len(), 1);
        // A plain entry across a gap waits; a rekey across a gap applies.
        let (s12, _) = sign(&admin, &entry(room, 12, [6; 32], details("x")));
        assert!(log.offer(&room, &s12).is_empty());
        let member = crate::random_bytes::<32>();
        let secret = crate::random_bytes::<32>();
        let rk = rekey_action(&room, 2, &secret, &[(member_pub(&member), Some(crate::room::member_kem_public(&member)))], vec![]);
        let (s11, _) = sign(&admin, &entry(room, 11, h9, rk.clone()));
        let got = log.offer(&room, &s11);
        assert_eq!(got.len(), 1);
        let Action::Rekey { entries, .. } = &got[0].action else { panic!() };
        assert_eq!(open_rekey(&room, entries, &member), Some(secret));
        assert!(open_rekey(&room, entries, &crate::random_bytes::<32>()).is_none());
    }

    #[test]
    fn moderators_sign_with_room_only_keys() {
        let (room, _, admin) = new_room_with_admin();
        let (m_secret, other) = (crate::random_bytes::<32>(), crate::random_bytes::<32>());
        let ask = crate::random_bytes::<32>();
        let m = new_moderator(&room, &member_pub(&m_secret), Some(&crate::room::member_kem_public(&m_secret)), Some(&ask));
        let mods = vec![m.clone()];
        // Only the named member can open the moderator key and the ask key.
        let (seed, got_ask) = my_moderator(&room, &mods, &m_secret).unwrap();
        assert_eq!(got_ask, Some(ask));
        assert!(my_moderator(&room, &mods, &other).is_none());
        // Their actions verify; anyone else's don't; the admin's do.
        let hide = ModAction::Hide { session_id: "s".into(), index: 1 };
        let signed = sign_mod(&seed, &room, hide.clone());
        let (who, e) = verify_mod(&room, &mods, &signed).unwrap();
        assert_eq!((who, e.action), (m.key, hide.clone()));
        assert!(verify_mod(&room, &mods, &sign_mod(&other, &room, hide.clone())).is_none());
        assert!(verify_mod(&room, &mods, &sign_mod(&admin, &room, hide.clone())).is_some());
        // Removed from the list: refused. Another room: refused.
        assert!(verify_mod(&room, &[], &signed).is_none());
        let (room2, _, _) = new_room_with_admin();
        assert!(verify_mod(&room2, &mods, &signed).is_none());
        // A moderator entry whose sealed seed doesn't match its key is ignored.
        let mut bad = m.clone();
        bad.key = [9; 32];
        assert!(my_moderator(&room, &[bad], &m_secret).is_none());
        // No ask key when approval is off.
        let mut m2 = m;
        reseal_ask(&room, &mut m2, None);
        assert_eq!(my_moderator(&room, &[m2], &m_secret).unwrap().1, None);
    }

    #[test]
    fn cuts_drop_later_and_unknown_streams() {
        let cut: Cut = vec![("alice".into(), 4)];
        assert!(!beyond_cut(&cut, "alice", 4));
        assert!(beyond_cut(&cut, "alice", 5), "after the cut: dropped");
        assert!(beyond_cut(&cut, "mallory", 0), "a stream the admin never saw: dropped");
    }
}
