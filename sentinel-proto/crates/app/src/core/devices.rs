//! Several devices on one account (spec section 6).
//!
//! - **Linking:** this device shows a link code; the new device leaves a
//!   request (its own messaging card) in a mailbox only the code opens; both
//!   show the same check code; once the person allows it here, this device
//!   sends the account over (sealed post-quantum to the new device): the
//!   identity, feed key, recovery pin, profile, follows, rooms, approved
//!   followers, hidden people, topics and settings. Never credits (they could
//!   be spent twice) and never message history.
//! - Room admin rights stay on the device that made the room (two devices
//!   writing one room's rulebook would fork it).
//! - Each device keeps its own messaging keys. Contacts send to every
//!   device; my devices send each other copies of what I send, follow, join
//!   or hide; and once there's more than one device, each reads my own posts
//!   and cards from the network.
//! - Removing a device stops sending to it. It still holds the account key:
//!   to cut it off completely, move the account to a new key (recovery).

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use sentinel_core::link::{self, LinkBlob, LinkCode, LinkRequest};
use sentinel_core::social::{self, ContactCard};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use super::{Core, Followed, Store};

/// How long a link code works.
const OFFER_SECS: u64 = 30 * 60;

#[derive(Clone, Serialize, Deserialize)]
pub struct LinkOffer {
    pub code: String,
    pub created: u64,
    /// Requests that arrived: (request, check code).
    pub requests: Vec<(LinkRequest, String)>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LinkJoin {
    pub code: String,
    pub answer_secret: [u8; 32],
    pub kem_seed: Vec<u8>,
    pub request: LinkRequest,
    pub check: String,
    /// The request reached the mailbox.
    pub sent: bool,
}

/// The account, as handed to a new device.
#[derive(Serialize, Deserialize)]
struct Handover {
    identity: [u8; 32],
    feed_key: Option<[u8; 32]>,
    recovery_pin: Option<sentinel_core::recovery::RecoveryPin>,
    recovery_gen: Option<u32>,
    name: String,
    bio: String,
    avatar: Option<sentinel_core::media::MediaRef>,
    banner: Option<sentinel_core::media::MediaRef>,
    pillar: Option<String>,
    following: Vec<Followed>,
    rooms: Vec<super::rooms::RoomState>,
    circle: super::circle::Circle,
    muted: Vec<String>,
    blocked: Vec<String>,
    topics: Vec<String>,
    privacy: super::Privacy,
    conversations: Vec<super::Conversation>,
    devices: Vec<ContactCard>,
    device_names: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub this: bool,
    pub last_seen_days: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkView {
    /// This device's link code (while offering).
    pub code: Option<String>,
    /// Requests waiting: (index, device name, check code).
    pub requests: Vec<(usize, String, String)>,
    /// This (new) device is waiting to be let in: its check code.
    pub joining: Option<String>,
}

fn hex(b: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

impl Core {
    pub fn devices(&self) -> Result<Vec<DeviceView>> {
        let (_, store) = self.unlocked()?;
        let now = social::coarse_minute();
        let mut out = vec![DeviceView { id: String::new(), name: "This device".into(), this: true, last_seen_days: 0 }];
        for c in &store.my_devices {
            let id = hex(&c.olm_identity);
            out.push(DeviceView {
                name: store.device_names.get(&id).cloned().unwrap_or_else(|| "Another device".into()),
                id,
                this: false,
                last_seen_days: now.saturating_sub(c.minute) / (24 * 60),
            });
        }
        Ok(out)
    }

    /// Stop sending to one of my devices.
    pub fn remove_device(&self, id: &str) -> Result<()> {
        self.update(|s| {
            s.my_devices.retain(|c| hex(&c.olm_identity) != id);
            s.device_outbox.retain(|o| hex(&o.olm) != id);
        })
    }

    pub fn link_view(&self) -> Result<LinkView> {
        let (_, store) = self.unlocked()?;
        let offer = store.link_offer.filter(|o| super::unix_now() < o.created + OFFER_SECS);
        Ok(LinkView {
            code: offer.as_ref().map(|o| o.code.clone()),
            requests: offer.map(|o| o.requests.iter().enumerate().map(|(i, (r, c))| (i, r.device.clone(), c.clone())).collect()).unwrap_or_default(),
            joining: store.link_join.map(|j| j.check),
        })
    }

    /// Existing device: make a link code (valid 30 minutes).
    pub fn link_start(&self) -> Result<String> {
        let (_, store) = self.unlocked()?;
        let pillar = store.pillar.context("Connect first.")?;
        let code = LinkCode::new(&pillar).to_text();
        self.update(|s| s.link_offer = Some(LinkOffer { code: code.clone(), created: super::unix_now(), requests: Vec::new() }))?;
        Ok(code)
    }

    pub fn link_cancel(&self) -> Result<()> {
        self.update(|s| s.link_offer = None)
    }

    /// Existing device: let the requesting device in.
    pub async fn link_approve(&self, index: usize) -> Result<()> {
        let (key, store) = self.unlocked()?;
        let offer = store.link_offer.clone().context("No device is waiting.")?;
        if super::unix_now() >= offer.created + OFFER_SECS {
            bail!("The link code expired. Start again.");
        }
        let (req, _) = offer.requests.get(index).cloned().context("That request is gone.")?;
        let code = LinkCode::parse(&offer.code).context("bad link code")?;
        let my_card = store.dm.as_ref().and_then(|d| d.last_card.clone());
        let mut devices = store.my_devices.clone();
        if let Some(c) = my_card {
            super::merge_card(&mut devices, c);
        }
        let mut names = store.device_names.clone();
        if let Some(c) = devices.iter().find(|c| Some(c.olm_identity) == store.dm.as_ref().and_then(|d| d.last_card.as_ref().map(|x| x.olm_identity))) {
            names.entry(hex(&c.olm_identity)).or_insert_with(|| "My first device".into());
        }
        let rooms = store
            .rooms
            .iter()
            .filter(|r| !r.waiting)
            .map(|r| {
                let mut r = r.clone();
                // The new device starts its own sessions and keeps no history;
                // room admin rights stay here.
                r.outbound = None;
                r.outbound_id = None;
                r.inbound.clear();
                r.messages.clear();
                r.queue.clear();
                r.cursors.clear();
                r.seen.clear();
                r.needs_hello = true;
                r.admin = None;
                r.paid.clear();
                r.rekey_repost = None;
                r
            })
            .collect();
        let conversations = store
            .conversations
            .iter()
            .map(|c| {
                let mut c = c.clone();
                c.messages.clear();
                c
            })
            .collect();
        let h = Handover {
            identity: key.to_bytes(),
            feed_key: store.feed_key,
            recovery_pin: store.recovery_pin,
            recovery_gen: store.recovery_gen,
            name: store.name.clone(),
            bio: store.bio.clone(),
            avatar: store.avatar.clone(),
            banner: store.banner.clone(),
            pillar: store.pillar.clone(),
            following: store.following.clone(),
            rooms,
            circle: store.circle.clone(),
            muted: store.muted.clone(),
            blocked: store.blocked.clone(),
            topics: store.topics.clone(),
            privacy: store.privacy.clone(),
            conversations,
            devices,
            device_names: names,
        };
        let json = zeroize::Zeroizing::new(serde_json::to_vec(&h)?);
        let sealed = link::seal_answer(&req, &json).context("couldn't seal the account")?;
        let blob = link::seal(&code, &LinkBlob::Answer { to: req.answer_to, sealed });
        self.deposit_sealed(&code.pillar, &code.box_secret(), blob).await?;
        self.update(|s| {
            super::merge_card(&mut s.my_devices, req.card.clone());
            s.device_names.insert(hex(&req.card.olm_identity), req.device.chars().take(40).collect());
            s.link_offer = None;
        })
    }

    /// New device: ask to join the account behind `code`. Makes a local
    /// account for this device (its own passphrase and messaging keys)
    /// that waits for the answer.
    pub fn link_join(&self, code: &str, device: &str, pass: &str, mode: &str) -> Result<String> {
        let code = LinkCode::parse(code).context("That isn't a link code (it starts with sentinel://link/).")?;
        let device = device.trim();
        if device.is_empty() || device.chars().count() > 40 {
            bail!("Give this device a short name, like Phone or Laptop.");
        }
        self.create_from(sentinel_core::recovery::RecoverySecret::generate(), "Linking…", pass, mode, false)?;
        let (key, store) = self.unlocked()?;
        let st = store.dm.clone().context("no messaging keys")?;
        let mut account = super::dms::load_account_pub(&key, &st)?;
        let card = sentinel_core::dm::make_card(&mut account, sentinel_core::dm::inbox_public(&st.inbox_secret), Some(sentinel_core::dm::inbox_kem_public(&st.inbox_secret)), st.fetch_secret, code.pillar.clone());
        let answer_secret = sentinel_core::random_bytes::<32>();
        let kem = sentinel_core::pq::kem_seed();
        let request = LinkRequest {
            card,
            answer_to: link::answer_public(&answer_secret),
            answer_kem: sentinel_core::pq::kem_public(&kem),
            device: device.to_owned(),
        };
        let check = link::check_code(&code, &request);
        let pickled = account.pickle().encrypt(&super::pickle_key(&key));
        self.update(|s| {
            if let Some(d) = s.dm.as_mut() {
                d.account = pickled;
            }
            // Throwaway words: the real ones come with the account.
            s.recovery_pending = None;
            // Work from the account's home Pillar (named in the code) at once.
            s.pillar = Some(code.pillar.clone());
            s.link_join = Some(LinkJoin { code: code.to_text(), answer_secret, kem_seed: kem.to_vec(), request, check: check.clone(), sent: false });
        })?;
        Ok(check)
    }

    /// New device: give up waiting.
    pub fn link_join_cancel(&self) -> Result<()> {
        self.update(|s| s.link_join = None)
    }

    /// New device, while waiting: leave the request (once).
    pub(super) async fn link_send_request(&self) -> Result<()> {
        let (_, store) = self.unlocked()?;
        let Some(j) = store.link_join.filter(|j| !j.sent) else { return Ok(()) };
        let code = LinkCode::parse(&j.code).context("bad link code")?;
        let blob = link::seal(&code, &LinkBlob::Request(j.request.clone()));
        self.deposit_sealed(&code.pillar, &code.box_secret(), blob).await?;
        self.update(|s| {
            if let Some(x) = s.link_join.as_mut() {
                x.sent = true;
            }
        })
    }

    /// Link mailboxes to read: (pillar, box secret).
    pub(super) fn link_boxes(store: &Store) -> Vec<(String, [u8; 32])> {
        let mut out = Vec::new();
        if let Some(o) = store.link_offer.as_ref().filter(|o| super::unix_now() < o.created + OFFER_SECS) {
            if let Some(c) = LinkCode::parse(&o.code) {
                out.push((c.pillar.clone(), c.box_secret()));
            }
        }
        if let Some(c) = store.link_join.as_ref().and_then(|j| LinkCode::parse(&j.code)) {
            out.push((c.pillar.clone(), c.box_secret()));
        }
        out
    }

    /// A blob from a link mailbox. Returns true if it was one of mine.
    pub(super) fn link_blob(&self, bytes: &[u8]) -> Result<bool> {
        let (key, store) = self.unlocked()?;
        if let Some(o) = store.link_offer.clone() {
            if let Some(code) = LinkCode::parse(&o.code) {
                if let Some(LinkBlob::Request(req)) = link::open(&code, bytes) {
                    let check = link::check_code(&code, &req);
                    self.update(|s| {
                        if let Some(x) = s.link_offer.as_mut() {
                            if !x.requests.iter().any(|(r, _)| *r == req) && x.requests.len() < 5 {
                                x.requests.push((req, check));
                            }
                        }
                    })?;
                    return Ok(true);
                }
            }
        }
        if let Some(j) = store.link_join.clone() {
            if let Some(code) = LinkCode::parse(&j.code) {
                if let Some(LinkBlob::Answer { to, sealed }) = link::open(&code, bytes) {
                    if to != j.request.answer_to {
                        return Ok(true); // someone else's answer
                    }
                    let kem: [u8; 64] = j.kem_seed.as_slice().try_into().context("bad key")?;
                    let plain = link::open_answer(&j.answer_secret, &kem, &sealed).context("couldn't open the account")?;
                    let h: Handover = serde_json::from_slice(&plain)?;
                    self.apply_handover(&key, h)?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// New device: become the account.
    fn apply_handover(&self, key: &super::Keys, h: Handover) -> Result<()> {
        let _ = key;
        let id = ed25519_dalek::SigningKey::from_bytes(&h.identity);
        self.update(|s| {
            s.identity = Some(h.identity);
            s.feed_key = h.feed_key;
            s.recovery_pin = h.recovery_pin;
            s.recovery_gen = h.recovery_gen;
            s.recovery_pending = None;
            s.name = h.name;
            s.bio = h.bio;
            s.avatar = h.avatar;
            s.banner = h.banner;
            // The account's home Pillar: where followers find my cards.
            if h.pillar.is_some() {
                s.pillar = h.pillar;
            }
            s.following = h.following.into_iter().map(|mut f| {
                f.cursor = 0;
                f
            }).collect();
            s.rooms = h.rooms;
            s.circle = h.circle;
            s.muted = h.muted;
            s.blocked = h.blocked;
            s.topics = h.topics;
            s.privacy = h.privacy;
            s.conversations = h.conversations;
            s.my_devices = h.devices;
            s.device_names = h.device_names;
            s.link_join = None;
            s.profile_published = true; // the other device already did
            s.self_cursor = 0;
            if let Some(d) = s.dm.as_mut() {
                d.card_minute = 0; // publish this device's card under the account
                d.card_pillar = None;
            }
            s.mail_cursors.clear();
        })?;
        self.with(|i| {
            if let Some(k) = i.key.as_mut() {
                k.id = id;
            }
        });
        // Work from the account's home Pillar from now on.
        self.start_pool();
        Ok(())
    }

    /// Apply what my other devices did (follows, rooms, hidden people).
    pub(super) fn apply_device_sync(self: &Arc<Self>, app: &AppHandle) -> Result<()> {
        let mut items = Vec::new();
        self.update(|s| items = std::mem::take(&mut s.incoming_sync))?;
        for it in items {
            match it {
                sentinel_core::dm::DeviceSync::Follow { link } => {
                    let _ = self.follow(app.clone(), &link);
                }
                sentinel_core::dm::DeviceSync::Unfollow { author } => {
                    let a = social::author_text(&author);
                    self.update(|s| s.following.retain(|f| f.author != a))?;
                }
                sentinel_core::dm::DeviceSync::Room { link } => {
                    let _ = self.join_room(app.clone(), &link);
                }
                sentinel_core::dm::DeviceSync::Hide { author, block, on } => {
                    let a = social::author_text(&author);
                    if block {
                        let _ = self.set_blocked(&a, on);
                    } else {
                        let _ = self.set_muted(&a, on);
                    }
                }
                sentinel_core::dm::DeviceSync::Delete { peer, room, keys, room_keys } => {
                    self.update(|s| super::deletion::apply(s, peer, room, &keys, &room_keys))?;
                    let _ = app.emit("messages", ());
                }
                sentinel_core::dm::DeviceSync::Sent { .. } | sentinel_core::dm::DeviceSync::Received { .. } => {}
            }
        }
        let _ = app.emit("timeline", ());
        let _ = app.emit("rooms", ());
        Ok(())
    }
}
