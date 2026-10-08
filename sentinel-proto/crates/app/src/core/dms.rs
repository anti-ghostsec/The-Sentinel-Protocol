//! Direct messages (spec §6.3, §10.2): Olm Double Ratchet sessions,
//! sealed-sender delivery into rotating inboxes, authenticated first contact.
//!
//! Several devices: every device has its own messaging keys (card). A
//! message goes to each of the recipient's devices, and a copy to each of my
//! other devices (marked as sent by me), each over its own session.

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use sentinel_core::dm;
use sentinel_core::social::{self, ContactCard};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};

use super::{handle_of, merge_card, pickle_key, Conversation, Core, DmState, Message, Outgoing};

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConversationView {
    pub author: String,
    pub name: String,
    pub handle: String,
    pub last: Option<String>,
    pub minute: u64,
    pub can_message: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MessageView {
    pub mine: bool,
    pub text: String,
    pub minute: u64,
    pub sent: bool,
    /// For selecting and deleting ("minute:hash").
    pub id: String,
}

/// A message's id in the UI (same on all my devices).
pub(super) fn message_id(minute: u64, text: &str) -> String {
    let (m, h) = dm::message_key(minute, text);
    format!("{m}:{}", data_encoding::HEXLOWER.encode(&h))
}

fn hex(b: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

fn load_account(key: &super::Keys, st: &DmState) -> Result<Account> {
    let p = AccountPickle::from_encrypted(&st.account, &pickle_key(key)).map_err(|_| anyhow!("messaging keys unreadable"))?;
    Ok(Account::from_pickle(p))
}

pub(super) fn load_account_pub(key: &super::Keys, st: &DmState) -> Result<Account> {
    load_account(key, st)
}

fn load_session(key: &super::Keys, pickled: &str) -> Option<Session> {
    SessionPickle::from_encrypted(pickled, &pickle_key(key)).ok().map(Session::from_pickle)
}

/// My contact card as sent inside a first DM. No prekeys are needed here:
/// the recipient answers on the session I started.
/// Every device card I know for `author` (their devices, newest first).
pub(super) fn cards_for(store: &super::Store, author: &str) -> Vec<ContactCard> {
    let mut out: Vec<ContactCard> = Vec::new();
    let conv = store.conversations.iter().find(|c| c.author == author);
    let f = store.following.iter().find(|f| f.author == author);
    for c in conv.into_iter().flat_map(|c| c.cards.iter().chain(c.card.iter())).chain(f.into_iter().flat_map(|f| f.cards.iter().chain(f.card.iter()))) {
        merge_card(&mut out, c.clone());
    }
    out
}

fn my_intro_card(account: &Account, st: &DmState, pillar: &str) -> ContactCard {
    ContactCard {
        olm_identity: account.curve25519_key().to_bytes(),
        one_time_keys: Vec::new(),
        fallback_key: None,
        inbox_pub: dm::inbox_public(&st.inbox_secret),
        inbox_ids: dm::upcoming_inbox_ids(&st.fetch_secret),
        pillar: pillar.to_owned(),
        minute: social::coarse_minute(),
        inbox_kem: Some(dm::inbox_kem_public(&st.inbox_secret)),
    }
}

impl Core {
    /// Publish (or refresh, daily) my contact card, sealed under my feed key.
    pub async fn publish_card(&self) -> Result<()> {
        let (key, store) = self.unlocked()?;
        let pillar = store.pillar.clone().context("no Pillar")?;
        let st = store.dm.clone().context("no messaging keys")?;
        let fresh = st.card_pillar.as_deref() == Some(pillar.as_str())
            && social::coarse_minute().saturating_sub(st.card_minute) < 24 * 60;
        if fresh {
            return Ok(());
        }
        let mut account = load_account(&key, &st)?;
        let card = dm::make_card(&mut account, dm::inbox_public(&st.inbox_secret), Some(dm::inbox_kem_public(&st.inbox_secret)), st.fetch_secret, pillar.clone());
        let feed_key = store.feed_key.context("no feed key")?;
        let env = social::card_envelope(&key, &feed_key, &card).map_err(|e| anyhow!(e))?;
        let pickled = account.pickle().encrypt(&pickle_key(&key));
        self.update(|s| {
            if let Some(d) = s.dm.as_mut() {
                d.account = pickled;
            }
        })?;
        self.put(env.encode()?).await?;
        self.update(|s| {
            if let Some(d) = s.dm.as_mut() {
                d.card_minute = card.minute;
                d.card_pillar = Some(pillar);
                d.last_card = Some(card.clone());
            }
        })
    }

    pub fn conversations(&self) -> Result<Vec<ConversationView>> {
        let (_, store) = self.unlocked()?;
        let mut out: Vec<ConversationView> = store
            .conversations
            .iter()
            .filter(|c| !store.blocked.contains(&c.author))
            .map(|c| ConversationView {
                author: c.author.clone(),
                name: c.name.clone(),
                handle: handle_of(&c.author),
                last: c.messages.iter().rev().find(|m| !m.text.is_empty()).map(|m| m.text.clone()),
                minute: c.messages.last().map(|m| m.minute).unwrap_or(0),
                can_message: true,
            })
            .collect();
        // People I follow who published a card can be messaged too.
        for f in &store.following {
            if !out.iter().any(|c| c.author == f.author) {
                out.push(ConversationView {
                    author: f.author.clone(),
                    name: f.name.clone().unwrap_or_else(|| handle_of(&f.author)),
                    handle: handle_of(&f.author),
                    last: None,
                    minute: 0,
                    can_message: f.card.is_some(),
                });
            }
        }
        out.sort_by(|a, b| b.minute.cmp(&a.minute));
        Ok(out)
    }

    pub fn thread(&self, author: &str) -> Result<Vec<MessageView>> {
        let (_, store) = self.unlocked()?;
        Ok(store
            .conversations
            .iter()
            .find(|c| c.author == author)
            // (Messages without text are control messages: never shown.)
            .map(|c| c.messages.iter().filter(|m| !m.text.is_empty()).map(|m| MessageView { mine: m.mine, text: m.text.clone(), minute: m.minute, sent: m.sent, id: message_id(m.minute, &m.text) }).collect())
            .unwrap_or_default())
    }

    /// Encrypt and send a DM. Stored locally first, delivered in the background.
    pub fn send_dm(self: &Arc<Self>, app: AppHandle, author: &str, text: &str) -> Result<()> {
        self.send_dm_with(app, author, text, Vec::new(), None, None)
    }

    /// A DM that may carry credits, a room purchase or grant, or an
    /// approved-followers message.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn send_dm_with(
        self: &Arc<Self>,
        app: AppHandle,
        author: &str,
        text: &str,
        credits: Vec<sentinel_core::credits::Bundle>,
        purchase: Option<dm::RoomPurchase>,
        grant: Option<String>,
    ) -> Result<()> {
        self.send_dm_full(app, author, text, credits, purchase, grant, None, None)
    }

    /// A DM that may carry credits, a room purchase or a room grant.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn send_dm_full(
        self: &Arc<Self>,
        app: AppHandle,
        author: &str,
        text: &str,
        credits: Vec<sentinel_core::credits::Bundle>,
        purchase: Option<dm::RoomPurchase>,
        grant: Option<String>,
        circle: Option<dm::CircleMsg>,
        delete: Option<dm::DeleteRequest>,
    ) -> Result<()> {
        let text = text.trim().to_owned();
        // (A delete request has no text: it's never shown.)
        if (text.is_empty() && delete.is_none()) || text.chars().count() > 4000 {
            bail!("Messages must be 1–4000 characters.");
        }
        let (key, store) = self.unlocked()?;
        let st = store.dm.clone().context("no messaging keys")?;
        let my_pillar = store.pillar.clone().context("Connect first so others can reply.")?;
        let conv = store.conversations.iter().find(|c| c.author == author).cloned();
        let card = conv
            .as_ref()
            .and_then(|c| c.card.clone())
            .or_else(|| store.following.iter().find(|f| f.author == author).and_then(|f| f.card.clone()))
            .context("They haven't shared a way to message them yet. Follow them with their link first.")?;

        let _ = card;
        let targets = cards_for(&store, author);
        let me = social::author_text(&key.verifying_key().to_bytes());
        let account = load_account(&key, &st)?;
        let introduced = conv.as_ref().is_some_and(|c| c.introduced);
        // Disappearing messages: the timer travels with the message, so the
        // other side deletes it too.
        let expire_days = store.privacy.disappearing.then_some(super::DISAPPEAR_DAYS);
        let minute = social::coarse_minute();
        let peer_key = social::author_from_text(author).context("not an account")?;
        // Their devices, then my other devices (a copy marked as sent by me).
        let mut out: Vec<Outgoing> = Vec::new();
        let mut sessions: Vec<(String, String)> = Vec::new();
        let mine: Vec<ContactCard> = store.my_devices.clone();
        for (to, own) in targets.iter().map(|c| (c, false)).chain(mine.iter().map(|c| (c, true))) {
            let peer = hex(&to.olm_identity);
            let mut session = match st.sessions.get(&peer).and_then(|p| load_session(&key, p)) {
                Some(s) => s,
                None => match dm::outbound_session(&account, to) {
                    Some(s) => s,
                    None => continue,
                },
            };
            let intro = (own || !introduced).then(|| my_intro_card(&account, &st, &my_pillar));
            let payload = dm::DmPayload {
                expire_days,
                from: key.verifying_key().to_bytes(),
                name: store.name.clone(),
                text: text.clone(),
                minute,
                // Keep introducing myself until they've replied.
                card_mac: intro.as_ref().map(|c| dm::card_mac(&key, &to.inbox_pub, c)),
                card: intro,
                reply: Some(dm::ReplyInfo {
                    pillar: my_pillar.clone(),
                    inbox_pub: dm::inbox_public(&st.inbox_secret),
                    inbox_ids: dm::upcoming_inbox_ids(&st.fetch_secret),
                    inbox_kem: Some(dm::inbox_kem_public(&st.inbox_secret)),
                }),
                credits: if own || out.iter().any(|o| targets.iter().any(|t| t.olm_identity == o.olm)) { Vec::new() } else { credits.clone() },
                purchase: if own || out.iter().any(|o| targets.iter().any(|t| t.olm_identity == o.olm)) { None } else { purchase.clone() },
                grant: if own { None } else { grant.clone() },
                circle: if own { None } else { circle.clone() },
                sync: own.then(|| match &delete {
                    Some(d) => dm::DeviceSync::Delete { peer: Some(peer_key), room: None, keys: if d.all { Vec::new() } else { d.keys.clone() }, room_keys: Vec::new() },
                    None => dm::DeviceSync::Sent { peer: peer_key },
                }),
                delete: if own { None } else { delete.clone() },
            };
            let Some(blob) = dm::encrypt(&account, &mut session, &payload, to) else { continue };
            sessions.push((peer, session.pickle().encrypt(&pickle_key(&key))));
            out.push(Outgoing { olm: to.olm_identity, blob });
        }
        if out.iter().all(|o| mine.iter().any(|m| m.olm_identity == o.olm)) {
            bail!("Couldn't start an encrypted session with them.");
        }
        let author_s = author.to_owned();
        self.update(|s| {
            if let Some(d) = s.dm.as_mut() {
                for (peer, p) in &sessions {
                    d.sessions.insert(peer.clone(), p.clone());
                }
                for t in &targets {
                    d.owners.insert(hex(&t.olm_identity), author_s.clone());
                }
                for m in &mine {
                    d.owners.insert(hex(&m.olm_identity), me.clone());
                }
            }
            let name = s
                .following
                .iter()
                .find(|f| f.author == author_s)
                .and_then(|f| f.name.clone())
                .or_else(|| conv.as_ref().map(|c| c.name.clone()))
                .unwrap_or_else(|| handle_of(&author_s));
            let idx = match s.conversations.iter().position(|c| c.author == author_s) {
                Some(i) => i,
                None => {
                    s.conversations.push(Conversation {
                        author: author_s.clone(),
                        name,
                        card: targets.first().cloned(),
                        messages: Vec::new(),
                        introduced: false,
                        cards: targets.clone(),
                    });
                    s.conversations.len() - 1
                }
            };
            // Credits travelling in it: remembered until it's clear they
            // arrived, so a lost message doesn't lose them.
            if !credits.is_empty() {
                s.sent_credits.push(super::SentCredits { to: author_s.clone(), minute, text: text.clone(), parts: credits.iter().flat_map(|b| b.parts.clone()).collect() });
            }
            // The sealed copies are kept until delivered (retried on every sync).
            s.conversations[idx].messages.push(Message { mine: true, text, minute, sent: false, blob: None, expire_days, out });
        })?;

        let core = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            if core.retry_dms().await.unwrap_or(0) > 0 {
                let _ = app.emit("messages", ());
            }
        });
        Ok(())
    }

    /// Deliver every undelivered copy (oldest first, in order per
    /// conversation and device), and sync messages to my other devices.
    /// Returns how many were delivered.
    pub async fn retry_dms(&self) -> Result<usize> {
        let (_, store) = self.unlocked()?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let mut delivered = 0;
        for c in &store.conversations {
            let cards = cards_for(&store, &c.author);
            for m in c.messages.iter().filter(|m| m.mine && !m.sent) {
                // Older single-copy messages.
                let mut pending: Vec<Outgoing> = m.out.clone();
                if let (Some(b), Some(first)) = (&m.blob, cards.first()) {
                    pending.push(Outgoing { olm: first.olm_identity, blob: b.clone() });
                }
                let mut stuck = false;
                for o in pending {
                    let Some(card) = cards.iter().chain(store.my_devices.iter()).find(|x| x.olm_identity == o.olm).cloned() else {
                        // That device is gone: drop the copy.
                        self.drop_copy(&c.author, &o)?;
                        continue;
                    };
                    if self.deposit_dm(&net, &card, &o.blob).await.is_err() {
                        stuck = true;
                        break; // keep order: try again next sync
                    }
                    delivered += 1;
                    self.drop_copy(&c.author, &o)?;
                }
                if stuck {
                    break;
                }
            }
        }
        // Sync messages for my other devices.
        for o in store.device_outbox.clone() {
            let Some(card) = store.my_devices.iter().find(|x| x.olm_identity == o.olm).cloned() else {
                self.update(|s| s.device_outbox.retain(|x| x.blob != o.blob))?;
                continue;
            };
            if self.deposit_dm(&net, &card, &o.blob).await.is_ok() {
                self.update(|s| s.device_outbox.retain(|x| x.blob != o.blob))?;
            }
        }
        Ok(delivered)
    }

    /// One copy delivered (or its device gone): remove it; the message
    /// counts as sent once no copies are left.
    fn drop_copy(&self, author: &str, o: &Outgoing) -> Result<()> {
        self.update(|s| {
            if let Some(cc) = s.conversations.iter_mut().find(|x| x.author == author) {
                for mm in cc.messages.iter_mut().filter(|x| x.mine && !x.sent) {
                    if mm.blob.as_ref() == Some(&o.blob) {
                        mm.blob = None;
                    }
                    mm.out.retain(|x| x.blob != o.blob);
                    if mm.blob.is_none() && mm.out.is_empty() {
                        mm.sent = true;
                    }
                }
            }
        })
    }

    async fn deposit_dm(&self, net: &sentinel_net::transport::Net, card: &ContactCard, blob: &[u8]) -> Result<()> {
        let inbox = dm::deliver_to(&card.inbox_ids).context("card too old")?;
        // Only the shard of their inbox is named, never the inbox.
        let shard = dm::shard_of(&inbox);
        let data = dm::deposit_pow_data(shard, blob);
        let bits = dm::deposit_bits(blob.len());
        let nonce = tokio::task::spawn_blocking(move || sentinel_core::pow::stamp(dm::DEPOSIT_POW_DOMAIN, &data, bits)).await?;
        self.deposit(net, &card.pillar, shard, blob.to_vec(), nonce).await
    }

    /// Tell my other devices about something I did (follow, join, hide).
    pub fn sync_to_devices(&self, what: dm::DeviceSync) -> Result<()> {
        self.sync_to_devices_with(what, String::new(), social::coarse_minute(), None)
    }

    /// The same, carrying a message's text (a message passed on to my
    /// other devices).
    pub(super) fn sync_to_devices_with(&self, what: dm::DeviceSync, text: String, minute: u64, expire_days: Option<u16>) -> Result<()> {
        let (key, store) = self.unlocked()?;
        if store.my_devices.is_empty() {
            return Ok(());
        }
        let st = store.dm.clone().context("no messaging keys")?;
        let my_pillar = store.pillar.clone().context("not connected")?;
        let account = load_account(&key, &st)?;
        let mut out = Vec::new();
        let mut sessions = Vec::new();
        for to in &store.my_devices {
            let peer = hex(&to.olm_identity);
            let mut session = match st.sessions.get(&peer).and_then(|p| load_session(&key, p)) {
                Some(s) => s,
                None => match dm::outbound_session(&account, to) {
                    Some(s) => s,
                    None => continue,
                },
            };
            let intro = my_intro_card(&account, &st, &my_pillar);
            let payload = dm::DmPayload {
                from: key.verifying_key().to_bytes(),
                name: store.name.clone(),
                text: text.clone(),
                minute,
                card_mac: Some(dm::card_mac(&key, &to.inbox_pub, &intro)),
                card: Some(intro),
                reply: None,
                expire_days,
                credits: Vec::new(),
                purchase: None,
                grant: None,
                circle: None,
                sync: Some(what.clone()),
                delete: None,
            };
            let Some(blob) = dm::encrypt(&account, &mut session, &payload, to) else { continue };
            sessions.push((peer, session.pickle().encrypt(&pickle_key(&key))));
            out.push(Outgoing { olm: to.olm_identity, blob });
        }
        self.update(|s| {
            if let Some(d) = s.dm.as_mut() {
                for (peer, p) in sessions {
                    d.sessions.insert(peer, p);
                }
            }
            s.device_outbox.extend(out);
        })
    }

    /// Fetch and decrypt new messages from my inbox (today's and yesterday's
    /// rotating IDs). Returns how many arrived.
    pub async fn poll_inbox(&self) -> Result<usize> {
        Ok(self.poll_mail().await?.0)
    }

    /// Decrypt one deposited blob and file it in the right conversation.
    pub(super) fn receive_blob(&self, key: &super::Keys, blob: &[u8]) -> Result<bool> {
        let (_, store) = self.unlocked()?;
        let st = store.dm.clone().context("no messaging keys")?;
        let Some((sender, msg)) = dm::unseal(&st.inbox_secret, blob) else { return Ok(false) };
        let peer = hex(&sender);
        let mut account = load_account(key, &st)?;
        let existing = st.sessions.get(&peer).and_then(|p| load_session(key, p));
        let had_session = existing.is_some();
        let Some((session, payload)) = dm::decrypt(&mut account, existing, sender, &msg) else { return Ok(false) };

        // Who is this? First contact must carry a valid signed card bound to
        // the Olm identity; afterwards the session itself authenticates.
        let author = social::author_text(&payload.from);
        let (owner, card) = if had_session && st.owners.get(&peer) == Some(&author) {
            (author.clone(), None)
        } else {
            match dm::authenticate_first(&payload, sender, &st.inbox_secret) {
                Some(card) => (author.clone(), Some(card)),
                None => return Ok(false), // unauthenticated: drop
            }
        };

        // Blocked: dropped unread (consumed, so it isn't fetched again).
        if store.blocked.iter().any(|a| *a == owner) {
            return Ok(true);
        }
        // From one of my own devices: what I did there.
        let me = social::author_text(&key.verifying_key().to_bytes());
        if owner == me {
            let session_p = session.pickle().encrypt(&pickle_key(key));
            let account_p = account.pickle().encrypt(&pickle_key(key));
            self.update(|s| {
                if let Some(d) = s.dm.as_mut() {
                    d.sessions.insert(peer.clone(), session_p);
                    d.account = account_p;
                    d.owners.insert(peer.clone(), me.clone());
                }
                if let Some(c) = card {
                    merge_card(&mut s.my_devices, c);
                }
                match payload.sync.clone() {
                    Some(dm::DeviceSync::Sent { peer }) => {
                        let to = social::author_text(&peer);
                        if let Some(c) = s.conversations.iter_mut().find(|c| c.author == to) {
                            c.messages.push(Message { mine: true, text: payload.text.clone(), minute: payload.minute, sent: true, blob: None, expire_days: payload.expire_days, out: Vec::new() });
                        } else {
                            let name = s.following.iter().find(|f| f.author == to).and_then(|f| f.name.clone()).unwrap_or_else(|| handle_of(&to));
                            s.conversations.push(Conversation {
                                author: to,
                                name,
                                card: None,
                                messages: vec![Message { mine: true, text: payload.text.clone(), minute: payload.minute, sent: true, blob: None, expire_days: payload.expire_days, out: Vec::new() }],
                                introduced: true,
                                cards: Vec::new(),
                            });
                        }
                    }
                    Some(dm::DeviceSync::Received { peer, name }) => {
                        let from = social::author_text(&peer);
                        let m = Message { mine: false, text: payload.text.clone(), minute: payload.minute, sent: true, blob: None, expire_days: payload.expire_days, out: Vec::new() };
                        match s.conversations.iter_mut().find(|c| c.author == from) {
                            Some(c) => {
                                if !c.messages.iter().any(|x| !x.mine && x.text == m.text && x.minute == m.minute) {
                                    c.messages.push(m);
                                }
                            }
                            None => s.conversations.push(Conversation { author: from, name: name.chars().take(social::MAX_NAME_CHARS).collect(), card: None, messages: vec![m], introduced: false, cards: Vec::new() }),
                        }
                    }
                    Some(other) => s.incoming_sync.push(other),
                    None => {}
                }
            })?;
            return Ok(true);
        }
        let session_p = session.pickle().encrypt(&pickle_key(key));
        let account_p = account.pickle().encrypt(&pickle_key(key));
        self.update(|s| {
            if let Some(d) = s.dm.as_mut() {
                d.sessions.insert(peer.clone(), session_p);
                d.account = account_p;
                d.owners.insert(peer.clone(), owner.clone());
                if !had_session {
                    d.card_minute = 0; // a prekey was used: republish my card
                }
            }
            let idx = match s.conversations.iter().position(|c| c.author == owner) {
                Some(i) => i,
                None => {
                    s.conversations.push(Conversation {
                        author: owner.clone(),
                        name: payload.name.chars().take(social::MAX_NAME_CHARS).collect(),
                        card: None,
                        messages: Vec::new(),
                        introduced: false,
                        cards: Vec::new(),
                    });
                    s.conversations.len() - 1
                }
            };
            if let Some(c) = &payload.circle {
                super::circle::receive(s, &owner, &payload.name, c);
            }
            let c = &mut s.conversations[idx];
            if let Some(card) = card {
                merge_card(&mut c.cards, card.clone());
                c.card = Some(card);
            }
            // Keep their delivery details fresh (rotating inbox IDs).
            if let (Some(r), Some(cc)) = (payload.reply.clone(), c.card.as_mut()) {
                cc.pillar = r.pillar;
                cc.inbox_pub = r.inbox_pub;
                cc.inbox_ids = r.inbox_ids;
                if r.inbox_kem.is_some() {
                    cc.inbox_kem = r.inbox_kem;
                }
            }
            c.introduced = true; // they replied, so they have my card
            // Payments and grants are handled on the next sync (they need
            // the network: tokens are swapped at the mint at once).
            if !payload.credits.is_empty() || payload.purchase.is_some() {
                s.incoming_payments.push(super::IncomingPayment {
                    from: owner.clone(),
                    bundles: payload.credits.clone(),
                    purchase: payload.purchase.clone(),
                    confirmed: 0,
                    checked: false,
                });
            }
            if let Some(g) = &payload.grant {
                s.incoming_grants.push((owner.clone(), g.clone()));
            }
            // They asked my app to delete messages of our conversation.
            if let Some(d) = &payload.delete {
                if d.all {
                    c.messages.retain(|m| m.mine && !m.sent); // (mine still being sent stay)
                } else {
                    c.messages.retain(|m| !d.keys.contains(&dm::message_key(m.minute, &m.text)));
                }
            }
            // The same message may also arrive passed on by my other device.
            if !payload.text.is_empty() && !c.messages.iter().any(|x| !x.mine && x.text == payload.text && x.minute == payload.minute) {
                c.messages.push(Message {
                    mine: false,
                    text: payload.text.clone(),
                    minute: payload.minute,
                    sent: true,
                    blob: None,
                    expire_days: payload.expire_days.map(|d| d.clamp(1, 365)),
                    out: Vec::new(),
                });
            }
        })?;
        // My other devices may not be known to them yet: pass it on.
        if !payload.text.is_empty() {
            if let Some(peer) = social::author_from_text(&owner) {
                let _ = self.sync_to_devices_with(dm::DeviceSync::Received { peer, name: payload.name.clone() }, payload.text.clone(), payload.minute, payload.expire_days);
            }
        }
        Ok(true)
    }
}
