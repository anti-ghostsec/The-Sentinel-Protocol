//! Deleting messages in bulk: everything, a conversation (all or selected,
//! optionally asking the other person's app to delete them too), or a room
//! (on my devices only: only a room's admin and moderators can hide
//! messages for everyone). My other devices delete the same messages.
//!
//! Honest limit: asking the other person's app to delete is a request their
//! app honours; nothing can force a modified app, or erase a screenshot.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use sentinel_core::dm::{self, DeleteRequest, DeviceSync};
use sentinel_core::social;
use tauri::{AppHandle, Emitter};

use super::{Core, Store};

fn parse_dm_ids(ids: &[String]) -> Vec<(u64, [u8; 8])> {
    ids.iter()
        .filter_map(|id| {
            let (m, h) = id.split_once(':')?;
            let h: [u8; 8] = data_encoding::HEXLOWER.decode(h.as_bytes()).ok()?.try_into().ok()?;
            Some((m.parse().ok()?, h))
        })
        .collect()
}

fn parse_room_ids(ids: &[String]) -> Vec<(String, u32)> {
    ids.iter().filter_map(|id| { let (s, i) = id.rsplit_once(':')?; Some((s.to_owned(), i.parse().ok()?)) }).collect()
}

/// Delete in the store: a conversation (`peer`), a room (`room`), or
/// everything (neither). Empty key lists = all of them.
pub(super) fn apply(s: &mut Store, peer: Option<[u8; 32]>, room: Option<[u8; 32]>, keys: &[(u64, [u8; 8])], room_keys: &[(String, u32)]) {
    let keep_dm = |m: &super::Message| (m.mine && !m.sent) || (!keys.is_empty() && !keys.contains(&dm::message_key(m.minute, &m.text)));
    match (peer, room) {
        (Some(p), _) => {
            let a = social::author_text(&p);
            if let Some(c) = s.conversations.iter_mut().find(|c| c.author == a) {
                c.messages.retain(keep_dm);
            }
        }
        (None, Some(r)) => {
            if let Some(x) = s.rooms.iter_mut().find(|x| x.room_id == r) {
                if room_keys.is_empty() {
                    x.messages.retain(|m| m.mine && !m.sent);
                } else {
                    x.messages.retain(|m| !room_keys.iter().any(|(sess, i)| *sess == m.session && *i == m.index));
                }
            }
        }
        (None, None) => {
            for c in s.conversations.iter_mut() {
                c.messages.retain(|m| m.mine && !m.sent);
            }
            for x in s.rooms.iter_mut() {
                x.messages.retain(|m| m.mine && !m.sent);
            }
        }
    }
}

impl Core {
    /// Delete messages of one conversation (`ids` empty = all), on this
    /// device and my other ones; `theirs`: also ask their app to.
    pub fn delete_dm_messages(self: &Arc<Self>, app: AppHandle, author: &str, ids: Vec<String>, theirs: bool) -> Result<usize> {
        let peer = social::author_from_text(author).context("not an account")?;
        let keys = parse_dm_ids(&ids);
        if !ids.is_empty() && keys.is_empty() {
            bail!("Nothing to delete.");
        }
        let before = self.count(|s| s.conversations.iter().find(|c| c.author == author).map(|c| c.messages.len()).unwrap_or(0))?;
        self.update(|s| apply(s, Some(peer), None, &keys, &[]))?;
        let after = self.count(|s| s.conversations.iter().find(|c| c.author == author).map(|c| c.messages.len()).unwrap_or(0))?;
        if theirs {
            // Also tells my other devices (their copy of the request).
            self.send_dm_full(app.clone(), author, "", Vec::new(), None, None, None, Some(DeleteRequest { all: keys.is_empty(), keys: keys.clone() }))?;
        } else {
            let _ = self.sync_to_devices(DeviceSync::Delete { peer: Some(peer), room: None, keys, room_keys: Vec::new() });
        }
        let _ = app.emit("messages", ());
        Ok(before - after)
    }

    /// Delete messages of one room on my devices (`ids` empty = all).
    pub fn delete_room_messages(&self, app: AppHandle, id: &str, ids: Vec<String>) -> Result<usize> {
        let (_, store) = self.unlocked()?;
        let r = store.rooms.iter().find(|r| data_encoding::HEXLOWER.encode(&r.room_id) == id).context("no such room")?;
        let room_id = r.room_id;
        let room_keys = parse_room_ids(&ids);
        if !ids.is_empty() && room_keys.is_empty() {
            bail!("Nothing to delete.");
        }
        let before = r.messages.len();
        self.update(|s| apply(s, None, Some(room_id), &[], &room_keys))?;
        let after = self.count(|s| s.rooms.iter().find(|x| x.room_id == room_id).map(|x| x.messages.len()).unwrap_or(0))?;
        let _ = self.sync_to_devices(DeviceSync::Delete { peer: None, room: Some(room_id), keys: Vec::new(), room_keys });
        let _ = app.emit("rooms", ());
        Ok(before - after)
    }

    /// Delete every message in every conversation and room, on this device
    /// and my other ones.
    pub fn delete_all_messages(&self, app: AppHandle) -> Result<usize> {
        let count = |s: &Store| s.conversations.iter().map(|c| c.messages.len()).sum::<usize>() + s.rooms.iter().map(|r| r.messages.len()).sum::<usize>();
        let before = self.count(count)?;
        self.update(|s| apply(s, None, None, &[], &[]))?;
        let after = self.count(count)?;
        let _ = self.sync_to_devices(DeviceSync::Delete { peer: None, room: None, keys: Vec::new(), room_keys: Vec::new() });
        let _ = app.emit("messages", ());
        let _ = app.emit("rooms", ());
        Ok(before - after)
    }

    fn count(&self, f: impl Fn(&Store) -> usize) -> Result<usize> {
        Ok(f(&self.unlocked()?.1))
    }
}
