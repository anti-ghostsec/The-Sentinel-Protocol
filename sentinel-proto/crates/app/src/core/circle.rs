//! Approved followers (spec §8.4): an audience the author approves person
//! by person and can remove people from.
//!
//! - Someone who already follows me (by link) asks, in an encrypted DM.
//! - Approving sends them the current **circle key**, in the same DM channel.
//! - Approved-followers posts are sealed only for that key: people who just
//!   have my link can't read them, and neither can Pillars. Sealed posts all
//!   look alike, so nobody can tell which audience a post had.
//! - Removing someone makes a new key (next epoch), sent only to the people
//!   who remain. The removed person keeps what they already read, nothing
//!   newer.
//!
//! Requests and approvals travel only inside end-to-end encrypted DMs, and
//! a key is accepted only from someone I follow and asked.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sentinel_core::dm::CircleMsg;
use sentinel_core::social;
use std::sync::Arc;
use tauri::AppHandle;

use super::{handle_of, Core};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Circle {
    pub epoch: u32,
    pub key: Option<[u8; 32]>,
    /// Approved followers (author keys).
    pub members: Vec<String>,
    /// Pending requests: (author, name they gave).
    pub requests: Vec<(String, String)>,
}

/// Most circle keys kept per followed account (older posts stay readable).
const KEEP_KEYS: usize = 16;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CirclePerson {
    pub author: String,
    pub name: String,
    pub handle: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CircleView {
    pub requests: Vec<CirclePerson>,
    pub members: Vec<CirclePerson>,
}

impl Core {
    /// My current approved-followers key (made on first use).
    pub(super) fn circle_key(&self) -> Result<[u8; 32]> {
        if let Some(k) = self.unlocked()?.1.circle.key {
            return Ok(k);
        }
        let k = sentinel_core::random_bytes::<32>();
        self.update(|s| {
            if s.circle.key.is_none() {
                s.circle.key = Some(k);
                s.circle.epoch = 1;
            }
        })?;
        self.unlocked()?.1.circle.key.context("circle key")
    }

    pub fn circle_view(&self) -> Result<CircleView> {
        let (_, store) = self.unlocked()?;
        let name_of = |a: &str, fallback: &str| {
            store
                .following
                .iter()
                .find(|f| f.author == a)
                .and_then(|f| f.name.clone())
                .or_else(|| store.conversations.iter().find(|c| c.author == a).map(|c| c.name.clone()))
                .unwrap_or_else(|| if fallback.is_empty() { handle_of(a) } else { fallback.to_owned() })
        };
        Ok(CircleView {
            requests: store
                .circle
                .requests
                .iter()
                .filter(|(a, _)| !store.blocked.contains(a))
                .map(|(a, n)| CirclePerson { author: a.clone(), name: name_of(a, n), handle: handle_of(a) })
                .collect(),
            members: store.circle.members.iter().map(|a| CirclePerson { author: a.clone(), name: name_of(a, ""), handle: handle_of(a) }).collect(),
        })
    }

    /// Ask someone I follow to approve me.
    pub fn request_circle(self: &Arc<Self>, app: AppHandle, author: &str) -> Result<()> {
        let (_, store) = self.unlocked()?;
        if !store.following.iter().any(|f| f.author == author) {
            bail!("Follow them with their link first.");
        }
        self.send_dm_full(app, author, "Asked to be an approved follower.", Vec::new(), None, None, Some(CircleMsg::Request), None)?;
        self.update(|s| {
            if let Some(f) = s.following.iter_mut().find(|f| f.author == author) {
                if f.circle_state.is_empty() {
                    f.circle_state = "requested".into();
                }
            }
        })
    }

    /// Approve a request (or add someone who can be messaged).
    pub fn approve_circle(self: &Arc<Self>, app: AppHandle, author: &str) -> Result<()> {
        social::author_from_text(author).context("not an account")?;
        let key = self.circle_key()?;
        let epoch = self.unlocked()?.1.circle.epoch;
        self.send_dm_full(app, author, "Approved you as a follower.", Vec::new(), None, None, Some(CircleMsg::Grant { epoch, key }), None)?;
        self.update(|s| {
            s.circle.requests.retain(|(a, _)| a != author);
            if !s.circle.members.iter().any(|a| a == author) {
                s.circle.members.push(author.to_owned());
            }
        })
    }

    pub fn decline_circle(&self, author: &str) -> Result<()> {
        self.update(|s| s.circle.requests.retain(|(a, _)| a != author))
    }

    /// Remove someone: new key for everyone who remains. Their copy of the
    /// old key opens only posts they could already read.
    pub fn remove_circle(self: &Arc<Self>, app: AppHandle, author: &str) -> Result<usize> {
        let key = sentinel_core::random_bytes::<32>();
        let mut epoch = 0;
        let mut remaining = Vec::new();
        self.update(|s| {
            s.circle.members.retain(|a| a != author);
            s.circle.epoch += 1;
            s.circle.key = Some(key);
            epoch = s.circle.epoch;
            remaining = s.circle.members.clone();
        })?;
        let mut sent = 0;
        for a in remaining {
            if self.send_dm_full(app.clone(), &a, "Updated the key for approved followers.", Vec::new(), None, None, Some(CircleMsg::Grant { epoch, key }), None).is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }
}

/// Handle a circle message that arrived in a DM from `from` (already
/// authenticated). Applied inside the store update.
pub(super) fn receive(s: &mut super::Store, from: &str, name: &str, msg: &CircleMsg) {
    if s.blocked.iter().any(|a| a == from) {
        return;
    }
    match msg {
        CircleMsg::Request => {
            if !s.circle.members.iter().any(|a| a == from) && !s.circle.requests.iter().any(|(a, _)| a == from) {
                let name: String = name.chars().take(social::MAX_NAME_CHARS).collect();
                s.circle.requests.push((from.to_owned(), name));
                s.circle.requests.truncate(500);
            }
        }
        CircleMsg::Grant { key, .. } => {
            // Only from someone I follow and asked (or was approved by):
            // nobody can push keys at me to tag what I read.
            if let Some(f) = s.following.iter_mut().find(|f| f.author == from && !f.circle_state.is_empty()) {
                if !f.circle_keys.contains(key) {
                    f.circle_keys.push(*key);
                    let n = f.circle_keys.len();
                    if n > KEEP_KEYS {
                        f.circle_keys.drain(..n - KEEP_KEYS);
                    }
                }
                f.circle_state = "approved".into();
            }
        }
    }
}
