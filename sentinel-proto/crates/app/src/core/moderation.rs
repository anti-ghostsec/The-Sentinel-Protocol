//! Reporting harmful content, and handling reports on my own Pillar.
//!
//! Each report goes to whoever can actually see the content, and nobody
//! gets new powers to read anything private:
//!
//! - **Public posts and public room listings** go to the Pillars and
//!   Archives that hold them (they can open public content). After a few
//!   reports a Pillar hides it from Discover until its operator removes it
//!   or keeps it (see the Pillar's `reports`).
//! - **Room messages** go to the room's admin and moderators, sealed to
//!   them (see `rooms::report_room_message`).
//! - **Private messages** go to nobody: only the two people can read them.
//!   The app offers blocking instead.
//!
//! There is no shared or public list of what was removed: each Pillar only
//! remembers, privately, what it removed itself.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sentinel_core::object::{Address, Envelope};
use sentinel_core::social;
use sentinel_core::wire::{Request, Response};

use super::{request, Core};

/// Report categories, as the app shows them.
#[derive(Serialize)]
pub struct CategoryView {
    pub id: String,
    pub label: String,
}

pub fn categories() -> Vec<CategoryView> {
    super::REPORT_CATEGORY_NAMES.iter().map(|(id, label)| CategoryView { id: (*id).into(), label: (*label).into() }).collect()
}

fn category_index(category: &str) -> Result<u8> {
    social::REPORT_CATEGORIES.iter().position(|c| *c == category).map(|i| i as u8).context("Choose what's wrong with it.")
}

/// A reported item on my Pillar, as I (its operator) see it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostReportView {
    pub address: String,
    /// "child-abuse ×2, spam ×1".
    pub summary: String,
    pub total: u32,
    /// Hidden from Discover until I decide.
    pub hidden: bool,
    /// What it says (public content), if it's still here.
    pub preview: String,
    pub has_media: bool,
}

impl Core {
    /// Report a public post. Returns how many Pillars and Archives got it.
    /// It's hidden on this device at once.
    pub async fn report_post(&self, post_id: &str, category: &str) -> Result<usize> {
        let cat = category_index(category)?;
        let addr = Address::from_text(post_id).context("bad post")?;
        let (_, store) = self.unlocked()?;
        let mut pillars: Vec<String> = Vec::new();
        let mut chunks: Vec<[u8; 32]> = Vec::new();
        if let Some(d) = store.discovered.iter().find(|d| d.id == post_id) {
            pillars.push(d.pillar.clone());
            for m in &d.media {
                chunks.extend(m.chunks.iter().chain(m.manifest.iter()));
                pillars.extend(m.archives.iter().cloned());
            }
            if let Some(f) = store.following.iter().find(|f| f.author == d.author) {
                pillars.push(f.pillar.clone());
            }
        } else if let Some(p) = store.posts.iter().find(|p| p.id == post_id && !p.mine) {
            if !p.discoverable {
                bail!("Only public posts can be reported to Pillars: a post for people with the link can't be seen by anyone else. You can unfollow or block instead.");
            }
            if let Some(f) = store.following.iter().find(|f| f.author == p.author) {
                pillars.push(f.pillar.clone());
            }
            for m in &p.media {
                chunks.extend(m.chunks.iter().chain(m.manifest.iter()));
                pillars.extend(m.archives.iter().cloned());
            }
        } else {
            bail!("That post is no longer here.");
        }
        pillars.sort();
        pillars.dedup();
        chunks.truncate(5000);
        let reached = self.send_report(addr.0, chunks, cat, pillars).await;
        // Gone from this device now, and not shown again.
        let _ = self.update(|s| {
            s.discovered.retain(|d| d.id != post_id);
            if !s.reported.contains(&post_id.to_owned()) {
                s.reported.push(post_id.to_owned());
            }
            if s.reported.len() > 2000 {
                s.reported.remove(0);
            }
        });
        Ok(reached)
    }

    /// Report a public room's Discover listing.
    pub async fn report_room_listing(&self, room_id: &str, category: &str) -> Result<usize> {
        let cat = category_index(category)?;
        let (_, store) = self.unlocked()?;
        let r = store.discovered_rooms.iter().find(|r| r.room_id == room_id).context("That room is no longer listed here.")?;
        let addr = Address::from_text(&r.address).context("This listing can't be reported (refresh Discover and try again).")?;
        let reached = self.send_report(addr.0, Vec::new(), cat, vec![r.pillar.clone()]).await;
        let address = r.address.clone();
        let _ = self.update(|s| {
            s.discovered_rooms.retain(|x| x.room_id != room_id);
            if !s.reported.contains(&address) {
                s.reported.push(address.clone());
            }
        });
        Ok(reached)
    }

    /// Send one report to each Pillar, each over its own circuit.
    async fn send_report(&self, address: [u8; 32], chunks: Vec<[u8; 32]>, category: u8, pillars: Vec<String>) -> usize {
        let Some(net) = self.with(|i| i.net.clone()) else { return 0 };
        let Ok((key, _)) = self.unlocked() else { return 0 };
        let token = social::report_token(&key, &address);
        let data = social::report_pow_data(&address, &token, category);
        let Ok(nonce) = tokio::task::spawn_blocking(move || sentinel_core::pow::stamp(social::REPORT_POW_DOMAIN, &data, social::REPORT_POW_BITS)).await else { return 0 };
        let sends = pillars.iter().filter(|p| !p.is_empty()).map(|p| {
            let (net, chunks) = (net.clone(), chunks.clone());
            async move {
                let r = tokio::time::timeout(std::time::Duration::from_secs(90), async {
                    let mut s = net.connect_hedged(p).await?;
                    anyhow::Ok(matches!(request(&mut s, &Request::Report { address, chunks, category, token, nonce }).await?, Response::Pong))
                })
                .await;
                matches!(r, Ok(Ok(true)))
            }
        });
        let n = futures::future::join_all(sends).await.into_iter().filter(|ok| *ok).count();
        sentinel_net::note(format!("Sentinel: report delivered to {n} Pillar(s)"));
        n
    }

    fn host_store(&self) -> Result<std::path::PathBuf> {
        Ok(sentinel_net::data_root(&format!("{}-host", super::role()))?.join("objects"))
    }

    /// Reports about public content on my Pillar.
    pub fn host_reports(&self) -> Result<Vec<HostReportView>> {
        self.unlocked()?;
        let store = self.host_store()?;
        let explore = sentinel_core::seal::explore_key();
        Ok(pillar::list_reports(&store)
            .into_iter()
            .map(|r| {
                let (preview, has_media) = std::fs::read(store.join(&r.address))
                    .ok()
                    .and_then(|b| Envelope::decode_verified(&b).ok())
                    .and_then(|env| social::open_record(&env, &[explore]))
                    .map(|rec| match rec {
                        social::Record::Post(p) => (p.text.chars().take(500).collect(), !p.media.is_empty()),
                        social::Record::RoomListing(l) => (format!("Room listing: {} — {}", l.name, l.description).chars().take(500).collect(), false),
                        _ => (String::new(), false),
                    })
                    .unwrap_or_else(|| (String::new(), !r.chunks.is_empty()));
                HostReportView { summary: r.summary(), total: r.total(), hidden: r.hidden, address: r.address, preview, has_media }
            })
            .collect())
    }

    /// Remove reported content from my Pillar (and refuse it if re-uploaded).
    pub fn host_remove(&self, address: &str) -> Result<()> {
        self.unlocked()?;
        pillar::remove_reported(&self.host_store()?, address)
    }

    /// Keep reported content on my Pillar (dismiss its reports).
    pub fn host_keep(&self, address: &str) -> Result<()> {
        self.unlocked()?;
        pillar::keep_reported(&self.host_store()?, address)
    }
}
