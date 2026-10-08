//! Profiles and identity tools.
//!
//! - Profile = name, bio, profile picture and header image. Pictures are
//!   re-encoded (cropped, all metadata gone), encrypted and stored like any
//!   media; the profile record is sealed for people with my link only.
//! - Safety numbers let two people check, out of band, that they hold each
//!   other's real identity keys (no one in between).
//! - Passphrase change, encrypted backup/restore, and a panic wipe.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use sentinel_core::media::{self, MediaRef, Shape};
use sentinel_core::{identity, social};
use serde::Serialize;

use super::{handle_of, Core};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    pub author: String,
    pub name: String,
    pub handle: String,
    pub bio: String,
    pub avatar: bool,
    pub banner: bool,
    pub mine: bool,
    pub following: bool,
    pub can_message: bool,
    /// Follow link (mine only).
    pub link: Option<String>,
    pub muted: bool,
    pub blocked: bool,
    /// Approved-followers status with them: "" | "requested" | "approved"
    /// (mine to them), and whether they're in my approved followers.
    pub circle_state: String,
    pub in_my_circle: bool,
}

/// Someone I've muted or blocked (for the list in Privacy).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenView {
    pub author: String,
    pub name: String,
    pub handle: String,
    pub blocked: bool,
}

/// Backup file: magic | u32 identity length | identity file | store file.
/// Both parts are already encrypted (passphrase / identity-derived key).
const BACKUP_MAGIC: &[u8; 8] = &[0x53, 0x9b, 0x2e, 0x71, 0xc4, 0x0d, 0xa8, 0x36];

impl Core {
    pub fn my_profile(&self) -> Result<ProfileView> {
        let (key, store) = self.unlocked()?;
        let me = social::author_text(&key.verifying_key().to_bytes());
        Ok(ProfileView {
            handle: handle_of(&me),
            author: me,
            name: store.name.clone(),
            bio: store.bio.clone(),
            avatar: store.avatar.is_some(),
            banner: store.banner.is_some(),
            mine: true,
            following: false,
            can_message: false,
            link: self.status().link,
            muted: false,
            blocked: false,
            circle_state: String::new(),
            in_my_circle: false,
        })
    }

    /// Someone else's profile as I know it (followed or discovered).
    pub fn user_profile(&self, author: &str) -> Result<ProfileView> {
        let (key, store) = self.unlocked()?;
        if author == social::author_text(&key.verifying_key().to_bytes()) {
            return self.my_profile();
        }
        let f = store.following.iter().find(|f| f.author == author);
        let conv = store.conversations.iter().find(|c| c.author == author);
        Ok(ProfileView {
            author: author.to_owned(),
            name: f.and_then(|f| f.name.clone()).or_else(|| conv.map(|c| c.name.clone())).unwrap_or_else(|| handle_of(author)),
            handle: handle_of(author),
            bio: f.map(|f| f.bio.clone()).unwrap_or_default(),
            avatar: f.is_some_and(|f| f.avatar.is_some()),
            banner: f.is_some_and(|f| f.banner.is_some()),
            mine: false,
            following: f.is_some(),
            can_message: f.is_some_and(|f| f.card.is_some()) || conv.is_some_and(|c| c.card.is_some()),
            link: None,
            muted: store.muted.iter().any(|a| a == author),
            blocked: store.blocked.iter().any(|a| a == author),
            circle_state: f.map(|f| f.circle_state.clone()).unwrap_or_default(),
            in_my_circle: store.circle.members.iter().any(|a| a == author),
        })
    }

    /// Mute (hide their posts) or unmute someone. Local only.
    pub fn set_muted(&self, author: &str, on: bool) -> Result<()> {
        social::author_from_text(author).context("not an account")?;
        self.update(|s| {
            s.muted.retain(|a| a != author);
            if on {
                s.muted.push(author.to_owned());
            }
        })
    }

    /// Block (hide everywhere and drop their messages) or unblock. Local
    /// only: nobody is told, so blocking never reveals anything.
    pub fn set_blocked(&self, author: &str, on: bool) -> Result<()> {
        social::author_from_text(author).context("not an account")?;
        self.update(|s| {
            s.blocked.retain(|a| a != author);
            if on {
                s.blocked.push(author.to_owned());
            }
        })
    }

    pub fn hidden_people(&self) -> Result<Vec<HiddenView>> {
        let (_, store) = self.unlocked()?;
        let name_of = |a: &str| {
            store
                .following
                .iter()
                .find(|f| f.author == a)
                .and_then(|f| f.name.clone())
                .or_else(|| store.conversations.iter().find(|c| c.author == a).map(|c| c.name.clone()))
                .unwrap_or_else(|| handle_of(a))
        };
        let mut out: Vec<HiddenView> = store.blocked.iter().map(|a| HiddenView { author: a.clone(), name: name_of(a), handle: handle_of(a), blocked: true }).collect();
        out.extend(store.muted.iter().filter(|a| !store.blocked.contains(a)).map(|a| HiddenView { author: a.clone(), name: name_of(a), handle: handle_of(a), blocked: false }));
        Ok(out)
    }

    pub fn update_profile(&self, name: &str, bio: &str) -> Result<()> {
        let name = name.trim();
        let bio = bio.trim();
        if name.is_empty() || name.chars().count() > social::MAX_NAME_CHARS {
            bail!("Name must be 1–40 characters.");
        }
        if bio.chars().count() > social::MAX_BIO_CHARS {
            bail!("Bio must be at most 300 characters.");
        }
        self.update(|s| {
            s.name = name.to_owned();
            s.bio = bio.to_owned();
            s.profile_published = false;
        })
    }

    /// Set the profile picture or header from a file (re-encoded, cropped).
    pub async fn set_profile_image(&self, path: PathBuf, shape: Shape) -> Result<()> {
        self.unlocked()?;
        let bytes = tokio::fs::read(&path).await.context("couldn't read the file")?;
        let s = tokio::task::spawn_blocking(move || media::sanitize_profile_image(&bytes, shape)).await??;
        let local = self.local()?;
        let hosts = self.media_hosts()?;
        let (mut r, chunks) = media::encrypt_file(&s);
        let mut pending = Vec::new();
        for (addr, ct) in r.chunks.iter().zip(chunks) {
            local.put_outbox(addr, &ct)?;
            pending.push(data_encoding::HEXLOWER.encode(addr));
        }
        r.archives = hosts;
        self.forget_picture(shape)?;
        self.update(|st| {
            match shape {
                Shape::Avatar => st.avatar = Some(r),
                Shape::Banner => st.banner = Some(r),
            }
            st.profile_chunks.extend(pending);
            st.profile_published = false;
        })?;
        self.with(|i| i.sessions.retain(|k, _| !k.starts_with(shape_prefix(shape))));
        Ok(())
    }

    pub fn remove_profile_image(&self, shape: Shape) -> Result<()> {
        self.forget_picture(shape)?;
        self.update(|st| {
            match shape {
                Shape::Avatar => st.avatar = None,
                Shape::Banner => st.banner = None,
            }
            st.profile_published = false;
        })?;
        self.with(|i| i.sessions.retain(|k, _| !k.starts_with(shape_prefix(shape))));
        Ok(())
    }

    /// Drop a replaced/removed picture: never upload its pending chunks and
    /// delete its local encrypted copy.
    fn forget_picture(&self, shape: Shape) -> Result<()> {
        let (_, st) = self.unlocked()?;
        let old = match shape {
            Shape::Avatar => st.avatar.clone(),
            Shape::Banner => st.banner.clone(),
        };
        let Some(old) = old else { return Ok(()) };
        let names: Vec<String> = old.chunks.iter().map(|a| data_encoding::HEXLOWER.encode(a)).collect();
        if let Ok(local) = self.local() {
            for a in &old.chunks {
                local.remove_outbox(a);
            }
        }
        self.update(|s| s.profile_chunks.retain(|c| !names.contains(c)))
    }

    /// Upload pending profile-picture chunks to their hosts, then move
    /// them to the cache.
    pub(super) async fn upload_profile_chunks(&self, chunks: &[String], hosts: &[String]) -> Result<()> {
        let local = self.local()?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        for host in hosts {
            let mut s = net.connect_hedged(host).await?;
            for name in chunks {
                let addr: [u8; 32] = data_encoding::HEXLOWER.decode(name.as_bytes())?.try_into().map_err(|_| anyhow!("bad chunk"))?;
                // Chunks of a replaced picture may be gone: skip them.
                let Some(data) = local.get(&addr) else { continue };
                super::media_app::put_chunk_pub(&mut s, data).await?;
            }
        }
        for name in chunks {
            if let Ok(addr) = <[u8; 32]>::try_from(data_encoding::HEXLOWER.decode(name.as_bytes()).unwrap_or_default()) {
                if let Some(ct) = local.get(&addr) {
                    local.put_cache(&addr, &ct, true);
                }
                local.remove_outbox(&addr);
            }
        }
        let done: Vec<String> = chunks.to_vec();
        self.update(|s| s.profile_chunks.retain(|c| !done.contains(c)))
    }

    /// The picture reference for `author` ("me" or an author key).
    pub(super) fn profile_media(&self, author: &str, shape: Shape) -> Result<(MediaRef, Option<String>)> {
        let (key, store) = self.unlocked()?;
        let me = social::author_text(&key.verifying_key().to_bytes());
        if author == "me" || author == me {
            let r = match shape {
                Shape::Avatar => store.avatar.clone(),
                Shape::Banner => store.banner.clone(),
            };
            return Ok((r.context("no picture")?, store.pillar.clone()));
        }
        let f = store.following.iter().find(|f| f.author == author).context("unknown account")?;
        let r = match shape {
            Shape::Avatar => f.avatar.clone(),
            Shape::Banner => f.banner.clone(),
        };
        Ok((r.context("no picture")?, Some(f.pillar.clone())))
    }

    /// Safety number for me and `author`: the same 60 digits on both
    /// devices only if each holds the other's real identity key. Compare
    /// in person or over another channel.
    pub fn safety_number(&self, author: &str) -> Result<String> {
        let (key, _) = self.unlocked()?;
        let mine = key.verifying_key().to_bytes();
        let theirs = social::author_from_text(author).context("bad account")?;
        let (a, b) = if mine <= theirs { (mine, theirs) } else { (theirs, mine) };
        let mut m = a.to_vec();
        m.extend_from_slice(&b);
        // 60 bytes of output: 12 groups of 5 digits, each from 40 bits.
        let mut h = [0u8; 60];
        blake3::Hasher::new_derive_key("sentinel/v0/safety-number").update(&m).finalize_xof().fill(&mut h);
        let mut digits = String::new();
        for (i, c) in h.chunks(5).enumerate() {
            let n = c.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64) % 100_000;
            if i > 0 {
                digits.push(' ');
            }
            digits.push_str(&format!("{n:05}"));
        }
        Ok(digits)
    }

    /// Choose a key file (for unlocking, a new account, or adding one).
    /// Only its fingerprint is kept, in memory; the file is only read.
    pub fn choose_keyfile(&self, path: &std::path::Path) -> Result<String> {
        use std::io::Read;
        use zeroize::Zeroize;
        let mut buf = Vec::new();
        std::fs::File::open(path)?.take(1 << 20).read_to_end(&mut buf)?;
        let digest = identity::keyfile_digest(&buf);
        buf.zeroize();
        let digest = digest.context("That file is too small to be a key file (it needs at least 64 bytes).")?;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        self.with(|i| i.chosen_keyfile = Some((zeroize::Zeroizing::new(digest), name.clone())));
        Ok(name)
    }

    /// Make a new key file (random bytes) and choose it.
    pub fn make_keyfile(&self, path: &std::path::Path) -> Result<String> {
        let mut bytes = Vec::with_capacity(4096);
        while bytes.len() < 4096 {
            bytes.extend_from_slice(&sentinel_core::random_bytes::<32>());
        }
        std::fs::write(path, &bytes)?;
        self.choose_keyfile(path)
    }

    pub fn forget_keyfile_choice(&self) {
        self.with(|i| i.chosen_keyfile = None);
    }

    /// Add or change the key file (the one just chosen), or remove it.
    /// Needs the current passphrase. Returns whether one is now required.
    pub fn set_keyfile(&self, current: &str, remove: bool) -> Result<bool> {
        self.unlocked()?;
        let path = super::identity_path()?;
        let file = std::fs::read(&path)?;
        let old = self.with(|i| i.keyfile.clone());
        let key = identity::open(&file, current.as_bytes(), old.as_deref()).map_err(|_| anyhow!("The current passphrase is wrong."))?;
        let new = if remove {
            None
        } else {
            Some(self.with(|i| i.chosen_keyfile.take()).context("Choose a key file first.")?.0)
        };
        let sealed = identity::reseal(&file, &key, current.as_bytes(), new.as_deref())?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, sealed)?;
        std::fs::rename(&tmp, &path)?;
        let on = new.is_some();
        self.with(|i| i.keyfile = new);
        Ok(on)
    }

    pub fn change_passphrase(&self, old: &str, new: &str) -> Result<()> {
        if new.chars().count() < 12 {
            bail!("The new passphrase must be at least 12 characters.");
        }
        let path = super::identity_path()?;
        let file = std::fs::read(&path)?;
        let keyfile = self.with(|i| i.keyfile.clone());
        let key = identity::open(&file, old.as_bytes(), keyfile.as_deref()).map_err(|_| anyhow!("The current passphrase is wrong."))?;
        // Keeps the emergency passphrase (if any) and the key file as they are.
        let sealed = identity::reseal(&file, &key, new.as_bytes(), keyfile.as_deref())?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, sealed)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Set an emergency passphrase (or remove it, with an empty one). Typed
    /// at unlock instead of the real one, it silently wipes this account and
    /// opens an empty account named `decoy_name`. Whether one is set can't
    /// be told from the key file.
    pub fn set_emergency(&self, current: &str, emergency: &str, decoy_name: &str) -> Result<bool> {
        let (_, store) = self.unlocked()?;
        let path = super::identity_path()?;
        let file = std::fs::read(&path)?;
        let keyfile = self.with(|i| i.keyfile.clone());
        let kf = keyfile.as_deref();
        let key = identity::open(&file, current.as_bytes(), kf).map_err(|_| anyhow!("The current passphrase is wrong."))?;
        let sealed = if emergency.is_empty() {
            identity::set_emergency(&file, &key, current.as_bytes(), kf, None)?
        } else {
            if emergency.chars().count() < 12 {
                bail!("The emergency passphrase must be at least 12 characters.");
            }
            if emergency == current {
                bail!("The emergency passphrase must be different from your real one.");
            }
            let name = decoy_name.trim();
            if name.is_empty() || name.chars().count() > social::MAX_NAME_CHARS {
                bail!("The decoy name must be 1–40 characters.");
            }
            let decoy = identity::Decoy { name: name.to_owned(), bridges: store.mode == "bridges" };
            identity::set_emergency(&file, &key, current.as_bytes(), kf, Some((emergency.as_bytes(), &decoy)))?
        };
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, sealed)?;
        std::fs::rename(&tmp, &path)?;
        Ok(!emergency.is_empty())
    }

    /// Write an encrypted recovery backup to `path`: the identity (sealed
    /// by the passphrase) and a **reduced** store — profile, follows, room
    /// memberships, keys and credits. Message history and encryption
    /// sessions are left out: a backup must not keep messages past their
    /// disappearing timer, and restored sessions would desync with contacts
    /// (after a restore, contacts' next messages start fresh sessions).
    pub fn export_backup(&self, path: &Path) -> Result<()> {
        let (key, full) = self.unlocked()?;
        let id = std::fs::read(super::identity_path()?)?;
        let mut st = full.clone();
        st.posts.retain(|p| p.mine && p.sent && p.draft.is_none());
        for p in st.posts.iter_mut() {
            p.raw = None;
            p.pending_chunks.clear();
        }
        st.discovered.clear();
        st.liked.clear();
        st.conversations.iter_mut().for_each(|c| c.messages.clear());
        if let Some(d) = st.dm.as_mut() {
            d.sessions.clear();
            d.owners.clear();
            d.cursors.clear();
        }
        for r in st.rooms.iter_mut() {
            r.messages.clear();
            r.inbound.clear();
            r.outbound = None;
            r.outbound_id = None;
            r.seen.clear();
            r.queue.clear();
            r.needs_hello = true;
        }
        st.mail_cursors.clear();
        st.mail_seen.clear();
        st.incoming_payments.clear();
        st.incoming_grants.clear();
        st.audits.clear();
        let store = super::seal_store(&key, &st)?;
        let mut out = BACKUP_MAGIC.to_vec();
        out.extend_from_slice(&(id.len() as u32).to_le_bytes());
        out.extend_from_slice(&id);
        out.extend_from_slice(&store);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Restore a backup onto a device with no account yet.
    pub fn import_backup(&self, path: &Path) -> Result<()> {
        if super::identity_path()?.exists() {
            bail!("An account already exists on this device.");
        }
        let b = std::fs::read(path)?;
        if b.len() < 12 || &b[..8] != BACKUP_MAGIC {
            bail!("That isn't a Sentinel backup.");
        }
        let n = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
        let id = b.get(12..12 + n).context("backup is damaged")?;
        let store = b.get(12 + n..).filter(|s| s.len() > 24).context("backup is damaged")?;
        std::fs::write(super::identity_path()?, id)?;
        std::fs::write(super::store_path()?, store)?;
        Ok(())
    }

    /// Delete everything this account keeps on this device. The WebView's
    /// own folder is in use while the app runs: it is deleted at the next
    /// start, before any window opens.
    pub fn panic_wipe(&self) -> Result<()> {
        // Stops the hosted Pillar process and drops Tor.
        self.lock();
        // The disguise stays (it vanishing would give the wipe away).
        let look = crate::disguise::take_raw();
        let role = super::role();
        let dirs: Vec<std::path::PathBuf> = [role.clone(), format!("{role}-host"), "pt".to_owned()]
            .iter()
            .filter_map(|r| sentinel_net::data_root(r).ok())
            .collect();
        // Windows won't delete files a program still has open. The Pillar
        // process exits within moments of being stopped, so retry briefly
        // (kept short: a long pause would make an emergency unlock slower
        // than a normal one). Files this app's own Tor connection still
        // holds (its directory cache) are deleted at the next start, before
        // anything opens them.
        for _ in 0..6 {
            for d in &dirs {
                let _ = std::fs::remove_dir_all(d);
            }
            // Done once only files held by this app's own Tor remain (they
            // won't free up in this session; waiting would only add delay).
            // The Pillar's folders (its onion-service keys) must be fully gone.
            let pending = dirs[1..].iter().any(|d| d.exists()) || dirs.iter().take(1).any(|d| {
                std::fs::read_dir(d).map(|rd| rd.flatten().any(|e| !matches!(e.file_name().to_str(), Some("tor-state" | "tor-cache" | "tor-state-bridges" | "tor-cache-bridges")))).unwrap_or(false)
            });
            if !pending {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        let mut left = Vec::new();
        for d in &dirs {
            collect_files(d, &mut left);
        }
        crate::oshardening::schedule_webview_wipe(&left);
        if let Some(b) = look {
            crate::disguise::put_raw(&b);
        }
        Ok(())
    }
}

/// Every file under `dir` (for files a wipe couldn't delete yet).
fn collect_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let path = e.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

pub(super) fn shape_prefix(shape: Shape) -> &'static str {
    match shape {
        Shape::Avatar => "avatar:",
        Shape::Banner => "banner:",
    }
}
