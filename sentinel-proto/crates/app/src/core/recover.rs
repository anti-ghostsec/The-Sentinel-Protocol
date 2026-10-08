//! Recovery words and moving to a new key (spec section 6).
//!
//! - New accounts are made from recovery words: identity generation 0, its
//!   feed key and a recovery key. The words stay in the encrypted store only
//!   until the person confirms writing them down.
//! - **Recover on a new device:** typing the words rebuilds the account
//!   (same identity, same feed key), then catches up with any moves made
//!   since by looking for successions signed by its own recovery key.
//! - **Move to a new key** (device taken, or a key that may be known): the
//!   recovery key signs a succession to the next generation; followers
//!   switch. The key file's key stays the storage root, so nothing on the
//!   device needs re-encrypting.

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use sentinel_core::object::Envelope;
use sentinel_core::recovery::{self, RecoverySecret};
use sentinel_core::social;
use sentinel_core::wire::{Request, Response};
use serde::Serialize;

use super::{request, Core, Keys};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryView {
    /// The account has recovery words.
    pub set: bool,
    /// They're still on this device, waiting to be written down.
    pub pending: bool,
    /// How many times the account has moved to a new key.
    pub generation: u32,
}

impl Core {
    pub fn recovery_status(&self) -> Result<RecoveryView> {
        let (_, store) = self.unlocked()?;
        Ok(RecoveryView { set: store.recovery_pin.is_some(), pending: store.recovery_pending.is_some(), generation: store.recovery_gen.unwrap_or(0) })
    }

    /// The words, while they're still kept here.
    pub fn recovery_words(&self) -> Result<Vec<String>> {
        let (_, store) = self.unlocked()?;
        let secret = store.recovery_pending.context("Your recovery words were removed from this device after you wrote them down.")?;
        Ok(RecoverySecret::from_bytes(secret).words())
    }

    /// "I've written them down": remove them from this device.
    pub fn recovery_confirm(&self) -> Result<()> {
        self.update(|s| s.recovery_pending = None)
    }

    /// Older accounts: make recovery words (the account's key stays; its
    /// first move goes to a key made from the words).
    pub fn recovery_create(&self) -> Result<()> {
        let (_, store) = self.unlocked()?;
        if store.recovery_pin.is_some() {
            bail!("This account already has recovery words.");
        }
        let r = RecoverySecret::generate();
        self.update(|s| {
            s.recovery_pin = Some(r.pin());
            s.recovery_pending = Some(*r.bytes());
            s.profile_published = false; // followers learn the pin
        })
    }

    /// Move this account to a new key, signed with the recovery words.
    /// `taken`: the old device is in someone else's hands, so the feed key
    /// isn't passed on (they could read it): private posts then need the
    /// new follow link.
    pub async fn move_account(&self, words: &str, taken: bool) -> Result<()> {
        let r = RecoverySecret::from_words(words).context("Those words aren't right (check the spelling and order).")?;
        let (key, store) = self.unlocked()?;
        if store.recovery_pin != Some(r.pin()) {
            bail!("Those are not this account's recovery words.");
        }
        let gen = store.recovery_gen.map(|g| g + 1).unwrap_or(1);
        let old = key.verifying_key().to_bytes();
        let old_feed = store.feed_key.context("no feed key")?;
        let bytes = recovery::succession_from(&r, old, &old_feed, !taken, gen).context("couldn't sign the move")?;
        self.publish_everywhere(&bytes).await?;
        let new_id = r.identity(gen);
        self.switch_identity(&new_id, r.feed_key(gen), gen)
    }

    /// Put an object on my Pillar, my backups and the seed Pillars (a move
    /// must be findable even by someone recovering from scratch).
    async fn publish_everywhere(&self, bytes: &[u8]) -> Result<()> {
        let net = self.with(|i| i.net.clone()).context("Connect first.")?;
        let (_, store) = self.unlocked()?;
        let mut targets: Vec<String> = store.pillar.iter().chain(store.replicas.iter()).cloned().collect();
        for s in sentinel_net::seed_pillars() {
            if !targets.contains(&s) {
                targets.push(s);
            }
        }
        let mut stored = 0;
        for t in targets {
            if let Ok(mut s) = net.connect_hedged(&t).await {
                if let Ok(Response::Stored(_)) = request(&mut s, &Request::Put(bytes.to_vec())).await {
                    stored += 1;
                }
            }
        }
        if stored == 0 {
            bail!("No Pillar took the move. Nothing changed; try again when connected.");
        }
        Ok(())
    }

    /// Use a new identity from now on (the storage root stays).
    fn switch_identity(&self, new_id: &SigningKey, feed_key: [u8; 32], gen: u32) -> Result<()> {
        let seed = new_id.to_bytes();
        self.update(|s| {
            s.identity = Some(seed);
            s.feed_key = Some(feed_key);
            s.recovery_gen = Some(gen);
            s.profile_published = false;
            if let Some(d) = s.dm.as_mut() {
                d.card_minute = 0; // republish my contact card under the new key
                d.card_pillar = None;
            }
            for r in s.rooms.iter_mut() {
                r.needs_hello = true; // introduce the new identity in rooms
            }
        })?;
        self.with(|i| {
            if let Some(k) = i.key.as_mut() {
                k.id = SigningKey::from_bytes(&seed);
            }
        });
        Ok(())
    }

    /// New device: rebuild the account from its recovery words.
    pub fn recover_account(&self, words: &str, name: &str, pass: &str, mode: &str) -> Result<()> {
        let r = RecoverySecret::from_words(words).context("Those words aren't right (check the spelling and order).")?;
        self.create_from(r, name, pass, mode, true)
    }

    /// Recovered: find moves made since generation 0 (signed by my own
    /// recovery key) and catch up to the latest key.
    pub async fn catch_up_generation(&self) -> Result<()> {
        let (_, store) = self.unlocked()?;
        if !store.recovery_catch_up {
            return Ok(());
        }
        let (Some(secret), Some(pin)) = (store.recovery_pending, store.recovery_pin) else { return Ok(()) };
        let r = RecoverySecret::from_bytes(secret);
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let mut sources: Vec<String> = store.pillar.iter().cloned().collect();
        for s in sentinel_net::seed_pillars() {
            if !sources.contains(&s) {
                sources.push(s);
            }
        }
        let mut best = store.recovery_gen.unwrap_or(0);
        let mut reached = false;
        for p in sources {
            let Ok(mut s) = net.connect_hedged(&p).await else { continue };
            reached = true;
            let bits = store.author_depth.get(&p).copied().unwrap_or(0).min(8);
            let prefix = social::bucket_prefix(social::author_bucket(&pin.ed), bits);
            let mut after = 0;
            for _ in 0..64 {
                let list = match request(&mut s, &Request::AuthorBucket { bits, prefix, after }).await {
                    Ok(Response::Blobs(l)) if !l.is_empty() => l,
                    _ => break,
                };
                for (seq, bytes) in list {
                    after = after.max(seq);
                    let Ok(env) = Envelope::decode_verified(&bytes) else { continue };
                    // Sealed with the feed key of the generation before it.
                    if let Some(m) = (0..64u32).find_map(|g| recovery::verify(&env, &pin, &r.feed_key(g))) {
                        if m.gen > best && m.new == r.identity(m.gen).verifying_key().to_bytes() {
                            best = m.gen;
                        }
                    }
                }
            }
        }
        if !reached {
            return Ok(()); // try again next time
        }
        if best > store.recovery_gen.unwrap_or(0) {
            self.switch_identity(&r.identity(best), r.feed_key(best), best)?;
        }
        // They typed the words to get here: nothing to write down, and the
        // words don't stay on this device.
        self.update(|s| {
            s.recovery_catch_up = false;
            s.recovery_pending = None;
        })
    }
}

impl Core {
    /// Make an account from recovery words (new or recovered).
    pub(super) fn create_from(&self, r: RecoverySecret, name: &str, pass: &str, mode: &str, recovered: bool) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > social::MAX_NAME_CHARS {
            bail!("Name must be 1–40 characters.");
        }
        if pass.chars().count() < 12 {
            bail!("Passphrase must be at least 12 characters.");
        }
        if !matches!(mode, "tor" | "bridges") {
            bail!("unknown connection mode");
        }
        let id_path = super::identity_path()?;
        if id_path.exists() {
            bail!("An account already exists on this device.");
        }
        let root = r.identity(0);
        // A key file chosen on the new-account screen.
        let keyfile = self.with(|i| i.chosen_keyfile.take()).map(|(d, _)| d);
        std::fs::write(&id_path, sentinel_core::identity::seal(&root, pass.as_bytes(), keyfile.as_deref())?)?;
        self.with(|i| i.keyfile = keyfile);
        let mut store = super::Store {
            name: name.to_owned(),
            mode: mode.to_owned(),
            bridges_set: "snowflake".into(),
            feed_key: Some(r.feed_key(0)),
            recovery_pin: Some(r.pin()),
            recovery_gen: Some(0),
            // New accounts: kept until written down. Recovered ones: kept
            // until the catch-up with later moves is done (then removed).
            recovery_pending: Some(*r.bytes()),
            recovery_catch_up: recovered,
            ..Default::default()
        };
        let key = Keys::new(root, &store);
        super::ensure_keys(&key, &mut store);
        super::save_store(&key, &store)?;
        let local = super::local::LocalChunks::open(&key)?;
        self.with(|i| {
            i.key = Some(key);
            i.store = Some(store);
            i.local = Some(local);
        });
        Ok(())
    }
}
