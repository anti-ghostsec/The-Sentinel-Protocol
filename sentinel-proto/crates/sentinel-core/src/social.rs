//! Social records (spec §7): posts, profiles, contact cards, follow links.
//!
//! Every record is **sealed** before it leaves the device (spec §12.4, see
//! `seal`): Pillars store only ciphertext. Followers read with the author's
//! feed key (carried in the follow link); discoverable posts are also
//! readable with topic/explore keys. Timestamps are coarsened to the minute.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::object::Envelope;
use crate::seal;

pub const KIND_POST: &str = "post";
pub const KIND_PROFILE: &str = "profile";
pub const KIND_CARD: &str = "card";
pub const KIND_ROOM_LISTING: &str = "room-listing";
/// Longest room description in a listing.
pub const MAX_ROOM_DESCRIPTION: usize = 300;

/// Maximum post length in characters.
pub const MAX_POST_CHARS: usize = 500;
/// Maximum display-name length in characters.
pub const MAX_NAME_CHARS: usize = 40;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PostBody {
    pub text: String,
    /// Unix time in whole minutes (coarsened).
    pub minute: u64,
    /// Structured discovery topics (spec §10.4.1), normalised, at most 3.
    #[serde(default)]
    pub topics: Vec<String>,
    /// Whether the author offered this post to the public discovery pool.
    #[serde(default)]
    pub discoverable: bool,
    /// Embedded media (images, GIFs, short video), encrypted and chunked.
    #[serde(default)]
    pub media: Vec<crate::media::MediaRef>,
}

/// Maximum topics per post.
pub const MAX_TOPICS: usize = 3;
/// Author buckets (spec §10.1): every stored object is also filed under one
/// of 256 buckets derived from its author. Readers download whole buckets
/// (at a depth they choose), so a Pillar never learns which accounts they
/// follow — only that someone fetched a bucket shared by many authors.
pub fn author_bucket(author: &[u8; 32]) -> u8 {
    blake3::derive_key("sentinel/v1/author-bucket", author)[0]
}

/// Does `bucket` fall under the top-`bits` prefix `prefix`? (bits 0..=8;
/// 0 = every bucket.)
pub fn bucket_in_prefix(bucket: u8, bits: u8, prefix: u8) -> bool {
    bits == 0 || (bits <= 8 && (bucket as u16 >> (8 - bits as u16)) as u8 == prefix)
}

/// The prefix of `bucket` at depth `bits`.
pub fn bucket_prefix(bucket: u8, bits: u8) -> u8 {
    if bits == 0 { 0 } else { (bucket as u16 >> (8 - bits.min(8) as u16)) as u8 }
}

/// Number of discovery shards (spec §10.4.2). Shard `DISCOVERY_SHARDS`
/// (one past the topic shards) is the "recent" exploration shard.
pub const DISCOVERY_SHARDS: u16 = 64;
pub const RECENT_SHARD: u16 = DISCOVERY_SHARDS;

/// Normalise a topic to `seg/seg/seg` with `[a-z0-9-]` segments.
pub fn normalize_topic(raw: &str) -> Option<String> {
    let s = raw.trim().trim_start_matches('#').to_lowercase();
    let segs: Vec<String> = s
        .split('/')
        .map(|seg| {
            seg.trim()
                .chars()
                .map(|c| if c.is_whitespace() || c == '_' { '-' } else { c })
                .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                .collect::<String>()
                .trim_matches('-')
                .to_owned()
        })
        .collect();
    if segs.is_empty() || segs.len() > 3 || segs.iter().any(|g| g.is_empty() || g.len() > 32) {
        return None;
    }
    Some(segs.join("/"))
}

/// Discovery shard for a topic. Filed by the **top-level** segment, so
/// readers of `ai` and of `ai/llm` fetch the same bucket; many topics share
/// a shard (k-anonymity).
pub fn topic_shard(topic: &str) -> u16 {
    let top = topic.split('/').next().unwrap_or(topic);
    let h = blake3::derive_key("sentinel/v0/topic-shard", top.as_bytes());
    u16::from_le_bytes([h[0], h[1]]) % DISCOVERY_SHARDS
}

/// `ai/llm/local` → [`ai`, `ai/llm`, `ai/llm/local`].
pub fn topic_prefixes(topic: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut acc = String::new();
    for seg in topic.split('/') {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        out.push(acc.clone());
    }
    out
}

/// Key a reader subscribed to `topic` uses. Authors seal discoverable posts
/// under every prefix of each topic, so this also opens child-topic posts.
pub fn reader_key_for_subscription(topic: &str) -> [u8; 32] {
    seal::topic_key(topic)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct ProfileBody {
    pub name: String,
    /// Unix time in whole minutes; the newest profile wins.
    pub minute: u64,
    /// Short description (plain text).
    #[serde(default)]
    pub bio: String,
    /// Profile picture (square, re-encoded, encrypted like any media).
    #[serde(default)]
    pub avatar: Option<crate::media::MediaRef>,
    /// Header image (3:1, re-encoded, encrypted).
    #[serde(default)]
    pub banner: Option<crate::media::MediaRef>,
    /// My recovery key pin: followers keep the first one they see, and only
    /// that key can move my account to a new identity.
    #[serde(default)]
    pub recovery: Option<crate::recovery::RecoveryPin>,
    /// My ML-DSA-65 key: followers pin it and then accept only my objects
    /// that carry a valid post-quantum signature.
    #[serde(default, with = "opt_bytes")]
    pub pq_key: Option<Vec<u8>>,
}

/// `Option<Vec<u8>>` as a CBOR byte string (compact).
mod opt_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_bytes(b),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        match ciborium::value::Value::deserialize(d)? {
            ciborium::value::Value::Bytes(b) => Ok(Some(b)),
            _ => Ok(None),
        }
    }
}

/// Maximum bio length in characters.
pub const MAX_BIO_CHARS: usize = 300;

/// What someone needs to send me encrypted messages (spec §6.3, §10.2).
/// Sealed under my feed key, so only people with my follow link get it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ContactCard {
    /// Olm (Double Ratchet) Curve25519 identity key.
    pub olm_identity: [u8; 32],
    /// Olm one-time prekeys.
    pub one_time_keys: Vec<[u8; 32]>,
    /// Olm fallback prekey (used when one-time keys run out).
    pub fallback_key: Option<[u8; 32]>,
    /// X25519 public key for sealed-sender inbox delivery.
    pub inbox_pub: [u8; 32],
    /// My upcoming rotating inbox IDs `(day, id)`. Each ID is the hash of a
    /// fetch token only I hold, so contacts can deposit but not list or
    /// count my inbox.
    pub inbox_ids: Vec<(u64, [u8; 32])>,
    /// Pillar that holds my inbox.
    pub pillar: String,
    pub minute: u64,
    /// ML-KEM-768 key for my inbox (this month's): sealed-sender delivery to
    /// me is post-quantum hybrid.
    #[serde(default)]
    pub inbox_kem: Option<Vec<u8>>,
}

/// Current Unix time coarsened to the minute.
pub fn coarse_minute() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0)
}

fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

/// Seal a post. Followers-only unless `discoverable`, in which case topic
/// and explore keys can also open it and it is filed in discovery shards.
pub fn post_envelope_with(
    key: &SigningKey,
    feed_key: &[u8; 32],
    text: &str,
    topics: &[String],
    discoverable: bool,
) -> Result<Envelope, &'static str> {
    post_envelope_full(key, feed_key, text, topics, discoverable, Vec::new())
}

pub fn post_envelope_full(
    key: &SigningKey,
    feed_key: &[u8; 32],
    text: &str,
    topics: &[String],
    discoverable: bool,
    media: Vec<crate::media::MediaRef>,
) -> Result<Envelope, &'static str> {
    let text = text.trim();
    if media.len() > 4 {
        return Err("at most 4 media per post");
    }
    if text.is_empty() && media.is_empty() {
        return Err("post is empty");
    }
    if text.chars().count() > MAX_POST_CHARS {
        return Err("post is too long");
    }
    let mut norm: Vec<String> = Vec::new();
    for t in topics {
        let t = normalize_topic(t).ok_or("invalid topic")?;
        if !norm.contains(&t) {
            norm.push(t);
        }
    }
    if norm.len() > MAX_TOPICS {
        return Err("at most 3 topics");
    }
    let body = PostBody { text: text.to_owned(), minute: coarse_minute(), topics: norm.clone(), discoverable, media };
    let mut readers = vec![*feed_key];
    let mut shards = Vec::new();
    if discoverable {
        let mut topic_keys: Vec<[u8; 32]> = Vec::new();
        for t in &norm {
            for p in topic_prefixes(t) {
                let k = seal::topic_key(&p);
                if !topic_keys.contains(&k) {
                    topic_keys.push(k);
                }
            }
            let s = topic_shard(t);
            if !shards.contains(&s) {
                shards.push(s);
            }
        }
        if topic_keys.len() > seal::SLOTS - 2 {
            return Err("topics too deep (use fewer or shorter topics)");
        }
        readers.extend(topic_keys);
        readers.push(seal::explore_key());
        shards.push(RECENT_SHARD);
    }
    seal::seal(key, KIND_POST, encode(&body), &readers, shards)
}

pub fn post_envelope(key: &SigningKey, feed_key: &[u8; 32], text: &str) -> Result<Envelope, &'static str> {
    post_envelope_with(key, feed_key, text, &[], false)
}

pub fn profile_envelope(key: &SigningKey, feed_key: &[u8; 32], name: &str) -> Result<Envelope, &'static str> {
    profile_envelope_full(key, feed_key, ProfileBody { name: name.to_owned(), ..Default::default() })
}

/// Seal a full profile (name, bio, pictures) for people with my link.
pub fn profile_envelope_full(key: &SigningKey, feed_key: &[u8; 32], mut body: ProfileBody) -> Result<Envelope, &'static str> {
    body.name = body.name.trim().to_owned();
    body.bio = body.bio.trim().to_owned();
    if body.name.is_empty() || body.name.chars().count() > MAX_NAME_CHARS {
        return Err("name must be 1–40 characters");
    }
    if body.bio.chars().count() > MAX_BIO_CHARS {
        return Err("bio must be at most 300 characters");
    }
    for m in body.avatar.iter().chain(body.banner.iter()) {
        if m.kind != "image" || !m.inline() {
            return Err("profile pictures must be images");
        }
    }
    body.minute = coarse_minute();
    seal::seal(key, KIND_PROFILE, encode(&body), &[*feed_key], vec![])
}

pub fn card_envelope(key: &SigningKey, feed_key: &[u8; 32], card: &ContactCard) -> Result<Envelope, &'static str> {
    seal::seal(key, KIND_CARD, encode(card), &[*feed_key], vec![])
}

/// A public room's entry in Discover (spec §10.4, §6.2.7). Signed with the
/// room's **admin key**, not anyone's account, so listing a room doesn't
/// publicly tie it to its creator (a paid room's buy link does carry the
/// creator's follow link: payment needs it).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomListing {
    pub name: String,
    pub description: String,
    pub topics: Vec<String>,
    /// free | pass | membership
    pub access: String,
    pub price: u32,
    /// How to get in: an invite link (free rooms) or a buy link (paid).
    pub link: String,
    pub minute: u64,
}

/// Seal a room listing for Discover (topic and explore keys, filed in the
/// topic shards and the recent shard, exactly like a discoverable post).
pub fn room_listing_envelope(admin: &SigningKey, listing: &RoomListing) -> Result<Envelope, &'static str> {
    if listing.name.trim().is_empty() || listing.name.chars().count() > 60 {
        return Err("room name must be 1-60 characters");
    }
    if listing.description.chars().count() > MAX_ROOM_DESCRIPTION {
        return Err("description is too long");
    }
    let mut norm: Vec<String> = Vec::new();
    for t in &listing.topics {
        let t = normalize_topic(t).ok_or("invalid topic")?;
        if !norm.contains(&t) {
            norm.push(t);
        }
    }
    if norm.is_empty() || norm.len() > MAX_TOPICS {
        return Err("give 1-3 topics");
    }
    let body = RoomListing { topics: norm.clone(), minute: coarse_minute(), ..listing.clone() };
    let mut readers: Vec<[u8; 32]> = Vec::new();
    let mut shards = Vec::new();
    for t in &norm {
        for p in topic_prefixes(t) {
            let k = seal::topic_key(&p);
            if !readers.contains(&k) {
                readers.push(k);
            }
        }
        let sh = topic_shard(t);
        if !shards.contains(&sh) {
            shards.push(sh);
        }
    }
    if readers.len() > seal::SLOTS - 1 {
        return Err("topics too deep (use fewer or shorter topics)");
    }
    readers.push(seal::explore_key());
    shards.push(RECENT_SHARD);
    seal::seal(admin, KIND_ROOM_LISTING, encode(&body), &readers, shards)
}

/// A sealed record opened with one of `keys`.
pub enum Record {
    Post(PostBody),
    Profile(ProfileBody),
    Card(ContactCard),
    RoomListing(RoomListing),
}

pub fn open_record(env: &Envelope, keys: &[[u8; 32]]) -> Option<Record> {
    open_record_pinned(env, keys, None)
}

/// Open a record; with `pinned` (the author's ML-DSA key), only if its
/// post-quantum signature is valid.
pub fn open_record_pinned(env: &Envelope, keys: &[[u8; 32]], pinned: Option<&[u8]>) -> Option<Record> {
    let (kind, body) = seal::open_pinned(env, keys, pinned)?;
    match kind.as_str() {
        KIND_POST => ciborium::from_reader(body.as_slice()).ok().map(Record::Post),
        KIND_PROFILE => ciborium::from_reader(body.as_slice()).ok().map(Record::Profile),
        KIND_CARD => ciborium::from_reader(body.as_slice()).ok().map(Record::Card),
        KIND_ROOM_LISTING => ciborium::from_reader(body.as_slice()).ok().map(Record::RoomListing),
        _ => None,
    }
}

/// Normalise and check a v3 onion address (`<56 base32>.onion`).
pub fn valid_onion(s: &str) -> Option<String> {
    let a = s.trim().to_ascii_lowercase();
    let host = a.strip_suffix(".onion")?;
    (host.len() == 56 && host.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))).then_some(a)
}

/// Text form of an author key (lower-case base32).
pub fn author_text(author: &[u8; 32]) -> String {
    data_encoding::BASE32_NOPAD.encode(author).to_lowercase()
}

pub fn author_from_text(s: &str) -> Option<[u8; 32]> {
    let v = data_encoding::BASE32_NOPAD.decode(s.trim().to_uppercase().as_bytes()).ok()?;
    v.try_into().ok()
}

/// A follow link: who, which Pillar holds their posts, and the feed key
/// that decrypts them. `sentinel://follow/<author>@<pillar-host>#<feed-key>`.
/// No IP addresses (I1). Links without a key (discovered authors) can read
/// only discoverable posts until the author's key is learned.
#[derive(Clone, Debug, PartialEq)]
pub struct FollowLink {
    pub author: [u8; 32],
    pub pillar: String,
    pub feed_key: Option<[u8; 32]>,
}

impl FollowLink {
    pub fn to_text(&self) -> String {
        let host = self.pillar.trim_end_matches(".onion");
        let mut s = format!("sentinel://follow/{}@{}", author_text(&self.author), host);
        if let Some(k) = &self.feed_key {
            s.push('#');
            s.push_str(&data_encoding::BASE32_NOPAD.encode(k).to_lowercase());
        }
        s
    }

    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.trim().strip_prefix("sentinel://follow/")?;
        let (rest, key) = match rest.split_once('#') {
            Some((r, k)) => (r, Some(k)),
            None => (rest, None),
        };
        let (a, p) = rest.split_once('@')?;
        let author = author_from_text(a)?;
        let pillar = format!("{}.onion", p.trim_end_matches(".onion").to_ascii_lowercase());
        let host = pillar.strip_suffix(".onion")?;
        if host.len() != 56 || !host.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)) {
            return None;
        }
        let feed_key = match key {
            Some(k) => {
                let v = data_encoding::BASE32_NOPAD.decode(k.trim().to_uppercase().as_bytes()).ok()?;
                Some(v.try_into().ok()?)
            }
            None => None,
        };
        Some(FollowLink { author, pillar, feed_key })
    }
}

/// Domain for follow-notice proof-of-work stamps.
pub const FOLLOW_POW_DOMAIN: &str = "sentinel/v0/follow-notice-pow";

/// Anonymous follow token (spec §10.4.7): stable for one (follower, author)
/// pair so notices dedupe and can be withdrawn, but unlinkable across
/// authors and to the follower's identity.
pub fn follow_token(follower: &SigningKey, author: &[u8; 32]) -> [u8; 32] {
    let k = blake3::derive_key("sentinel/v0/follow-token", &follower.to_bytes());
    *blake3::keyed_hash(&k, author).as_bytes()
}

/// Bytes covered by a follow notice's proof-of-work.
pub fn follow_pow_data(author: &[u8; 32], token: &[u8; 32], follow: bool) -> Vec<u8> {
    let mut d = Vec::with_capacity(65);
    d.extend_from_slice(author);
    d.extend_from_slice(token);
    d.push(follow as u8);
    d
}

/// Domain and difficulty for Pillar announcement proof-of-work.
pub const ANNOUNCE_POW_DOMAIN: &str = "sentinel/v0/pillar-announce-pow";
pub const ANNOUNCE_POW_BITS: u32 = 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_listings_open_with_topic_keys_and_need_topics() {
        let admin = crate::identity::generate();
        let l = RoomListing { name: "Night Owls".into(), description: "late talk".into(), topics: vec!["Night/Talk".into()], access: "free".into(), price: 0, link: "x".into(), minute: 0 };
        let env = room_listing_envelope(&admin, &l).unwrap();
        // Anyone browsing the topic (or exploring) can open it.
        let Some(Record::RoomListing(got)) = open_record(&env, &[seal::topic_key("night")]) else { panic!() };
        assert_eq!(got.topics, vec!["night/talk".to_string()]);
        assert!(open_record(&env, &[seal::explore_key()]).is_some());
        // Signed by the room's own key, not an account.
        assert_eq!(env.author, admin.verifying_key().to_bytes());
        // No topics: refused (a listing must be findable by topic).
        assert!(room_listing_envelope(&admin, &RoomListing { topics: vec![], ..l }).is_err());
    }

    #[test]
    fn author_bucket_prefixes() {
        let b = 0b1011_0110u8;
        assert!(bucket_in_prefix(b, 0, 0));
        assert!(bucket_in_prefix(b, 1, 1) && !bucket_in_prefix(b, 1, 0));
        assert!(bucket_in_prefix(b, 4, 0b1011) && !bucket_in_prefix(b, 4, 0b1010));
        assert!(bucket_in_prefix(b, 8, b));
        assert_eq!(bucket_prefix(b, 3), 0b101);
        assert_eq!(bucket_prefix(b, 0), 0);
        assert!(!bucket_in_prefix(b, 9, 0), "depth beyond 8 is refused");
    }

    #[test]
    fn sealed_post_roundtrip_and_limits() {
        let k = crate::identity::generate();
        let feed = crate::random_bytes::<32>();
        let env = post_envelope(&k, &feed, "  hello  ").unwrap();
        let back = Envelope::decode_verified(&env.encode().unwrap()).unwrap();
        match open_record(&back, &[feed]) {
            Some(Record::Post(p)) => assert_eq!(p.text, "hello"),
            _ => panic!("expected post"),
        }
        assert!(open_record(&back, &[crate::random_bytes::<32>()]).is_none());
        assert!(post_envelope(&k, &feed, "   ").is_err());
        assert!(post_envelope(&k, &feed, &"x".repeat(501)).is_err());
    }

    #[test]
    fn discoverable_post_opens_with_topic_but_shards_hide_topics() {
        let k = crate::identity::generate();
        let feed = crate::random_bytes::<32>();
        let env = post_envelope_with(&k, &feed, "robots!", &["#Robotics".into(), "robotics".into()], true).unwrap();
        let sealed = seal::sealed_body(&env).unwrap();
        assert!(sealed.shards.contains(&topic_shard("robotics")) && sealed.shards.contains(&RECENT_SHARD));
        match open_record(&env, &[reader_key_for_subscription("robotics")]) {
            Some(Record::Post(p)) => assert_eq!(p.topics, vec!["robotics".to_owned()]),
            _ => panic!("topic readers should open it"),
        }
        assert!(post_envelope_with(&k, &feed, "x", &["a".into(), "b".into(), "c".into(), "d".into()], true).is_err());
        // A followers-only post has no shards and no topic slots.
        let private = post_envelope_with(&k, &feed, "private", &["robotics".into()], false).unwrap();
        assert!(seal::sealed_body(&private).unwrap().shards.is_empty());
        assert!(open_record(&private, &[seal::topic_key("robotics"), seal::explore_key()]).is_none());
    }

    #[test]
    fn parent_topic_reads_child() {
        let k = crate::identity::generate();
        let feed = crate::random_bytes::<32>();
        let env = post_envelope_with(&k, &feed, "llm news", &["ai/llm".into()], true).unwrap();
        // Authors seal under every prefix, so a reader of "ai" opens "ai/llm".
        assert!(open_record(&env, &[reader_key_for_subscription("ai")]).is_some());
        assert!(open_record(&env, &[reader_key_for_subscription("ai/llm")]).is_some());
        assert!(open_record(&env, &[reader_key_for_subscription("ai/vision")]).is_none());
        assert_eq!(topic_shard("ai"), topic_shard("ai/llm"));
    }

    #[test]
    fn follow_link_roundtrip_with_and_without_key() {
        let with = FollowLink { author: [7; 32], pillar: format!("{}.onion", "a".repeat(56)), feed_key: Some([9; 32]) };
        assert_eq!(FollowLink::parse(&with.to_text()), Some(with.clone()));
        let without = FollowLink { feed_key: None, ..with };
        assert_eq!(FollowLink::parse(&without.to_text()), Some(without));
        assert!(FollowLink::parse("sentinel://follow/xyz@example.com").is_none());
        assert!(FollowLink::parse("https://evil.example/follow").is_none());
    }

    #[test]
    fn topics_normalise_and_shards_stable() {
        assert_eq!(normalize_topic("#Robotics").as_deref(), Some("robotics"));
        assert_eq!(normalize_topic("Technology / Robotics").as_deref(), Some("technology/robotics"));
        assert_eq!(normalize_topic("indie games").as_deref(), Some("indie-games"));
        assert!(normalize_topic("a/b/c/d").is_none());
        assert!(normalize_topic("###").is_none());
        assert_eq!(topic_shard("ai/llm"), topic_shard("ai/llm"));
        assert!(topic_shard("drones") < DISCOVERY_SHARDS);
    }

    #[test]
    fn follow_tokens_unlinkable_across_authors() {
        let k = crate::identity::generate();
        assert_eq!(follow_token(&k, &[1; 32]), follow_token(&k, &[1; 32]));
        assert_ne!(follow_token(&k, &[1; 32]), follow_token(&k, &[2; 32]));
        assert_ne!(follow_token(&k, &[1; 32]), follow_token(&crate::identity::generate(), &[1; 32]));
    }
}
