//! Request/response messages between client and Pillar.
//!
//! Deliberately contains no client identifiers, timestamps, versions or
//! capabilities beyond what each request needs (spec I7, I14).

use serde::{Deserialize, Serialize};

use crate::object::Address;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Liveness/latency probe. Payload is padding chosen by the client.
    Ping,
    /// Store an encoded, signed envelope.
    Put(#[serde(with = "bytes")] Vec<u8>),
    /// Fetch an object by content address.
    Get(Address),
    /// List an author's objects in arrival order, starting after position
    /// `after`. Returns at most `MAX_LIST` entries.
    List { author: [u8; 32], after: u64 },
    /// List a discovery shard (spec §10.4.2) after position `after`.
    Shard { shard: u16, after: u64 },
    /// Anonymous follow (or unfollow) notice with a proof-of-work stamp.
    FollowNotice { author: [u8; 32], token: [u8; 32], follow: bool, nonce: u64 },
    /// Approximate follower count for an author.
    FollowerCount { author: [u8; 32] },
    /// Ask a Pillar for other Pillars it knows (directory gossip).
    Pillars,
    /// Announce a Pillar's onion address, with a proof-of-work stamp.
    /// The receiver verifies it is reachable before listing it.
    /// `archive_gb` > 0 also offers that much media storage (Archive role).
    Announce {
        onion: String,
        nonce: u64,
        #[serde(default)]
        archive_gb: u32,
    },
    /// Ask for known Archives (nodes storing media chunks).
    Archives,
    /// Deposit a sealed blob into a mailbox shard (see `dm` shards).
    Deposit {
        shard: u16,
        #[serde(with = "bytes")]
        blob: Vec<u8>,
        nonce: u64,
    },
    /// Fetch deposits whose shard starts with `prefix` (`bits` long; 0 =
    /// all), newer than sequence number `after`.
    Fetch { bits: u8, prefix: u16, after: u64 },
    /// The prefix length this node recommends (answered with `Count`).
    MailboxDepth,
    /// Store an encrypted media chunk (content-addressed), with a small
    /// proof-of-work over its hash.
    PutChunk {
        #[serde(with = "bytes")]
        data: Vec<u8>,
        nonce: u64,
    },
    /// Fetch an encrypted media chunk by address. Fetching also keeps the
    /// chunk alive (Archives expire chunks nobody has fetched for a while).
    GetChunk([u8; 32]),
    /// Cover traffic: ignored by the node, answered with `reply` bytes
    /// (capped), so dummy exchanges look like real ones on the wire.
    Noise {
        #[serde(with = "bytes")]
        pad: Vec<u8>,
        reply: u32,
    },
    /// Proof of storage: `keyed_hash(nonce, chunk)` — only a node that
    /// really holds the chunk's bytes can answer (spec §14.8).
    Prove { addr: [u8; 32], nonce: [u8; 32] },
    /* ---- credits (spec §21.1) ---- */
    /// The mint's long-term public key (answered with `MintKey`); epoch
    /// keys are derived from it (see `credits::epoch_key`).
    MintKey,
    /// Free credits for proof-of-work (the Free class).
    MintFaucet { blinded: Vec<Vec<u8>>, nonce: u64 },
    /// Spend tokens and get the same number of fresh blinded tokens back
    /// (how a payee takes ownership of a payment).
    MintSwap { tokens: Vec<crate::credits::Token>, blinded: Vec<Vec<u8>> },
    /// Keep chunks beyond the free expiry, paid in credits.
    Pin { addrs: Vec<[u8; 32]>, months: u32, bundles: Vec<crate::credits::Bundle> },
    /// Mint -> Archive: rewards are ready; send this many blinded requests.
    /// `mint` names the mint (checked against its published key).
    RewardOffer { count: u32, mint: String },
    /// Mint -> Archive: the evaluated rewards.
    RewardIssue { evals: Vec<Vec<u8>>, proof: Vec<u8>, mint: String, epoch: u32 },
    /// Which of these chunk addresses the node holds (bitmap, for resuming
    /// uploads and repair). At most `MAX_HAVE` addresses.
    HaveChunks(Vec<[u8; 32]>),
    /// A mint's public supply figures (answered with `MintStats`).
    MintStats,
    /// Every object (sealed, inline) filed under the author buckets in the
    /// top-`bits` prefix `prefix`, newer than `after` (answered with
    /// `Blobs`: (sequence, object bytes), oldest first).
    AuthorBucket { bits: u8, prefix: u8, after: u64 },
    /// The signed update bundle this Pillar carries for `product` (`app` or
    /// `pillar`): answered with `Update` (its header) or `NotFound`.
    UpdateInfo { product: String },
    /// Up to `UPDATE_CHUNK` bytes of that bundle from `offset` (`Object`).
    UpdateChunk { product: String, offset: u64 },
    /// Signed revocations of releases this Pillar knows (`Object`: CBOR list).
    UpdateRevocations,
    /// This Pillar's mix key (`Object`: CBOR `mix::MixKey`).
    MixKey,
    /// A mixed message: this Pillar opens its layer, waits, then passes it
    /// on or deposits it (answered with `Pong` at once).
    Mix { packet: Vec<u8>, nonce: u64 },
    /* ---- quantum-safe credits (`pqcash`) ---- */
    /// The mint's checkpoint-signing key (`Object`: CBOR `pq::HybridPublic`).
    PqMintKey,
    /// Spend notes of key period `epoch` (proofs bound to `commitments`)
    /// for the same number of fresh notes in the current list.
    PqSwap {
        epoch: u32,
        #[serde(with = "bytes_list")]
        proofs: Vec<Vec<u8>>,
        commitments: Vec<[u8; 32]>,
    },
    /// Trade old blind tokens (this mint's) for fresh notes.
    PqUpgrade { tokens: Vec<crate::credits::Token>, commitments: Vec<[u8; 32]> },
    /// Commitments of a key period's list from position `from`
    /// (answered with `PqLeaves`).
    PqLeaves { epoch: u32, from: u64 },
    /// The latest signed checkpoint of a key period's list (`Object`:
    /// CBOR `pqcash::SignedCheckpoint`).
    PqCheckpoint { epoch: u32 },
    /// Mint -> Archive: rewards are ready; send this many commitments.
    RewardOfferPq { count: u32, mint: String },
    /// Mint -> Archive: they're in the list from position `first`.
    RewardAppended { mint: String, epoch: u32, first: u64 },
}

/// Bytes per `UpdateChunk` answer.
pub const UPDATE_CHUNK: usize = 1 << 20;

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Stored(Address),
    Object(#[serde(with = "bytes")] Vec<u8>),
    NotFound,
    Rejected(String),
    /// `(position, address)` pairs for a `List` request.
    Index(Vec<(u64, Address)>),
    /// A count (followers).
    Count(u64),
    /// Onion addresses of known Pillars.
    Pillars(Vec<String>),
    /// `(position, blob)` pairs from an inbox.
    Blobs(Vec<(u64, Vec<u8>)>),
    /// Answer to `Prove`.
    Proof([u8; 32]),
    MintKey(Vec<u8>),
    /// Blindly evaluated tokens and the DLEQ proof.
    Minted { evals: Vec<Vec<u8>>, proof: Vec<u8>, epoch: u32 },
    /// Blinded token requests (Archive -> mint, for rewards).
    Blinded(Vec<Vec<u8>>),
    /// One bit per requested address (bit i of byte i/8 = present).
    Have(#[serde(with = "bytes")] Vec<u8>),
    /// Per epoch: (epoch, tokens issued, tokens spent). Supply = issued - spent.
    MintStats(Vec<(u32, u64, u64)>),
    /// An update bundle's start (magic, length and signed header) and its
    /// total size.
    Update { prefix: Vec<u8>, size: u64 },
    /// Commitments joined the list of key period `epoch` from `first`.
    PqAppended { epoch: u32, first: u64 },
    /// Part of a list: its total size and the commitments asked for.
    PqLeaves { total: u64, leaves: Vec<[u8; 32]> },
    /// Commitments (Archive -> mint, for rewards).
    Commitments(Vec<[u8; 32]>),
}

/// Maximum entries returned by one `List` request.
pub const MAX_LIST: usize = 200;
/// Maximum addresses in one `HaveChunks` request.
pub const MAX_HAVE: usize = 4096;

pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

pub fn decode<T: for<'de> Deserialize<'de>>(b: &[u8]) -> Option<T> {
    ciborium::from_reader(b).ok()
}

mod bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        match ciborium::value::Value::deserialize(d)? {
            ciborium::value::Value::Bytes(b) => Ok(b),
            _ => Err(serde::de::Error::custom("expected bytes")),
        }
    }
}

/// A list of byte strings as CBOR byte strings (proofs are large: arrays
/// of numbers would nearly double them).
mod bytes_list {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for b in v {
            seq.serialize_element(&serde_bytes_compat(b))?;
        }
        seq.end()
    }
    struct B<'a>(&'a [u8]);
    impl serde::Serialize for B<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(self.0)
        }
    }
    fn serde_bytes_compat(b: &[u8]) -> B<'_> {
        B(b)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        match ciborium::value::Value::deserialize(d)? {
            ciborium::value::Value::Array(items) => items
                .into_iter()
                .map(|i| match i {
                    ciborium::value::Value::Bytes(b) => Ok(b),
                    _ => Err(serde::de::Error::custom("expected bytes")),
                })
                .collect(),
            _ => Err(serde::de::Error::custom("expected a list")),
        }
    }
}
