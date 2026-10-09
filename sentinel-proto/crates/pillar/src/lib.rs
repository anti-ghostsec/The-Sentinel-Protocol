//! Sentinel Pillar: an always-on storage node reachable only as a Tor v3
//! onion service (spec §3.1, §9.8). Embeddable: the `pillar` binary and the
//! desktop app ("Run a Pillar") both use `start`.
//!
//! Risk-limiting properties:
//! - Onion-only: no listening socket on any interface; the host's IP and
//!   location are hidden from everyone, including its users.
//! - No client IPs exist to log; no request logging at all.
//! - Stores only signed objects (public posts/profiles) and anonymous
//!   counters — never identities of readers or followers.
//! - Storage quota and automatic expiry bound what a host keeps.
//! - **Archive role** (optional): stores encrypted media chunks up to its own
//!   capacity; chunks nobody fetched for `chunk_retention_days` expire.
//! - File times are rounded down to the day, so a seized disk doesn't show
//!   when exactly anything arrived.
//! - Directory announcements need proof-of-work and a live reachability check.
//! - Only BEGIN requests to the Sentinel port are accepted; anything else
//!   tears down the circuit (uniform behaviour keeps the service bland).

mod directory;
mod economy;
mod relay;
mod reports;
mod pqmint;
mod earning;
pub use economy::take_rewards;
pub use reports::{keep as keep_reported, list as list_reports, remove as remove_reported, Report};
#[cfg(feature = "test-hooks")]
pub use economy::check_rewards;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use arti_client::TorClient;
use futures::StreamExt;
use safelog::DisplayRedacted;
use sentinel_core::cell::{read_message, write_message};
use sentinel_core::object::{Address, Envelope};
use sentinel_core::wire::{self, Request, Response};
use sentinel_core::{dm, media, pow, seal, social};
use sentinel_net::SENTINEL_PORT;
use tokio::io::AsyncWriteExt;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsNickname, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;

/// Requests allowed per stream before the Pillar closes it (DoS bound).
const MAX_REQUESTS_PER_STREAM: usize = 256;
/// Idle stream timeout. Must exceed the client pool's maximum stream age.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Streams one rendezvous circuit may open before it is torn down.
const MAX_STREAMS_PER_CIRCUIT: u32 = 8;
/// Most data in one inbox, room-box or author-bucket reply. These replies
/// encode each byte as a CBOR number (up to 2 bytes on the wire), so the
/// data is kept under half the 2 MiB message limit: a bigger reply can't be
/// sent at all, and the reader would get nothing, ever, from that bucket.
const FETCH_REPLY_BYTES: usize = 900 * 1024;
/// Directory size bound.
const MAX_KNOWN_PILLARS: usize = 500;
/// How many Pillars to return per directory request.
const PILLARS_PER_REPLY: usize = 50;

pub struct PillarConfig {
    /// Folder for objects and indexes (local, non-synced).
    pub store: PathBuf,
    /// Local nickname for the onion key (never published).
    pub nickname: String,
    /// Refuse new objects once stored data exceeds this.
    pub quota_bytes: u64,
    /// Delete stored objects older than this.
    pub retention_days: u64,
    /// Pillars to announce to and learn the directory from.
    pub seeds: Vec<String>,
    /// Media chunk capacity. A small value lets a plain Pillar hold inline
    /// media; `archive` advertises it as an Archive.
    pub chunk_quota_bytes: u64,
    /// Chunks not fetched for this long are deleted.
    pub chunk_retention_days: u64,
    /// Advertise this node as an Archive in the directory.
    pub archive: bool,
    /// Run the credits mint (one per network in this prototype).
    /// The network's mints (pin payments, rewards).
    pub mints: Vec<String>,
    /// Mint: base seconds between Archive check rounds (randomised x1-3).
    pub mint_interval: u64,
    /// Folder of signed update bundles to pass on (`app.bin`, `pillar.bin`).
    pub updates: Option<PathBuf>,
    /// Seconds before the first round of fetching updates from other
    /// Pillars (default: a random 5–35 minutes).
    pub spread_after: Option<u64>,
}

#[derive(Default)]
pub struct Stats {
    pub streams: AtomicU64,
    pub stored: AtomicU64,
    pub served: AtomicU64,
    pub rejected: AtomicU64,
    pub used_bytes: AtomicU64,
    pub chunk_bytes: AtomicU64,
}

struct Ctx {
    store: PathBuf,
    stats: Arc<Stats>,
    tor: Arc<TorClient<PreferredRuntime>>,
    quota_bytes: u64,
    chunk_quota_bytes: AtomicU64,
    archive_gb: std::sync::atomic::AtomicU32,
    /// Wakes the announce loop when the Archive setting changes.
    reannounce: tokio::sync::Notify,
    self_onion: String,
    /// Last mailbox sequence number handed out.
    mail_seq: AtomicU64,
    /// Sequence for objects filed in author buckets.
    obj_seq: AtomicU64,
    /// Deposits currently stored (for the recommended fetch depth).
    mail_count: AtomicU64,
    econ: economy::Econ,
    mint_interval: u64,
    updates: Option<PathBuf>,
    /// Mix key (secret kept in the data folder).
    mix: sentinel_core::mix::MixSecret,
    /// Mixed packets seen (replays are dropped) and how many are waiting.
    mix_seen: std::sync::Mutex<std::collections::VecDeque<[u8; 32]>>,
    /// Which listed Pillars answered lately (memory only; see `directory`).
    dir: Arc<directory::Directory>,
}

/// Most mixed packets held at once.
const MAX_MIX_WAITING: u64 = 20_000;

/// The mix secret, made once and kept beside the Pillar's data.
fn load_mix_secret(store: &Path) -> sentinel_core::mix::MixSecret {
    let path = store.join("mix.key");
    if let Ok(b) = std::fs::read(&path) {
        if let Ok(a) = <[u8; 32]>::try_from(b.as_slice()) {
            return sentinel_core::mix::MixSecret::from_bytes(a);
        }
    }
    let s = sentinel_core::mix::MixSecret::generate();
    let _ = std::fs::create_dir_all(store);
    let _ = std::fs::write(&path, s.bytes());
    s
}

/// A running Pillar. Dropping it stops the service and its tasks.
pub struct RunningPillar {
    pub onion: String,
    pub stats: Arc<Stats>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    ctx: Arc<Ctx>,
    _service: Arc<tor_hsservice::RunningOnionService>,
}

impl RunningPillar {
    /// Change the Archive setting while running (0 GB = no Archive, just
    /// the small media cache). Takes effect at once; the directory hears
    /// about it on the next announce, a few minutes later.
    pub fn set_archive(&self, archive_gb: u32, chunk_quota_bytes: u64) {
        self.ctx.archive_gb.store(archive_gb, Ordering::Relaxed);
        self.ctx.chunk_quota_bytes.store(chunk_quota_bytes, Ordering::Relaxed);
        self.ctx.reannounce.notify_one();
    }
}

impl Drop for RunningPillar {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Launch the onion service and start serving. `tor` should be a client
/// dedicated to this Pillar (own state and guards), never shared with a
/// user account.
pub async fn start(tor: Arc<TorClient<PreferredRuntime>>, cfg: PillarConfig) -> Result<RunningPillar> {
    for dir in ["authors", "shards", "followers", "inboxes", "chunks"] {
        tokio::fs::create_dir_all(cfg.store.join(dir)).await?;
    }
    let nickname: HsNickname = cfg.nickname.parse().context("invalid nickname")?;
    // Proof-of-work DoS defence: flooded Pillars stay reachable (§17).
    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .enable_pow(true)
        .max_concurrent_streams_per_circuit(MAX_STREAMS_PER_CIRCUIT)
        .build()?;
    let (service, rend_requests) = tor.launch_onion_service(svc_cfg)?.context("onion service disabled in config")?;
    let onion = service.onion_address().context("onion service has no address")?.display_unredacted().to_string();

    let stats = Arc::new(Stats::default());
    let (objects, chunks) = usage(&cfg.store);
    stats.used_bytes.store(objects, Ordering::Relaxed);
    stats.chunk_bytes.store(chunks, Ordering::Relaxed);
    let archive_gb = if cfg.archive { (cfg.chunk_quota_bytes / 1_000_000_000).min(u32::MAX as u64) as u32 } else { 0 };
    let ctx = Arc::new(Ctx {
        store: cfg.store.clone(),
        stats: Arc::clone(&stats),
        tor: Arc::clone(&tor),
        quota_bytes: cfg.quota_bytes,
        chunk_quota_bytes: AtomicU64::new(cfg.chunk_quota_bytes),
        archive_gb: std::sync::atomic::AtomicU32::new(archive_gb),
        reannounce: tokio::sync::Notify::new(),
        self_onion: onion.clone(),
        mail_seq: AtomicU64::new(0),
        obj_seq: AtomicU64::new(0),
        mail_count: AtomicU64::new(0),
        econ: economy::Econ::load(&cfg.store, &onion, cfg.mints.clone())?,
        mint_interval: cfg.mint_interval,
        updates: cfg.updates.clone(),
        mix: load_mix_secret(&cfg.store),
        mix_seen: std::sync::Mutex::new(std::collections::VecDeque::new()),
        dir: Arc::default(),
    });
    let (max_seq, count) = mailbox_scan(&cfg.store);
    // The counter survives restarts even after every deposit expired (a
    // reset would make readers with a higher cursor miss new mail). A
    // counter, not a clock: sequence numbers reveal order, not times.
    let saved = std::fs::read_to_string(cfg.store.join("mail-seq.txt")).ok().and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(0);
    ctx.mail_seq.store(max_seq.max(saved), Ordering::Relaxed);
    {
        let store = cfg.store.clone();
        let seq = tokio::task::spawn_blocking(move || author_buckets_init(&store)).await.unwrap_or(0);
        ctx.obj_seq.store(seq, Ordering::Relaxed);
    }
    ctx.mail_count.store(count, Ordering::Relaxed);

    let mut tasks = Vec::new();

    // Serve.
    {
        let ctx = Arc::clone(&ctx);
        tasks.push(tokio::spawn(async move {
            let mut streams = Box::pin(tor_hsservice::handle_rend_requests(rend_requests));
            while let Some(req) = streams.next().await {
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    // Errors are not printed: they could carry per-connection detail.
                    let _ = handle_stream(req, ctx).await;
                });
            }
        }));
    }

    // Expiry: delete objects older than the retention window, daily.
    {
        let store = cfg.store.clone();
        let stats = Arc::clone(&stats);
        let max_age = Duration::from_secs(cfg.retention_days.max(1) * 86_400);
        let chunk_age = Duration::from_secs(cfg.chunk_retention_days.max(1) * 86_400);
        let prune_ctx = Arc::clone(&ctx);
        tasks.push(tokio::spawn(async move {
            loop {
                let s2 = store.clone();
                let _ = tokio::task::spawn_blocking(move || prune(&s2, max_age, chunk_age)).await;
                let (objects, chunks) = usage(&store);
                stats.used_bytes.store(objects, Ordering::Relaxed);
                stats.chunk_bytes.store(chunks, Ordering::Relaxed);
                prune_ctx.mail_count.store(mailbox_scan(&store).1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(86_400)).await;
            }
        }));
    }

    if let Some(m) = &ctx.econ.mint {
        println!("[pillar] credit mint (seed Pillar); credit key {} pq={}", data_encoding::HEXLOWER.encode(&m.public_key()), data_encoding::HEXLOWER.encode(&sentinel_core::pqcash::key_fingerprint(&m.pq.public())));
        tasks.push(tokio::spawn(economy::mint_loop(Arc::clone(&ctx))));
        tasks.push(tokio::spawn(economy::checkpoint_loop(Arc::clone(&ctx))));
    }

    // Mixed messages whose last step is a deposit here.
    {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(u16, Vec<u8>, u64)>();
        let _ = MIX_LOCAL.set(tx);
        let ctx = Arc::clone(&ctx);
        tasks.push(tokio::spawn(async move {
            while let Some((shard, blob, nonce)) = rx.recv().await {
                let _ = handle_request(Request::Deposit { shard, blob, nonce }, &ctx).await;
            }
        }));
    }

    // Pass signed releases and revocations on, Pillar to Pillar.
    tasks.push(tokio::spawn(spread_updates(Arc::clone(&ctx), cfg.seeds.clone(), cfg.spread_after)));

    // Messages taken on but not passed on yet: retried for days.
    tasks.push(tokio::spawn(relay::retry_loop(ctx.store.clone(), mix_ctx(&ctx))));

    // Test the Pillars and Archives we list, so gone ones aren't handed out.
    tasks.push(tokio::spawn(directory::check_loop(Arc::clone(&ctx))));

    // Announce ourselves to seeds and learn the directory, every 6 h.
    {
        let ctx = Arc::clone(&ctx);
        let seeds = cfg.seeds.clone();
        tasks.push(tokio::spawn(async move {
            // Give the descriptor time to publish before others test us.
            tokio::time::sleep(Duration::from_secs(90)).await;
            let data = ctx.self_onion.as_bytes().to_vec();
            let nonce = tokio::task::spawn_blocking(move || {
                pow::stamp(social::ANNOUNCE_POW_DOMAIN, &data, social::ANNOUNCE_POW_BITS)
            })
            .await
            .unwrap_or(0);
            loop {
                for seed in seeds.iter().filter(|s| **s != ctx.self_onion) {
                    let _ = announce_to(&ctx, seed, nonce).await;
                    // Spread announcements out (no burst that ties them together).
                    tokio::time::sleep(Duration::from_secs(5 + random_below(60))).await;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(6 * 3600)) => {}
                    _ = ctx.reannounce.notified() => {
                        // Not right away: the seeds shouldn't see the change
                        // at the moment the person flips the switch.
                        tokio::time::sleep(Duration::from_secs(60 + random_below(540))).await;
                    }
                }
            }
        }));
    }

    Ok(RunningPillar { onion, stats, tasks, ctx, _service: service })
}

async fn announce_to(ctx: &Ctx, seed: &str, nonce: u64) -> Result<()> {
    let iso = ctx.tor.isolated_client();
    let mut s = iso.connect((seed, SENTINEL_PORT)).await?;
    exchange(&mut s, &Request::Announce { onion: ctx.self_onion.clone(), nonce, archive_gb: ctx.archive_gb.load(Ordering::Relaxed) }).await?;
    if let Response::Pillars(list) = exchange(&mut s, &Request::Pillars).await? {
        for p in list {
            let _ = add_known(&known_path(&ctx.store), &p, &ctx.self_onion).await;
        }
    }
    if let Response::Pillars(list) = exchange(&mut s, &Request::Archives).await? {
        for p in list {
            let _ = add_known(&archives_path(&ctx.store), &p, &ctx.self_onion).await;
        }
    }
    add_known(&known_path(&ctx.store), seed, &ctx.self_onion).await
}

async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, req: &Request) -> Result<Response> {
    tokio::time::timeout(Duration::from_secs(90), async {
        write_message(s, &wire::encode(req)).await?;
        let b = read_message(s).await?;
        wire::decode(&b).context("bad response")
    })
    .await
    .context("timed out")?
}

fn known_path(store: &Path) -> PathBuf {
    store.join("known-pillars.txt")
}

fn archives_path(store: &Path) -> PathBuf {
    store.join("known-archives.txt")
}

fn random_below(n: u64) -> u64 {
    u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % n.max(1)
}

/// Midnight UTC of today: the only timestamp ever written to stored files.
fn day_floor() -> SystemTime {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
    SystemTime::UNIX_EPOCH + Duration::from_secs(now - now % 86_400)
}

/// Round a file's (or folder's) modified, accessed and — on Windows —
/// created times down to the day, best effort. (Hosts should still use
/// full-disk encryption: filesystem journals can keep exact times.)
fn coarsen_mtime(path: &Path) {
    let mut o = std::fs::File::options();
    o.write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.custom_flags(0x0200_0000); // FILE_FLAG_BACKUP_SEMANTICS: allows folders
    }
    if let Ok(f) = o.open(path) {
        let d = day_floor();
        let t = std::fs::FileTimes::new().set_modified(d).set_accessed(d);
        #[cfg(windows)]
        let t = {
            use std::os::windows::fs::FileTimesExt;
            t.set_created(d)
        };
        let _ = f.set_times(t);
    }
}

/// Coarsen a file and the folders above it up to the store root.
fn coarsen_path(path: &Path) {
    coarsen_mtime(path);
    let mut dir = path.parent();
    for _ in 0..2 {
        let Some(d) = dir else { break };
        coarsen_mtime(d);
        dir = d.parent();
    }
}

/// Write a new file and coarsen its timestamp.
async fn write_coarse(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    tokio::fs::write(path, bytes).await?;
    let p = path.to_owned();
    let _ = tokio::task::spawn_blocking(move || coarsen_path(&p)).await;
    Ok(())
}

fn valid_onion(s: &str) -> bool {
    let Some(host) = s.strip_suffix(".onion") else { return false };
    host.len() == 56 && host.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
}

static KNOWN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Pillars and Archives not seen for this many days are dropped from the
/// lists: live ones re-announce every 6 hours (and seeds list them), so a
/// gone one stops being handed to new apps, which would otherwise wait on it.
const KNOWN_KEEP_DAYS: u64 = 3;

fn today_day() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs() / 86_400
}

/// "<onion> <day last seen>" per line (older lists have no day: counted as
/// seen today, so they age out normally).
fn parse_known(t: &str) -> Vec<(String, u64)> {
    let today = today_day();
    t.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let onion = w.next()?.to_owned();
            let day = w.next().and_then(|d| d.parse().ok()).unwrap_or(today);
            valid_onion(&onion).then_some((onion, day))
        })
        .collect()
}

fn fresh(day: u64) -> bool {
    day + KNOWN_KEEP_DAYS >= today_day()
}

/// The Pillars (or Archives) in a list that were seen lately.
pub(crate) fn read_known_text(t: &str) -> Vec<String> {
    parse_known(t).into_iter().filter(|(_, d)| fresh(*d)).map(|(o, _)| o).collect()
}

async fn read_known(list: &Path) -> Vec<String> {
    tokio::fs::read_to_string(list).await.map(|t| read_known_text(&t)).unwrap_or_default()
}

/// Add a Pillar to a list, or mark it seen today; drop stale entries.
async fn add_known(list: &Path, onion: &str, self_onion: &str) -> Result<()> {
    let onion = onion.trim().to_ascii_lowercase();
    if !valid_onion(&onion) || onion == self_onion {
        return Ok(());
    }
    let _g = KNOWN_LOCK.lock().await;
    let mut known = tokio::fs::read_to_string(list).await.map(|t| parse_known(&t)).unwrap_or_default();
    let today = today_day();
    match known.iter_mut().find(|(o, _)| *o == onion) {
        Some(e) => {
            if e.1 == today {
                return Ok(());
            }
            e.1 = today;
        }
        None => known.push((onion, today)),
    }
    known.retain(|(_, d)| fresh(*d));
    while known.len() > MAX_KNOWN_PILLARS {
        known.remove(0);
    }
    let text: String = known.iter().map(|(o, d)| format!("{o} {d}\n")).collect();
    tokio::fs::write(list, text).await?;
    Ok(())
}

async fn handle_stream(req: StreamRequest, ctx: Arc<Ctx>) -> Result<()> {
    let ok_port = matches!(req.request(), IncomingStreamRequest::Begin(b) if b.port() == SENTINEL_PORT);
    if !ok_port {
        ctx.stats.rejected.fetch_add(1, Ordering::Relaxed);
        req.shutdown_circuit()?;
        return Ok(());
    }
    let mut stream = req.accept(Connected::new_empty()).await?;
    ctx.stats.streams.fetch_add(1, Ordering::Relaxed);
    let mut reward = economy::RewardState::new();
    for _ in 0..MAX_REQUESTS_PER_STREAM {
        let msg = match tokio::time::timeout(IDLE_TIMEOUT, read_message(&mut stream)).await {
            Ok(Ok(m)) => m,
            _ => break,
        };
        let resp = match wire::decode::<Request>(&msg) {
            Some(r) => match economy::handle_reward(&r, &ctx, &mut reward).await {
                Some(resp) => resp,
                None => handle_request(r, &ctx).await,
            },
            None => Response::Rejected("malformed request".into()),
        };
        write_message(&mut stream, &wire::encode(&resp)).await?;
    }
    Ok(())
}

fn bucket_path(store: &Path, bucket: u8) -> PathBuf {
    store.join("abuckets").join(format!("{bucket:02x}"))
}

/// Make sure every stored object is filed in an author bucket (older
/// stores had only per-author lists) and return the highest sequence.
fn author_buckets_init(store: &Path) -> u64 {
    let dir = store.join("abuckets");
    let saved = std::fs::read_to_string(store.join("obj-seq.txt")).ok().and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(0);
    if dir.is_dir() {
        let max = (0..=255u8)
            .filter_map(|b| std::fs::read_to_string(bucket_path(store, b)).ok())
            .flat_map(|t| t.lines().filter_map(|l| l.split_once(' ')?.0.parse::<u64>().ok()).collect::<Vec<_>>())
            .max()
            .unwrap_or(0);
        return max.max(saved);
    }
    let _ = std::fs::create_dir_all(&dir);
    let mut seq = saved;
    let mut lines: std::collections::HashMap<u8, String> = std::collections::HashMap::new();
    if let Ok(rd) = std::fs::read_dir(store.join("authors")) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(author) = name.strip_suffix(".idx").and_then(social::author_from_text) else { continue };
            let b = social::author_bucket(&author);
            for a in std::fs::read_to_string(e.path()).unwrap_or_default().lines().filter(|l| !l.is_empty()) {
                seq += 1;
                lines.entry(b).or_default().push_str(&format!("{seq} {a}\n"));
            }
        }
    }
    for (b, text) in lines {
        let p = bucket_path(store, b);
        let _ = std::fs::write(&p, text);
        coarsen_path(&p);
    }
    let _ = std::fs::write(store.join("obj-seq.txt"), seq.to_string());
    seq
}

/// Serialises index appends so concurrent uploads can't interleave lines.
static INDEX_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn index_path(store: &Path, author: &[u8; 32]) -> PathBuf {
    store.join("authors").join(format!("{}.idx", social::author_text(author)))
}

/// Mailbox shard folder (contents are sealed ciphertext).
fn shard_dir(store: &Path, shard: u16) -> PathBuf {
    store.join("inboxes").join(format!("{shard:04x}"))
}

/// (highest sequence number, number of deposits) on disk.
fn mailbox_scan(store: &Path) -> (u64, u64) {
    let (mut max, mut n) = (0u64, 0u64);
    if let Ok(rd) = std::fs::read_dir(store.join("inboxes")) {
        for d in rd.filter_map(|e| e.ok()) {
            if let Ok(files) = std::fs::read_dir(d.path()) {
                for f in files.filter_map(|e| e.ok()) {
                    if let Ok(q) = f.file_name().to_string_lossy().parse::<u64>() {
                        max = max.max(q);
                        n += 1;
                    }
                }
            }
        }
    }
    (max, n)
}

/// Deposits a reply aims to cover per prefix per day.
const MAILBOX_TARGET_PER_DAY: u64 = 3000;
/// Most deposits one shard folder may hold.
const MAX_PER_SHARD: usize = 5000;
/// Most deposits overall (every fetch scans them: bound the work a flood
/// of cheap deposits could cause).
const MAX_MAILBOX_TOTAL: u64 = 200_000;

fn shard_path(store: &Path, shard: u16) -> PathBuf {
    store.join("shards").join(format!("{shard}.idx"))
}

/// Anonymous follow tokens (never identities) for an author.
fn followers_path(store: &Path, author: &[u8; 32]) -> PathBuf {
    store.join("followers").join(format!("{}.tok", social::author_text(author)))
}

async fn read_lines(path: &Path) -> Vec<Address> {
    match tokio::fs::read_to_string(path).await {
        Ok(text) => text.lines().filter_map(Address::from_text).collect(),
        Err(_) => Vec::new(),
    }
}

async fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(path).await?;
    f.write_all(format!("{line}\n").as_bytes()).await?;
    f.flush().await?;
    drop(f);
    let p = path.to_owned();
    let _ = tokio::task::spawn_blocking(move || coarsen_path(&p)).await;
    Ok(())
}

/// One page of an index after position `after`; `u64::MAX` = the newest page.
fn page(all: Vec<Address>, after: u64) -> Vec<(u64, Address)> {
    let start = if after == u64::MAX { all.len().saturating_sub(wire::MAX_LIST) } else { (after as usize).min(all.len()) };
    all[start..].iter().take(wire::MAX_LIST).enumerate().map(|(i, a)| ((start + i + 1) as u64, *a)).collect()
}

/// Bytes in files directly inside `dir`.
fn files_size(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| e.ok()).filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len()).sum())
        .unwrap_or(0)
}

/// (objects + inboxes + indexes, media chunks) in bytes, counted from disk
/// so quotas hold across restarts.
fn usage(store: &Path) -> (u64, u64) {
    let mut objects = files_size(store);
    for sub in ["authors", "shards", "followers"] {
        objects += files_size(&store.join(sub));
    }
    if let Ok(rd) = std::fs::read_dir(store.join("inboxes")) {
        for b in rd.filter_map(|e| e.ok()) {
            objects += files_size(&b.path());
        }
    }
    (objects, files_size(&store.join("chunks")))
}

fn older_than(m: &std::fs::Metadata, max_age: Duration, now: SystemTime) -> bool {
    m.modified().ok().and_then(|t| now.duration_since(t).ok()).is_some_and(|age| age > max_age)
}

/// Delete expired data: objects older than `max_age`, inbox deposits after
/// 7 days, chunks nobody fetched within `chunk_age`. Index files are
/// rewritten without entries whose object is gone, so they don't keep a
/// growing history of what once existed.
fn prune(store: &Path, max_age: Duration, chunk_age: Duration) {
    let now = SystemTime::now();
    if let Ok(rd) = std::fs::read_dir(store) {
        for e in rd.filter_map(|e| e.ok()) {
            let Ok(m) = e.metadata() else { continue };
            if m.is_file() && !e.file_name().to_string_lossy().ends_with(".txt") && older_than(&m, max_age, now) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let inbox_age = Duration::from_secs(7 * 86_400);
    if let Ok(boxes) = std::fs::read_dir(store.join("inboxes")) {
        for b in boxes.filter_map(|e| e.ok()) {
            if let Ok(files) = std::fs::read_dir(b.path()) {
                for f in files.filter_map(|e| e.ok()) {
                    if f.metadata().is_ok_and(|m| older_than(&m, inbox_age, now)) {
                        let _ = std::fs::remove_file(f.path());
                    }
                }
            }
            let _ = std::fs::remove_dir(b.path()); // only succeeds when empty
        }
    }
    // Author buckets: forget entries whose object has expired.
    for b in 0..=255u8 {
        let p = bucket_path(store, b);
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let kept: String = text
            .lines()
            .filter(|l| l.split_once(' ').is_some_and(|(_, a)| store.join(a).is_file()))
            .map(|l| format!("{l}\n"))
            .collect();
        if kept.len() != text.len() {
            let _ = std::fs::write(&p, kept);
            coarsen_path(&p);
        }
    }
    // Paid pins keep chunks past the free expiry.
    let pins = economy::load_pins(store);
    let unix = now.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Ok(rd) = std::fs::read_dir(store.join("chunks")) {
        for e in rd.filter_map(|e| e.ok()) {
            let pinned = pins.get(&*e.file_name().to_string_lossy()).is_some_and(|u| *u > unix);
            if !pinned && e.metadata().is_ok_and(|m| older_than(&m, chunk_age, now)) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    for sub in ["authors", "shards"] {
        let Ok(rd) = std::fs::read_dir(store.join(sub)) else { continue };
        for e in rd.filter_map(|e| e.ok()) {
            let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
            let kept: Vec<&str> = text.lines().filter(|l| store.join(l.trim()).is_file()).collect();
            if kept.is_empty() {
                let _ = std::fs::remove_file(e.path());
            } else if kept.len() != text.lines().count() {
                let _ = std::fs::write(e.path(), kept.join("\n") + "\n");
                coarsen_mtime(&e.path());
            }
        }
    }
}

async fn handle_request(req: Request, ctx: &Ctx) -> Response {
    if let Some(r) = economy::handle(&req, ctx).await {
        return r;
    }
    let store = &ctx.store;
    let stats = &ctx.stats;
    match req {
        Request::Ping => Response::Pong,
        Request::Put(bytes) => {
            if stats.used_bytes.load(Ordering::Relaxed) + bytes.len() as u64 > ctx.quota_bytes {
                return Response::Rejected("Pillar is full".into());
            }
            let env = match Envelope::decode_verified(&bytes) {
                Ok(env) => env,
                Err(_) => {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    return Response::Rejected("invalid or unsigned object".into());
                }
            };
            // Encryption is mandatory: Pillars store only sealed objects
            // (spec §12.4), so a host never holds readable content by default.
            let Some(sealed) = seal::sealed_body(&env) else {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                return Response::Rejected("only encrypted (sealed) objects are accepted".into());
            };
            let addr = Address::of(&bytes);
            if reports::removed(store).contains(&addr.to_text()) {
                return Response::Rejected("removed by this Pillar".into());
            }
            let path = store.join(addr.to_text());
            let _guard = INDEX_LOCK.lock().await;
            if tokio::fs::try_exists(&path).await.unwrap_or(false) {
                return Response::Stored(addr); // duplicate: already indexed
            }
            if write_coarse(&path, &bytes).await.is_err() {
                return Response::Rejected("storage error".into());
            }
            if append_line(&index_path(store, &env.author), &addr.to_text()).await.is_err() {
                let _ = tokio::fs::remove_file(&path).await;
                return Response::Rejected("storage error".into());
            }
            // Also file it under its author's bucket (readers fetch whole
            // buckets, never one account's list).
            let seq = ctx.obj_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = append_line(&bucket_path(store, social::author_bucket(&env.author)), &format!("{seq} {}", addr.to_text())).await;
            let _ = tokio::fs::write(store.join("obj-seq.txt"), seq.to_string()).await;
            // Discoverable objects go into the discovery shards named on the
            // sealed wrapper (§10.4.2). The Pillar never sees topics — only
            // shard numbers, each shared by many topics.
            let mut shards: Vec<u16> = Vec::new();
            for s in sealed.shards.iter().take(social::MAX_TOPICS + 1) {
                if *s <= social::RECENT_SHARD && !shards.contains(s) {
                    shards.push(*s);
                }
            }
            for s in shards {
                let _ = append_line(&shard_path(store, s), &addr.to_text()).await;
            }
            stats.used_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            stats.stored.fetch_add(1, Ordering::Relaxed);
            Response::Stored(addr)
        }
        Request::AuthorBucket { bits, prefix, after } => {
            if bits > 8 || (bits < 8 && prefix as u16 >= 1 << bits) {
                return Response::Rejected("no such bucket".into());
            }
            let mut entries: Vec<(u64, String)> = Vec::new();
            for b in 0..=255u8 {
                if !social::bucket_in_prefix(b, bits, prefix) {
                    continue;
                }
                if let Ok(text) = tokio::fs::read_to_string(bucket_path(store, b)).await {
                    for l in text.lines() {
                        if let Some((n, a)) = l.split_once(' ') {
                            if let Ok(n) = n.parse::<u64>() {
                                if n > after {
                                    entries.push((n, a.to_owned()));
                                }
                            }
                        }
                    }
                }
            }
            entries.sort();
            let mut out = Vec::new();
            let mut total = 0usize;
            for (n, a) in entries {
                let Some(addr) = Address::from_text(&a) else { continue };
                let Ok(bytes) = tokio::fs::read(store.join(addr.to_text())).await else { continue };
                total += bytes.len();
                if total > FETCH_REPLY_BYTES && !out.is_empty() {
                    break;
                }
                out.push((n, bytes));
            }
            stats.served.fetch_add(out.len() as u64, Ordering::Relaxed);
            Response::Blobs(out)
        }
        Request::List { author, after } => Response::Index(page(read_lines(&index_path(store, &author)).await, after)),
        Request::Shard { shard, after } => {
            if shard > social::RECENT_SHARD {
                return Response::Rejected("no such shard".into());
            }
            // Reported content waiting for the operator is left out; the
            // positions stay the same, so readers' places don't shift.
            let hidden = reports::hidden(store);
            let list = page(read_lines(&shard_path(store, shard)).await, after);
            Response::Index(if hidden.is_empty() { list } else { list.into_iter().filter(|(_, a)| !hidden.contains(&a.to_text())).collect() })
        }
        Request::Report { address, chunks, category, token, nonce } => {
            if usize::from(category) >= social::REPORT_CATEGORIES.len()
                || chunks.len() > 5000
                || !pow::check(social::REPORT_POW_DOMAIN, &social::report_pow_data(&address, &token, category), nonce, social::REPORT_POW_BITS)
            {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                return Response::Rejected("invalid report".into());
            }
            let store = store.clone();
            let _ = tokio::task::spawn_blocking(move || reports::record(&store, &address, &chunks, category, &token)).await;
            Response::Pong
        }
        Request::FollowNotice { author, token, follow, nonce } => {
            let data = social::follow_pow_data(&author, &token, follow);
            if !pow::check(social::FOLLOW_POW_DOMAIN, &data, nonce, pow::DEFAULT_BITS) {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                return Response::Rejected("insufficient proof of work".into());
            }
            let path = followers_path(store, &author);
            let _guard = INDEX_LOCK.lock().await;
            let mut tokens: Vec<String> = tokio::fs::read_to_string(&path)
                .await
                .map(|t| t.lines().filter(|l| !l.is_empty()).map(str::to_owned).collect())
                .unwrap_or_default();
            let tok = data_encoding::HEXLOWER.encode(&token);
            let present = tokens.contains(&tok);
            if follow && !present {
                tokens.push(tok);
            } else if !follow && present {
                tokens.retain(|t| *t != tok);
            }
            if tokio::fs::write(&path, tokens.join("\n") + "\n").await.is_err() {
                return Response::Rejected("storage error".into());
            }
            Response::Count(tokens.len() as u64)
        }
        Request::FollowerCount { author } => {
            let n = tokio::fs::read_to_string(followers_path(store, &author))
                .await
                .map(|t| t.lines().filter(|l| !l.is_empty()).count())
                .unwrap_or(0);
            Response::Count(n as u64)
        }
        Request::Get(addr) => match tokio::fs::read(store.join(addr.to_text())).await {
            Ok(bytes) => {
                stats.served.fetch_add(1, Ordering::Relaxed);
                Response::Object(bytes)
            }
            Err(_) => Response::NotFound,
        },
        Request::Pillars => {
            // A random sample of the ones that answered lately, the more
            // reliable first (never ones that are failing).
            let mut known = ctx.dir.sample(read_known(&known_path(store)).await, PILLARS_PER_REPLY - 1);
            known.push(ctx.self_onion.clone());
            Response::Pillars(known)
        }
        Request::Deposit { shard, blob, nonce } => {
            if blob.len() > dm::MAX_BLOB
                || !pow::check(dm::DEPOSIT_POW_DOMAIN, &dm::deposit_pow_data(shard, &blob), nonce, dm::deposit_bits(blob.len()))
            {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                return Response::Rejected("invalid deposit".into());
            }
            if stats.used_bytes.load(Ordering::Relaxed) + blob.len() as u64 > ctx.quota_bytes {
                return Response::Rejected("Pillar is full".into());
            }
            let dir = shard_dir(store, shard);
            let _guard = INDEX_LOCK.lock().await;
            if tokio::fs::create_dir_all(&dir).await.is_err() {
                return Response::Rejected("storage error".into());
            }
            if ctx.mail_count.load(Ordering::Relaxed) >= MAX_MAILBOX_TOTAL || std::fs::read_dir(&dir).map(|r| r.count()).unwrap_or(0) >= MAX_PER_SHARD {
                return Response::Rejected("mailbox full".into());
            }
            // A global, ever-increasing sequence number: readers page with it
            // across every shard they fetch, and expiry never reuses one.
            let seq = ctx.mail_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = write_coarse(&store.join("mail-seq.txt"), seq.to_string().as_bytes()).await;
            if write_coarse(&dir.join(format!("{seq:016}")), &blob).await.is_err() {
                return Response::Rejected("storage error".into());
            }
            stats.used_bytes.fetch_add(blob.len() as u64, Ordering::Relaxed);
            ctx.mail_count.fetch_add(1, Ordering::Relaxed);
            // Plain acknowledgement: nothing about who else uses the shard.
            Response::Pong
        }
        Request::UpdateInfo { product } => update_info(ctx, &product).await.unwrap_or(Response::NotFound),
        Request::MixKey => Response::Object(ctx.mix.public().encode()),
        Request::Mix { packet, nonce } => {
            use sentinel_core::mix;
            if packet.len() > mix::MAX_PACKET || !pow::check(mix::MIX_POW_DOMAIN, &mix::pow_data(&packet), nonce, mix::MIX_POW_BITS) {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                return Response::Rejected("invalid".into());
            }
            let id = blake3::derive_key("sentinel/v0/mix-seen", &packet);
            {
                let mut seen = ctx.mix_seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if seen.contains(&id) {
                    return Response::Pong; // a replay: already handled
                }
                seen.push_back(id);
                if seen.len() > 50_000 {
                    seen.pop_front();
                }
            }
            let Some((step, delay)) = mix::unwrap(&ctx.mix, &packet) else {
                return Response::Rejected("invalid".into());
            };
            let ctx2 = mix_ctx(ctx);
            if ctx2.waiting.load(Ordering::Relaxed) >= MAX_MIX_WAITING {
                return Response::Rejected("busy".into());
            }
            ctx2.waiting.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(u64::from(delay))).await;
                // Once now; if the next Pillar doesn't answer, it's kept on
                // disk and retried for days (see `relay`): the sender may
                // already be offline and can't be told.
                let done = matches!(tokio::time::timeout(Duration::from_secs(120), mix_step(&ctx2, &step)).await, Ok(Ok(())));
                if !done {
                    relay::keep(&ctx2.store, &step).await;
                }
                ctx2.waiting.fetch_sub(1, Ordering::Relaxed);
            });
            Response::Pong
        }
        Request::UpdateRevocations => match &ctx.updates {
            Some(dir) => Response::Object(sentinel_core::update::encode_revocations(&load_revocations(dir).await)),
            None => Response::NotFound,
        },
        Request::UpdateChunk { product, offset } => {
            let Some(path) = update_path(ctx, &product) else { return Response::NotFound };
            match read_at(&path, offset, wire::UPDATE_CHUNK).await {
                Some(b) => Response::Object(b),
                None => Response::NotFound,
            }
        }
        Request::MailboxDepth => {
            // Deposits live 7 days. Choose the shortest prefix that keeps a
            // day's deposits per prefix near the target: everyone fetching
            // the same prefix is the anonymity set.
            let per_day = ctx.mail_count.load(Ordering::Relaxed) / 7;
            let mut depth = 0u64;
            while depth < 16 && (per_day >> depth) > MAILBOX_TARGET_PER_DAY {
                depth += 1;
            }
            Response::Count(depth)
        }
        Request::Fetch { bits, prefix, after } => {
            if bits > 16 {
                return Response::Rejected("bad prefix".into());
            }
            let mut found: Vec<(u64, PathBuf)> = Vec::new();
            if let Ok(rd) = std::fs::read_dir(store.join("inboxes")) {
                for d in rd.filter_map(|e| e.ok()) {
                    let Ok(shard) = u16::from_str_radix(&d.file_name().to_string_lossy(), 16) else { continue };
                    if !dm::prefix_matches(shard, bits, prefix) {
                        continue;
                    }
                    if let Ok(files) = std::fs::read_dir(d.path()) {
                        found.extend(
                            files
                                .filter_map(|e| e.ok())
                                .filter_map(|e| Some((e.file_name().to_string_lossy().parse::<u64>().ok()?, e.path())))
                                .filter(|(n, _)| *n > after),
                        );
                    }
                }
            }
            found.sort();
            // Bounded by bytes as well as count (a reply over the message
            // limit would fail every time); the reader pages with `after`.
            let mut out = Vec::new();
            let mut total = 0usize;
            for (n, p) in found.into_iter().take(200) {
                if let Ok(b) = tokio::fs::read(&p).await {
                    total += b.len() + 16;
                    if total > FETCH_REPLY_BYTES && !out.is_empty() {
                        break;
                    }
                    out.push((n, b));
                }
            }
            Response::Blobs(out)
        }
        Request::PutChunk { data, nonce } => {
            // Media chunks are ciphertext with keys this node is never given.
            // Every chunk has exactly the same size (spec §5.7).
            if (data.len() != media::CHUNK_CT && data.len() != media::CHUNK_CT_V0)
                || !pow::check(media::CHUNK_POW_DOMAIN, blake3::hash(&data).as_bytes(), nonce, media::CHUNK_POW_BITS)
            {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                return Response::Rejected("invalid chunk".into());
            }
            let addr = Address::of(&data);
            if reports::removed(store).contains(&addr.to_text()) {
                return Response::Rejected("removed by this Pillar".into());
            }
            let path = store.join("chunks").join(addr.to_text());
            if tokio::fs::try_exists(&path).await.unwrap_or(false) {
                let p = path.clone();
                let _ = tokio::task::spawn_blocking(move || coarsen_mtime(&p)).await; // keep alive
                return Response::Stored(addr);
            }
            if stats.chunk_bytes.load(Ordering::Relaxed) + data.len() as u64 > ctx.chunk_quota_bytes.load(Ordering::Relaxed) {
                return Response::Rejected("storage full".into());
            }
            if write_coarse(&path, &data).await.is_err() {
                return Response::Rejected("storage error".into());
            }
            stats.chunk_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
            Response::Stored(addr)
        }
        Request::GetChunk(addr) => {
            let path = store.join("chunks").join(Address(addr).to_text());
            match tokio::fs::read(&path).await {
                Ok(bytes) => {
                    stats.served.fetch_add(1, Ordering::Relaxed);
                    // Fetching keeps a chunk alive (popular media stays).
                    let _ = tokio::task::spawn_blocking(move || coarsen_mtime(&path)).await;
                    Response::Object(bytes)
                }
                Err(_) => Response::NotFound,
            }
        }
        // Credits requests are answered by `economy::handle` above.
        Request::MintKey
        | Request::MintFaucet { .. }
        | Request::MintSwap { .. }
        | Request::Pin { .. }
        | Request::RewardOffer { .. }
        | Request::RewardIssue { .. }
        | Request::RewardOfferPq { .. }
        | Request::RewardAppended { .. }
        | Request::PqMintKey
        | Request::Vouched
        | Request::PqSwap { .. }
        | Request::PqUpgrade { .. }
        | Request::PqLeaves { .. }
        | Request::PqCheckpoint { .. }
        | Request::MintStats => Response::NotFound,
        Request::Noise { reply, .. } => Response::Object(vec![0u8; (reply as usize).min(256 * 1024)]),
        Request::Prove { addr, nonce } => match tokio::fs::read(store.join("chunks").join(Address(addr).to_text())).await {
            Ok(bytes) => Response::Proof(media::proof(&nonce, &bytes)),
            Err(_) => Response::NotFound,
        },
        Request::HaveChunks(addrs) => {
            if addrs.len() > wire::MAX_HAVE {
                return Response::Rejected("too many addresses".into());
            }
            let mut bits = vec![0u8; addrs.len().div_ceil(8)];
            for (i, a) in addrs.iter().enumerate() {
                if store.join("chunks").join(Address(*a).to_text()).is_file() {
                    bits[i / 8] |= 1 << (i % 8);
                }
            }
            Response::Have(bits)
        }
        Request::Archives => {
            let mut known = ctx.dir.sample(read_known(&archives_path(store)).await, PILLARS_PER_REPLY - 1);
            if ctx.archive_gb.load(Ordering::Relaxed) > 0 {
                known.push(ctx.self_onion.clone());
            }
            Response::Pillars(known)
        }
        Request::Announce { onion, nonce, archive_gb } => {
            let onion = onion.trim().to_ascii_lowercase();
            if !valid_onion(&onion) || !pow::check(social::ANNOUNCE_POW_DOMAIN, onion.as_bytes(), nonce, social::ANNOUNCE_POW_BITS) {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                return Response::Rejected("invalid announcement".into());
            }
            // Verify it is a live Pillar before listing it (in the background).
            let tor = Arc::clone(&ctx.tor);
            let store = store.clone();
            let self_onion = ctx.self_onion.clone();
            let dir = Arc::clone(&ctx.dir);
            tokio::spawn(async move {
                let iso = tor.isolated_client();
                let Ok(mut s) = iso.connect((onion.as_str(), SENTINEL_PORT)).await else { return };
                if let Ok(Response::Pong) = exchange(&mut s, &Request::Ping).await {
                    dir.ok(&onion);
                    let _ = add_known(&known_path(&store), &onion, &self_onion).await;
                    if archive_gb > 0 {
                        let _ = add_known(&archives_path(&store), &onion, &self_onion).await;
                    }
                }
            });
            Response::Pong
        }
    }
}

/// Where a product's update bundle lives (only the known names).
fn update_path(ctx: &Ctx, product: &str) -> Option<PathBuf> {
    let dir = ctx.updates.as_ref()?;
    matches!(product, "app" | "app-android" | "pillar").then(|| dir.join(format!("{product}.bin")))
}

async fn read_at(path: &std::path::Path, offset: u64, max: usize) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = tokio::fs::File::open(path).await.ok()?;
    f.seek(std::io::SeekFrom::Start(offset)).await.ok()?;
    let mut buf = Vec::with_capacity(max);
    f.take(max as u64).read_to_end(&mut buf).await.ok()?;
    Some(buf)
}

/// The bundle's signed header, if it's genuinely signed by the release keys
/// (a Pillar never passes on something it can't vouch for).
async fn update_info(ctx: &Ctx, product: &str) -> Option<Response> {
    let path = update_path(ctx, product)?;
    let size = tokio::fs::metadata(&path).await.ok()?.len();
    let prefix = read_at(&path, 0, 12 + sentinel_core::update::MAX_HEADER).await?;
    let (h, start) = sentinel_core::update::read_header(&prefix).ok()?;
    let platform = h.manifest.platform.clone();
    sentinel_core::update::verify_header(&h, &sentinel_core::update::release_keys(), product, &platform, "0.0.0").ok()?;
    // Never pass on a revoked release.
    let id = sentinel_core::update::manifest_id(&h.manifest);
    if load_revocations(ctx.updates.as_ref()?).await.iter().any(|r| r.revocation.manifest == id) {
        return None;
    }
    Some(Response::Update { prefix: prefix[..start].to_vec(), size })
}

/// Valid revocations: the merged list, plus any `*.revoke` file an
/// operator dropped in the folder.
async fn load_revocations(dir: &std::path::Path) -> Vec<sentinel_core::update::RevocationDoc> {
    use sentinel_core::update as up;
    let keys = up::release_keys();
    let mut list = Vec::new();
    if let Ok(b) = tokio::fs::read(dir.join("revoked.cbor")).await {
        up::merge_revocations(&mut list, up::decode_revocations(&b), &keys);
    }
    if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(e)) = rd.next_entry().await {
            if e.file_name().to_string_lossy().ends_with(".revoke") {
                if let Ok(b) = tokio::fs::read(e.path()).await {
                    if let Some(d) = up::decode_revocation(&b) {
                        up::merge_revocations(&mut list, vec![d], &keys);
                    }
                }
            }
        }
    }
    list
}

/// The version of the bundle this Pillar carries for `product`, if any.
async fn carried_version(dir: &std::path::Path, product: &str) -> Option<String> {
    let prefix = read_at(&dir.join(format!("{product}.bin")), 0, 12 + sentinel_core::update::MAX_HEADER).await?;
    let (h, _) = sentinel_core::update::read_header(&prefix).ok()?;
    Some(h.manifest.version)
}

/// Pass releases on: every few hours ask a few other Pillars for newer
/// signed bundles and revocations, so every Pillar ends up with the same
/// ones (an app takes a release only when several Pillars carry it).
async fn spread_updates(ctx: Arc<Ctx>, seeds: Vec<String>, first: Option<u64>) {
    use sentinel_core::update as up;
    let Some(dir) = ctx.updates.clone() else { return };
    let _ = tokio::fs::create_dir_all(&dir).await;
    tokio::time::sleep(Duration::from_secs(first.unwrap_or_else(|| 300 + random_below(1800)))).await;
    loop {
        let mut peers: Vec<String> = read_known(&known_path(&ctx.store)).await;
        for s in &seeds {
            if !peers.contains(s) {
                peers.push(s.clone());
            }
        }
        peers.retain(|p| *p != ctx.self_onion);
        // A few at random each round.
        for _ in 0..peers.len() {
            let i = random_below(peers.len() as u64) as usize;
            let j = random_below(peers.len() as u64) as usize;
            peers.swap(i, j);
        }
        let mut reached = 0;
        for peer in peers.into_iter().take(4) {
            let iso = ctx.tor.isolated_client();
            let Ok(mut s) = iso.connect((peer.as_str(), SENTINEL_PORT)).await else { continue };
            reached += 1;
            // Revocations first: they decide what may be passed on.
            if let Ok(Response::Object(b)) = exchange(&mut s, &Request::UpdateRevocations).await {
                let mut list = load_revocations(&dir).await;
                if up::merge_revocations(&mut list, up::decode_revocations(&b), &up::release_keys()) {
                    let _ = tokio::fs::write(dir.join("revoked.cbor"), up::encode_revocations(&list)).await;
                }
            }
            for product in ["app", "app-android", "pillar"] {
                let _ = fetch_bundle(&ctx, &mut s, &dir, product).await;
            }
            tokio::time::sleep(Duration::from_secs(10 + random_below(120))).await;
        }
        // Nobody reachable (just started, or the network is down): try again
        // soon rather than in hours.
        let wait = if reached == 0 { 600 + random_below(600) } else { 2 * 3600 + random_below(4 * 3600) };
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}

/// Download a newer signed bundle from a peer (checked in full before use).
async fn fetch_bundle<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(ctx: &Ctx, s: &mut S, dir: &std::path::Path, product: &str) -> Result<()> {
    use sentinel_core::update as up;
    use tokio::io::AsyncWriteExt;
    let Response::Update { prefix, size } = exchange(s, &Request::UpdateInfo { product: product.into() }).await? else { return Ok(()) };
    let (h, _) = up::read_header(&prefix)?;
    let mine = carried_version(dir, product).await.unwrap_or_else(|| "0.0.0".into());
    let keys = up::release_keys();
    if size > up::MAX_BUNDLE || up::verify_header(&h, &keys, product, &h.manifest.platform.clone(), &mine).is_err() {
        return Ok(()); // not newer than mine (or not genuine)
    }
    let id = up::manifest_id(&h.manifest);
    if load_revocations(dir).await.iter().any(|r| r.revocation.manifest == id) {
        return Ok(());
    }
    let part = dir.join(format!("{product}.part"));
    let mut out = tokio::fs::File::create(&part).await?;
    let mut have = 0u64;
    while have < size {
        let Response::Object(b) = exchange(s, &Request::UpdateChunk { product: product.into(), offset: have }).await? else { anyhow::bail!("stopped") };
        if b.is_empty() {
            anyhow::bail!("stopped");
        }
        let take = b.len().min((size - have) as usize);
        out.write_all(&b[..take]).await?;
        have += take as u64;
    }
    out.flush().await?;
    drop(out);
    let p2 = part.clone();
    let product2 = product.to_owned();
    let ok = tokio::task::spawn_blocking(move || up::verify_bundle_file(&p2, &up::release_keys(), &product2, None, &mine).is_ok()).await.unwrap_or(false);
    if !ok {
        let _ = tokio::fs::remove_file(&part).await;
        return Ok(());
    }
    tokio::fs::rename(&part, dir.join(format!("{product}.bin"))).await?;
    let _ = ctx;
    Ok(())
}

/// What a waiting mixed packet needs from the Pillar.
struct MixCtx {
    tor: Arc<TorClient<PreferredRuntime>>,
    store: PathBuf,
    self_onion: String,
    waiting: Arc<AtomicU64>,
    deliver_local: tokio::sync::mpsc::UnboundedSender<(u16, Vec<u8>, u64)>,
}

static MIX_LOCAL: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<(u16, Vec<u8>, u64)>> = std::sync::OnceLock::new();
static MIX_WAITING: std::sync::OnceLock<Arc<AtomicU64>> = std::sync::OnceLock::new();

fn mix_ctx(ctx: &Ctx) -> MixCtx {
    MixCtx {
        tor: Arc::clone(&ctx.tor),
        store: ctx.store.clone(),
        self_onion: ctx.self_onion.clone(),
        waiting: MIX_WAITING.get_or_init(|| Arc::new(AtomicU64::new(0))).clone(),
        deliver_local: MIX_LOCAL.get().cloned().expect("mix delivery started"),
    }
}

/// Carry out one mix step: pass the packet on, or deposit it.
async fn mix_step(ctx: &MixCtx, step: &sentinel_core::mix::Step) -> Result<()> {
    use sentinel_core::mix::{self, Step};
    match step {
        Step::Forward { to, packet } => {
            let p = packet.clone();
            let data = mix::pow_data(&p);
            let nonce = tokio::task::spawn_blocking(move || pow::stamp(mix::MIX_POW_DOMAIN, &data, mix::MIX_POW_BITS)).await?;
            let iso = ctx.tor.isolated_client();
            let mut s = iso.connect((to.as_str(), SENTINEL_PORT)).await?;
            match exchange(&mut s, &Request::Mix { packet: p, nonce }).await? {
                Response::Pong => Ok(()),
                other => anyhow::bail!("not taken: {other:?}"),
            }
        }
        Step::Deliver { pillar, shard, blob, nonce } => {
            if *pillar == ctx.self_onion {
                ctx.deliver_local.send((*shard, blob.clone(), *nonce))?;
                return Ok(());
            }
            let iso = ctx.tor.isolated_client();
            let mut s = iso.connect((pillar.as_str(), SENTINEL_PORT)).await?;
            match exchange(&mut s, &Request::Deposit { shard: *shard, blob: blob.clone(), nonce: *nonce }).await? {
                Response::Pong => Ok(()),
                other => anyhow::bail!("not delivered: {other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fullest_reply_still_fits_in_one_message() {
        // Random (incompressible) data, in the largest objects allowed, up
        // to the reply limit: the encoded reply must still be sendable.
        let mut out = Vec::new();
        let mut total = 0;
        let mut n = 0u64;
        while total + sentinel_core::object::MAX_OBJECT_LEN <= FETCH_REPLY_BYTES {
            let b: Vec<u8> = (0..sentinel_core::object::MAX_OBJECT_LEN).map(|i| (i as u8).wrapping_mul(97).wrapping_add(200)).collect();
            total += b.len();
            n += 1;
            out.push((n, b));
        }
        // Fill the rest with mailbox-sized blobs of high bytes (2 bytes each on the wire).
        while total + dm::MAX_BLOB <= FETCH_REPLY_BYTES {
            total += dm::MAX_BLOB;
            n += 1;
            out.push((n, vec![255u8; dm::MAX_BLOB]));
        }
        let encoded = wire::encode(&Response::Blobs(out));
        assert!(encoded.len() <= sentinel_core::cell::MAX_MESSAGE, "{} > {}", encoded.len(), sentinel_core::cell::MAX_MESSAGE);
    }

    #[test]
    fn gone_pillars_age_out_of_the_lists() {
        let a = "a".repeat(56) + ".onion";
        let b = "b".repeat(56) + ".onion";
        let c = "c".repeat(56) + ".onion";
        let today = today_day();
        // Seen today, seen 3 days ago (kept), seen 4 days ago (dropped);
        // an old line without a day counts as seen today.
        let text = format!("{a} {today}\n{b} {}\n{c} {}\nnot-an-onion\n", today - 3, today - 4);
        assert_eq!(read_known_text(&text), vec![a.clone(), b]);
        assert_eq!(read_known_text(&format!("{a}\n")), vec![a]);
    }
}
