//! Media and files in the app (spec §5.7, §14.7).
//!
//! Sending: attach (metadata removed on this device) → small media is
//! encrypted at once and shown inline; large files and other attachments
//! become **upload jobs**: a first pass derives every chunk address (the
//! source file is never copied), then chunks are re-derived, encrypted and
//! uploaded in parallel to two Archives, resumably. The post is sealed and
//! published only when every chunk is stored.
//!
//! Reading: chunks are fetched over Tor from the Archives named in the post
//! (each file gets its own connections, never shared with another file, so
//! an Archive can't link what one reader views), verified against their
//! addresses and decrypted in memory. Large audio/video streams through a
//! local-only URL scheme with range requests; files are saved only on
//! request. Decrypted bytes never touch disk except a file the user saves.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use sentinel_core::media::{self, MediaRef, Sanitized, CHUNK};
use sentinel_core::sanitize::{self, Format, Patch};
use sentinel_core::wire::{Request, Response};
use sentinel_net::transport::Io;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use super::{request, Core};

/// Parallel transfers per file (each on its own circuit).
const WORKERS: usize = 4;
/// Archives each file is stored on.
const COPIES: usize = 2;
/// Fetch sessions idle longer than this are closed.
const SESSION_IDLE: Duration = Duration::from_secs(120);
/// Chunks read ahead (in parallel, one circuit each) while streaming.
const READ_AHEAD: u64 = 6;
/// Circuits kept warm per host for one file while it is being read.
const WARM_STREAMS: usize = 4;

/// An attachment waiting for its post (memory only).
pub enum Attachment {
    Inline(Sanitized),
    File(PendingFile),
}

#[derive(Clone)]
pub struct PendingFile {
    pub path: PathBuf,
    pub len: u64,
    pub mtime: u64,
    pub fmt: Format,
    pub kind: &'static str,
    pub mime: &'static str,
    pub dims: (u32, u32),
    pub name: String,
    /// Rebuild with FFmpeg instead of patching in place.
    pub remux: Option<super::ffmpeg::Plan>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Attached {
    pub id: String,
    pub kind: String,
    pub width: u32,
    pub height: u32,
    pub size: u64,
    pub name: String,
    pub inline: bool,
    pub cleaned: bool,
    /// Audio/video cleaned in place, without FFmpeg: metadata is gone but
    /// the container layout is the original one.
    pub partial: bool,
}

/// A post whose large attachments are still being prepared/uploaded.
#[derive(Clone, Serialize, Deserialize)]
pub struct Draft {
    pub text: String,
    pub topics: Vec<String>,
    pub discoverable: bool,
    #[serde(default)]
    pub approved_only: bool,
    pub ready: Vec<MediaRef>,
    pub jobs: Vec<UploadJob>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UploadJob {
    /// Source file (kept only in the encrypted store, removed once sent).
    pub path: String,
    pub len: u64,
    pub mtime: u64,
    pub fmt: String,
    pub kind: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub name: String,
    pub cleaned: bool,
    pub key: [u8; 32],
    pub total: u64,
    #[serde(default)]
    pub manifest: Vec<[u8; 32]>,
    pub hosts: Vec<String>,
    /// Chunks `[0, done)` are stored on every host.
    #[serde(default)]
    pub done: u64,
    #[serde(default)]
    pub manifest_sent: bool,
    /// Chunk format (see `MediaRef::v`).
    #[serde(default)]
    pub v: u8,
    /// FFmpeg rebuild plan: chunks come from the encrypted outbox (written
    /// in pass 1), not from the source file.
    #[serde(default)]
    pub remux: Option<super::ffmpeg::Plan>,
    /// Erasure coding across `hosts` (None = every host gets every chunk).
    /// With it, `done` counts stripes instead of chunks.
    #[serde(default)]
    pub ec: Option<sentinel_core::erasure::Layout>,
    #[serde(default)]
    pub error: Option<String>,
}

impl UploadJob {
    fn finished(&self) -> bool {
        !self.manifest.is_empty() && self.done >= self.units() && self.manifest_sent
    }

    fn media_ref(&self) -> MediaRef {
        MediaRef {
            kind: self.kind.clone(),
            mime: self.mime.clone(),
            width: self.width,
            height: self.height,
            size: self.len,
            key: self.key,
            chunks: Vec::new(),
            manifest: self.manifest.clone(),
            total: self.total,
            name: Some(self.name.clone()),
            archives: self.hosts.clone(),
            cleaned: self.cleaned,
            v: self.v,
            ec: self.ec,
        }
    }

    /// Upload units: chunks, or stripes when erasure coded.
    pub fn units(&self) -> u64 {
        match self.ec {
            Some(l) => l.stripes(self.total),
            None => self.total,
        }
    }

    /// Fraction done (prepare counts as the first 10%).
    pub fn progress(&self) -> f32 {
        if self.manifest.is_empty() {
            return 0.0;
        }
        0.1 + 0.9 * (self.done as f32 / self.units().max(1) as f32)
    }
}

fn fmt_name(f: Format) -> &'static str {
    match f {
        Format::Image => "image",
        Format::Gif => "gif",
        Format::Mp4 => "mp4",
        Format::Webm => "webm",
        Format::Matroska => "mkv",
        Format::Mp3 => "mp3",
        Format::Flac => "flac",
        Format::Wav => "wav",
        Format::Other => "other",
    }
}

fn fmt_from(s: &str) -> Format {
    match s {
        "image" => Format::Image,
        "gif" => Format::Gif,
        "mp4" => Format::Mp4,
        "webm" => Format::Webm,
        "mkv" => Format::Matroska,
        "mp3" => Format::Mp3,
        "flac" => Format::Flac,
        "wav" => Format::Wav,
        _ => Format::Other,
    }
}

/// A neutral default name shown to readers: never the original file name
/// (names often carry dates, places or real names). The sender can edit it.
fn default_name(kind: &str, mime: &str, original: Option<&std::path::Path>) -> String {
    let ext = match mime {
        "image/jpeg" => "jpg".to_owned(),
        "image/png" => "png".to_owned(),
        "image/gif" => "gif".to_owned(),
        "video/mp4" => "mp4".to_owned(),
        "video/webm" => "webm".to_owned(),
        "video/x-matroska" => "mkv".to_owned(),
        "audio/mpeg" => "mp3".to_owned(),
        "audio/flac" => "flac".to_owned(),
        "audio/wav" => "wav".to_owned(),
        "audio/mp4" => "m4a".to_owned(),
        _ => original
            .and_then(|p| p.extension())
            .map(|e| e.to_string_lossy().to_lowercase())
            .filter(|e| !e.is_empty() && e.len() <= 8 && e.bytes().all(|b| b.is_ascii_alphanumeric()))
            .unwrap_or_else(|| "bin".into()),
    };
    let base = match kind {
        "image" | "gif" => "image",
        "video" => "video",
        "audio" => "audio",
        _ => "file",
    };
    format!("{base}.{ext}")
}

/// Clean a user-chosen display name: printable, no path separators.
fn clean_name(s: &str) -> Option<String> {
    let n: String = s
        .trim()
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .take(media::MAX_NAME)
        .collect();
    let n = n.trim().trim_matches('.').to_owned();
    (!n.is_empty()).then_some(n)
}

fn new_id() -> String {
    data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<12>())
}

fn mtime_of(m: &std::fs::Metadata) -> u64 {
    m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0)
}

/// Readable source of a job's chunks: the original file with metadata
/// patches applied on the fly.
struct Source {
    file: std::fs::File,
    len: u64,
    patches: Vec<Patch>,
}

impl Source {
    fn open(path: &str, len: u64, mtime: u64, fmt: Format, cleaned: bool) -> Result<Self> {
        let mut file = std::fs::File::open(path).context("the original file is no longer available")?;
        let m = file.metadata()?;
        if m.len() != len || mtime_of(&m) != mtime {
            bail!("the original file changed after it was attached; attach it again");
        }
        let patches = if cleaned { sanitize::scan(fmt, &mut file, len)?.patches } else { Vec::new() };
        Ok(Source { file, len, patches })
    }

    /// Plaintext of chunk `i` (empty for padding chunks past the end).
    fn chunk(&mut self, i: u64) -> Result<Vec<u8>> {
        let start = i.saturating_mul(CHUNK as u64);
        if start >= self.len {
            return Ok(Vec::new());
        }
        let n = (self.len - start).min(CHUNK as u64) as usize;
        let mut buf = vec![0u8; n];
        self.file.seek(SeekFrom::Start(start))?;
        self.file.read_exact(&mut buf)?;
        sanitize::apply(&self.patches, start, &mut buf);
        Ok(buf)
    }
}

/// Where an upload's encrypted chunks come from: re-derived from the source
/// file, or (FFmpeg-rebuilt files) read from the encrypted outbox.
enum JobSource {
    File(Source, [u8; 32]),
    Outbox(super::local::LocalChunks, Arc<Vec<[u8; 32]>>),
}

impl JobSource {
    fn open(job: &UploadJob, local: &super::local::LocalChunks, addrs: Option<Arc<Vec<[u8; 32]>>>) -> Result<JobSource> {
        if job.remux.is_some() {
            return Ok(JobSource::Outbox(local.clone(), addrs.context("upload index missing")?));
        }
        Ok(JobSource::File(Source::open(&job.path, job.len, job.mtime, fmt_from(&job.fmt), job.cleaned)?, job.key))
    }

    /// Ciphertext of data chunk `i`.
    fn ct(&mut self, i: u64) -> Result<Vec<u8>> {
        match self {
            JobSource::File(src, key) => Ok(media::encrypt_chunk(key, i, &src.chunk(i)?)),
            JobSource::Outbox(local, addrs) => local.get(addrs.get(i as usize).context("chunk out of range")?).context("prepared chunk missing; attach the file again"),
        }
    }
}

/// Per-file fetch state: the resolved reference, all chunk addresses, and
/// connections used only for this file.
pub struct Session {
    pub r: MediaRef,
    hosts: Vec<String>,
    addrs: std::sync::OnceLock<Vec<[u8; 32]>>,
    streams: tokio::sync::Mutex<Vec<(String, Box<dyn Io>)>>,
    mem: Mutex<VecDeque<([u8; 32], Arc<Vec<u8>>)>>,
    /// Fetches in progress, shared so a chunk is never requested twice.
    inflight: Mutex<HashMap<[u8; 32], Arc<tokio::sync::OnceCell<Arc<Vec<u8>>>>>>,
    last: Mutex<Instant>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransferEvent {
    pub key: String,
    /// prepare | upload | download
    pub kind: String,
    pub done: u64,
    pub total: u64,
    /// running | done | error | cancelled
    pub state: String,
    pub error: Option<String>,
    pub path: Option<String>,
}

fn emit_transfer(app: &AppHandle, key: &str, kind: &str, done: u64, total: u64, state: &str, error: Option<String>, path: Option<String>) {
    let _ = app.emit(
        "transfer",
        TransferEvent { key: key.into(), kind: kind.into(), done, total, state: state.into(), error, path },
    );
}

impl Core {
    fn high_risk(&self) -> bool {
        self.with(|i| i.store.as_ref().is_some_and(|s| s.privacy.high_risk))
    }

    pub(super) fn local(&self) -> Result<super::local::LocalChunks> {
        self.with(|i| i.local.clone()).context("locked")
    }

    fn insert_attachment(&self, a: Attachment) -> String {
        let id = new_id();
        self.with(|i| {
            if i.attachments.len() >= 16 {
                i.attachments.clear(); // abandoned drafts
            }
            i.attachments.insert(id.clone(), a);
        });
        id
    }

    /// Attach bytes (small media pasted/picked in the page).
    pub async fn attach(&self, bytes: Vec<u8>) -> Result<Attached> {
        self.unlocked()?;
        let s = tokio::task::spawn_blocking(move || media::sanitize(&bytes)).await??;
        let out = Attached {
            id: String::new(),
            kind: s.kind.into(),
            width: s.width,
            height: s.height,
            size: s.bytes.len() as u64,
            name: default_name(s.kind, s.mime, None),
            inline: true,
            cleaned: true,
            partial: matches!(s.kind, "video" | "audio"),
        };
        let id = self.insert_attachment(Attachment::Inline(s));
        Ok(Attached { id, ..out })
    }

    /// Attach a file from disk (dialog or drag-and-drop). Small media is
    /// cleaned in memory and shown inline; everything else becomes a file
    /// attachment, cleaned in place where the format allows.
    pub async fn attach_path(&self, path: PathBuf) -> Result<Attached> {
        self.unlocked()?;
        let (meta, head) = {
            let p = path.clone();
            tokio::task::spawn_blocking(move || -> Result<(std::fs::Metadata, Vec<u8>)> {
                let mut f = std::fs::File::open(&p).context("couldn't open the file")?;
                let m = f.metadata()?;
                if !m.is_file() {
                    bail!("not a file");
                }
                let mut head = vec![0u8; 64];
                let n = f.read(&mut head)?;
                head.truncate(n);
                Ok((m, head))
            })
            .await??
        };
        let len = meta.len();
        if len > media::MAX_FILE {
            bail!("files over 1 TB can't be shared yet");
        }
        let fmt = sanitize::detect(&head);
        // Phones: audio and video are rebuilt by the phone's own encoders
        // into a fresh MP4 (then cleaned in place below, like any MP4).
        #[cfg(target_os = "android")]
        let (path, meta, len, fmt) = if matches!(fmt, Format::Mp4 | Format::Webm | Format::Matroska | Format::Mp3 | Format::Flac | Format::Wav) {
            let p = path.clone();
            match tokio::task::spawn_blocking(move || crate::android::rebuild(&p)).await? {
                Some(out) => {
                    let m = std::fs::metadata(&out)?;
                    let mut h = vec![0u8; 64];
                    let n = std::fs::File::open(&out)?.read(&mut h)?;
                    h.truncate(n);
                    let l = m.len();
                    (out, m, l, sanitize::detect(&h))
                }
                None => (path, meta, len, fmt),
            }
        } else {
            (path, meta, len, fmt)
        };
        // Audio and video: rebuild with the bundled FFmpeg when available
        // (re-encoded or remuxed into a fresh container: no device or app
        // fingerprints). Images keep their own re-encoder.
        if !matches!(fmt, Format::Image | Format::Gif) {
            if let Some(dir) = tokio::task::spawn_blocking(super::ffmpeg::locate).await? {
                let (d, p) = (dir.clone(), path.clone());
                if let Some(plan) = tokio::task::spawn_blocking(move || super::ffmpeg::probe(&d, &p, len)).await? {
                    let (kind, mime) = plan.kind();
                    if len as usize <= 2 * media::MAX_INLINE {
                        let (d, p, pl) = (dir.clone(), path.clone(), plan.clone());
                        if let Some(bytes) = tokio::task::spawn_blocking(move || super::ffmpeg::clean_to_memory(&d, &p, &pl, media::MAX_INLINE)).await? {
                            let size = bytes.len() as u64;
                            let s = Sanitized { bytes, kind, mime, width: plan.width, height: plan.height };
                            let id = self.insert_attachment(Attachment::Inline(s));
                            return Ok(Attached { id, kind: kind.into(), width: plan.width, height: plan.height, size, name: default_name(kind, mime, None), inline: true, cleaned: true, partial: false });
                        }
                    }
                    let name = default_name(kind, mime, None);
                    let dims = (plan.width, plan.height);
                    let pf = PendingFile { path, len, mtime: mtime_of(&meta), fmt: Format::Other, kind, mime, dims, name: name.clone(), remux: Some(plan) };
                    let id = self.insert_attachment(Attachment::File(pf));
                    return Ok(Attached { id, kind: kind.into(), width: dims.0, height: dims.1, size: len, name, inline: false, cleaned: true, partial: false });
                }
            }
        }
        let small = match fmt {
            Format::Image => len as usize <= media::MAX_IMAGE_INPUT,
            Format::Gif | Format::Mp4 | Format::Webm | Format::Mp3 | Format::Flac | Format::Wav => len as usize <= media::MAX_INLINE,
            _ => false,
        };
        if small {
            let bytes = tokio::fs::read(&path).await?;
            if let Ok(a) = self.attach(bytes).await {
                return Ok(a);
            }
            if fmt == Format::Image {
                bail!("this image couldn't be read");
            }
        }
        let (kind, mime) = media::kind_of(fmt);
        // Find the metadata now, so a file we can't clean is refused before
        // it is ever queued (never share a "cleanable" file uncleaned).
        let dims = if fmt.cleaned() && fmt != Format::Image && fmt != Format::Gif {
            let p = path.clone();
            tokio::task::spawn_blocking(move || -> Result<(u32, u32)> {
                let mut f = std::fs::File::open(&p)?;
                Ok(sanitize::scan(fmt, &mut f, len).map_err(|e| anyhow!("{e} — it can't be shared with its metadata removed"))?.dims)
            })
            .await??
        } else {
            (0, 0)
        };
        let (fmt, kind, mime) = if fmt == Format::Image || fmt == Format::Gif {
            // Too large to re-encode: share as an opaque file.
            (Format::Other, "file", "application/octet-stream")
        } else {
            (fmt, kind, mime)
        };
        let (kind, mime) = if fmt == Format::Mp4 && dims == (0, 0) { ("audio", "audio/mp4") } else { (kind, mime) };
        let name = default_name(kind, mime, Some(&path));
        let pf = PendingFile { path, len, mtime: mtime_of(&meta), fmt, kind, mime, dims, name: name.clone(), remux: None };
        let id = self.insert_attachment(Attachment::File(pf));
        Ok(Attached { id, kind: kind.into(), width: dims.0, height: dims.1, size: len, name, inline: false, cleaned: fmt.cleaned(), partial: fmt.cleaned() && matches!(kind, "video" | "audio") })
    }

    pub fn rename_attachment(&self, id: &str, name: &str) -> Result<String> {
        let name = clean_name(name).context("Names can't be empty.")?;
        self.with(|i| match i.attachments.get_mut(id) {
            Some(Attachment::File(f)) => {
                f.name = name.clone();
                Ok(name)
            }
            _ => Err(anyhow!("no such file")),
        })
    }

    pub fn discard_attachment(&self, id: &str) {
        self.with(|i| {
            i.attachments.remove(id);
        });
    }

    /// Decrypted bytes of an attachment still in compose (inline previews).
    pub fn attachment_bytes(&self, id: &str) -> Result<Vec<u8>> {
        self.with(|i| match i.attachments.get(id) {
            Some(Attachment::Inline(s)) => Ok(s.bytes.clone()),
            _ => Err(anyhow!("no preview")),
        })
    }

    /// Where new media goes: two Archives from the directory (never this
    /// device's own hosted node), else my Pillar and its backup.
    pub(super) fn media_hosts(&self) -> Result<Vec<String>> {
        self.media_hosts_n(COPIES)
    }

    /// Up to `n` distinct Archives (never my own), falling back to my
    /// Pillar and its backup.
    pub(super) fn media_hosts_n(&self, n: usize) -> Result<Vec<String>> {
        let (_, store) = self.unlocked()?;
        let own = self.with(|i| i.hosted.as_ref().map(|h| h.onion.clone()));
        // Never my own node; skip Archives that keep failing storage checks.
        let mut archives: Vec<String> = store
            .known_archives
            .iter()
            .filter(|a| Some(*a) != own.as_ref())
            .filter(|a| !store.archive_health.get(*a).is_some_and(|h| h.unreliable()))
            .cloned()
            .collect();
        super::shuffle(&mut archives);
        archives.truncate(n);
        if archives.is_empty() {
            archives.extend(store.pillar.iter().cloned());
            archives.extend(store.replicas.iter().take(COPIES - 1).cloned());
        }
        // Opt-in self-seeding: my own Archive holds a copy too.
        if store.self_seed && !store.privacy.high_risk {
            if let Some(o) = own {
                if !archives.contains(&o) && archives.len() < 16 {
                    archives.push(o);
                }
            }
        }
        if archives.is_empty() {
            bail!("no storage available yet; connect first");
        }
        Ok(archives)
    }

    /// Turn compose attachments into ready inline media (encrypted now,
    /// chunks kept in the outbox) and upload jobs for files.
    pub(super) fn take_attachments(&self, ids: &[String]) -> Result<(Vec<MediaRef>, Vec<String>, Vec<UploadJob>)> {
        let local = self.local()?;
        let hosts = self.media_hosts()?;
        // Large files: erasure-code across up to 6 Archives when at least 3
        // are known (any one can vanish); otherwise replicate.
        let (file_hosts, layout) = {
            let wide = self.media_hosts_n(6)?;
            match sentinel_core::erasure::Layout::for_hosts(wide.len()) {
                Some(l) => (wide, Some(l)),
                None => (hosts.clone(), None),
            }
        };
        let mut ready = Vec::new();
        let mut pending = Vec::new();
        let mut jobs = Vec::new();
        for id in ids.iter().take(4) {
            let Some(a) = self.with(|i| i.attachments.remove(id)) else { continue };
            match a {
                Attachment::Inline(s) => {
                    let (mut r, chunks) = media::encrypt_file(&s);
                    for (addr, ct) in r.chunks.iter().zip(chunks) {
                        local.put_outbox(addr, &ct)?;
                        pending.push(data_encoding::HEXLOWER.encode(addr));
                    }
                    r.archives = hosts.clone();
                    ready.push(r);
                }
                Attachment::File(f) => {
                    let real = f.len.div_ceil(CHUNK as u64).max(1);
                    jobs.push(UploadJob {
                        path: f.path.to_string_lossy().into_owned(),
                        len: f.len,
                        mtime: f.mtime,
                        fmt: fmt_name(f.fmt).into(),
                        kind: f.kind.into(),
                        mime: f.mime.into(),
                        width: f.dims.0,
                        height: f.dims.1,
                        name: f.name,
                        cleaned: f.fmt.cleaned() || f.remux.is_some(),
                        key: sentinel_core::random_bytes::<32>(),
                        total: media::bucket(real),
                        manifest: Vec::new(),
                        hosts: file_hosts.clone(),
                        done: 0,
                        manifest_sent: false,
                        v: 1,
                        ec: layout,
                        remux: f.remux.clone(),
                        error: None,
                    });
                }
            }
        }
        Ok((ready, pending, jobs))
    }

    /// Upload a post's small-media chunks from the outbox to every host,
    /// then move them to the cache.
    pub(super) async fn upload_chunks(&self, post_id: &str, chunks: &[String], hosts: &[String]) -> Result<()> {
        let local = self.local()?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        for host in hosts {
            let mut s = net.connect_hedged(host).await?;
            for name in chunks {
                let addr: [u8; 32] = data_encoding::HEXLOWER.decode(name.as_bytes())?.try_into().map_err(|_| anyhow!("bad chunk"))?;
                let data = local.get(&addr).context("media missing from the outbox")?;
                put_chunk(&mut s, data).await?;
            }
        }
        let cache = !self.high_risk();
        for name in chunks {
            if let Ok(addr) = <[u8; 32]>::try_from(data_encoding::HEXLOWER.decode(name.as_bytes()).unwrap_or_default()) {
                if let Some(ct) = local.get(&addr) {
                    local.put_cache(&addr, &ct, cache);
                }
                local.remove_outbox(&addr);
            }
        }
        self.update(|st| {
            if let Some(p) = st.posts.iter_mut().find(|p| p.id == post_id) {
                p.pending_chunks.clear();
            }
        })
    }

    /* ---------------- large uploads ---------------- */

    /// Background uploader: prepares and uploads draft jobs one at a time,
    /// then seals and publishes the post. Runs until the app locks.
    pub(super) async fn run_uploader(self: Arc<Self>, app: AppHandle) {
        loop {
            let next = self.unlocked().ok().and_then(|(_, s)| {
                s.posts.iter().find_map(|p| {
                    let d = p.draft.as_ref()?;
                    d.jobs.iter().position(|j| !j.finished()).map(|ji| (p.id.clone(), ji)).or(Some((p.id.clone(), usize::MAX)))
                })
            });
            match next {
                None => tokio::time::sleep(Duration::from_secs(15)).await,
                Some((post_id, usize::MAX)) => {
                    match self.seal_draft(&post_id) {
                        // Send right away (a High-risk delay, if any, still applies).
                        Ok(()) => {
                            self.flush_outbox().await;
                        }
                        Err(e) => {
                            self.set_job_error(&post_id, 0, &e.to_string());
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                    }
                    let _ = app.emit("timeline", ());
                }
                Some((post_id, ji)) => {
                    let key = format!("{post_id}:{ji}");
                    match self.run_job(&app, &post_id, ji).await {
                        Ok(()) => emit_transfer(&app, &key, "upload", 1, 1, "done", None, None),
                        Err(e) => {
                            self.set_job_error(&post_id, ji, &e.to_string());
                            emit_transfer(&app, &key, "upload", 0, 1, "error", Some(e.to_string()), None);
                            tokio::time::sleep(Duration::from_secs(60)).await; // retry later
                        }
                    }
                    let _ = app.emit("timeline", ());
                }
            }
        }
    }

    fn set_job_error(&self, post_id: &str, ji: usize, e: &str) {
        let _ = self.update(|s| {
            if let Some(j) = s.posts.iter_mut().find(|p| p.id == post_id).and_then(|p| p.draft.as_mut()).and_then(|d| d.jobs.get_mut(ji)) {
                j.error = Some(e.chars().take(200).collect());
            }
        });
    }

    fn job(&self, post_id: &str, ji: usize) -> Result<UploadJob> {
        let (_, s) = self.unlocked()?;
        s.posts.iter().find(|p| p.id == post_id).and_then(|p| p.draft.as_ref()).and_then(|d| d.jobs.get(ji)).cloned().context("job gone")
    }

    fn save_job(&self, post_id: &str, ji: usize, f: impl FnOnce(&mut UploadJob)) -> Result<()> {
        self.update(|s| {
            if let Some(j) = s.posts.iter_mut().find(|p| p.id == post_id).and_then(|p| p.draft.as_mut()).and_then(|d| d.jobs.get_mut(ji)) {
                f(j);
            }
        })
    }

    async fn run_job(&self, app: &AppHandle, post_id: &str, ji: usize) -> Result<()> {
        let key = format!("{post_id}:{ji}");
        let mut job = self.job(post_id, ji)?;
        let local = self.local()?;
        // Pass 1: derive every chunk address, build the encrypted manifest.
        if job.manifest.is_empty() && job.remux.is_some() {
            let j = job.clone();
            let l = local.clone();
            let app2 = app.clone();
            let key2 = key.clone();
            let (manifest, len, total) = tokio::task::spawn_blocking(move || prepare_remux(&j, &l, &app2, &key2)).await??;
            self.save_job(post_id, ji, |j| {
                j.manifest = manifest.clone();
                j.len = len;
                j.total = total;
                j.error = None;
            })?;
            job.manifest = manifest;
            job.len = len;
            job.total = total;
        }
        if job.manifest.is_empty() {
            let j = job.clone();
            let l = local.clone();
            let app2 = app.clone();
            let key2 = key.clone();
            let manifest = tokio::task::spawn_blocking(move || -> Result<Vec<[u8; 32]>> {
                let mut src = Source::open(&j.path, j.len, j.mtime, fmt_from(&j.fmt), j.cleaned)?;
                let mut addrs = Vec::with_capacity(j.total as usize);
                let mut parity_addrs = Vec::new();
                let per = j.ec.map(|l| l.data as u64).unwrap_or(j.total.max(1));
                let mut stripe: Vec<Vec<u8>> = Vec::new();
                for i in 0..j.total {
                    let plain = src.chunk(i)?;
                    let ct = media::encrypt_chunk(&j.key, i, &plain);
                    addrs.push(media::address(&ct));
                    if let Some(l) = j.ec {
                        stripe.push(ct);
                        if stripe.len() as u64 == per || i + 1 == j.total {
                            parity_addrs.extend(l.encode(&stripe).iter().map(|c| media::address(c)));
                            stripe.clear();
                        }
                    }
                    if i % 64 == 0 {
                        emit_transfer(&app2, &key2, "prepare", i, j.total, "running", None, None);
                    }
                }
                addrs.extend(parity_addrs);
                let (maddrs, mchunks) = media::build_manifest(&j.key, &addrs);
                for (a, c) in maddrs.iter().zip(mchunks) {
                    l.put_outbox(a, &c)?;
                }
                Ok(maddrs)
            })
            .await??;
            self.save_job(post_id, ji, |j| {
                j.manifest = manifest.clone();
                j.error = None;
            })?;
            job.manifest = manifest;
        }
        let r = job.media_ref();
        let addrs = Arc::new(manifest_addrs(&local, &r)?);
        let net = self.with(|i| i.net.clone()).context("not connected")?;

        // Pass 2: re-derive, encrypt and upload chunks in parallel.
        let next = Arc::new(AtomicU64::new(job.done));
        let completed = Arc::new(Mutex::new(BTreeSet::<u64>::new()));
        let frontier = Arc::new(AtomicU64::new(job.done));
        let failed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let mut tasks = Vec::new();
        let units = job.units();
        for _ in 0..WORKERS.min(units.saturating_sub(job.done).max(1) as usize) {
            let (job, addrs, next, completed, frontier, failed, net, local) =
                (job.clone(), Arc::clone(&addrs), Arc::clone(&next), Arc::clone(&completed), Arc::clone(&frontier), Arc::clone(&failed), net.clone(), local.clone());
            tasks.push(tokio::spawn(async move {
                let res: Result<()> = async {
                    let mut src = JobSource::open(&job, &local, Some(Arc::clone(&addrs)))?;
                    let mut streams: HashMap<String, Box<dyn Io>> = HashMap::new();
                    loop {
                        if failed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_some() {
                            return Ok(());
                        }
                        let i = next.fetch_add(1, Ordering::SeqCst);
                        if i >= job.units() {
                            return Ok(());
                        }
                        match job.ec {
                            None => {
                                let ct = tokio::task::block_in_place(|| src.ct(i))?;
                                if media::address(&ct) != addrs[i as usize] {
                                    bail!("the original file changed during upload; attach it again");
                                }
                                for host in &job.hosts {
                                    put_with_retry(&net, &mut streams, host, &ct).await?;
                                }
                            }
                            Some(l) => {
                                // Stripe i: re-derive its data chunks and parity,
                                // check every address, send each chunk to its
                                // one Archive.
                                let first = i * l.data as u64;
                                let last = (first + l.data as u64).min(job.total);
                                let mut cts = Vec::new();
                                for c in first..last {
                                    let ct = tokio::task::block_in_place(|| src.ct(c))?;
                                    if media::address(&ct) != addrs[c as usize] {
                                        bail!("the original file changed during upload; attach it again");
                                    }
                                    cts.push(ct);
                                }
                                let parity = tokio::task::block_in_place(|| l.encode(&cts));
                                for (pi, pc) in parity.iter().enumerate() {
                                    if media::address(pc) != addrs[l.parity_pos(job.total, i, pi as u64) as usize] {
                                        bail!("upload index inconsistent");
                                    }
                                }
                                for (t, ct) in cts.iter().enumerate() {
                                    put_with_retry(&net, &mut streams, &job.hosts[l.host_of(i, t as u64)], ct).await?;
                                }
                                for (pi, pc) in parity.iter().enumerate() {
                                    put_with_retry(&net, &mut streams, &job.hosts[l.host_of(i, (l.data as usize + pi) as u64)], pc).await?;
                                }
                            }
                        }
                        let mut c = completed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        c.insert(i);
                        let mut f = frontier.load(Ordering::SeqCst);
                        while c.remove(&f) {
                            f += 1;
                        }
                        frontier.store(f, Ordering::SeqCst);
                    }
                }
                .await;
                if let Err(e) = res {
                    *failed.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(e.to_string());
                }
            }));
        }
        // Persist progress while workers run.
        let mut last_saved = job.done;
        loop {
            let all_done = tasks.iter().all(|t| t.is_finished());
            let f = frontier.load(Ordering::SeqCst);
            if f != last_saved && (f - last_saved >= 8 || all_done) {
                self.save_job(post_id, ji, |j| j.done = f)?;
                last_saved = f;
            }
            emit_transfer(app, &key, "upload", f, units, "running", None, None);
            if all_done {
                break;
            }
            if self.unlocked().is_err() {
                for t in &tasks {
                    t.abort();
                }
                bail!("locked");
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
        }
        if let Some(e) = failed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
            bail!(e);
        }
        if frontier.load(Ordering::SeqCst) < units {
            bail!("upload incomplete");
        }
        // The manifest goes last: the post is only readable once complete.
        let mut streams: HashMap<String, Box<dyn Io>> = HashMap::new();
        for a in &job.manifest {
            let ct = local.get(a).context("manifest missing")?;
            for host in &job.hosts {
                put_with_retry(&net, &mut streams, host, &ct).await?;
            }
        }
        // Storage challenges for later audits, made while the source is
        // still here (it is forgotten when the post is sealed).
        let j = job.clone();
        let (l2, a2) = (local.clone(), Arc::clone(&addrs));
        let audits = tokio::task::spawn_blocking(move || make_audits(&j, &l2, a2)).await?.unwrap_or_default();
        self.update(|s| s.audits.extend(audits))?;
        // Rebuilt files: the encrypted copy is no longer needed locally.
        if job.remux.is_some() {
            let manifest: std::collections::HashSet<[u8; 32]> = job.manifest.iter().copied().collect();
            for a in addrs.iter().filter(|a| !manifest.contains(*a)) {
                local.remove_outbox(a);
            }
        }
        self.save_job(post_id, ji, |j| {
            j.done = j.units();
            j.manifest_sent = true;
            j.error = None;
        })
    }

    /// All jobs done: seal the post with every media reference and queue it.
    fn seal_draft(&self, post_id: &str) -> Result<()> {
        let (key, store) = self.unlocked()?;
        let p = store.posts.iter().find(|p| p.id == post_id).context("post gone")?;
        let d = p.draft.clone().context("not a draft")?;
        let feed_key = if d.approved_only { self.circle_key()? } else { store.feed_key.context("no feed key")? };
        let mut all = d.ready.clone();
        all.extend(d.jobs.iter().map(|j| j.media_ref()));
        let env = sentinel_core::social::post_envelope_full(&key, &feed_key, &d.text, &d.topics, d.discoverable, all.clone())
            .map_err(|e| anyhow!(e))?;
        let bytes = env.encode()?;
        let id = sentinel_core::object::Address::of(&bytes).to_text();
        let minute = sentinel_core::social::coarse_minute();
        let delay = if store.privacy.high_risk { super::high_risk_delay() } else { 0 };
        self.update(|s| {
            if let Some(p) = s.posts.iter_mut().find(|p| p.id == post_id) {
                p.not_before = delay;
                p.id = id.clone();
                p.raw = Some(bytes);
                p.media = all;
                p.minute = minute;
                p.draft = None; // forgets the source paths
            }
        })
    }

    /* ---------------- reading ---------------- */

    /// Find a media reference by post and index, and the hosts to fetch from.
    fn resolve(&self, post_id: &str, index: usize) -> Result<(MediaRef, Vec<String>)> {
        // Profile pictures: "avatar:<author>" / "banner:<author>".
        for (prefix, shape) in [("avatar:", media::Shape::Avatar), ("banner:", media::Shape::Banner)] {
            if let Some(author) = post_id.strip_prefix(prefix) {
                let (r, fallback) = self.profile_media(author, shape)?;
                if !r.validate() || !r.inline() {
                    bail!("this picture reference is invalid");
                }
                let hosts = if r.archives.is_empty() { fallback.into_iter().collect() } else { r.archives.clone() };
                return Ok((r, hosts));
            }
        }
        let (_, store) = self.unlocked()?;
        let (r, fallback) = if let Some(p) = store.posts.iter().find(|p| p.id == post_id) {
            let r = match &p.draft {
                Some(d) => d.ready.get(index).cloned(),
                None => p.media.get(index).cloned(),
            }
            .context("no such media")?;
            let pillar = if p.mine {
                store.pillar.clone()
            } else {
                store.following.iter().find(|f| f.author == p.author).map(|f| f.pillar.clone())
            };
            (r, pillar)
        } else if let Some(d) = store.discovered.iter().find(|d| d.id == post_id) {
            (d.media.get(index).cloned().context("no such media")?, Some(d.pillar.clone()))
        } else {
            bail!("no such post");
        };
        if !r.validate() {
            bail!("this media reference is invalid");
        }
        let hosts = if r.archives.is_empty() { fallback.into_iter().collect() } else { r.archives.clone() };
        Ok((r, hosts))
    }

    async fn session(&self, post_id: &str, index: usize) -> Result<Arc<Session>> {
        let k = format!("{post_id}:{index}");
        let now = Instant::now();
        let existing = self.with(|i| {
            i.sessions.retain(|_, s| now.duration_since(*s.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner)) < SESSION_IDLE);
            i.sessions.get(&k).cloned()
        });
        if let Some(s) = existing {
            *s.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = now;
            return Ok(s);
        }
        let (r, hosts) = self.resolve(post_id, index)?;
        let sess = Arc::new(Session {
            r: r.clone(),
            hosts,
            addrs: std::sync::OnceLock::new(),
            streams: tokio::sync::Mutex::new(Vec::new()),
            mem: Mutex::new(VecDeque::new()),
            inflight: Mutex::new(HashMap::new()),
            last: Mutex::new(now),
        });
        // Warm several circuits for this file in the background: building a
        // circuit (seconds) is the main cost of reading over Tor.
        if r.real_chunks() > 1 || !r.manifest.is_empty() {
            self.warm(&sess);
        }
        let addrs = if r.manifest.is_empty() {
            r.chunks.clone()
        } else {
            let parts = futures::future::try_join_all(r.manifest.iter().map(|a| self.fetch_chunk(&sess, a))).await?;
            let mut addrs = Vec::new();
            for (i, ct) in parts.iter().enumerate() {
                addrs.extend(media::open_manifest_chunk(&r, i, ct).context("media index failed to verify")?);
            }
            if addrs.len() as u64 != r.entries() {
                bail!("media index is inconsistent");
            }
            addrs
        };
        let _ = sess.addrs.set(addrs);
        self.with(|i| i.sessions.insert(k, Arc::clone(&sess)));
        Ok(sess)
    }

    /// Open `WARM_STREAMS` circuits per host in the background, used only
    /// for this file (so an Archive can't link it with other files).
    fn warm(&self, sess: &Arc<Session>) {
        let Some(net) = self.with(|i| i.net.clone()) else { return };
        for h in &sess.hosts {
            for _ in 0..WARM_STREAMS {
                let (net, h, sess) = (net.clone(), h.clone(), Arc::downgrade(sess));
                tokio::spawn(async move {
                    if let Ok(s) = net.connect_hedged(&h).await {
                        if let Some(sess) = sess.upgrade() {
                            sess.streams.lock().await.push((h, s));
                        }
                    }
                });
            }
        }
    }

    /// One encrypted chunk: memory, local store, then the hosts in random
    /// order. Verified against its address. Hosts that lacked it are healed
    /// in the background (re-uploaded on an isolated circuit).
    async fn fetch_chunk(&self, sess: &Session, addr: &[u8; 32]) -> Result<Vec<u8>> {
        self.fetch_chunk_from(sess, addr, None).await
    }

    /// Like `fetch_chunk`, but only from `only` (erasure-coded chunks live
    /// on exactly one Archive).
    async fn fetch_chunk_from(&self, sess: &Session, addr: &[u8; 32], only: Option<&str>) -> Result<Vec<u8>> {
        if let Some(b) = sess.mem.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().find(|(a, _)| a == addr).map(|(_, b)| Arc::clone(b)) {
            return Ok((*b).clone());
        }
        let local = self.local()?;
        if let Some(ct) = local.get(addr) {
            return Ok(ct);
        }
        let cell = Arc::clone(sess.inflight.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(*addr).or_default());
        let r = cell.get_or_try_init(|| async { self.fetch_network(sess, addr, only).await.map(Arc::new) }).await.map(|v| (**v).clone());
        sess.inflight.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(addr);
        r
    }

    async fn fetch_network(&self, sess: &Session, addr: &[u8; 32], only: Option<&str>) -> Result<Vec<u8>> {
        let local = self.local()?;
        let net = self.with(|i| i.net.clone()).context("not connected")?;
        let mut hosts = match only {
            Some(h) => vec![h.to_owned()],
            None => sess.hosts.clone(),
        };
        super::shuffle(&mut hosts);
        let mut missing: Vec<String> = Vec::new();
        for host in &hosts {
            let pooled = {
                let mut st = sess.streams.lock().await;
                st.iter().position(|(h, _)| h == host).map(|i| st.remove(i).1)
            };
            let mut s = match pooled {
                Some(s) => s,
                None => match net.connect_hedged(host).await {
                    Ok(s) => s,
                    Err(_) => continue,
                },
            };
            match request(&mut s, &Request::GetChunk(*addr)).await {
                Ok(Response::Object(ct)) if media::address(&ct) == *addr => {
                    sess.streams.lock().await.push((host.clone(), s));
                    local.put_cache(addr, &ct, !self.high_risk());
                    {
                        let mut m = sess.mem.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        m.push_back((*addr, Arc::new(ct.clone())));
                        while m.len() > 2 * READ_AHEAD as usize + 4 {
                            m.pop_front();
                        }
                    }
                    for h in missing {
                        let (net, ct) = (net.clone(), ct.clone());
                        tokio::spawn(async move {
                            if let Ok(mut s) = net.connect_hedged(&h).await {
                                let _ = put_chunk(&mut s, ct).await;
                            }
                        });
                    }
                    return Ok(ct);
                }
                Ok(Response::NotFound) => {
                    sess.streams.lock().await.push((host.clone(), s));
                    missing.push(host.clone());
                }
                _ => {} // broken stream or bad data: drop it, try the next host
            }
        }
        Err(super::local::not_found())
    }

    async fn plain_chunk(&self, sess: &Session, i: u64) -> Result<Vec<u8>> {
        let addr = *sess.addrs.get().and_then(|a| a.get(i as usize)).context("chunk out of range")?;
        let ct = match sess.r.ec {
            None => self.fetch_chunk(sess, &addr).await?,
            Some(l) => {
                let (st, t) = (i / l.data as u64, i % l.data as u64);
                let host = sess.hosts.get(l.host_of(st, t)).context("bad layout")?;
                match self.fetch_chunk_from(sess, &addr, Some(host)).await {
                    Ok(ct) => ct,
                    // Its Archive lost it or is gone: rebuild from the stripe.
                    Err(_) => self.rebuild(sess, l, st, t, &addr).await?,
                }
            }
        };
        media::decrypt_chunk_at(&sess.r, &addr, i, &ct).context("media chunk failed to decrypt")
    }

    /// Rebuild data chunk `t` of stripe `st` from the others (fetched in
    /// parallel, each from its own Archive), verify it, and give it back to
    /// the Archive that should hold it.
    async fn rebuild(&self, sess: &Session, l: sentinel_core::erasure::Layout, st: u64, t: u64, addr: &[u8; 32]) -> Result<Vec<u8>> {
        let addrs = sess.addrs.get().context("no index")?;
        let total = sess.r.total_chunks();
        let first = st * l.data as u64;
        let real = ((first + l.data as u64).min(total) - first) as usize;
        let mut wanted: Vec<(usize, [u8; 32], String)> = Vec::new();
        for k in 0..real {
            if k as u64 != t {
                wanted.push((k, addrs[(first + k as u64) as usize], sess.hosts[l.host_of(st, k as u64)].clone()));
            }
        }
        for pi in 0..l.parity as u64 {
            let pos = l.parity_pos(total, st, pi) as usize;
            wanted.push((l.data as usize + pi as usize, addrs[pos], sess.hosts[l.host_of(st, l.data as u64 + pi)].clone()));
        }
        let got = futures::future::join_all(wanted.iter().map(|(k, a, h)| async move { (*k, self.fetch_chunk_from(sess, a, Some(h)).await.ok()) })).await;
        let mut have: Vec<Option<Vec<u8>>> = vec![None; (l.data + l.parity) as usize];
        for (k, c) in got {
            have[k] = c;
        }
        let data = l.reconstruct(have, real).context("too many pieces of this file are gone")?;
        let ct = data.into_iter().nth(t as usize).context("rebuild failed")?;
        if media::address(&ct) != *addr {
            bail!("rebuilt chunk failed verification");
        }
        // Heal: return the chunk to its Archive in the background.
        if let Some(net) = self.with(|i| i.net.clone()) {
            let (host, c) = (sess.hosts[l.host_of(st, t)].clone(), ct.clone());
            tokio::spawn(async move {
                if let Ok(mut s) = net.connect_hedged(&host).await {
                    let _ = put_chunk(&mut s, c).await;
                }
            });
        }
        Ok(ct)
    }

    /// Decrypted bytes of one inline media item (images, GIFs, short clips).
    pub async fn media_bytes(&self, post_id: &str, index: usize) -> Result<Vec<u8>> {
        let sess = self.session(post_id, index).await?;
        if !sess.r.inline() {
            bail!("too large to display inline");
        }
        let mut out = Vec::with_capacity(sess.r.size as usize);
        for i in 0..sess.r.real_chunks() {
            out.extend(self.plain_chunk(&sess, i).await?);
        }
        out.truncate(sess.r.size as usize);
        Ok(out)
    }

    /// Serve a byte range of streamable media to the player (local URL
    /// scheme). At most two chunks per response; the player asks for more.
    pub async fn stream_range(self: &Arc<Self>, post_id: &str, index: usize, range: Option<&str>) -> Result<(Vec<u8>, u64, u64, u64, String)> {
        let sess = self.session(post_id, index).await?;
        if !(sess.r.streamable() || sess.r.inline()) {
            bail!("not streamable");
        }
        let size = sess.r.size;
        let (start, end) = parse_range(range, size).context("bad range")?;
        let first = start / CHUNK as u64;
        let last = (end / CHUNK as u64).min(first + 1);
        let mut data = Vec::new();
        for i in first..=last {
            data.extend(self.plain_chunk(&sess, i).await?);
        }
        let off = (start - first * CHUNK as u64) as usize;
        let take = ((end - start + 1) as usize).min(data.len().saturating_sub(off));
        let body = data[off..off + take].to_vec();
        let mime = sess.r.mime.clone();
        // Read ahead the next chunks in parallel (memory only), each on its
        // own circuit, so playback outruns a single Tor circuit's speed.
        let real = sess.r.real_chunks();
        for i in (last + 1)..(last + 1 + READ_AHEAD).min(real) {
            let (core, sess) = (Arc::clone(self), Arc::clone(&sess));
            tokio::spawn(async move {
                let _ = core.plain_chunk(&sess, i).await;
            });
        }
        let end = start + body.len() as u64 - 1;
        Ok((body, start, end, size, mime))
    }

    /// Download a file to a path the user chose (explicit save only).
    pub async fn save_media(self: &Arc<Self>, app: AppHandle, post_id: String, index: usize, path: PathBuf) -> Result<()> {
        let sess = self.session(&post_id, index).await?;
        let key = format!("{post_id}:{index}");
        let cancel = Arc::new(AtomicBool::new(false));
        self.with(|i| i.transfers.insert(key.clone(), Arc::clone(&cancel)));
        let part = path.with_extension(format!(
            "{}sentinel-part",
            path.extension().map(|e| format!("{}.", e.to_string_lossy())).unwrap_or_default()
        ));
        let core = Arc::clone(self);
        tokio::spawn(async move {
            let res = core.download(&app, &key, &sess, &part, &cancel).await;
            core.with(|i| i.transfers.remove(&key));
            match res {
                Ok(()) => match std::fs::rename(&part, &path).map_err(anyhow::Error::from).and_then(|()| crate::dialog::finish_save(&path)) {
                    Ok(()) => emit_transfer(&app, &key, "download", 1, 1, "done", None, Some(path.to_string_lossy().into())),
                    Err(e) => emit_transfer(&app, &key, "download", 0, 1, "error", Some(e.to_string()), None),
                },
                Err(e) => {
                    let _ = std::fs::remove_file(&part);
                    let state = if cancel.load(Ordering::SeqCst) { "cancelled" } else { "error" };
                    emit_transfer(&app, &key, "download", 0, 1, state, Some(e.to_string()), None);
                }
            }
        });
        Ok(())
    }

    async fn download(self: &Arc<Self>, app: &AppHandle, key: &str, sess: &Arc<Session>, part: &std::path::Path, cancel: &Arc<AtomicBool>) -> Result<()> {
        let size = sess.r.size;
        let file = std::fs::File::create(part)?;
        file.set_len(size)?;
        let file = Arc::new(Mutex::new(file));
        let real = sess.r.real_chunks();
        // Padding chunks are fetched too (and discarded), so an Archive sees
        // the padded size, not the real one.
        let total = sess.r.total_chunks();
        let next = Arc::new(AtomicU64::new(0));
        let done = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();
        for _ in 0..WORKERS {
            let (sess, file, next, done, cancel) = (Arc::clone(sess), Arc::clone(&file), Arc::clone(&next), Arc::clone(&done), Arc::clone(cancel));
            let core = Arc::clone(self);
            tasks.push(tokio::spawn(async move {
                loop {
                    if cancel.load(Ordering::SeqCst) {
                        bail!("cancelled");
                    }
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= total {
                        return Ok(());
                    }
                    // Same path as playback: right Archive first, rebuild
                    // from the stripe if needed, verified and decrypted.
                    let mut tries = 0;
                    let plain = loop {
                        match core.plain_chunk(&sess, i).await {
                            Ok(p) => break p,
                            Err(e) if tries >= 3 => return Err(e),
                            Err(_) => {
                                tries += 1;
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                        }
                    };
                    if i < real {
                        let mut f = file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        f.seek(SeekFrom::Start(i * CHUNK as u64))?;
                        std::io::Write::write_all(&mut *f, &plain)?;
                    }
                    done.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        loop {
            let finished = tasks.iter().all(|t| t.is_finished());
            emit_transfer(app, key, "download", done.load(Ordering::SeqCst), total, "running", None, None);
            if finished {
                break;
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
        }
        for t in tasks {
            t.await??;
        }
        file.lock().unwrap_or_else(std::sync::PoisonError::into_inner).sync_all()?;
        Ok(())
    }

    /// Delete one of my posts that hasn't been published yet.
    pub fn discard_draft(&self, post_id: &str) -> Result<()> {
        self.update(|s| s.posts.retain(|p| !(p.id == post_id && p.mine && !p.sent)))
    }

    pub fn cancel_transfer(&self, key: &str) {
        self.with(|i| {
            if let Some(c) = i.transfers.get(key) {
                c.store(true, Ordering::SeqCst);
            }
        });
    }

    /// Which Archive holds which chunks of an item (data, parity and
    /// manifest), for pinning.
    pub(super) async fn media_placement(&self, post_id: &str, index: usize) -> Result<(Vec<(String, Vec<[u8; 32]>)>, MediaRef)> {
        let sess = self.session(post_id, index).await?;
        let r = sess.r.clone();
        let addrs = sess.addrs.get().cloned().unwrap_or_default();
        let mut by: Vec<(String, Vec<[u8; 32]>)> = sess.hosts.iter().map(|h| (h.clone(), r.manifest.clone())).collect();
        match r.ec {
            None => {
                for (_, v) in by.iter_mut() {
                    v.extend(addrs.iter().copied());
                }
            }
            Some(l) => {
                let total = r.total_chunks();
                for i in 0..total {
                    let (st, t) = (i / l.data as u64, i % l.data as u64);
                    by[l.host_of(st, t)].1.push(addrs[i as usize]);
                }
                for st in 0..l.stripes(total) {
                    for pi in 0..l.parity as u64 {
                        by[l.host_of(st, l.data as u64 + pi)].1.push(addrs[l.parity_pos(total, st, pi) as usize]);
                    }
                }
            }
        }
        Ok((by, r))
    }

    /// Display name for a save dialog.
    pub fn media_name(&self, post_id: &str, index: usize) -> Result<String> {
        let (r, _) = self.resolve(post_id, index)?;
        Ok(r.name.clone().and_then(|n| clean_name(&n)).unwrap_or_else(|| default_name(&r.kind, &r.mime, None)))
    }
}

/// Pass 1 for FFmpeg-rebuilt files: stream FFmpeg's output straight into
/// encrypted chunks in the outbox (no plaintext copy on disk), pad to the
/// size bucket, add parity, build the manifest. Returns (manifest, real
/// length, total chunks).
fn prepare_remux(job: &UploadJob, local: &super::local::LocalChunks, app: &AppHandle, tkey: &str) -> Result<(Vec<[u8; 32]>, u64, u64)> {
    let plan = job.remux.as_ref().context("no plan")?;
    let dir = super::ffmpeg::locate().context("the bundled FFmpeg is missing or was modified")?;
    let src = std::path::Path::new(&job.path);
    let m = std::fs::metadata(src).context("the original file is no longer available")?;
    if m.len() != job.len || mtime_of(&m) != job.mtime {
        bail!("the original file changed after it was attached; attach it again");
    }
    let mut child = super::ffmpeg::start(&dir, src, plan)?;
    let mut out = child.stdout.take().context("FFmpeg didn't start")?;
    let mut addrs = Vec::new();
    let mut parity = Vec::new();
    let mut stripe: Vec<Vec<u8>> = Vec::new();
    let mut len = 0u64;
    let mut i = 0u64;
    let push = |ct: Vec<u8>, addrs: &mut Vec<[u8; 32]>, parity: &mut Vec<[u8; 32]>, stripe: &mut Vec<Vec<u8>>, last: bool| -> Result<()> {
        let a = media::address(&ct);
        local.put_outbox(&a, &ct)?;
        addrs.push(a);
        if let Some(l) = job.ec {
            stripe.push(ct);
            if stripe.len() == l.data as usize || last {
                for pc in l.encode(stripe) {
                    let pa = media::address(&pc);
                    local.put_outbox(&pa, &pc)?;
                    parity.push(pa);
                }
                stripe.clear();
            }
        }
        Ok(())
    };
    let mut buf = vec![0u8; CHUNK];
    loop {
        let mut filled = 0;
        while filled < CHUNK {
            let n = out.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        len += filled as u64;
        push(media::encrypt_chunk(&job.key, i, &buf[..filled]), &mut addrs, &mut parity, &mut stripe, false)?;
        i += 1;
        if i % 16 == 0 {
            emit_transfer(app, tkey, "prepare", i, i + 16, "running", None, None);
        }
        if filled < CHUNK {
            break;
        }
    }
    if !child.wait()?.success() || len == 0 {
        bail!("this file couldn't be rebuilt; it may be damaged");
    }
    // Pad the chunk count to its bucket with indistinguishable empty chunks.
    let real = i.max(1);
    let total = media::bucket(real);
    while i < total {
        let last = i + 1 == total;
        push(media::encrypt_chunk(&job.key, i, &[]), &mut addrs, &mut parity, &mut stripe, last)?;
        i += 1;
    }
    if let (Some(l), false) = (job.ec, stripe.is_empty()) {
        for pc in l.encode(&stripe) {
            let pa = media::address(&pc);
            local.put_outbox(&pa, &pc)?;
            parity.push(pa);
        }
    }
    addrs.extend(parity);
    let (maddrs, mchunks) = media::build_manifest(&job.key, &addrs);
    for (a, c) in maddrs.iter().zip(mchunks) {
        local.put_outbox(a, &c)?;
    }
    Ok((maddrs, len, total))
}

/// Pick a few random chunks per host and precompute single-use challenges.
fn make_audits(job: &UploadJob, local: &super::local::LocalChunks, addrs: Arc<Vec<[u8; 32]>>) -> Result<Vec<super::audit::Audit>> {
    let mut src = JobSource::open(job, local, Some(addrs))?;
    let rnd = |n: u64| u64::from_le_bytes(sentinel_core::random_bytes::<8>()) % n.max(1);
    let mut out = Vec::new();
    for (h, host) in job.hosts.iter().enumerate() {
        for _ in 0..super::audit::PER_HOST {
            let ct = match job.ec {
                None => src.ct(rnd(job.total))?,
                Some(l) => {
                    // A random stripe, and the chunk in it this host holds.
                    let st = rnd(l.stripes(job.total));
                    let n = (l.data + l.parity) as u64;
                    let hosts = l.hosts as u64;
                    let t = (h as u64 + hosts - st % hosts) % hosts;
                    if t >= n {
                        continue;
                    }
                    let first = st * l.data as u64;
                    let last = (first + l.data as u64).min(job.total);
                    let mut cts = Vec::new();
                    for c in first..last {
                        cts.push(src.ct(c)?);
                    }
                    if t < l.data as u64 {
                        match cts.get(t as usize) {
                            Some(c) => c.clone(),
                            None => continue, // virtual padding slot
                        }
                    } else {
                        l.encode(&cts)[(t - l.data as u64) as usize].clone()
                    }
                }
            };
            let nonce = sentinel_core::random_bytes::<32>();
            out.push(super::audit::Audit {
                host: host.clone(),
                addr: media::address(&ct),
                nonce,
                expected: media::proof(&nonce, &ct),
                due: super::audit::random_due(),
            });
        }
    }
    Ok(out)
}

/// Addresses of every chunk of a file, read from its manifest chunks in the
/// local outbox (my own uploads).
fn manifest_addrs(local: &super::local::LocalChunks, r: &MediaRef) -> Result<Vec<[u8; 32]>> {
    let mut addrs = Vec::new();
    for (i, a) in r.manifest.iter().enumerate() {
        let ct = local.get(a).context("upload index missing; attach the file again")?;
        addrs.extend(media::open_manifest_chunk(r, i, &ct).context("upload index unreadable")?);
    }
    if addrs.len() as u64 != r.entries() {
        bail!("upload index inconsistent");
    }
    Ok(addrs)
}

pub(super) async fn put_chunk_pub(s: &mut Box<dyn Io>, data: Vec<u8>) -> Result<()> {
    put_chunk(s, data).await
}

async fn put_chunk(s: &mut Box<dyn Io>, data: Vec<u8>) -> Result<()> {
    let h = media::address(&data);
    let nonce = tokio::task::spawn_blocking(move || sentinel_core::pow::stamp(media::CHUNK_POW_DOMAIN, &h, media::CHUNK_POW_BITS)).await?;
    match request(s, &Request::PutChunk { data, nonce }).await? {
        Response::Stored(_) => Ok(()),
        Response::Rejected(r) => bail!("storage refused: {r}"),
        other => bail!("unexpected answer: {other:?}"),
    }
}

/// Upload one chunk to `host`, reconnecting once if the stream broke.
async fn put_with_retry(net: &sentinel_net::transport::Net, streams: &mut HashMap<String, Box<dyn Io>>, host: &str, ct: &[u8]) -> Result<()> {
    for attempt in 0..3 {
        if !streams.contains_key(host) {
            streams.insert(host.to_owned(), net.connect_hedged(host).await?);
        }
        let s = streams.get_mut(host).expect("just inserted");
        match put_chunk(s, ct.to_vec()).await {
            Ok(()) => return Ok(()),
            Err(e) if e.to_string().starts_with("storage refused") => return Err(e),
            Err(e) => {
                streams.remove(host);
                if attempt == 2 {
                    return Err(e);
                }
            }
        }
    }
    unreachable!()
}

/// `bytes=a-b` / `bytes=a-` → inclusive (start, end) clipped to `size`.
fn parse_range(h: Option<&str>, size: u64) -> Option<(u64, u64)> {
    if size == 0 {
        return None;
    }
    let Some(h) = h else { return Some((0, size - 1)) };
    let spec = h.trim().strip_prefix("bytes=")?.split(',').next()?.trim();
    let (a, b) = spec.split_once('-')?;
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        let n = n.min(size);
        return Some((size - n, size - 1));
    }
    let start: u64 = a.parse().ok()?;
    if start >= size {
        return None;
    }
    let end = if b.is_empty() { size - 1 } else { b.parse::<u64>().ok()?.min(size - 1) };
    (end >= start).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range(Some("bytes=0-"), 100), Some((0, 99)));
        assert_eq!(parse_range(Some("bytes=10-19"), 100), Some((10, 19)));
        assert_eq!(parse_range(Some("bytes=-10"), 100), Some((90, 99)));
        assert_eq!(parse_range(Some("bytes=100-"), 100), None);
        assert_eq!(parse_range(None, 5), Some((0, 4)));
    }

    #[test]
    fn names_are_neutral_and_clean() {
        let p = std::path::Path::new(r"C:\Users\Real Name\Desktop\protest_2026-10-04_GPS.zip");
        assert_eq!(default_name("file", "application/octet-stream", Some(p)), "file.zip");
        assert_eq!(default_name("video", "video/mp4", Some(p)), "video.mp4");
        assert_eq!(clean_name(r"..\..\evil:name.exe").as_deref(), Some("evilname.exe"));
        assert_eq!(clean_name("  "), None);
    }
}
