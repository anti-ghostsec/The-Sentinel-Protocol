//! Bundled FFmpeg: rebuild audio/video so files can't be traced to a device.
//!
//! In-place cleaning (`sentinel_core::sanitize`) removes metadata but keeps
//! the container's exact layout, which can identify the recording app or
//! camera model. With FFmpeg, audio and video are instead **re-encoded**
//! (up to `REENCODE_MAX`) or at least **remuxed into a fresh container**,
//! with all metadata, chapters, extra streams and encoder tags (H.264/HEVC
//! SEI) removed, bit-exact flags on, written as fragmented MP4.
//!
//! Safety rules:
//! - every bundled file is SHA-256 checked before each run;
//! - only `file` and `pipe` protocols are allowed, and the input format is
//!   pinned to an allow-list of real audio/video containers — a crafted
//!   playlist or concat file can neither go online nor pull in other local
//!   files;
//! - no console window; output goes straight to a pipe (never a temp file).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use sha2::{Digest, Sha256};

// The pinned checksums of the bundled FFmpeg for this system (none on
// phones: there, files are cleaned without it).
#[cfg(windows)]
const SUMS: &str = include_str!("../../../../vendor/ffmpeg/win64/SHA256SUMS.txt");
#[cfg(all(target_os = "linux", not(target_os = "android")))]
const SUMS: &str = include_str!("../../../../vendor/ffmpeg/linux64/SHA256SUMS.txt");
#[cfg(not(any(windows, all(target_os = "linux", not(target_os = "android")))))]
const SUMS: &str = "";

#[cfg(windows)]
const FFMPEG: &str = "ffmpeg.exe";
#[cfg(windows)]
const FFPROBE: &str = "ffprobe.exe";
#[cfg(not(windows))]
const FFMPEG: &str = "ffmpeg";
#[cfg(not(windows))]
const FFPROBE: &str = "ffprobe";

/// The app's resource folder (installed packages keep FFmpeg there).
static RESOURCES: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

pub fn set_resource_dir(p: PathBuf) {
    let _ = RESOURCES.set(p);
}
/// Files larger than this are remuxed instead of re-encoded (time).
pub const REENCODE_MAX: u64 = 1024 * 1024 * 1024;

/// Containers FFmpeg may read (as named by ffprobe's format_name).
const ALLOWED_FORMATS: &[&str] = &["mov", "mp4", "m4a", "3gp", "3g2", "mj2", "matroska", "webm", "mp3", "flac", "wav", "ogg", "avi", "mpegts", "asf", "flv"];
/// Video codecs that may be copied into MP4 when not re-encoding.
const MP4_VIDEO: &[&str] = &["h264", "hevc", "av1", "vp9", "mpeg4"];
const MP4_AUDIO: &[&str] = &["aac", "mp3", "alac", "flac", "opus"];

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Plan {
    /// Input format to force (from the allow-list).
    pub input: String,
    pub video: Option<String>,
    pub audio: Option<String>,
    pub width: u32,
    pub height: u32,
    pub reencode: bool,
}

impl Plan {
    pub fn kind(&self) -> (&'static str, &'static str) {
        if self.video.is_some() { ("video", "video/mp4") } else { ("audio", "audio/mp4") }
    }
}

/// Folder with the bundled binaries, verified. None = not available.
pub fn locate() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(r) = RESOURCES.get() {
        candidates.push(r.join("ffmpeg"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            candidates.push(d.join("ffmpeg"));
            candidates.push(d.join("resources").join("ffmpeg"));
        }
    }
    // Development builds run from the source tree. Never in release: the
    // path would embed the builder's folder (and user name) in the program.
    #[cfg(all(debug_assertions, windows))]
    candidates.push(PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../vendor/ffmpeg/win64")));
    #[cfg(all(debug_assertions, not(windows)))]
    candidates.push(PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../vendor/ffmpeg/linux64")));
    candidates.into_iter().find(|d| verify(d))
}

fn verify(dir: &Path) -> bool {
    let mut any = false;
    for line in SUMS.lines() {
        let Some((hash, name)) = line.split_once("  ") else { continue };
        let Ok(bytes) = std::fs::read(dir.join(name.trim())) else { return false };
        if data_encoding::HEXLOWER.encode(&Sha256::digest(&bytes)) != hash.trim() {
            return false;
        }
        any = true;
    }
    any
}

fn cmd(dir: &Path, exe: &str) -> Command {
    let mut c = Command::new(dir.join(exe));
    c.current_dir(dir).stdin(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    c
}

/// Inspect a file: an allow-listed container with audio and/or video.
pub fn probe(dir: &Path, path: &Path, len: u64) -> Option<Plan> {
    let out = cmd(dir, FFPROBE)
        .args(["-hide_banner", "-v", "error", "-protocol_whitelist", "file", "-show_entries", "format=format_name:stream=codec_type,codec_name,width,height", "-of", "json"])
        .arg(path)
        .stdout(Stdio::piped())
        .output()
        .ok()?;
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let fmt_names = j["format"]["format_name"].as_str()?;
    let input = fmt_names.split(',').find(|f| ALLOWED_FORMATS.contains(f))?.to_owned();
    let streams = j["streams"].as_array()?;
    let first = |t: &str| streams.iter().find(|s| s["codec_type"] == t);
    let v = first("video").filter(|s| !matches!(s["codec_name"].as_str(), Some("mjpeg" | "png" | "bmp"))); // cover art isn't video
    let a = first("audio");
    if v.is_none() && a.is_none() {
        return None;
    }
    let video = v.and_then(|s| s["codec_name"].as_str()).map(str::to_owned);
    let audio = a.and_then(|s| s["codec_name"].as_str()).map(str::to_owned);
    let copyable = video.as_deref().is_none_or(|c| MP4_VIDEO.contains(&c)) && audio.as_deref().is_none_or(|c| MP4_AUDIO.contains(&c));
    Some(Plan {
        input,
        width: v.and_then(|s| s["width"].as_u64()).unwrap_or(0) as u32,
        height: v.and_then(|s| s["height"].as_u64()).unwrap_or(0) as u32,
        reencode: len <= REENCODE_MAX || !copyable,
        video,
        audio,
    })
}

/// Start cleaning: fragmented MP4 on the child's stdout.
pub fn start(dir: &Path, path: &Path, plan: &Plan) -> std::io::Result<Child> {
    let mut c = cmd(dir, FFMPEG);
    c.args(["-hide_banner", "-nostdin", "-loglevel", "error", "-protocol_whitelist", "file,pipe", "-f", &plan.input, "-i"]);
    c.arg(path);
    c.args(["-map", "0:v:0?", "-map", "0:a:0?", "-sn", "-dn"]);
    c.args(["-map_metadata", "-1", "-map_metadata:s", "-1", "-map_chapters", "-1"]);
    c.args(["-fflags", "+bitexact", "-flags:v", "+bitexact", "-flags:a", "+bitexact"]);
    match (&plan.video, plan.reencode) {
        (None, _) => {}
        (Some(_), true) => {
            c.args(["-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p", "-bsf:v", "filter_units=remove_types=6"]);
        }
        (Some(codec), false) => {
            c.args(["-c:v", "copy"]);
            match codec.as_str() {
                "h264" => {
                    c.args(["-bsf:v", "filter_units=remove_types=6"]);
                }
                "hevc" => {
                    c.args(["-bsf:v", "filter_units=remove_types=39|40"]);
                }
                _ => {}
            }
        }
    }
    if plan.audio.is_some() {
        if plan.reencode {
            c.args(["-c:a", "aac", "-b:a", "160k"]);
        } else {
            c.args(["-c:a", "copy"]);
        }
    }
    c.args(["-f", "mp4", "-movflags", "frag_keyframe+empty_moov+default_base_moof", "pipe:1"]);
    c.stdout(Stdio::piped()).spawn()
}

/// Clean a small file completely in memory (inline media).
pub fn clean_to_memory(dir: &Path, path: &Path, plan: &Plan, max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut child = start(dir, path, plan).ok()?;
    let mut out = Vec::new();
    let mut stdout = child.stdout.take()?;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = stdout.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.len() > max {
            let _ = child.kill();
            return None;
        }
    }
    child.wait().ok()?.success().then_some(out).filter(|o| !o.is_empty())
}
