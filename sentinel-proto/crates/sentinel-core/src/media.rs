//! Media and files (spec §5.4, §5.7): sanitise on the sender's device, then
//! encrypt and chunk.
//!
//! - Content is cleaned by `sanitize` (images re-encoded; audio/video
//!   metadata blanked in place). Type is detected from content, never names.
//! - Each file gets a random key (never convergent, so identical files never
//!   share chunk addresses) and is split into fixed-size encrypted chunks
//!   addressed by BLAKE3 of the ciphertext.
//! - Every chunk has the same size, and the **chunk count is padded up to a
//!   size bucket** (~12% steps) with dummy chunks that look like real ones,
//!   so stored and transferred sizes don't fingerprint a file.
//! - Small files list their chunk addresses inside the (sealed) post. Large
//!   files put the list in encrypted **manifest chunks**; the post carries
//!   only the manifest addresses.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::sanitize::{self, Format};

/// Plaintext bytes per chunk (ciphertext + framing fits a 1 MiB cell bucket).
pub const CHUNK: usize = 1_048_576 - 1024;
/// Ciphertext size of every chunk (v1: 16-byte synthetic IV + AEAD).
pub const CHUNK_CT: usize = 16 + CHUNK + 4 + 16;
/// Chunk size of version-0 media (index-only nonces), still readable.
pub const CHUNK_CT_V0: usize = CHUNK + 4 + 16;
/// Largest file embedded inline in a post (shown/played in the timeline).
pub const MAX_INLINE: usize = 25 * 1024 * 1024;
/// Largest image accepted for re-encoding.
pub const MAX_IMAGE_INPUT: usize = 64 * 1024 * 1024;
/// Sanity bound on any shared file (validation of untrusted references).
pub const MAX_FILE: u64 = 1 << 40; // 1 TiB
/// Chunk addresses listed directly in a post; beyond this, a manifest.
pub const INLINE_LIST_MAX: usize = 256;
/// Images larger than this on either side are scaled down.
const MAX_DIM: u32 = 4096;
/// Proof-of-work for chunk uploads (anti-abuse without identity).
pub const CHUNK_POW_DOMAIN: &str = "sentinel/v0/chunk-pow";
pub const CHUNK_POW_BITS: u32 = 12;
/// Longest shared file name, in characters.
pub const MAX_NAME: usize = 120;

/// Reference to a media file or attachment inside a sealed post.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MediaRef {
    /// image | gif | video | audio | file
    pub kind: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    /// Real (unpadded) size in bytes.
    pub size: u64,
    pub key: [u8; 32],
    /// Chunk addresses, in order (small files), including padding chunks.
    pub chunks: Vec<[u8; 32]>,
    /// Manifest chunk addresses (large files); empty for small files.
    #[serde(default)]
    pub manifest: Vec<[u8; 32]>,
    /// Total chunks including padding (large files; small files use
    /// `chunks.len()`).
    #[serde(default)]
    pub total: u64,
    /// File name shown to readers (chosen by the sender, never automatic).
    #[serde(default)]
    pub name: Option<String>,
    /// Archives holding the chunks (onion addresses). Empty = the author's
    /// Pillar (posts from before Archives existed).
    #[serde(default)]
    pub archives: Vec<String>,
    /// Whether metadata was removed (false = opaque file, reader is warned).
    #[serde(default = "yes")]
    pub cleaned: bool,
    /// Chunk format: 0 = index nonces (old), 1 = synthetic IVs.
    #[serde(default)]
    pub v: u8,
    /// Erasure coding across `archives` (None = every Archive holds every
    /// chunk). Parity addresses follow the data addresses in the manifest.
    #[serde(default)]
    pub ec: Option<crate::erasure::Layout>,
}

fn yes() -> bool {
    true
}

impl MediaRef {
    /// Number of chunks holding real data.
    pub fn real_chunks(&self) -> u64 {
        self.size.div_ceil(CHUNK as u64).max(1)
    }

    /// Total data chunks (real + padding).
    pub fn total_chunks(&self) -> u64 {
        if self.manifest.is_empty() { self.chunks.len() as u64 } else { self.total }
    }

    /// Addresses listed in the manifest: data plus parity chunks.
    pub fn entries(&self) -> u64 {
        self.total_chunks() + self.ec.map(|l| l.parity_chunks(self.total_chunks())).unwrap_or(0)
    }

    /// Check an untrusted reference is internally consistent before acting
    /// on it (a hostile author could otherwise make readers fetch millions
    /// of chunks or allocate unbounded memory).
    pub fn validate(&self) -> bool {
        if self.size > MAX_FILE || !matches!(self.kind.as_str(), "image" | "gif" | "video" | "audio" | "file") {
            return false;
        }
        if self.mime.len() > 100 || self.name.as_ref().is_some_and(|n| n.chars().count() > MAX_NAME) {
            return false;
        }
        if self.archives.len() > 8 || self.archives.iter().any(|a| crate::social::valid_onion(a).is_none()) {
            return false;
        }
        let real = self.real_chunks();
        let total = self.total_chunks();
        // Total must be the real count padded to its bucket (or, for posts
        // made before padding, exactly the real count).
        if total != bucket(real) && total != real {
            return false;
        }
        if self.manifest.is_empty() {
            self.chunks.len() <= INLINE_LIST_MAX.max(bucket(INLINE_LIST_MAX as u64) as usize)
        } else {
            let ec_ok = match self.ec {
                None => true,
                Some(l) => {
                    l.data as usize == crate::erasure::DATA
                        && Some(l) == crate::erasure::Layout::for_hosts(l.hosts as usize)
                        && self.archives.len() == l.hosts as usize
                }
            };
            ec_ok && self.chunks.is_empty() && self.manifest.len() as u64 == manifest_chunks(self.entries())
        }
    }

    /// Whether the app may render this inline (decoded in the sandboxed
    /// renderer) rather than only offer it for saving.
    pub fn inline(&self) -> bool {
        self.size as usize <= MAX_INLINE && matches!(self.kind.as_str(), "image" | "gif" | "video" | "audio")
    }

    /// Whether the app may stream it for playback (large audio/video).
    pub fn streamable(&self) -> bool {
        matches!(self.kind.as_str(), "video" | "audio") && self.cleaned
    }
}

/// Pad a chunk count up to its size bucket: exact below 8, then steps of
/// ~12.5% (so a file's size is known only to within ~12%).
pub fn bucket(n: u64) -> u64 {
    if n <= 8 {
        return n.max(1);
    }
    let mut b = 8u64;
    while b < n {
        b += (b / 8).max(1);
    }
    b
}

/// Manifest chunks needed to list `total` chunk addresses.
pub fn manifest_chunks(total: u64) -> u64 {
    (total * 32).div_ceil(CHUNK as u64)
}

#[derive(Debug)]
pub struct Sanitized {
    pub bytes: Vec<u8>,
    pub kind: &'static str,
    pub mime: &'static str,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("this file can't be shown in a post (use JPEG, PNG, WebP, GIF, MP4, WebM or audio); attach it as a file instead")]
    Unsupported,
    #[error("file is too large to show inline (max 25 MB); it will be attached as a file")]
    TooLarge,
    #[error("the file couldn't be read: {0}")]
    Decode(String),
}

/// Kind and MIME type for a detected format.
pub fn kind_of(fmt: Format) -> (&'static str, &'static str) {
    match fmt {
        Format::Image => ("image", "image/jpeg"),
        Format::Gif => ("gif", "image/gif"),
        Format::Mp4 => ("video", "video/mp4"),
        Format::Webm => ("video", "video/webm"),
        Format::Matroska => ("file", "video/x-matroska"),
        Format::Mp3 => ("audio", "audio/mpeg"),
        Format::Flac => ("audio", "audio/flac"),
        Format::Wav => ("audio", "audio/wav"),
        Format::Other => ("file", "application/octet-stream"),
    }
}

/// Clean a small file in memory for inline display.
pub fn sanitize(input: &[u8]) -> Result<Sanitized, MediaError> {
    let fmt = sanitize::detect(input);
    match fmt {
        Format::Image => {
            if input.len() > MAX_IMAGE_INPUT {
                return Err(MediaError::TooLarge);
            }
            sanitize_image(input)
        }
        Format::Gif => {
            if input.len() > MAX_INLINE {
                return Err(MediaError::TooLarge);
            }
            sanitize_gif(input)
        }
        Format::Mp4 | Format::Webm | Format::Mp3 | Format::Flac | Format::Wav => {
            if input.len() > MAX_INLINE {
                return Err(MediaError::TooLarge);
            }
            let s = sanitize::scan(fmt, &mut std::io::Cursor::new(input), input.len() as u64)
                .map_err(|e| MediaError::Decode(e.to_string()))?;
            let mut bytes = input.to_vec();
            sanitize::apply(&s.patches, 0, &mut bytes);
            let (kind, mime) = kind_of(fmt);
            // MP4 with no video track is audio (M4A).
            let (kind, mime) = if fmt == Format::Mp4 && s.dims == (0, 0) { ("audio", "audio/mp4") } else { (kind, mime) };
            Ok(Sanitized { bytes, kind, mime, width: s.dims.0, height: s.dims.1 })
        }
        Format::Matroska | Format::Other => Err(MediaError::Unsupported),
    }
}

/// Profile picture shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Square, 400 x 400.
    Avatar,
    /// 3:1, 1500 x 500.
    Banner,
}

/// Re-encode an image for a profile: centre-cropped to the shape, resized,
/// JPEG (all metadata gone, like every other image).
pub fn sanitize_profile_image(input: &[u8], shape: Shape) -> Result<Sanitized, MediaError> {
    if input.len() > MAX_IMAGE_INPUT || sanitize::detect(input) != Format::Image && sanitize::detect(input) != Format::Gif {
        return Err(MediaError::Unsupported);
    }
    let img = image::load_from_memory(input).map_err(|e| MediaError::Decode(e.to_string()))?;
    let (tw, th) = match shape {
        Shape::Avatar => (400, 400),
        Shape::Banner => (1500, 500),
    };
    let img = img.resize_to_fill(tw, th, image::imageops::FilterType::Lanczos3);
    let rgb = img.to_rgb8();
    let mut out = std::io::Cursor::new(Vec::new());
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 88).encode_image(&rgb).map_err(|e| MediaError::Decode(e.to_string()))?;
    Ok(Sanitized { bytes: out.into_inner(), kind: "image", mime: "image/jpeg", width: tw, height: th })
}

fn sanitize_image(input: &[u8]) -> Result<Sanitized, MediaError> {
    let mut img = image::load_from_memory(input).map_err(|e| MediaError::Decode(e.to_string()))?;
    if img.width() > MAX_DIM || img.height() > MAX_DIM {
        img = img.resize(MAX_DIM, MAX_DIM, image::imageops::FilterType::Lanczos3);
    }
    let (w, h) = (img.width(), img.height());
    let mut out = std::io::Cursor::new(Vec::new());
    if img.color().has_alpha() {
        img.write_to(&mut out, image::ImageFormat::Png).map_err(|e| MediaError::Decode(e.to_string()))?;
        Ok(Sanitized { bytes: out.into_inner(), kind: "image", mime: "image/png", width: w, height: h })
    } else {
        let rgb = img.to_rgb8();
        let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 88);
        enc.encode_image(&rgb).map_err(|e| MediaError::Decode(e.to_string()))?;
        Ok(Sanitized { bytes: out.into_inner(), kind: "image", mime: "image/jpeg", width: w, height: h })
    }
}

fn sanitize_gif(input: &[u8]) -> Result<Sanitized, MediaError> {
    use image::AnimationDecoder;
    let dec = image::codecs::gif::GifDecoder::new(std::io::Cursor::new(input)).map_err(|e| MediaError::Decode(e.to_string()))?;
    let frames: Vec<image::Frame> = dec.into_frames().collect_frames().map_err(|e| MediaError::Decode(e.to_string()))?;
    let first = frames.first().ok_or_else(|| MediaError::Decode("empty GIF".into()))?;
    let (w, h) = first.buffer().dimensions();
    let mut out = Vec::new();
    {
        let mut enc = image::codecs::gif::GifEncoder::new_with_speed(&mut out, 10);
        enc.set_repeat(image::codecs::gif::Repeat::Infinite).map_err(|e| MediaError::Decode(e.to_string()))?;
        enc.encode_frames(frames).map_err(|e| MediaError::Decode(e.to_string()))?;
    }
    Ok(Sanitized { bytes: out, kind: "gif", mime: "image/gif", width: w, height: h })
}

fn nonce_v0(index: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..8].copy_from_slice(&index.to_le_bytes());
    n
}

/// Synthetic IV: derived from the key, index and padded plaintext, so a
/// repeated key (e.g. a failed random generator) still never repeats a
/// nonce for different content. Deterministic, so uploads can re-derive.
fn siv(key: &[u8; 32], index: u64, padded: &[u8]) -> [u8; 16] {
    let k = blake3::derive_key("sentinel/v0/media-siv", key);
    let mut h = blake3::Hasher::new_keyed(&k);
    h.update(&index.to_le_bytes());
    h.update(padded);
    h.finalize().as_bytes()[..16].try_into().unwrap()
}

fn nonce_v1(index: u64, iv: &[u8; 16]) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..8].copy_from_slice(&index.to_le_bytes());
    n[8..].copy_from_slice(iv);
    n
}

fn manifest_key(file_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("sentinel/v0/media-manifest", file_key)
}

/// Encrypt one chunk (`plain` ≤ CHUNK bytes; empty = a padding chunk). The
/// plaintext is padded to the full chunk size, so every chunk is identical
/// in size. Deterministic for a given key and index (the key is random per
/// file and never reused), which lets large uploads re-derive chunks from
/// the source file instead of keeping an encrypted copy.
pub fn encrypt_chunk(key: &[u8; 32], index: u64, plain: &[u8]) -> Vec<u8> {
    debug_assert!(plain.len() <= CHUNK);
    let mut p = Vec::with_capacity(CHUNK + 4);
    p.extend_from_slice(plain);
    p.resize(CHUNK, 0);
    p.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    let iv = siv(key, index, &p);
    let mut out = iv.to_vec();
    out.extend(XChaCha20Poly1305::new(key.into()).encrypt(XNonce::from_slice(&nonce_v1(index, &iv)), p.as_slice()).expect("encrypt"));
    out
}

fn open_chunk(key: &[u8; 32], index: u64, ct: &[u8], v: u8) -> Option<Vec<u8>> {
    let mut plain = if v == 0 {
        XChaCha20Poly1305::new(key.into()).decrypt(XNonce::from_slice(&nonce_v0(index)), ct).ok()?
    } else {
        let iv: [u8; 16] = ct.get(..16)?.try_into().ok()?;
        let p = XChaCha20Poly1305::new(key.into()).decrypt(XNonce::from_slice(&nonce_v1(index, &iv)), &ct[16..]).ok()?;
        // The IV must match the content (detects a forged IV).
        if siv(key, index, &p) != iv {
            return None;
        }
        p
    };
    if plain.len() != CHUNK + 4 {
        return None;
    }
    let real = u32::from_le_bytes(plain[CHUNK..].try_into().ok()?) as usize;
    plain.truncate(real.min(CHUNK));
    Some(plain)
}

/// Expected answer to a storage proof challenge.
pub fn proof(nonce: &[u8; 32], ct: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(nonce, ct).as_bytes()
}

pub fn address(ct: &[u8]) -> [u8; 32] {
    *blake3::hash(ct).as_bytes()
}

/// Decrypt data chunk `index` after checking it is the chunk expected.
pub fn decrypt_chunk_at(r: &MediaRef, expected: &[u8; 32], index: u64, ct: &[u8]) -> Option<Vec<u8>> {
    if &address(ct) != expected {
        return None; // tampered or wrong chunk
    }
    open_chunk(&r.key, index, ct, r.v)
}

/// Decrypt chunk `index` of a small file (addresses listed in the post).
pub fn decrypt_chunk(r: &MediaRef, index: usize, ct: &[u8]) -> Option<Vec<u8>> {
    decrypt_chunk_at(r, r.chunks.get(index)?, index as u64, ct)
}

/// Build manifest chunks listing `addrs`; returns (manifest addresses, chunks).
pub fn build_manifest(file_key: &[u8; 32], addrs: &[[u8; 32]]) -> (Vec<[u8; 32]>, Vec<Vec<u8>>) {
    let key = manifest_key(file_key);
    let flat: Vec<u8> = addrs.iter().flatten().copied().collect();
    let mut out_addrs = Vec::new();
    let mut out = Vec::new();
    for (i, part) in flat.chunks(CHUNK).enumerate() {
        let ct = encrypt_chunk(&key, i as u64, part);
        out_addrs.push(address(&ct));
        out.push(ct);
    }
    (out_addrs, out)
}

/// Decrypt manifest chunk `index`; returns the chunk addresses it lists.
pub fn open_manifest_chunk(r: &MediaRef, index: usize, ct: &[u8]) -> Option<Vec<[u8; 32]>> {
    if &address(ct) != r.manifest.get(index)? {
        return None;
    }
    let plain = open_chunk(&manifest_key(&r.key), index as u64, ct, r.v)?;
    if plain.len() % 32 != 0 {
        return None;
    }
    Some(plain.chunks(32).map(|c| c.try_into().unwrap()).collect())
}

/// Encrypt and chunk a small sanitised file held in memory. Returns the
/// reference (to embed in a sealed post) and the chunks (to upload).
pub fn encrypt_file(s: &Sanitized) -> (MediaRef, Vec<Vec<u8>>) {
    let key = crate::random_bytes::<32>();
    let real = (s.bytes.len() as u64).div_ceil(CHUNK as u64).max(1);
    let total = bucket(real);
    let mut chunks = Vec::new();
    for i in 0..total {
        let start = (i as usize).saturating_mul(CHUNK).min(s.bytes.len());
        let end = (start + CHUNK).min(s.bytes.len());
        let plain = if i < real { &s.bytes[start..end] } else { &[][..] };
        chunks.push(encrypt_chunk(&key, i, plain));
    }
    let r = MediaRef {
        kind: s.kind.into(),
        mime: s.mime.into(),
        width: s.width,
        height: s.height,
        size: s.bytes.len() as u64,
        key,
        chunks: chunks.iter().map(|c| address(c)).collect(),
        manifest: Vec::new(),
        total: 0,
        name: None,
        archives: Vec::new(),
        cleaned: true,
        v: 1,
        ec: None,
    };
    (r, chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg_with_exif() -> Vec<u8> {
        let img = image::RgbImage::from_pixel(40, 30, image::Rgb([200, 30, 30]));
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img).write_to(&mut out, image::ImageFormat::Jpeg).unwrap();
        let jpg = out.into_inner();
        let payload = b"Exif\0\0GPS-SECRET-LOCATION";
        let mut app1 = vec![0xFF, 0xE1];
        app1.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        app1.extend_from_slice(payload);
        let mut withexif = jpg[..2].to_vec();
        withexif.extend_from_slice(&app1);
        withexif.extend_from_slice(&jpg[2..]);
        withexif
    }

    #[test]
    fn image_metadata_is_removed() {
        let input = jpeg_with_exif();
        assert!(input.windows(10).any(|w| w == b"GPS-SECRET"));
        let s = sanitize(&input).unwrap();
        assert!(!s.bytes.windows(10).any(|w| w == b"GPS-SECRET"));
        assert_eq!((s.kind, s.width, s.height), ("image", 40, 30));
    }

    #[test]
    fn chunks_roundtrip_padded_and_tamper_evident() {
        let s = Sanitized { bytes: (0..(CHUNK * 16 + 5000)).map(|i| i as u8).collect(), kind: "video", mime: "video/mp4", width: 1, height: 1 };
        let (r, chunks) = encrypt_file(&s);
        assert_eq!(r.real_chunks(), 17);
        assert_eq!(chunks.len() as u64, bucket(17)); // padded with dummies
        assert!(chunks.len() > 17);
        assert!(chunks.iter().all(|c| c.len() == CHUNK_CT)); // uniform size
        assert!(r.validate());
        let mut back = Vec::new();
        for i in 0..r.real_chunks() as usize {
            back.extend(decrypt_chunk(&r, i, &chunks[i]).unwrap());
        }
        assert_eq!(back, s.bytes);
        let mut bad = chunks[0].clone();
        bad[10] ^= 1;
        assert!(decrypt_chunk(&r, 0, &bad).is_none());
    }

    #[test]
    fn buckets_hide_exact_sizes() {
        assert_eq!(bucket(1), 1);
        assert_eq!(bucket(8), 8);
        assert_eq!(bucket(9), 9);
        assert_eq!(bucket(10), 10);
        // Neighbouring sizes collapse into the same bucket further up.
        assert_eq!(bucket(1000), bucket(1001));
        for n in [9u64, 50, 999, 10_240, 102_400] {
            let b = bucket(n);
            assert!(b >= n && b <= n + n / 8 + 1, "{n} -> {b}");
        }
    }

    #[test]
    fn manifest_roundtrip_and_validation() {
        let key = crate::random_bytes::<32>();
        let total = bucket(20_000);
        let addrs: Vec<[u8; 32]> = (0..total).map(|i| *blake3::hash(&i.to_le_bytes()).as_bytes()).collect();
        let (maddrs, mchunks) = build_manifest(&key, &addrs);
        let r = MediaRef {
            kind: "file".into(),
            mime: "application/octet-stream".into(),
            width: 0,
            height: 0,
            size: 20_000 * CHUNK as u64 - 3,
            key,
            chunks: vec![],
            manifest: maddrs,
            total,
            name: Some("archive.7z".into()),
            archives: vec![],
            cleaned: false,
            v: 1,
            ec: None,
        };
        assert!(r.validate());
        let mut back = Vec::new();
        for (i, c) in mchunks.iter().enumerate() {
            back.extend(open_manifest_chunk(&r, i, c).unwrap());
        }
        assert_eq!(back, addrs);
        // A hostile reference claiming a tiny file but millions of chunks fails.
        let mut evil = r.clone();
        evil.size = 10;
        assert!(!evil.validate());
        let mut evil2 = r.clone();
        evil2.chunks = vec![[0; 32]; 5];
        assert!(!evil2.validate());
    }

    #[test]
    fn unknown_types_rejected_for_inline() {
        assert!(matches!(sanitize(b"PK\x03\x04zipdata"), Err(MediaError::Unsupported)));
    }
}
