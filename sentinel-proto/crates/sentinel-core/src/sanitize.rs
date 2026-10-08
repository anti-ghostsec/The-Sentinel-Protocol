//! Metadata removal for media and files of any size (spec §5.4, §5.7).
//!
//! Images are decoded and re-encoded (small enough to do in memory). Audio
//! and video are never re-encoded: their metadata is located and blanked
//! **in place**, producing a list of byte patches over the original file.
//! Patches keep every offset unchanged (metadata becomes padding of the same
//! size), so a 10 GB video is cleaned while it streams from disk into the
//! encryptor, without a second copy.
//!
//! Cleaned in place:
//! - MP4 / MOV / M4A: `udta`, `meta`, `uuid` (XMP), `ilst`, `keys` become
//!   `free` boxes; `free`/`skip`/`wide` contents (editors leave old metadata
//!   there) are zeroed; creation/modification times in `mvhd`/`tkhd`/`mdhd`
//!   are zeroed. Fragmented files (`moof`) are cleaned too.
//! - WebM / Matroska: `Tags`, `Attachments`, `Chapters` become `Void`;
//!   `DateUTC`, `Title`, `MuxingApp`, `WritingApp` and track names are zeroed.
//! - MP3: ID3v2 frames become padding, ID3v1 is emptied.
//! - FLAC: Vorbis comments, pictures and application blocks become padding.
//! - WAV: `LIST`/INFO, `bext`, `iXML`, `id3`, XMP chunks become `JUNK`.
//!
//! Everything else (archives, documents, Ogg, HEIC …) is passed through
//! unchanged as a *file* and the UI warns that it may carry metadata.

use std::io::{Read, Seek, SeekFrom};

/// Bytes that replace a region of the original file.
#[derive(Clone, Debug, PartialEq)]
pub enum PatchData {
    Bytes(Vec<u8>),
    Zeros(u64),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Patch {
    pub offset: u64,
    pub data: PatchData,
}

impl Patch {
    fn len(&self) -> u64 {
        match &self.data {
            PatchData::Bytes(b) => b.len() as u64,
            PatchData::Zeros(n) => *n,
        }
    }
}

/// What a file is, decided from its content (never its name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Image,
    Gif,
    Mp4,
    Webm,
    Matroska,
    Mp3,
    Flac,
    Wav,
    /// Anything else: shared as an opaque file, not cleaned.
    Other,
}

impl Format {
    /// Whether metadata is removed for this format.
    pub fn cleaned(self) -> bool {
        self != Format::Other
    }
}

pub fn detect(b: &[u8]) -> Format {
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) || b.starts_with(b"\x89PNG") || b.starts_with(b"BM") {
        return Format::Image;
    }
    if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        return Format::Image;
    }
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return Format::Gif;
    }
    if b.len() >= 12 && &b[4..8] == b"ftyp" {
        return Format::Mp4;
    }
    if b.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        // DocType "webm" is playable in the app; other Matroska is a file.
        return if b.windows(4).take(64).any(|w| w == b"webm") { Format::Webm } else { Format::Matroska };
    }
    if b.starts_with(b"fLaC") {
        return Format::Flac;
    }
    if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WAVE" {
        return Format::Wav;
    }
    if b.starts_with(b"ID3") || (b.len() >= 2 && b[0] == 0xFF && b[1] & 0xE0 == 0xE0 && b[1] & 0x06 != 0) {
        return Format::Mp3;
    }
    Format::Other
}

#[derive(Debug, thiserror::Error)]
pub enum SanitizeError {
    #[error("the file couldn't be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("the file is malformed: {0}")]
    Malformed(&'static str),
}

fn bad(what: &'static str) -> SanitizeError {
    SanitizeError::Malformed(what)
}

/// Result of scanning a file: patches to apply, plus what was learned.
#[derive(Clone, Debug, Default)]
pub struct Scan {
    pub patches: Vec<Patch>,
    /// Video width/height if found.
    pub dims: (u32, u32),
}

/// Find the metadata patches for a seekable source of `len` bytes.
pub fn scan<R: Read + Seek>(fmt: Format, r: &mut R, len: u64) -> Result<Scan, SanitizeError> {
    let mut s = Scan::default();
    match fmt {
        Format::Mp4 => mp4(r, 0, len, 0, &mut s)?,
        Format::Webm | Format::Matroska => ebml(r, len, &mut s)?,
        Format::Mp3 => mp3(r, len, &mut s)?,
        Format::Flac => flac(r, len, &mut s)?,
        Format::Wav => wav(r, len, &mut s)?,
        Format::Image | Format::Gif | Format::Other => {}
    }
    s.patches.sort_by_key(|p| p.offset);
    // Patches must not overlap (they describe disjoint metadata regions).
    for w in s.patches.windows(2) {
        if w[0].offset + w[0].len() > w[1].offset {
            return Err(bad("overlapping metadata regions"));
        }
    }
    Ok(s)
}

/// Apply patches to the bytes `buf` that start at file offset `at`.
pub fn apply(patches: &[Patch], at: u64, buf: &mut [u8]) {
    let end = at + buf.len() as u64;
    for p in patches {
        let (ps, pe) = (p.offset, p.offset + p.len());
        if pe <= at || ps >= end {
            continue;
        }
        let from = ps.max(at);
        let to = pe.min(end);
        for pos in from..to {
            let v = match &p.data {
                PatchData::Bytes(b) => b[(pos - ps) as usize],
                PatchData::Zeros(_) => 0,
            };
            buf[(pos - at) as usize] = v;
        }
    }
}

fn read_at<R: Read + Seek>(r: &mut R, at: u64, n: usize) -> Result<Vec<u8>, SanitizeError> {
    r.seek(SeekFrom::Start(at))?;
    let mut b = vec![0u8; n];
    r.read_exact(&mut b)?;
    Ok(b)
}

/// Largest metadata-bearing structure read into memory at once.
const MAX_IN_MEMORY: u64 = 512 * 1024 * 1024;

/* ---------------- MP4 / MOV ---------------- */

/// Boxes whose contents are metadata (never needed to play the file).
const MP4_METADATA: &[&[u8; 4]] = &[b"udta", b"meta", b"uuid", b"XMP_", b"\xa9xyz", b"ilst", b"keys"];
/// Padding boxes: contents are junk, often stale metadata left by editors.
const MP4_PADDING: &[&[u8; 4]] = &[b"free", b"skip", b"wide"];
/// Containers worth reading into memory and cleaning recursively.
const MP4_SCRUB_WHOLE: &[&[u8; 4]] = &[b"moov", b"moof"];
const MP4_CONTAINERS: &[&[u8; 4]] = &[b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf", b"moof", b"traf", b"mvex"];

/// Top level: walk boxes by seeking; read `moov`/`moof` into memory to
/// clean them; blank top-level metadata and padding in place.
fn mp4<R: Read + Seek>(r: &mut R, start: u64, end: u64, _depth: u8, s: &mut Scan) -> Result<(), SanitizeError> {
    let mut pos = start;
    while pos + 8 <= end {
        let h = read_at(r, pos, 8)?;
        let size32 = u32::from_be_bytes(h[..4].try_into().unwrap()) as u64;
        let typ: [u8; 4] = h[4..8].try_into().unwrap();
        let (size, header) = match size32 {
            1 => {
                if pos + 16 > end {
                    return Err(bad("MP4 box header"));
                }
                (u64::from_be_bytes(read_at(r, pos + 8, 8)?.try_into().unwrap()), 16)
            }
            0 => (end - pos, 8),
            n => (n, 8),
        };
        if size < header || pos + size > end {
            return Err(bad("MP4 box size"));
        }
        if MP4_METADATA.contains(&&typ) {
            s.patches.push(Patch { offset: pos + 4, data: PatchData::Bytes(b"free".to_vec()) });
            s.patches.push(Patch { offset: pos + header, data: PatchData::Zeros(size - header) });
        } else if MP4_PADDING.contains(&&typ) {
            s.patches.push(Patch { offset: pos + header, data: PatchData::Zeros(size - header) });
        } else if MP4_SCRUB_WHOLE.contains(&&typ) {
            if size > MAX_IN_MEMORY {
                return Err(bad("MP4 index too large"));
            }
            let mut b = read_at(r, pos, size as usize)?;
            let orig = b.clone();
            mp4_mem(&mut b, header as usize, size as usize, 0, &mut s.dims)?;
            if b != orig {
                s.patches.push(Patch { offset: pos, data: PatchData::Bytes(b) });
            }
        }
        pos += size;
    }
    Ok(())
}

/// Clean boxes inside an in-memory region.
pub(crate) fn mp4_mem(b: &mut [u8], start: usize, end: usize, depth: u8, dims: &mut (u32, u32)) -> Result<(), SanitizeError> {
    if depth > 10 {
        return Ok(());
    }
    let mut pos = start;
    while pos + 8 <= end {
        let size32 = u32::from_be_bytes(b[pos..pos + 4].try_into().unwrap()) as usize;
        let typ: [u8; 4] = b[pos + 4..pos + 8].try_into().unwrap();
        let (size, header) = match size32 {
            1 => {
                if pos + 16 > end {
                    return Err(bad("MP4 box header"));
                }
                (u64::from_be_bytes(b[pos + 8..pos + 16].try_into().unwrap()) as usize, 16)
            }
            0 => (end - pos, 8),
            n => (n, 8),
        };
        if size < header || pos.checked_add(size).is_none_or(|e| e > end) {
            return Err(bad("MP4 box size"));
        }
        let body = pos + header;
        let box_end = pos + size;
        if MP4_METADATA.contains(&&typ) {
            b[pos + 4..pos + 8].copy_from_slice(b"free");
            b[body..box_end].fill(0);
        } else if MP4_PADDING.contains(&&typ) {
            b[body..box_end].fill(0);
        } else if MP4_CONTAINERS.contains(&&typ) {
            mp4_mem(b, body, box_end, depth + 1, dims)?;
        } else if &typ == b"mvhd" || &typ == b"tkhd" || &typ == b"mdhd" {
            // Full box: version(1) flags(3), then creation & modification time.
            if body + 4 <= box_end {
                let n = if b[body] == 1 { 16 } else { 8 };
                if body + 4 + n <= box_end {
                    b[body + 4..body + 4 + n].fill(0);
                }
                if &typ == b"tkhd" && box_end >= body + 8 {
                    // Width/height are the last 8 bytes (16.16 fixed point).
                    let w = u32::from_be_bytes(b[box_end - 8..box_end - 4].try_into().unwrap()) >> 16;
                    let h = u32::from_be_bytes(b[box_end - 4..box_end].try_into().unwrap()) >> 16;
                    if w > 0 && h > 0 {
                        *dims = (w, h);
                    }
                }
            }
        }
        pos = box_end;
    }
    Ok(())
}

/* ---------------- WebM / Matroska (EBML) ---------------- */

const EBML_VOID: u8 = 0xEC;
const MKV_SEGMENT: u32 = 0x1853_8067;
const MKV_CLUSTER: u32 = 0x1F43_B675;
const MKV_INFO: u32 = 0x1549_A966;
const MKV_TRACKS: u32 = 0x1654_AE6B;
/// Whole elements turned into `Void`.
const MKV_DROP: &[u32] = &[0x1254_C367 /* Tags */, 0x1941_A469 /* Attachments */, 0x1043_A770 /* Chapters */];
/// String/date elements whose contents are zeroed (Info and Tracks).
const MKV_ZERO: &[u32] = &[
    0x4461,   // DateUTC
    0x7BA9,   // Title
    0x4D80,   // MuxingApp
    0x5741,   // WritingApp
    0x536E,   // Track Name
    0x25_8688, // CodecName
];

/// Read an EBML variable-length integer: (value, width). For IDs the
/// marker bit is kept; for sizes it is removed. `None` value = unknown size.
fn vint(b: &[u8], keep_marker: bool) -> Option<(Option<u64>, usize)> {
    let first = *b.first()?;
    let width = first.leading_zeros() as usize + 1;
    if width > 8 || b.len() < width {
        return None;
    }
    let mut v: u64 = if keep_marker { first as u64 } else { (first as u64) & ((1u64 << (8 - width)) - 1) };
    for x in &b[1..width] {
        v = (v << 8) | *x as u64;
    }
    let all_ones = !keep_marker && v == (1u64 << (7 * width)) - 1;
    Some((if all_ones { None } else { Some(v) }, width))
}

/// Header of the element at `pos`: (id, data size, header length).
fn ebml_header<R: Read + Seek>(r: &mut R, pos: u64, end: u64) -> Result<(u32, Option<u64>, u64), SanitizeError> {
    let n = (end - pos).min(12) as usize;
    let h = read_at(r, pos, n)?;
    let (id, iw) = vint(&h, true).ok_or(bad("EBML id"))?;
    let (size, sw) = vint(h.get(iw..).ok_or(bad("EBML size"))?, false).ok_or(bad("EBML size"))?;
    Ok((id.unwrap_or(0) as u32, size, (iw + sw) as u64))
}

/// Turn the element at `pos` (header `hlen`, data `size`) into Void: a
/// 1-byte Void ID plus a size field widened to fill the old header.
fn ebml_void(pos: u64, hlen: u64, size: u64, s: &mut Scan) -> Result<(), SanitizeError> {
    let w = (hlen - 1) as usize;
    if !(1..=8).contains(&w) || size >= (1u64 << (7 * w)) - 1 {
        return Err(bad("EBML element can't be voided"));
    }
    let mut hdr = vec![EBML_VOID];
    let marked = size | (1u64 << (7 * w));
    hdr.extend_from_slice(&marked.to_be_bytes()[8 - w..]);
    s.patches.push(Patch { offset: pos, data: PatchData::Bytes(hdr) });
    s.patches.push(Patch { offset: pos + hlen, data: PatchData::Zeros(size) });
    Ok(())
}

fn ebml<R: Read + Seek>(r: &mut R, len: u64, s: &mut Scan) -> Result<(), SanitizeError> {
    let mut pos = 0;
    while pos < len {
        let (id, size, hlen) = ebml_header(r, pos, len)?;
        let data = pos + hlen;
        let end = match size {
            Some(n) => data.checked_add(n).filter(|e| *e <= len).ok_or(bad("EBML size"))?,
            None => len,
        };
        if id == MKV_SEGMENT {
            ebml_segment(r, data, end, s)?;
        }
        pos = end;
    }
    Ok(())
}

fn ebml_segment<R: Read + Seek>(r: &mut R, start: u64, end: u64, s: &mut Scan) -> Result<(), SanitizeError> {
    let mut pos = start;
    while pos + 2 <= end {
        let (id, size, hlen) = ebml_header(r, pos, end)?;
        let data = pos + hlen;
        let Some(size) = size else {
            // Unknown-size element (live recordings): only clusters do this,
            // and metadata elements precede them.
            if id == MKV_CLUSTER {
                return Ok(());
            }
            return Err(bad("EBML unknown size"));
        };
        let elem_end = data.checked_add(size).filter(|e| *e <= end).ok_or(bad("EBML size"))?;
        if MKV_DROP.contains(&id) {
            ebml_void(pos, hlen, size, s)?;
        } else if id == MKV_INFO || id == MKV_TRACKS {
            ebml_zero_children(r, data, elem_end, 0, s)?;
        }
        pos = elem_end;
    }
    Ok(())
}

/// Zero the data of identifying string elements under Info / Tracks.
fn ebml_zero_children<R: Read + Seek>(r: &mut R, start: u64, end: u64, depth: u8, s: &mut Scan) -> Result<(), SanitizeError> {
    if depth > 4 {
        return Ok(());
    }
    let mut pos = start;
    while pos + 2 <= end {
        let (id, size, hlen) = ebml_header(r, pos, end)?;
        let size = size.ok_or(bad("EBML unknown size"))?;
        let data = pos + hlen;
        let elem_end = data.checked_add(size).filter(|e| *e <= end).ok_or(bad("EBML size"))?;
        if MKV_ZERO.contains(&id) {
            s.patches.push(Patch { offset: data, data: PatchData::Zeros(size) });
        } else if id == 0xAE /* TrackEntry */ {
            ebml_zero_children(r, data, elem_end, depth + 1, s)?;
        } else if id == 0xE0 /* Video */ {
            let mut d = data;
            while d + 2 <= elem_end {
                let (cid, csize, chl) = ebml_header(r, d, elem_end)?;
                let csize = csize.ok_or(bad("EBML size"))?;
                if (cid == 0xB0 || cid == 0xBA) && csize <= 8 {
                    let v = read_at(r, d + chl, csize as usize)?.iter().fold(0u64, |a, x| (a << 8) | *x as u64) as u32;
                    if cid == 0xB0 { s.dims.0 = v } else { s.dims.1 = v }
                }
                d += chl + csize;
            }
        }
        pos = elem_end;
    }
    Ok(())
}

/* ---------------- MP3 ---------------- */

fn mp3<R: Read + Seek>(r: &mut R, len: u64, s: &mut Scan) -> Result<(), SanitizeError> {
    // ID3v2 at the start: keep the 10-byte header (flags cleared), turn
    // everything after it into padding — a valid, empty tag.
    if len >= 10 {
        let h = read_at(r, 0, 10)?;
        if &h[..3] == b"ID3" {
            let size = ((h[6] as u64 & 0x7F) << 21) | ((h[7] as u64 & 0x7F) << 14) | ((h[8] as u64 & 0x7F) << 7) | (h[9] as u64 & 0x7F);
            let footer = if h[5] & 0x10 != 0 { 10 } else { 0 };
            let total = (10 + size + footer).min(len);
            s.patches.push(Patch { offset: 5, data: PatchData::Bytes(vec![0]) });
            // The footer (if any) becomes padding too; the size field stays
            // valid because padding is part of the tag.
            if total > 10 {
                s.patches.push(Patch { offset: 10, data: PatchData::Zeros(total - 10) });
            }
        }
    }
    // ID3v1 at the end: keep the "TAG" marker, empty every field.
    if len >= 128 + 10 {
        let t = read_at(r, len - 128, 3)?;
        if &t == b"TAG" {
            s.patches.push(Patch { offset: len - 125, data: PatchData::Zeros(125) });
        }
    }
    Ok(())
}

/* ---------------- FLAC ---------------- */

fn flac<R: Read + Seek>(r: &mut R, len: u64, s: &mut Scan) -> Result<(), SanitizeError> {
    let mut pos = 4;
    loop {
        if pos + 4 > len {
            return Err(bad("FLAC metadata"));
        }
        let h = read_at(r, pos, 4)?;
        let last = h[0] & 0x80 != 0;
        let typ = h[0] & 0x7F;
        let size = u32::from_be_bytes([0, h[1], h[2], h[3]]) as u64;
        // 2 APPLICATION, 4 VORBIS_COMMENT, 6 PICTURE -> 1 PADDING.
        if matches!(typ, 2 | 4 | 6) {
            s.patches.push(Patch { offset: pos, data: PatchData::Bytes(vec![(h[0] & 0x80) | 1]) });
            s.patches.push(Patch { offset: pos + 4, data: PatchData::Zeros(size.min(len - pos - 4)) });
        }
        pos += 4 + size;
        if last || typ == 127 {
            return Ok(());
        }
    }
}

/* ---------------- WAV ---------------- */

const WAV_METADATA: &[&[u8; 4]] = &[b"LIST", b"bext", b"iXML", b"id3 ", b"ID3 ", b"_PMX", b"cart", b"DISP"];

fn wav<R: Read + Seek>(r: &mut R, len: u64, s: &mut Scan) -> Result<(), SanitizeError> {
    let mut pos = 12;
    while pos + 8 <= len {
        let h = read_at(r, pos, 8)?;
        let id: [u8; 4] = h[..4].try_into().unwrap();
        let size = u32::from_le_bytes(h[4..8].try_into().unwrap()) as u64;
        let body = (size + 1) & !1; // chunks are word-aligned
        if WAV_METADATA.contains(&&id) {
            s.patches.push(Patch { offset: pos, data: PatchData::Bytes(b"JUNK".to_vec()) });
            s.patches.push(Patch { offset: pos + 8, data: PatchData::Zeros(size.min(len - pos - 8)) });
        }
        pos += 8 + body;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn clean(b: &[u8]) -> Vec<u8> {
        let fmt = detect(b);
        let s = scan(fmt, &mut Cursor::new(b), b.len() as u64).unwrap();
        let mut out = b.to_vec();
        apply(&s.patches, 0, &mut out);
        out
    }

    fn has(b: &[u8], needle: &[u8]) -> bool {
        b.windows(needle.len()).any(|w| w == needle)
    }

    fn bx(t: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(t);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn mp4_top_level_and_nested_metadata_removed() {
        let mut mvhd = vec![0u8; 100];
        mvhd[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        let moov = [bx(b"mvhd", &mvhd), bx(b"udta", b"GPS +40.7-074.0 iPhone")].concat();
        let file = [
            bx(b"ftyp", b"isom\0\0\0\0isom"),
            bx(b"free", b"old XMP CreatorTool=SECRET"),
            bx(b"moov", &moov),
            bx(b"mdat", b"VIDEO-DATA"),
            bx(b"uuid", b"XMP-SECRET-UUID-BOX"),
        ]
        .concat();
        let out = clean(&file);
        assert_eq!(out.len(), file.len());
        for secret in [&b"iPhone"[..], b"SECRET", &0x1234_5678u32.to_be_bytes()] {
            assert!(!has(&out, secret));
        }
        assert!(has(&out, b"VIDEO-DATA"));
    }

    fn ebml_el(id: &[u8], data: &[u8]) -> Vec<u8> {
        let mut v = id.to_vec();
        v.push(0x80 | data.len() as u8); // 1-byte size (tests keep data < 127)
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn webm_tags_and_writing_app_removed() {
        let header = ebml_el(&[0x1A, 0x45, 0xDF, 0xA3], &ebml_el(&[0x42, 0x82], b"webm"));
        let info = ebml_el(&[0x15, 0x49, 0xA9, 0x66], &[ebml_el(&[0x57, 0x41], b"SecretCam v2"), ebml_el(&[0x7B, 0xA9], b"My Title")].concat());
        let tags = ebml_el(&[0x12, 0x54, 0xC3, 0x67], b"LOCATION=SECRETPLACE");
        let cluster = ebml_el(&[0x1F, 0x43, 0xB6, 0x75], b"FRAMES");
        let seg_body = [info, tags, cluster].concat();
        let mut seg = vec![0x18, 0x53, 0x80, 0x67, 0x40 | 0, seg_body.len() as u8];
        seg[4] = 0x40; // 2-byte size
        seg.extend_from_slice(&seg_body);
        let file = [header, seg].concat();
        assert_eq!(detect(&file), Format::Webm);
        let out = clean(&file);
        assert_eq!(out.len(), file.len());
        for secret in [&b"SecretCam"[..], b"My Title", b"SECRETPLACE"] {
            assert!(!has(&out, secret));
        }
        assert!(has(&out, b"FRAMES"));
    }

    #[test]
    fn mp3_flac_wav_tags_removed() {
        // MP3: ID3v2 with a title frame, a frame header, ID3v1.
        let frames = b"TIT2\0\0\0\x08\0\0\0SECRET1";
        let mut mp3f = b"ID3\x03\0\0\0\0\0".to_vec();
        mp3f.push(frames.len() as u8);
        mp3f.extend_from_slice(frames);
        mp3f.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        mp3f.extend_from_slice(&[0u8; 200]);
        let mut v1 = b"TAGSECRET2".to_vec();
        v1.resize(128, 0);
        mp3f.extend_from_slice(&v1);
        let out = clean(&mp3f);
        assert!(!has(&out, b"SECRET"));
        assert!(has(&out, &[0xFF, 0xFB, 0x90, 0x00]));

        // FLAC: STREAMINFO, VORBIS_COMMENT (last).
        let mut fl = b"fLaC".to_vec();
        fl.extend_from_slice(&[0, 0, 0, 34]);
        fl.extend_from_slice(&[7u8; 34]);
        let vc = b"ARTIST=SECRET3";
        fl.extend_from_slice(&[0x84, 0, 0, vc.len() as u8]);
        fl.extend_from_slice(vc);
        fl.extend_from_slice(b"AUDIOFRAMES");
        let out = clean(&fl);
        assert!(!has(&out, b"SECRET3"));
        assert_eq!(out[42], 0x81); // now PADDING, still last
        assert!(has(&out, b"AUDIOFRAMES"));

        // WAV: fmt, LIST/INFO, data.
        let mut w = b"RIFF\0\0\0\0WAVE".to_vec();
        w.extend_from_slice(b"fmt \x04\0\0\0abcd");
        let info = b"INFOIART\x08\0\0\0SECRET4!";
        w.extend_from_slice(b"LIST");
        w.extend_from_slice(&(info.len() as u32).to_le_bytes());
        w.extend_from_slice(info);
        w.extend_from_slice(b"data\x04\0\0\0PCM!");
        let out = clean(&w);
        assert!(!has(&out, b"SECRET4"));
        assert!(has(&out, b"JUNK") && has(&out, b"PCM!"));
    }

    #[test]
    fn apply_works_across_buffer_boundaries() {
        let patches = vec![Patch { offset: 3, data: PatchData::Bytes(vec![9, 9, 9, 9]) }];
        let mut a = vec![0u8; 5];
        apply(&patches, 0, &mut a);
        let mut b = vec![0u8; 5];
        apply(&patches, 5, &mut b);
        assert_eq!(a, vec![0, 0, 0, 9, 9]);
        assert_eq!(b, vec![9, 9, 0, 0, 0]);
    }

    #[test]
    fn other_files_pass_through() {
        assert_eq!(detect(b"PK\x03\x04zip"), Format::Other);
        assert_eq!(detect(b"7z\xBC\xAF\x27\x1C"), Format::Other);
        assert!(!Format::Other.cleaned());
    }
}
