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
//! - MP4 / MOV / M4A: `udta`, `meta`, `uuid` (XMP), `ilst`, `keys` and any
//!   top-level box that isn't needed to play become `free` boxes;
//!   `free`/`skip`/`wide` contents (editors leave old metadata there) are
//!   zeroed; creation/modification times in `mvhd`/`tkhd`/`mdhd`, track
//!   languages, handler names ("GoPro AVC") and encoder names in video
//!   sample entries are blanked. Fragmented files (`moof`) are cleaned too;
//!   compressed headers (`cmov`) and boxes nested too deep are refused.
//! - WebM / Matroska: `Tags`, `Attachments`, `Chapters` become `Void`;
//!   `DateUTC`, `Title`, `MuxingApp`, `WritingApp`, track names and the
//!   original file names are zeroed, and old `Void` contents too. Elements
//!   after live-recording (unknown-size) clusters are cleaned as well.
//! - MP3: ID3v2 frames become padding, ID3v1 is emptied, APEv2, Lyrics3
//!   and appended ID3v2 tags are zeroed, and the encoder name (LAME, Lavf)
//!   is blanked. A FLAC file behind an ID3 tag is cleaned as FLAC too.
//! - FLAC: Vorbis comments, pictures, cue sheets and application blocks
//!   become padding.
//! - WAV: only the chunks needed to play (and a few harmless ones) are kept;
//!   the rest (`LIST`/INFO, `bext`, `iXML`, `axml`, XMP …) become `JUNK`.
//!
//! Everything else (archives, documents, Ogg, HEIC …) is passed through
//! unchanged as a *file* and the UI warns that it may carry metadata.
//!
//! MP4/MOV and WebM/Matroska files with any track other than video and
//! audio (GPS and sensor tracks from phones and action cameras, timecode,
//! captions) are refused: their samples sit among the media data, where
//! in-place cleaning can't reach them. FFmpeg's remux leaves them out.

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
    /// A track that isn't video or audio (GPS, sensor, timecode, captions
    /// ...): only FFmpeg can leave it out, so without it the file is refused.
    #[error("the file has a \"{0}\" track besides its video and audio (it may hold location or sensor data), which can only be removed with FFmpeg")]
    ExtraTrack(String),
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
        Format::Flac => flac(r, 0, len, &mut s)?,
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
/// Top-level boxes kept as they are (everything else becomes `free`).
const MP4_TOP_KEEP: &[&[u8; 4]] = &[b"ftyp", b"styp", b"mdat", b"mfra", b"sidx", b"ssix", b"pdin"];
/// Video sample entries (their 32-byte `compressorname` names the encoder).
const MP4_VIDEO_ENTRIES: &[&[u8; 4]] = &[
    b"avc1", b"avc3", b"hvc1", b"hev1", b"dvh1", b"dvhe", b"mp4v", b"vp08", b"vp09", b"av01", b"jpeg", b"mjpa", b"mjpb", b"apcn", b"apch", b"apcs", b"apco", b"ap4h", b"ap4x", b"s263", b"h263",
];
/// Undetermined language ("und", packed ISO 639-2).
const MP4_LANG_UND: [u8; 2] = [0x55, 0xC4];

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
            mp4_mem(&mut b, header as usize, size as usize, 0, &typ, &mut s.dims)?;
            if b != orig {
                s.patches.push(Patch { offset: pos, data: PatchData::Bytes(b) });
            }
        } else if !MP4_TOP_KEEP.contains(&&typ) {
            // Unknown at the top (vendor trailers, `emsg`, `prft` times …):
            // not needed to play, so blanked.
            s.patches.push(Patch { offset: pos + 4, data: PatchData::Bytes(b"free".to_vec()) });
            s.patches.push(Patch { offset: pos + header, data: PatchData::Zeros(size - header) });
        }
        pos += size;
    }
    Ok(())
}

/// Clean boxes inside an in-memory region.
pub(crate) fn mp4_mem(b: &mut [u8], start: usize, end: usize, depth: u8, parent: &[u8; 4], dims: &mut (u32, u32)) -> Result<(), SanitizeError> {
    if depth > 10 {
        return Err(bad("MP4 boxes nested too deep"));
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
        if &typ == b"cmov" {
            // A compressed header: its metadata (and tracks) can't be seen.
            return Err(bad("compressed MP4 header"));
        }
        if MP4_METADATA.contains(&&typ) {
            b[pos + 4..pos + 8].copy_from_slice(b"free");
            b[body..box_end].fill(0);
        } else if MP4_PADDING.contains(&&typ) {
            b[body..box_end].fill(0);
        } else if MP4_CONTAINERS.contains(&&typ) {
            mp4_mem(b, body, box_end, depth + 1, &typ, dims)?;
        } else if &typ == b"hdlr" {
            // Handler: version/flags(4), pre-defined(4), type(4), reserved(12),
            // then a name ("Core Media Video", "GoPro AVC"), blanked.
            if parent == b"mdia" {
                let kind: [u8; 4] = b.get(body + 8..body + 12).filter(|_| body + 12 <= box_end).ok_or(bad("MP4 handler"))?.try_into().unwrap();
                if &kind != b"vide" && &kind != b"soun" {
                    return Err(SanitizeError::ExtraTrack(String::from_utf8_lossy(&kind).into_owned()));
                }
            }
            if body + 24 < box_end {
                b[body + 24..box_end].fill(0);
            }
        } else if &typ == b"stsd" {
            // Sample descriptions: full box(4), entry count(4), entries.
            let mut e = body + 8;
            while e + 8 <= box_end {
                let esize = u32::from_be_bytes(b[e..e + 4].try_into().unwrap()) as usize;
                let etype: [u8; 4] = b[e + 4..e + 8].try_into().unwrap();
                if esize < 8 || e + esize > box_end {
                    return Err(bad("MP4 sample entry"));
                }
                // Visual sample entry: the encoder name sits at 50..82.
                if MP4_VIDEO_ENTRIES.contains(&&etype) && esize >= 82 {
                    b[e + 50..e + 82].fill(0);
                }
                e += esize;
            }
        } else if &typ == b"mvhd" || &typ == b"tkhd" || &typ == b"mdhd" {
            // Full box: version(1) flags(3), then creation & modification time.
            if body + 4 <= box_end {
                let n = if b[body] == 1 { 16 } else { 8 };
                if body + 4 + n <= box_end {
                    b[body + 4..body + 4 + n].fill(0);
                }
                // mdhd: the language after timescale and duration.
                if &typ == b"mdhd" {
                    let lang = if b[body] == 1 { body + 32 } else { body + 20 };
                    if lang + 2 <= box_end {
                        b[lang..lang + 2].copy_from_slice(&MP4_LANG_UND);
                    }
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
    0x7384,    // SegmentFilename
    0x3C_83AB, // PrevFilename
    0x3E_83BB, // NextFilename
];
/// What a Cluster may hold: anything else ends an unknown-size one.
const MKV_CLUSTER_CHILDREN: &[u32] = &[0xE7, 0xA3, 0xA0, 0xA7, 0xAB, 0x5854, 0xAF, 0xEC, 0xBF];

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
            // Unknown-size element (live recordings): only clusters do this.
            // It ends where something that isn't a cluster's child starts,
            // and whatever follows (tags at the end) is cleaned as well.
            if id != MKV_CLUSTER {
                return Err(bad("EBML unknown size"));
            }
            let mut c = data;
            while c + 2 <= end {
                let (cid, csize, chl) = ebml_header(r, c, end)?;
                if !MKV_CLUSTER_CHILDREN.contains(&cid) {
                    break;
                }
                let csize = csize.ok_or(bad("EBML unknown size"))?;
                c = (c + chl).checked_add(csize).filter(|e| *e <= end).ok_or(bad("EBML size"))?;
            }
            pos = c;
            continue;
        };
        let elem_end = data.checked_add(size).filter(|e| *e <= end).ok_or(bad("EBML size"))?;
        if MKV_DROP.contains(&id) {
            ebml_void(pos, hlen, size, s)?;
        } else if id == u32::from(EBML_VOID) {
            // Old contents of padding (editors leave stale data there).
            s.patches.push(Patch { offset: data, data: PatchData::Zeros(size) });
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
        if MKV_ZERO.contains(&id) || id == u32::from(EBML_VOID) {
            s.patches.push(Patch { offset: data, data: PatchData::Zeros(size) });
        } else if id == 0x83 /* TrackType */ && depth == 1 {
            // 1 video, 2 audio; anything else (subtitles, metadata ...) stays put.
            if size == 0 || size > 8 {
                return Err(bad("EBML track type"));
            }
            let t = read_at(r, data, size as usize)?.iter().fold(0u64, |a, x| (a << 8) | *x as u64);
            if t != 1 && t != 2 {
                let name = match t {
                    0x11 => "subtitle".to_owned(),
                    0x21 => "metadata".to_owned(),
                    n => format!("type {n}"),
                };
                return Err(SanitizeError::ExtraTrack(name));
            }
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
    let mut audio_start = 0;
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
            audio_start = total;
        }
    }
    // A FLAC file behind an ID3 tag (some taggers do this): clean it as FLAC.
    if audio_start + 4 <= len && read_at(r, audio_start, 4)? == b"fLaC" {
        return flac(r, audio_start, len, s);
    }
    // The encoder's name and version in the first frame's info tag.
    let n = (len - audio_start).min(4096) as usize;
    let head = read_at(r, audio_start, n)?;
    let info = head.windows(4).position(|w| w == b"Xing" || w == b"Info");
    let enc = info.and_then(|p| head[p..head.len().min(p + 200)].windows(4).position(|w| w == b"LAME" || w == b"Lavf" || w == b"Lavc").map(|i| p + i));
    if let Some(i) = enc {
        let at = audio_start + i as u64;
        s.patches.push(Patch { offset: at, data: PatchData::Zeros(9.min(len - at)) });
    }
    // Tags at the end, from the very end backwards: ID3v1, then APEv2,
    // Lyrics3 and an appended ID3v2 tag, in any order.
    let mut tail = len;
    if len >= 128 + 10 {
        let t = read_at(r, len - 128, 3)?;
        if &t == b"TAG" {
            // Keep the "TAG" marker, empty every field.
            s.patches.push(Patch { offset: len - 125, data: PatchData::Zeros(125) });
            tail = len - 128;
        }
    }
    for _ in 0..4 {
        if tail < audio_start + 32 {
            break;
        }
        let f = read_at(r, tail - 32, 32)?;
        if &f[..8] == b"APETAGEX" {
            // Size counts items and footer; a header (flag bit 31) comes on top.
            let size = u32::from_le_bytes(f[12..16].try_into().unwrap()) as u64;
            let header = if u32::from_le_bytes(f[20..24].try_into().unwrap()) & 0x8000_0000 != 0 { 32 } else { 0 };
            let start = tail.checked_sub(size + header).filter(|s| *s >= audio_start).ok_or(bad("APE tag"))?;
            s.patches.push(Patch { offset: start, data: PatchData::Zeros(tail - start) });
            tail = start;
            continue;
        }
        let l = read_at(r, tail - 15, 15)?;
        if &l[6..] == b"LYRICS200" {
            let size: u64 = std::str::from_utf8(&l[..6]).ok().and_then(|t| t.parse().ok()).ok_or(bad("Lyrics3 tag"))?;
            let start = tail.checked_sub(size + 15).filter(|s| *s >= audio_start).ok_or(bad("Lyrics3 tag"))?;
            s.patches.push(Patch { offset: start, data: PatchData::Zeros(tail - start) });
            tail = start;
            continue;
        }
        let i = read_at(r, tail - 10, 10)?;
        if &i[..3] == b"3DI" {
            // An ID3v2 footer: the tag (header, frames, footer) ends here.
            let size = ((i[6] as u64 & 0x7F) << 21) | ((i[7] as u64 & 0x7F) << 14) | ((i[8] as u64 & 0x7F) << 7) | (i[9] as u64 & 0x7F);
            let start = tail.checked_sub(size + 20).filter(|s| *s >= audio_start).ok_or(bad("ID3 tag"))?;
            s.patches.push(Patch { offset: start, data: PatchData::Zeros(tail - start) });
            tail = start;
            continue;
        }
        break;
    }
    Ok(())
}

/* ---------------- FLAC ---------------- */

fn flac<R: Read + Seek>(r: &mut R, start: u64, len: u64, s: &mut Scan) -> Result<(), SanitizeError> {
    let mut pos = start + 4;
    loop {
        if pos + 4 > len {
            return Err(bad("FLAC metadata"));
        }
        let h = read_at(r, pos, 4)?;
        let last = h[0] & 0x80 != 0;
        let typ = h[0] & 0x7F;
        let size = u32::from_be_bytes([0, h[1], h[2], h[3]]) as u64;
        // 2 APPLICATION, 4 VORBIS_COMMENT, 5 CUESHEET (catalog number,
        // ISRC), 6 PICTURE -> 1 PADDING.
        if matches!(typ, 2 | 4 | 5 | 6) {
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

/// Chunks kept (needed to play, or carrying nothing about the recording);
/// every other chunk becomes `JUNK`.
const WAV_KEEP: &[&[u8; 4]] = &[b"fmt ", b"data", b"fact", b"JUNK", b"junk", b"PAD ", b"pad ", b"ds64", b"cue ", b"smpl", b"inst", b"plst", b"wavl", b"slnt"];

fn wav<R: Read + Seek>(r: &mut R, len: u64, s: &mut Scan) -> Result<(), SanitizeError> {
    let mut pos = 12;
    while pos + 8 <= len {
        let h = read_at(r, pos, 8)?;
        let id: [u8; 4] = h[..4].try_into().unwrap();
        let size = u32::from_le_bytes(h[4..8].try_into().unwrap()) as u64;
        let body = (size + 1) & !1; // chunks are word-aligned
        if !WAV_KEEP.contains(&&id) {
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

    #[test]
    fn mp4_handler_encoder_language_and_vendor_boxes_blanked() {
        let mut hdlr = vec![0u8; 24];
        hdlr[8..12].copy_from_slice(b"vide");
        hdlr.extend_from_slice(b"GoPro AVC\0");
        let mut mdhd = vec![0u8; 24];
        mdhd[20..22].copy_from_slice(&[0x15, 0xC7]); // "eng"
        let mut entry = vec![0u8; 78];
        entry[42..42 + 13].copy_from_slice(b"\x0dSecretEncodr");
        let stsd = [vec![0u8; 4], 1u32.to_be_bytes().to_vec(), bx(b"avc1", &entry)].concat();
        let stbl = bx(b"stbl", &bx(b"stsd", &stsd));
        let mdia = bx(b"mdia", &[bx(b"mdhd", &mdhd), bx(b"hdlr", &hdlr), bx(b"minf", &stbl)].concat());
        let file = [bx(b"ftyp", b"isom\0\0\0\0isom"), bx(b"moov", &bx(b"trak", &mdia)), bx(b"mdat", b"VIDEO-DATA"), bx(b"prft", b"WALLCLOCK-TIME")].concat();
        let out = clean(&file);
        assert_eq!(out.len(), file.len());
        for secret in [&b"GoPro"[..], b"SecretEncodr", b"WALLCLOCK", &[0x15, 0xC7]] {
            assert!(!has(&out, secret), "{:?} left", String::from_utf8_lossy(secret));
        }
        assert!(has(&out, b"VIDEO-DATA") && has(&out, &MP4_LANG_UND));
        // A compressed header is refused.
        let cm = [bx(b"ftyp", b"isom\0\0\0\0isom"), bx(b"moov", &bx(b"cmov", b"zlib..."))].concat();
        assert!(scan(Format::Mp4, &mut Cursor::new(&cm), cm.len() as u64).is_err());
    }

    #[test]
    fn mp3_end_tags_encoder_and_id3_flac_cleaned() {
        let mut id3 = b"ID3\x04\0\0\0\0\0\x0a".to_vec();
        id3.extend_from_slice(b"TIT2SECRET");
        let mut frame = vec![0xFF, 0xFB, 0x90, 0x00];
        frame.extend_from_slice(&[0u8; 32]);
        frame.extend_from_slice(b"Xing\0\0\0\x0f");
        frame.extend_from_slice(&[0u8; 100]);
        frame.extend_from_slice(b"LAME3.100");
        frame.extend_from_slice(&[0u8; 400]);
        let items = b"Artist\0SECRETAPE";
        let mut ape = items.to_vec();
        let mut footer = b"APETAGEX".to_vec();
        footer.extend_from_slice(&2000u32.to_le_bytes());
        footer.extend_from_slice(&((items.len() + 32) as u32).to_le_bytes());
        footer.extend_from_slice(&1u32.to_le_bytes());
        footer.extend_from_slice(&0u32.to_le_bytes());
        footer.extend_from_slice(&[0u8; 8]);
        ape.extend_from_slice(&footer);
        let lyr = [b"LYRICSBEGIN".to_vec(), b"SECRETLYR".to_vec()].concat();
        let lyrics = [lyr.clone(), format!("{:06}", lyr.len()).into_bytes(), b"LYRICS200".to_vec()].concat();
        let mut tag = b"TAG".to_vec();
        tag.extend_from_slice(b"SECRETV1");
        tag.resize(128, 0);
        let file = [id3, frame, lyrics, ape, tag].concat();
        assert_eq!(detect(&file), Format::Mp3);
        let out = clean(&file);
        for secret in [&b"SECRET"[..], b"LAME3"] {
            assert!(!has(&out, secret));
        }
        assert!(has(&out, b"Xing"));
        // FLAC behind an ID3 tag: its comments go too.
        let mut f = b"ID3\x04\0\0\0\0\0\x04TIT2".to_vec();
        f.extend_from_slice(b"fLaC");
        f.extend_from_slice(&[0x00, 0, 0, 4, 1, 2, 3, 4]); // STREAMINFO (short, test only)
        f.extend_from_slice(&[0x84, 0, 0, 10]);
        f.extend_from_slice(b"ARTIST=SEC");
        let out = clean(&f);
        assert!(!has(&out, b"ARTIST=SEC"));
    }

    #[test]
    fn wav_keeps_only_known_chunks() {
        let chunk = |id: &[u8; 4], body: &[u8]| [id.to_vec(), (body.len() as u32).to_le_bytes().to_vec(), body.to_vec()].concat();
        let body = [b"WAVE".to_vec(), chunk(b"fmt ", &[1u8; 16]), chunk(b"axml", b"<x>SECRETXML</x>"), chunk(b"PEAK", b"TIMESTAMP!"), chunk(b"data", b"SAMPLES!")].concat();
        let file = [b"RIFF".to_vec(), (body.len() as u32).to_le_bytes().to_vec(), body].concat();
        let out = clean(&file);
        assert!(!has(&out, b"SECRETXML") && !has(&out, b"TIMESTAMP"));
        assert!(has(&out, b"SAMPLES!") && has(&out, b"fmt "));
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

    fn mp4_with_tracks(handlers: &[&[u8; 4]]) -> Vec<u8> {
        let traks: Vec<u8> = handlers
            .iter()
            .flat_map(|h| {
                let hdlr = bx(b"hdlr", &[&[0u8; 8][..], &h[..], &[0u8; 12]].concat());
                bx(b"trak", &bx(b"mdia", &[bx(b"mdhd", &[0u8; 24]), hdlr].concat()))
            })
            .collect();
        [bx(b"ftyp", b"isom\0\0\0\0isom"), bx(b"moov", &traks), bx(b"mdat", b"SAMPLES")].concat()
    }

    #[test]
    fn mp4_with_gps_or_other_data_tracks_is_refused() {
        let ok = mp4_with_tracks(&[b"vide", b"soun"]);
        assert!(scan(Format::Mp4, &mut Cursor::new(&ok), ok.len() as u64).is_ok());
        // GoPro GPS ("meta"), Google camera motion ("camm"), Apple's location
        // and timecode tracks ("mebx", "tmcd"), captions ("text").
        for extra in [b"meta", b"camm", b"mebx", b"tmcd", b"text"] {
            let f = mp4_with_tracks(&[b"vide", extra, b"soun"]);
            match scan(Format::Mp4, &mut Cursor::new(&f), f.len() as u64) {
                Err(SanitizeError::ExtraTrack(t)) => assert_eq!(t.as_bytes(), extra),
                other => panic!("{other:?}"),
            }
            // The in-memory path (small files) refuses it too.
            assert!(crate::media::sanitize(&f).is_err());
        }
        // A "meta" box's own handler (not a track's) is fine: the box is blanked.
        let hdlr = bx(b"hdlr", &[&[0u8; 8][..], &b"vide"[..], &[0u8; 12]].concat());
        let trak = bx(b"trak", &bx(b"mdia", &hdlr));
        let meta = bx(b"meta", &bx(b"hdlr", &[&[0u8; 8][..], &b"mdir"[..], &[0u8; 12]].concat()));
        let f = [bx(b"ftyp", b"isom\0\0\0\0isom"), bx(b"moov", &[trak, bx(b"udta", &meta)].concat())].concat();
        assert!(scan(Format::Mp4, &mut Cursor::new(&f), f.len() as u64).is_ok());
    }

    #[test]
    fn webm_with_subtitle_or_metadata_tracks_is_refused() {
        let file = |types: &[u8]| {
            let header = ebml_el(&[0x1A, 0x45, 0xDF, 0xA3], &ebml_el(&[0x42, 0x82], b"webm"));
            let entries: Vec<u8> = types.iter().flat_map(|t| ebml_el(&[0xAE], &ebml_el(&[0x83], &[*t]))).collect();
            let tracks = ebml_el(&[0x16, 0x54, 0xAE, 0x6B], &entries);
            let cluster = ebml_el(&[0x1F, 0x43, 0xB6, 0x75], b"FRAMES");
            let body = [tracks, cluster].concat();
            let mut seg = vec![0x18, 0x53, 0x80, 0x67, 0x40, body.len() as u8];
            seg.extend_from_slice(&body);
            [header, seg].concat()
        };
        let ok = file(&[1, 2]);
        assert!(scan(Format::Webm, &mut Cursor::new(&ok), ok.len() as u64).is_ok());
        for t in [0x11, 0x21, 0x03] {
            let f = file(&[1, t, 2]);
            assert!(matches!(scan(Format::Webm, &mut Cursor::new(&f), f.len() as u64), Err(SanitizeError::ExtraTrack(_))), "{t}");
        }
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
