//! Built-in pluggable transports and bridges (spec §9.8.4).
//!
//! The Tor Project's signed `lyrebird` binary (obfs4, WebTunnel, meek,
//! Snowflake) and its built-in bridge list are compiled into the client, so
//! bridge mode needs nothing installed. Provenance: `vendor/pt/PROVENANCE.md`.
//!
//! The binary is written to the local, non-synced data folder on first use and
//! its BLAKE3 hash is re-checked against the embedded copy before every
//! launch; a modified or corrupted file is replaced rather than executed.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

const PT_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vendor/pt/windows-x86_64/pt_config.json"
));

#[cfg(all(windows, target_arch = "x86_64"))]
const LYREBIRD: Option<&[u8]> = Some(include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vendor/pt/windows-x86_64/lyrebird.exe"
)));
#[cfg(not(all(windows, target_arch = "x86_64")))]
const LYREBIRD: Option<&[u8]> = None;

/// Built-in bridge sets shipped by the Tor Project that arti can use. (Tor's
/// built-in meek line omits the relay fingerprint, which arti requires.)
pub const BUILTIN_SETS: &[&str] = &["snowflake", "obfs4"];

/// Bridge lines for a built-in set.
pub fn builtin_bridges(set: &str) -> Result<Vec<String>> {
    let json: serde_json::Value = serde_json::from_str(PT_CONFIG).context("embedded pt_config.json is invalid")?;
    let list = json
        .get("bridges")
        .and_then(|b| b.get(set))
        .and_then(|v| v.as_array())
        .filter(|_| BUILTIN_SETS.contains(&set))
        .with_context(|| format!("no built-in bridge set '{set}' (have: {})", BUILTIN_SETS.join(", ")))?;
    let lines: Vec<String> = list.iter().filter_map(|v| v.as_str()).map(|s| s.trim().to_owned()).collect();
    if lines.is_empty() {
        bail!("built-in bridge set '{set}' is empty");
    }
    Ok(lines)
}

/// The address a bridge line connects to (None for lines without one).
fn bridge_addr(line: &str) -> Option<std::net::SocketAddr> {
    let mut words = line.split_whitespace();
    let mut first = words.next()?;
    if first.eq_ignore_ascii_case("bridge") {
        first = words.next()?;
    }
    let addr = if crate::bridge_transport(line).is_some() { words.next()? } else { first };
    addr.parse().ok()
}

/// Drop **built-in** bridges that don't accept connections at all.
///
/// The Tor library only uses its two "primary" bridges at a time and keeps
/// them across restarts, so a dead public bridge can stall bridge mode for
/// good. Public built-in bridges get a plain connection check (bridge mode
/// connects to them directly anyway, and their addresses are published).
/// Private bridges a person added are never probed: an extra connection to
/// a private bridge is a needless signal. Lines whose address is only a
/// placeholder (Snowflake goes through a broker) are kept as they are.
/// If nothing answers, the full list is returned and Tor decides.
///
/// Of the public bridges that answer, only the [`FASTEST`] quickest are kept,
/// quickest first: Tor tries two at a time and sticks with them, so a
/// crowded, slow bridge would otherwise hold up the start for minutes.
pub async fn drop_dead_builtin(lines: &[String]) -> Vec<String> {
    let public: Vec<String> = BUILTIN_SETS.iter().flat_map(|s| builtin_bridges(s).unwrap_or_default()).collect();
    let mut checks = tokio::task::JoinSet::new();
    for (i, l) in lines.iter().enumerate() {
        let addr = bridge_addr(l).filter(|a| public.contains(l) && !is_placeholder(a));
        checks.spawn(async move {
            let started = std::time::Instant::now();
            // (None: not a public bridge we probe; kept, ranked first.)
            let ms = match addr {
                None => Some(0),
                Some(a) => matches!(tokio::time::timeout(std::time::Duration::from_secs(6), tokio::net::TcpStream::connect(a)).await, Ok(Ok(_))).then(|| started.elapsed().as_millis().max(1)),
            };
            (i, ms)
        });
    }
    let mut timed: Vec<(u128, usize)> = Vec::new();
    while let Some(Ok((i, ms))) = checks.join_next().await {
        if let Some(ms) = ms {
            timed.push((ms, i));
        }
    }
    if timed.is_empty() {
        return lines.to_vec();
    }
    timed.sort();
    let mut probed = 0;
    timed
        .into_iter()
        .filter(|(ms, _)| {
            if *ms == 0 {
                return true;
            }
            probed += 1;
            probed <= FASTEST
        })
        .map(|(_, i)| lines[i].clone())
        .collect()
}

/// Public bridges kept after timing them.
pub const FASTEST: usize = 4;

/// Documentation-range addresses used by broker-based transports.
fn is_placeholder(a: &std::net::SocketAddr) -> bool {
    match a.ip() {
        std::net::IpAddr::V4(v4) => v4.octets()[..3] == [192, 0, 2],
        std::net::IpAddr::V6(_) => false,
    }
}

/// File name of the extracted built-in transport.
pub const BUILTIN_EXE: &str = if cfg!(windows) { "t.exe" } else { "t" };

/// Delete the extracted transport (when not using bridges).
pub fn remove_builtin_pt() {
    if let Ok(dir) = crate::data_root("pt") {
        let _ = std::fs::remove_file(dir.join(BUILTIN_EXE));
        let _ = std::fs::remove_file(dir.join(if cfg!(windows) { "lyrebird.exe" } else { "lyrebird" }));
    }
}

/// Folder containing the verified built-in transport program, extracting it
/// if needed. `None` on platforms without an embedded build.
pub fn builtin_pt_dir() -> Result<Option<PathBuf>> {
    let Some(bytes) = LYREBIRD else { return Ok(None) };
    let dir = crate::data_root("pt")?;
    // Neutral file name (a file called "lyrebird" announces a Tor
    // circumvention tool to anyone inspecting the device); it exists only
    // while bridge mode is used — `remove_builtin_pt` deletes it otherwise.
    let exe = dir.join(BUILTIN_EXE);
    let want = blake3::hash(bytes);
    let ok = std::fs::read(&exe).map(|b| blake3::hash(&b) == want).unwrap_or(false);
    if !ok {
        // Write to a temp file then rename, so a crash never leaves a
        // half-written executable that a later run might launch.
        let tmp = dir.join("t.tmp");
        std::fs::write(&tmp, bytes).context("extracting built-in transport")?;
        std::fs::rename(&tmp, &exe).context("installing built-in transport")?;
        let check = std::fs::read(&exe)?;
        if blake3::hash(&check) != want {
            bail!("built-in transport failed verification after extraction");
        }
    }
    Ok(Some(dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_addresses() {
        let a = bridge_addr("obfs4 203.0.113.9:443 316E64 cert=x iat-mode=0").unwrap();
        assert_eq!(a.port(), 443);
        assert_eq!(bridge_addr("Bridge 203.0.113.9:9001 316E64").unwrap().port(), 9001);
        assert!(is_placeholder(&bridge_addr("snowflake 192.0.2.3:80 2B28 url=x").unwrap()));
        assert!(bridge_addr("webtunnel [2001:db8::1]:443 ABCD url=https://x").is_some());
    }

    #[test]
    fn builtin_sets_parse() {
        for set in BUILTIN_SETS {
            let lines = builtin_bridges(set).unwrap();
            for l in &lines {
                crate::tor_config_with_bridges_check(l).unwrap();
                assert!(crate::bridge_transport(l).is_some());
            }
        }
        assert!(builtin_bridges("nonexistent").is_err());
    }
}
