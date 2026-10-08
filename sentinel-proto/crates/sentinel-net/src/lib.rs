//! Shared Tor configuration for all Sentinel binaries (spec §9.8).
//!
//! Privacy decisions encoded here:
//! - Full vanguards on every circuit type (defends guard-discovery attacks).
//! - Tor state, guards and keys live in a per-role directory under the local,
//!   non-synced app-data folder — never in a cloud-synced folder such as
//!   OneDrive, which would upload keys and guard choices to a third party.
//! - Onion addresses are allowed; nothing else in Sentinel ever needs an exit.

pub mod builtin_pt;
pub mod pool;
pub mod socks;
pub mod torchild;
pub mod transport;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BoolOrAuto, BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::TorClientConfig;
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;

/// Port every Sentinel onion service listens on (virtual; no local socket).
pub const SENTINEL_PORT: u16 = 7777;

/// Local, non-synced data root for a role (e.g. "client", "pillar").
pub fn data_root(role: &str) -> Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    }
    .context("cannot determine local app-data directory")?;

    let root = base.join("sentinel-proto").join(role);
    let lower = root.to_string_lossy().to_lowercase();
    for synced in ["onedrive", "dropbox", "google drive", "icloud"] {
        if lower.contains(synced) {
            bail!("refusing to store Tor/identity state in a cloud-synced folder: {}", root.display());
        }
    }
    std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
    Ok(root)
}

/// Opt-in diagnostic logging to stderr (never to disk). Off unless the user
/// passes `--debug-log`. arti's safe-logging stays on, so addresses and other
/// sensitive values are redacted in its messages.
pub fn enable_debug_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            std::env::var("SENTINEL_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with_writer(std::io::stderr)
        .try_init();
}

/// The connection log: the last lines from Tor and Sentinel's network code,
/// kept in memory only (never written to disk) so a tester can see and
/// share why connecting fails. arti's safe-logging stays on, so addresses
/// and other sensitive values are blanked out.
static MEMLOG: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<String>>> = std::sync::OnceLock::new();
const MEMLOG_LINES: usize = 400;

fn memlog() -> &'static std::sync::Mutex<std::collections::VecDeque<String>> {
    MEMLOG.get_or_init(Default::default)
}

/// Add a line to the connection log.
pub fn note(line: impl Into<String>) {
    let mut l = memlog().lock().unwrap_or_else(|e| e.into_inner());
    if l.len() >= MEMLOG_LINES {
        l.pop_front();
    }
    l.push_back(line.into());
}

/// The connection log as text.
pub fn connection_log() -> String {
    memlog().lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect::<Vec<_>>().join("\n")
}

struct MemWriter(Vec<u8>);

impl std::io::Write for MemWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for MemWriter {
    fn drop(&mut self) {
        for line in String::from_utf8_lossy(&self.0).lines() {
            if !line.trim().is_empty() {
                note(line.chars().take(400).collect::<String>());
            }
        }
    }
}

/// Send Tor's own messages (in-process Tor: phones) to the connection log.
pub fn enable_memory_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn,arti_client=info,tor_hsclient=debug,tor_circmgr=info,tor_guardmgr=info,tor_dirmgr=info"))
        .with_writer(|| MemWriter(Vec::new()))
        .with_ansi(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_target(true)
        .try_init();
}

/// Tor configuration for a role, with full vanguards and no bridges.
pub fn tor_config(role: &str) -> Result<TorClientConfig> {
    tor_config_with_bridges(role, &[], None)
}

/// Pluggable-transport programs and the transports each one provides.
/// `lyrebird` is the Tor Project's successor to obfs4proxy and now also
/// carries Snowflake.
const PT_PROGRAMS: &[(&str, &[&str])] = &[("lyrebird", &["obfs4", "webtunnel", "meek_lite", "snowflake"])];

/// Transport name used by a bridge line, if any (`None` = vanilla bridge).
pub fn bridge_transport(line: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    let mut first = words.next()?;
    if first.eq_ignore_ascii_case("bridge") {
        first = words.next()?;
    }
    // Vanilla bridge lines start with an address (digit or '[' for IPv6).
    let c = first.chars().next()?;
    if c.is_ascii_digit() || c == '[' {
        None
    } else {
        Some(first.to_owned())
    }
}

/// Validate a bridge line offline (syntax, address, fingerprint).
pub fn tor_config_with_bridges_check(line: &str) -> Result<()> {
    let _: BridgeConfigBuilder = line.parse().with_context(|| format!("invalid bridge line: {line}"))?;
    Ok(())
}

/// Locate the program providing `transport` in `pt_dir`.
pub fn find_pt_program(pt_dir: &Path, transport: &str) -> Option<PathBuf> {
    let (prog, _) = PT_PROGRAMS.iter().find(|(_, ts)| ts.contains(&transport))?;
    let exe = if cfg!(windows) { format!("{prog}.exe") } else { (*prog).to_owned() };
    let p = pt_dir.join(exe);
    if p.is_file() {
        return Some(p);
    }
    // The built-in copy uses a neutral name.
    let b = pt_dir.join(builtin_pt::BUILTIN_EXE);
    b.is_file().then_some(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_bridge_guards_are_tidied() {
        let dir = std::env::temp_dir().join(format!("sentinel-guards-{}", data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<6>())));
        std::fs::create_dir_all(dir.join("state")).unwrap();
        let keep = "2b280b23e1107bb62abfc40ddcc8824814f80a72";
        let gone = "000f3eb75342be371f1d8d3fae90890aeb5664ee";
        let saved = serde_json::json!({
            "default": { "guards": [] },
            "bridges": {
                "guards": [
                    { "id": { "rsa": keep }, "unlisted_since": "2026-10-04T06:42:47Z", "confirmed_at": "2026-09-30T14:55:00Z" },
                    { "id": { "rsa": gone }, "unlisted_since": null }
                ],
                "confirmed": [ { "rsa": gone }, { "rsa": keep } ]
            }
        });
        std::fs::write(dir.join("state/guards.json"), saved.to_string()).unwrap();
        let line = format!("snowflake 192.0.2.3:80 {} url=x", keep.to_uppercase());
        tidy_bridge_guards(&dir, &[line]);
        let j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("state/guards.json")).unwrap()).unwrap();
        let guards = j["bridges"]["guards"].as_array().unwrap();
        assert_eq!(guards.len(), 1);
        assert_eq!(guards[0]["id"]["rsa"], keep);
        assert!(guards[0]["unlisted_since"].is_null());
        assert_eq!(guards[0]["confirmed_at"], "2026-09-30T14:55:00Z", "other fields kept");
        assert_eq!(j["bridges"]["confirmed"].as_array().unwrap().len(), 1);
        assert!(j["default"].is_object(), "non-bridge state untouched");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn transport_detection() {
        assert_eq!(bridge_transport("192.0.2.1:443 316E643333645F6D79216558614D3931657A5F5F"), None);
        assert_eq!(bridge_transport("Bridge [2001:db8::1]:443 316E643333645F6D79216558614D3931657A5F5F"), None);
        assert_eq!(bridge_transport("obfs4 192.0.2.1:443 316E64 cert=x iat-mode=0").as_deref(), Some("obfs4"));
        assert_eq!(bridge_transport("Bridge snowflake 192.0.2.3:80 2B28 url=x").as_deref(), Some("snowflake"));
    }

    #[test]
    fn bridge_lines_validate_offline() {
        assert!(tor_config_with_bridges_check("192.0.2.55:443 316E643333645F6D79216558614D3931657A5F5F").is_ok());
        assert!(tor_config_with_bridges_check("not a bridge").is_err());
    }

    #[test]
    fn transport_without_program_fails_closed() {
        let lines = vec!["obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJl iat-mode=0".to_owned()];
        assert!(tor_config_with_bridges("test-bridges", &lines, None).is_err());
    }
}

/// Tor configuration that **only** enters the Tor network through the given
/// bridges (spec §9.8.4). With bridges configured, `bridges.enabled` is set
/// to an explicit `true`, so arti never falls back to public relays — if
/// every bridge fails, connecting fails rather than revealing Tor use.
pub fn tor_config_with_bridges(role: &str, bridges: &[String], pt_dir: Option<&Path>) -> Result<TorClientConfig> {
    // Select the TLS crypto backend explicitly (ring: small, long-audited).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = data_root(role)?;
    // Bridge and non-bridge operation keep separate state, so guard choices
    // made over public relays never leak into bridge mode or vice versa.
    let (state, cache) = if bridges.is_empty() {
        (root.join("tor-state"), root.join("tor-cache"))
    } else {
        (root.join("tor-state-bridges"), root.join("tor-cache-bridges"))
    };
    if !bridges.is_empty() {
        tidy_bridge_guards(&state, bridges);
        refresh_stale_bridge_cache(&state, &cache);
    }
    let mut b = TorClientConfigBuilder::from_directories(state, cache);
    b.vanguards().mode(ExplicitOrAuto::Explicit(VanguardMode::Full));
    b.address_filter().allow_onion_addrs(true);

    if !bridges.is_empty() {
        let mut needed: Vec<String> = Vec::new();
        for line in bridges {
            let bc: BridgeConfigBuilder = line
                .parse()
                .with_context(|| format!("invalid bridge line: {line}"))?;
            b.bridges().bridges().push(bc);
            if let Some(t) = bridge_transport(line) {
                if !needed.contains(&t) {
                    needed.push(t);
                }
            }
        }
        for t in &needed {
            let dir = pt_dir.with_context(|| {
                format!("bridge transport '{t}' needs its program; set the transports folder first")
            })?;
            let prog = find_pt_program(dir, t)
                .with_context(|| format!("no program for transport '{t}' in {}", dir.display()))?;
            let mut tc = TransportConfigBuilder::default();
            tc.protocols(vec![t.parse().with_context(|| format!("bad transport name {t}"))?])
                .path(CfgPath::new_literal(prog))
                .run_on_startup(false);
            b.bridges().transports().push(tc);
        }
        b.bridges().enabled(BoolOrAuto::Explicit(true));
    }
    Ok(b.build()?)
}

/// Tidy the Tor library's saved bridge list before it starts.
///
/// It remembers which bridges it used, including bridges no longer
/// configured, and marks them "unlisted" when it can't fetch their details.
/// Unlisted bridges count as unusable and the mark sticks, so a stale saved
/// list can stall bridge mode for good (seen live: every circuit refused
/// within seconds). Here we keep only bridges that are configured now (by
/// fingerprint) and clear the stale mark on those. Confirmed (preferred)
/// bridges stay preferred. If the file can't be read as expected, it's left
/// untouched.
///
/// When the set of bridges changes, the learned circuit-build timeout is
/// also discarded: a timeout learned over one transport (say obfs4) kills
/// every circuit over a slower one (Snowflake) as "too slow" (seen live).
/// Only a hash of the bridge set is kept, never the bridges themselves.
pub fn tidy_bridge_guards(state_dir: &Path, bridges: &[String]) {
    let mut ids: Vec<String> = bridges.iter().filter_map(|l| bridge_rsa(l)).collect();
    ids.sort();
    ids.dedup();
    let set_hash = data_encoding::HEXLOWER.encode(&blake3::derive_key("sentinel/v1/bridge-set", ids.join(",").as_bytes())[..16]);
    let marker = state_dir.join("bridge-set");
    if std::fs::read_to_string(&marker).ok().as_deref() != Some(set_hash.as_str()) {
        let _ = std::fs::remove_file(state_dir.join("state").join("circuit_timeouts.json"));
        // Also forget when bridge mode last worked: that was with other
        // bridges, so the cached directory is refetched through these.
        let _ = std::fs::remove_file(state_dir.join("bridges-ok"));
        let _ = std::fs::create_dir_all(state_dir);
        let _ = std::fs::write(&marker, &set_hash);
    }
    let path = state_dir.join("state").join("guards.json");
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Ok(mut j) = serde_json::from_str::<serde_json::Value>(&text) else { return };
    let wanted: Vec<String> = bridges.iter().filter_map(|l| bridge_rsa(l)).collect();
    let keep = |id: &serde_json::Value| id.get("rsa").and_then(|r| r.as_str()).is_some_and(|r| wanted.iter().any(|w| w.eq_ignore_ascii_case(r)));
    let Some(set) = j.get_mut("bridges").and_then(|b| b.as_object_mut()) else { return };
    let mut changed = false;
    if let Some(guards) = set.get_mut("guards").and_then(|g| g.as_array_mut()) {
        let before = guards.len();
        guards.retain(|g| g.get("id").is_some_and(|id| keep(id)));
        changed |= guards.len() != before;
        for g in guards.iter_mut() {
            if let Some(o) = g.as_object_mut() {
                if o.get("unlisted_since").is_some_and(|v| !v.is_null()) {
                    o.insert("unlisted_since".into(), serde_json::Value::Null);
                    changed = true;
                }
            }
        }
    }
    if let Some(confirmed) = set.get_mut("confirmed").and_then(|c| c.as_array_mut()) {
        let before = confirmed.len();
        confirmed.retain(|id| keep(id));
        changed |= confirmed.len() != before;
    }
    if changed {
        if let Ok(out) = serde_json::to_string(&j) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, out).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}

/// Where the time of the last working bridge-mode connection is kept.
static BRIDGE_OK_MARKER: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
/// A bridge-mode directory not confirmed working for this long is refetched.
const BRIDGE_CACHE_MAX_AGE: u64 = 24 * 3600;

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Discard a bridge-mode directory cache that hasn't been confirmed working
/// in the last day.
///
/// The Tor library happily starts from an expired cached directory and
/// reports itself ready before it has fetched the bridges' details through
/// the bridges; every connection then fails within seconds (seen live).
/// Without the cache it does a real start through the bridges, which waits
/// until they're usable. The marker holds only a time.
fn refresh_stale_bridge_cache(state: &Path, cache: &Path) {
    let marker = state.join("bridges-ok");
    let fresh = std::fs::read_to_string(&marker)
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .is_some_and(|t| unix_now().saturating_sub(t) < BRIDGE_CACHE_MAX_AGE);
    if !fresh {
        let _ = std::fs::remove_dir_all(cache);
    }
    *BRIDGE_OK_MARKER.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(marker);
}

/// Did bridge mode work for `role` in the last day?
pub fn bridges_recently_ok(role: &str) -> bool {
    let Ok(root) = data_root(role) else { return false };
    std::fs::read_to_string(root.join("tor-state-bridges").join("bridges-ok"))
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .is_some_and(|t| unix_now().saturating_sub(t) < BRIDGE_CACHE_MAX_AGE)
}

/// Is this process using bridges?
pub(crate) fn bridge_mode_active() -> bool {
    BRIDGE_OK_MARKER.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_some()
}

/// A connection worked: remember when (at most once an hour).
pub(crate) fn note_bridge_success() {
    let Some(marker) = BRIDGE_OK_MARKER.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone() else { return };
    let recent = std::fs::read_to_string(&marker)
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .is_some_and(|t| unix_now().saturating_sub(t) < 3600);
    if !recent {
        let _ = std::fs::write(&marker, unix_now().to_string());
    }
}

/// The RSA fingerprint in a bridge line (40 hex digits), lower-case.
fn bridge_rsa(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|w| w.len() == 40 && w.bytes().all(|c| c.is_ascii_hexdigit()))
        .map(|w| w.to_ascii_lowercase())
}

/// Seed lines: `<onion> [credit key hex]`.
fn seed_lines() -> Vec<(String, Option<Vec<u8>>)> {
    include_str!("seeds.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let onion = transport::check_onion(w.next()?).ok()?;
            let key = w.find_map(|k| data_encoding::HEXLOWER.decode(k.as_bytes()).ok().filter(|k| k.len() == 32));
            Some((onion, key))
        })
        .collect()
}

/// The network's credit mints. Minting is a Pillar duty: the established
/// (seed) Pillars are the mints, and credits need parts from a majority of
/// them. There is no separate mint role to run or trust.
pub fn default_mints() -> Vec<String> {
    seed_pillars()
}

/// A mint's long-term public key as shipped with the app. Pinned keys stop
/// a mint from handing different users different keys to tag their credits.
pub fn builtin_mint_key(onion: &str) -> Option<Vec<u8>> {
    seed_lines().into_iter().find(|(o, _)| o == onion)?.1
}

/// Fingerprint of a mint's quantum-safe checkpoint key as shipped with the
/// app (`pq=<hex>` on its line in the seed list), if there is one.
pub fn builtin_pq_fingerprint(onion: &str) -> Option<[u8; 32]> {
    include_str!("seeds.txt").lines().map(str::trim).filter(|l| !l.starts_with('#')).find_map(|l| {
        let mut w = l.split_whitespace();
        (transport::check_onion(w.next()?).ok()? == onion).then_some(())?;
        let hex = w.find_map(|t| t.strip_prefix("pq="))?;
        data_encoding::HEXLOWER.decode(hex.as_bytes()).ok()?.try_into().ok()
    })
}

/// The first mint (where single-mint wallets from older versions came from).
pub fn default_mint() -> Option<String> {
    default_mints().into_iter().next()
}

/// Built-in seed Pillars (spec §9.7 bootstrap): only a starting point — the
/// directory is learned from them and from Pillars that announce themselves.
pub fn seed_pillars() -> Vec<String> {
    seed_lines().into_iter().map(|(o, _)| o).collect()
}
