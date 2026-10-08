//! Network layer: every connection goes through Tor (spec §9.2, I2, I18, I19).
//!
//! - Destinations must be v3 `.onion` addresses; clearnet hostnames and IPs
//!   are rejected, so no exit relay is ever used and no DNS lookup happens.
//! - Each `connect` call is a separate isolation group: it never shares a
//!   circuit with any other request group (I13).
//! - External Tor is only accepted on a loopback SOCKS address, and isolation
//!   is done with fresh random SOCKS credentials per request group (Tor's
//!   default IsolateSOCKSAuth).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Result};
use arti_client::TorClient;
use futures::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};

/// When each hedged connection attempt starts (relative to the first).
/// A failed attempt also triggers the next one immediately.
pub const HEDGE_SCHEDULE: [std::time::Duration; 3] = [
    std::time::Duration::from_secs(0),
    std::time::Duration::from_secs(8),
    std::time::Duration::from_secs(20),
];

/// Total attempts (scheduled plus replacements for failed ones).
pub const MAX_ATTEMPTS: usize = 6;
/// How long bridge-mode connections keep retrying instant failures.
const BRIDGE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(150);

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// How to reach Tor. There is deliberately no non-Tor variant.
#[derive(Clone, Debug)]
pub enum NetMode {
    /// Embedded arti, public guards.
    Tor,
    /// Embedded arti entering only via these bridges. `pt_dir` holds the
    /// transport program (`None` = use the built-in one).
    TorBridges { bridges: Vec<String>, pt_dir: Option<PathBuf> },
    /// External Tor on a loopback SOCKS port.
    ExternalTor(SocketAddr),
}

/// A built-in Tor client.
pub type TorArc = Arc<TorClient<tor_rtcompat::PreferredRuntime>>;

#[derive(Clone)]
pub enum Net {
    Tor(Arc<TorClient<tor_rtcompat::PreferredRuntime>>),
    ExternalTor(SocketAddr),
    /// This app's own Tor client running in a separate process, behind a
    /// private SOCKS port (see `socks`). `bridges`: it enters Tor through
    /// bridges (connections are given more patience).
    Local { addr: SocketAddr, secret: Arc<str>, bridges: bool },
}

/// Validate a v3 onion address: 56 base32 chars + ".onion".
pub fn check_onion(addr: &str) -> Result<String> {
    let a = addr.trim().to_ascii_lowercase();
    let Some(host) = a.strip_suffix(".onion") else {
        bail!("destination must be a .onion address (no clearnet, no exits)");
    };
    if host.len() != 56 || !host.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)) {
        bail!("not a valid v3 onion address");
    }
    Ok(a)
}

impl Net {
    /// Start networking for `role`, reporting bootstrap progress (0.0–1.0
    /// plus a human-readable stage) through `progress`.
    pub async fn start(role: &str, mode: NetMode, progress: impl Fn(f32, String) + Send + 'static) -> Result<Self> {
        let cfg = match &mode {
            NetMode::Tor => crate::tor_config(role)?,
            NetMode::TorBridges { bridges, pt_dir } => {
                if bridges.is_empty() {
                    bail!("bridge mode with no bridges");
                }
                let pt_dir = match pt_dir {
                    Some(d) => Some(d.clone()),
                    None => crate::builtin_pt::builtin_pt_dir()?,
                };
                // Checking every public bridge at each start is a pattern a
                // censor could notice, so it's only done when bridge mode
                // hasn't worked in the last day.
                let bridges = if crate::bridges_recently_ok(role) { bridges.clone() } else { crate::builtin_pt::drop_dead_builtin(bridges).await };
                crate::tor_config_with_bridges(role, &bridges, pt_dir.as_deref())?
            }
            NetMode::ExternalTor(sa) => {
                if !sa.ip().is_loopback() {
                    bail!("External Tor SOCKS proxy must be on loopback (127.0.0.1 / ::1)");
                }
                progress(1.0, "Using external Tor".into());
                return Ok(Net::ExternalTor(*sa));
            }
        };
        let tor = TorClient::builder().config(cfg).create_unbootstrapped_async().await?;
        let mut events = tor.bootstrap_events();
        let watcher = tokio::spawn(async move {
            while let Some(st) = events.next().await {
                progress(st.as_frac(), st.to_string());
                if st.ready_for_traffic() {
                    break;
                }
            }
        });
        tor.bootstrap().await?;
        watcher.abort();
        Ok(Net::Tor(tor))
    }

    /// Open an isolated stream, hedging against slow rendezvous.
    ///
    /// Up to three independently isolated attempts start on `HEDGE_SCHEDULE`
    /// (or immediately when an earlier one fails, up to `MAX_ATTEMPTS`); the
    /// first to succeed wins and the rest are dropped. Privacy: extra attempts
    /// are separate isolation groups carrying no data.
    pub async fn connect_hedged(&self, onion: &str) -> Result<Box<dyn Io>> {
        use futures::stream::FuturesUnordered;

        let onion = check_onion(onion)?;
        let mut in_flight = FuturesUnordered::new();
        let mut launched = 0;
        let mut last_err = None;
        let start = tokio::time::Instant::now();
        loop {
            let scheduled_due = launched < HEDGE_SCHEDULE.len() && start.elapsed() >= HEDGE_SCHEDULE[launched];
            let replace_failed = in_flight.is_empty() && launched < MAX_ATTEMPTS;
            if scheduled_due || replace_failed {
                in_flight.push(self.connect(&onion));
                launched += 1;
                continue;
            }
            if in_flight.is_empty() {
                // Bridge mode: right after starting, the Tor library can say
                // it's ready before the bridges are usable, and attempts fail
                // at once. Keep trying, calmly, for a while (seen live).
                let bridges = crate::bridge_mode_active() || matches!(self, Net::Local { bridges: true, .. });
                if bridges && start.elapsed() < BRIDGE_PATIENCE {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    in_flight.push(self.connect(&onion));
                    continue;
                }
                return Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all connection attempts failed")));
            }
            let next_launch = HEDGE_SCHEDULE.get(launched).map(|d| start + *d);
            tokio::select! {
                Some(r) = in_flight.next() => match r {
                    Ok(s) => return Ok(s),
                    Err(e) => last_err = Some(e),
                },
                _ = async {
                    match next_launch {
                        Some(t) => tokio::time::sleep_until(t).await,
                        None => std::future::pending().await,
                    }
                } => {}
            }
        }
    }

    /// Open a stream to `onion` on a fresh, isolated circuit.
    pub async fn connect(&self, onion: &str) -> Result<Box<dyn Io>> {
        let onion = check_onion(onion)?;
        match self {
            Net::Tor(tor) => {
                let isolated = tor.isolated_client();
                let s = isolated.connect((onion.as_str(), crate::SENTINEL_PORT)).await?;
                crate::note_bridge_success();
                Ok(Box::new(s))
            }
            Net::Local { addr, secret, .. } => {
                // A fresh username per request: the Tor process gives every
                // connection its own circuit anyway.
                let user = data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<16>());
                let s = tokio_socks::tcp::Socks5Stream::connect_with_password(*addr, (onion.as_str(), crate::SENTINEL_PORT), &user, secret).await?;
                Ok(Box::new(s))
            }
            Net::ExternalTor(proxy) => {
                let user = data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<16>());
                let pass = data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<16>());
                // Hostname is passed to Tor unresolved: no local DNS.
                let s = tokio_socks::tcp::Socks5Stream::connect_with_password(
                    *proxy,
                    (onion.as_str(), crate::SENTINEL_PORT),
                    &user,
                    &pass,
                )
                .await?;
                Ok(Box::new(s))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::check_onion;

    #[test]
    fn onion_validation() {
        let good = format!("{}.onion", "a".repeat(56));
        assert!(check_onion(&good).is_ok());
        assert!(check_onion("example.com").is_err());
        assert!(check_onion("127.0.0.1").is_err());
        assert!(check_onion(&format!("{}.onion", "a".repeat(16))).is_err());
        assert!(check_onion(&format!("{}.onion", "1".repeat(56))).is_err());
    }
}
