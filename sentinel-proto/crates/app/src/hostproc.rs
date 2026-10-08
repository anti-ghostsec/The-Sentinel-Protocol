//! The Pillar a user hosts runs in its **own process** (a second copy of
//! this program started in Pillar mode), never inside the account process.
//!
//! - Isolation (spec §4, node/user separation): the Pillar's memory never
//!   holds the account's keys, and a fault in the Pillar can't touch them.
//! - Stopping really stops: ending the process frees every Tor lock, so the
//!   Pillar can be switched off and on again at will. (The Tor library can't
//!   relaunch an onion service inside a process that already stopped one.)
//! - Settings travel over a private pipe (bridge lines never appear on a
//!   command line other programs could read). If the app goes away, the pipe
//!   closes and the Pillar exits with it; the parent also kills it on drop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// The command-line switch that starts this program as a hosted Pillar.
pub const HOST_ARG: &str = "--host-pillar";

/// Sent once, as the first line on the Pillar's stdin.
#[derive(Serialize, Deserialize)]
pub struct HostConfig {
    pub role: String,
    /// Bridge lines (bridge mode), or None for plain Tor.
    pub bridges: Option<Vec<String>>,
    pub seeds: Vec<String>,
    pub archive_gb: u32,
    pub mints: Vec<String>,
    /// Signed update bundles this app downloaded: the hosted Pillar passes
    /// them on, so updates spread from Pillar to Pillar.
    #[serde(default)]
    pub updates: Option<std::path::PathBuf>,
}

/// Later lines on stdin.
#[derive(Serialize, Deserialize)]
struct Command {
    archive_gb: u32,
}

/// Lines the Pillar prints on stdout.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Report {
    Online { onion: String },
    Stats { used: u64, served: u64, chunks: u64 },
    Error { msg: String },
}

fn quota(gb: u32) -> u64 {
    if gb > 0 { gb as u64 * 1_000_000_000 } else { 500_000_000 }
}

fn report(r: &Report) {
    use std::io::Write;
    if let Ok(s) = serde_json::to_string(r) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{s}");
        let _ = out.flush();
    }
}

/// Entry point in the child process. Never returns.
pub fn child_main() -> ! {
    let code = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt.block_on(async {
            match run_child().await {
                Ok(()) => 0,
                Err(e) => {
                    report(&Report::Error { msg: e.to_string() });
                    1
                }
            }
        }),
        Err(_) => 1,
    };
    std::process::exit(code)
}

async fn run_child() -> Result<()> {
    use sentinel_net::transport::{Net, NetMode};
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let cfg: HostConfig = serde_json::from_str(&lines.next_line().await?.context("no settings")?)?;
    let mode = match cfg.bridges {
        Some(b) => NetMode::TorBridges { bridges: b, pt_dir: None },
        None => NetMode::Tor,
    };
    let tor = match Net::start(&cfg.role, mode, |_, _| {}).await? {
        Net::Tor(t) => t,
        _ => bail!("hosting needs the built-in Tor"),
    };
    let p = pillar::start(
        tor,
        pillar::PillarConfig {
            store: sentinel_net::data_root(&cfg.role)?.join("objects"),
            nickname: "sentinel-hosted".into(),
            quota_bytes: 2_000_000_000,
            retention_days: 60,
            seeds: cfg.seeds,
            chunk_quota_bytes: quota(cfg.archive_gb),
            chunk_retention_days: 90,
            archive: cfg.archive_gb > 0,
            mints: cfg.mints,
            mint_interval: 1200,
            updates: cfg.updates,
            spread_after: None,
        },
    )
    .await?;
    report(&Report::Online { onion: p.onion.clone() });
    loop {
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(l)) => {
                    if let Ok(c) = serde_json::from_str::<Command>(&l) {
                        p.set_archive(c.archive_gb, quota(c.archive_gb));
                    }
                }
                // The app closed the pipe (stopped hosting, or went away).
                _ => return Ok(()),
            },
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                report(&Report::Stats {
                    used: p.stats.used_bytes.load(Ordering::Relaxed),
                    served: p.stats.served.load(Ordering::Relaxed),
                    chunks: p.stats.chunk_bytes.load(Ordering::Relaxed),
                });
            }
        }
    }
}

#[derive(Default)]
pub struct HostStats {
    pub used_bytes: AtomicU64,
    pub served: AtomicU64,
    pub chunk_bytes: AtomicU64,
}

/// The parent's handle on a running Pillar process. Dropping it ends the
/// process.
pub struct HostedPillar {
    pub id: u64,
    pub onion: String,
    pub stats: Arc<HostStats>,
    commands: tokio::sync::mpsc::UnboundedSender<String>,
    _child: tokio::process::Child,
}

impl HostedPillar {
    /// Change the Archive setting at once (no restart).
    pub fn set_archive(&self, archive_gb: u32) {
        if let Ok(s) = serde_json::to_string(&Command { archive_gb }) {
            let _ = self.commands.send(s);
        }
    }
}

/// Start a Pillar process and wait until it's online. `on_exit` runs if it
/// stops on its own later (with its id).
pub async fn spawn(cfg: &HostConfig, on_exit: impl FnOnce(u64, Option<String>) + Send + 'static) -> Result<HostedPillar> {
    let exe = std::env::current_exe().context("can't find this program")?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg(HOST_ARG).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let mut child = cmd.spawn().context("couldn't start the Pillar process")?;
    let mut stdin = child.stdin.take().context("no pipe")?;
    let stdout = child.stdout.take().context("no pipe")?;
    stdin.write_all(format!("{}\n", serde_json::to_string(cfg)?).as_bytes()).await?;
    stdin.flush().await?;

    let mut lines = BufReader::new(stdout).lines();
    // Tor can take a while to start (bridges especially).
    let onion = tokio::time::timeout(Duration::from_secs(900), async {
        while let Some(l) = lines.next_line().await? {
            match serde_json::from_str::<Report>(&l) {
                Ok(Report::Online { onion }) => return Ok(onion),
                Ok(Report::Error { msg }) => bail!(msg),
                _ => {}
            }
        }
        bail!("the Pillar process stopped while starting")
    })
    .await
    .context("the Pillar took too long to start")??;

    let id = u64::from_le_bytes(sentinel_core::random_bytes::<8>());
    let stats = Arc::new(HostStats::default());
    let st = Arc::clone(&stats);
    tokio::spawn(async move {
        let mut last_error = None;
        while let Ok(Some(l)) = lines.next_line().await {
            match serde_json::from_str::<Report>(&l) {
                Ok(Report::Stats { used, served, chunks }) => {
                    st.used_bytes.store(used, Ordering::Relaxed);
                    st.served.store(served, Ordering::Relaxed);
                    st.chunk_bytes.store(chunks, Ordering::Relaxed);
                }
                Ok(Report::Error { msg }) => last_error = Some(msg),
                _ => {}
            }
        }
        on_exit(id, last_error);
    });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if stdin.write_all(format!("{line}\n").as_bytes()).await.is_err() || stdin.flush().await.is_err() {
                break;
            }
        }
        // Sender dropped: closing stdin tells the Pillar to stop.
    });
    Ok(HostedPillar { id, onion, stats, commands: tx, _child: child })
}
