//! The account's Tor client runs in its **own process** (a second copy of
//! this program started in Tor mode), reached through a private SOCKS port.
//!
//! - Locking or wiping ends that process, so every Tor file is released at
//!   once and can be deleted immediately (a Tor client inside the app keeps
//!   its files open until the app exits).
//! - The process holding the account's keys never parses network data.
//! - The port is on 127.0.0.1 only, needs a secret password only this app
//!   knows, and only connects to Sentinel onion services (see
//!   `sentinel_net::socks`).
//! - Settings travel over a private pipe; if the app goes away, the pipe
//!   closes and the Tor process exits with it.
//!
//! On phones the system doesn't let an app start a second copy of itself,
//! so the app ships a small separate Tor program (`libsentinel_tor.so`,
//! unpacked by the system next to the app's own library) speaking the same
//! protocol. If it's missing or won't start, Tor runs inside the app as
//! before.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sentinel_net::torchild::{Config, Report};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// The command-line switch that starts this program as the Tor process.
pub const TOR_ARG: &str = "--tor-process";

/// Entry point in the child process (desktops). Never returns.
pub fn child_main() -> ! {
    sentinel_net::torchild::child_main()
}

/// The app's handle on its Tor process. Dropping it ends the process.
pub struct TorProcess {
    pub id: u64,
    _stdin: Option<tokio::process::ChildStdin>,
    _child: Option<tokio::process::Child>,
}

/// Start the Tor process and wait until it's ready. Progress is reported
/// through `progress`; `on_exit` runs if it stops on its own later.
pub async fn spawn(
    role: &str,
    bridges: Option<Vec<String>>,
    progress: impl Fn(f32, String) + Send + 'static,
    on_exit: impl FnOnce(u64, Option<String>) + Send + 'static,
) -> Result<(TorProcess, sentinel_net::transport::Net)> {
    #[cfg(target_os = "android")]
    let exe = match android_tor_program() {
        Some(p) => p,
        None => {
            // Fallback: Tor inside the app.
            use sentinel_net::transport::{Net, NetMode};
            let _ = on_exit;
            let mode = match bridges {
                Some(b) => NetMode::TorBridges { bridges: b, pt_dir: None },
                None => NetMode::Tor,
            };
            let net = Net::start(role, mode, progress).await?;
            let id = u64::from_le_bytes(sentinel_core::random_bytes::<8>());
            return Ok((TorProcess { id, _stdin: None, _child: None }, net));
        }
    };
    #[cfg(not(target_os = "android"))]
    let exe = std::env::current_exe().context("can't find this program")?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg(TOR_ARG).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let mut child = cmd.spawn().context("couldn't start Tor")?;
    let mut stdin = child.stdin.take().context("no pipe")?;
    let stdout = child.stdout.take().context("no pipe")?;
    let secret = data_encoding::HEXLOWER.encode(&sentinel_core::random_bytes::<32>());
    let with_bridges = bridges.is_some();
    let cfg = Config { role: role.to_owned(), bridges, secret: secret.clone() };
    stdin.write_all(format!("{}\n", serde_json::to_string(&cfg)?).as_bytes()).await?;
    stdin.flush().await?;

    let mut lines = BufReader::new(stdout).lines();
    let port = tokio::time::timeout(Duration::from_secs(900), async {
        while let Some(l) = lines.next_line().await? {
            match serde_json::from_str::<Report>(&l) {
                Ok(Report::Progress { frac, text }) => progress(frac, text),
                Ok(Report::Ready { port }) => return Ok(port),
                Ok(Report::Error { msg }) => bail!(msg),
                Err(_) => {}
            }
        }
        bail!("Tor stopped while starting")
    })
    .await
    .context("Tor took too long to start")??;

    let id = u64::from_le_bytes(sentinel_core::random_bytes::<8>());
    tokio::spawn(async move {
        let mut last = None;
        while let Ok(Some(l)) = lines.next_line().await {
            if let Ok(Report::Error { msg }) = serde_json::from_str::<Report>(&l) {
                last = Some(msg);
            }
        }
        on_exit(id, last);
    });
    let net = sentinel_net::transport::Net::Local {
        addr: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        secret: Arc::from(secret.as_str()),
        bridges: with_bridges,
    };
    Ok((TorProcess { id, _stdin: Some(stdin), _child: Some(child) }, net))
}

/// The phone's separate Tor program: the system unpacks it next to the
/// app's own library (found through this process's memory map).
#[cfg(target_os = "android")]
fn android_tor_program() -> Option<std::path::PathBuf> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let lib = maps.lines().filter_map(|l| l.split_whitespace().nth(5)).find(|p| p.ends_with("/libsentinel_app_lib.so"))?;
    let exe = std::path::Path::new(lib).parent()?.join("libsentinel_tor.so");
    exe.is_file().then_some(exe)
}
