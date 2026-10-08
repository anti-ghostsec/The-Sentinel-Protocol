//! The Tor process: a separate process that runs the Tor client and offers
//! it to the app on a private SOCKS port (see the app's `torproc`). On
//! desktops it's a second copy of the app; on phones, where an app can't
//! start a second copy of itself, it's the small `sentinel-tor` program
//! shipped inside the app.
//!
//! Protocol: the app writes one line of settings ([`Config`]) to the
//! process's input, then reads [`Report`] lines from its output. When the
//! app closes the input (locked, wiped, or gone), the process exits.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub role: String,
    pub bridges: Option<Vec<String>>,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Report {
    Progress { frac: f32, text: String },
    Ready { port: u16 },
    Error { msg: String },
}

fn report(r: &Report) {
    use std::io::Write;
    if let Ok(s) = serde_json::to_string(r) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{s}");
        let _ = out.flush();
    }
}

/// Run as the Tor process. Never returns.
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

async fn run_child() -> anyhow::Result<()> {
    use crate::transport::{Net, NetMode};
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let cfg: Config = serde_json::from_str(&lines.next_line().await?.context("no settings")?)?;
    let mode = match cfg.bridges {
        Some(b) => NetMode::TorBridges { bridges: b, pt_dir: None },
        None => NetMode::Tor,
    };
    let net = Net::start(&cfg.role, mode, |frac, text| report(&Report::Progress { frac, text })).await?;
    let (port, _task) = crate::socks::serve(net, cfg.secret).await?;
    report(&Report::Ready { port });
    // Run until the app closes the pipe (locked, wiped, or gone).
    while let Ok(Some(_)) = lines.next_line().await {}
    Ok(())
}
