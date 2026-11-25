//! Standalone Sentinel Pillar (for always-on hosts). The desktop app embeds
//! the same code via "Run a Pillar". See `lib.rs` for the risk-limiting
//! properties.

use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use arti_client::TorClient;
use clap::Parser;

#[derive(Parser)]
#[command(about = "Sentinel Pillar — onion-only storage node")]
struct Args {
    /// Local nickname for the onion service keys (not published).
    #[arg(long, default_value = "sentinel-pillar")]
    nickname: String,
    /// Storage quota in GB.
    #[arg(long, default_value_t = 2)]
    quota_gb: u64,
    /// Delete stored objects after this many days.
    #[arg(long, default_value_t = 60)]
    retention_days: u64,
    /// Also act as an Archive: store up to this many GB of encrypted media
    /// chunks for others (0 = only a small cache for inline media).
    #[arg(long, default_value_t = 0)]
    archive_gb: u64,
    /// Delete media chunks nobody fetched for this many days.
    #[arg(long, default_value_t = 90)]
    chunk_retention_days: u64,
    /// Mint duty (seed Pillars): base seconds between Archive check rounds.
    #[arg(long, default_value_t = 1200)]
    mint_interval: u64,
    /// The network's mints (comma-separated onions); default: the seed
    /// Pillars. A Pillar on this list mints automatically.
    #[arg(long)]
    mints: Option<String>,
    /// Folder of signed update bundles to pass on to apps (`app.bin`,
    /// `pillar.bin`) and revocations (`*.revoke`). Default: `updates` in the
    /// data folder. Every Pillar fetches new signed releases from others and
    /// passes them on; only bundles signed by the release keys are served.
    #[arg(long)]
    updates: Option<std::path::PathBuf>,
    /// Seconds before first fetching updates from other Pillars (default:
    /// a random 5–35 minutes).
    #[arg(long)]
    spread_after: Option<u64>,
    /// Pillars to announce to and learn the directory from
    /// (comma-separated onions, or `none` for a private test Pillar);
    /// default: the built-in seeds.
    #[arg(long)]
    seeds: Option<String>,
    /// Separate data folder name (lets several test nodes share a machine).
    #[arg(long, default_value = "pillar")]
    data: String,
    /// Print redacted Tor diagnostics to stderr (never written to disk).
    #[arg(long)]
    debug_log: bool,
    /// Never open a terminal window (started without one, from a file
    /// manager say, the Pillar otherwise opens one to show what it's doing).
    #[arg(long)]
    headless: bool,
    /// Print this Pillar's credit keys (for the seed list; made now if it
    /// has none yet) and exit, without starting Tor.
    #[arg(long)]
    print_keys: bool,
    /// Move the credits this Pillar has earned into a file (to import in
    /// the app: Settings -> Credits), and exit without starting Tor.
    #[arg(long)]
    take_credits: Option<std::path::PathBuf>,
    /// List reports about public content this Pillar holds (posts, room
    /// listings, their media), and exit.
    #[arg(long)]
    reports: bool,
    /// Remove reported content (by its address from --reports): deleted
    /// here and refused if uploaded again. Exits.
    #[arg(long)]
    remove: Option<String>,
    /// Keep reported content: dismiss its reports. Exits.
    #[arg(long)]
    keep: Option<String>,
    /// Test builds: check that the parts in this file (from
    /// --take-credits) are in the list of the mint whose data folder is
    /// --data, and exit.
    #[cfg(feature = "test-hooks")]
    #[arg(long)]
    check_credits: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    if !args.headless && window::open() {
        return Ok(());
    }
    #[cfg(feature = "test-hooks")]
    if let Some(file) = &args.check_credits {
        let parts: Vec<(String, sentinel_core::credits::Token)> = serde_json::from_slice(&std::fs::read(file)?)?;
        let (found, all) = pillar::check_rewards(&sentinel_net::data_root(&args.data)?.join("objects"), &parts)?;
        println!("{found} of {all} credit parts are in the mint's list");
        return Ok(());
    }
    if args.reports || args.remove.is_some() || args.keep.is_some() {
        let store = sentinel_net::data_root(&args.data)?.join("objects");
        if let Some(a) = &args.remove {
            pillar::remove_reported(&store, a)?;
            println!("Removed {a}: deleted here, and refused if it's uploaded again.");
        } else if let Some(a) = &args.keep {
            pillar::keep_reported(&store, a)?;
            println!("Kept {a}: its reports are dismissed.");
        } else {
            let list = pillar::list_reports(&store);
            if list.is_empty() {
                println!("No reports.");
            }
            for r in list {
                println!("{}  {}{}  ({} media pieces)", r.address, r.summary(), if r.hidden { "  [hidden from Discover]" } else { "" }, r.chunks.len());
            }
            println!("\nRemove: pillar --remove <address>    Keep: pillar --keep <address>");
        }
        return Ok(());
    }
    if let Some(out) = &args.take_credits {
        let store = sentinel_net::data_root(&args.data)?.join("objects");
        let earned = pillar::take_rewards(&store);
        std::fs::write(out, serde_json::to_vec(&earned)?)?;
        println!("{} credit parts written to {}. Import them in the app, then delete the file (it is like cash).", earned.len(), out.display());
        return Ok(());
    }
    if args.print_keys {
        let store = sentinel_net::data_root(&args.data)?.join("objects");
        let seed = pillar::mint_seed(&store)?;
        let voprf = sentinel_core::credits::Mint::from_seed(&seed).public_key();
        let pq = sentinel_core::pqcash::key_fingerprint(&sentinel_core::pqcash::mint_signer(&seed).public());
        println!("{} pq={}", data_encoding::HEXLOWER.encode(&voprf), data_encoding::HEXLOWER.encode(&pq));
        eprintln!("[pillar] for seeds.txt: put this Pillar's onion address in front of that line");
        return Ok(());
    }
    if args.debug_log {
        sentinel_net::enable_debug_log();
    }
    eprintln!("[pillar] bootstrapping Tor (full vanguards)...");
    let tor = TorClient::create_bootstrapped(sentinel_net::tor_config(&args.data)?).await?;
    let pillar = pillar::start(
        tor,
        pillar::PillarConfig {
            store: sentinel_net::data_root(&args.data)?.join("objects"),
            nickname: args.nickname,
            quota_bytes: args.quota_gb * 1_000_000_000,
            retention_days: args.retention_days,
            seeds: match args.seeds.as_deref() {
                Some("none") => Vec::new(),
                Some(list) => list.split(',').filter_map(|o| sentinel_net::transport::check_onion(o).ok()).collect(),
                None => sentinel_net::seed_pillars(),
            },
            chunk_quota_bytes: if args.archive_gb > 0 { args.archive_gb * 1_000_000_000 } else { 1_000_000_000 },
            chunk_retention_days: args.chunk_retention_days,
            archive: args.archive_gb > 0,
            mints: args
                .mints
                .as_deref()
                .map(|m| m.split(',').filter_map(|o| sentinel_net::transport::check_onion(o).ok()).collect())
                .unwrap_or_else(sentinel_net::default_mints),
            mint_interval: args.mint_interval,
            updates: Some(match args.updates.clone() {
                Some(d) => d,
                None => sentinel_net::data_root(&args.data)?.join("updates"),
            }),
            spread_after: args.spread_after,
        },
    )
    .await?;
    println!("{}", pillar.onion);
    eprintln!("[pillar] onion service launched; descriptor publication can take a minute or two.");

    let mut t = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = t.tick() => {
                let s = &pillar.stats;
                eprintln!(
                    "[pillar] streams={} stored={} served={} rejected={} used={}MB chunks={}MB",
                    s.streams.load(Ordering::Relaxed),
                    s.stored.load(Ordering::Relaxed),
                    s.served.load(Ordering::Relaxed),
                    s.rejected.load(Ordering::Relaxed),
                    s.used_bytes.load(Ordering::Relaxed) / 1_000_000,
                    s.chunk_bytes.load(Ordering::Relaxed) / 1_000_000,
                );
            }
        }
    }
    Ok(())
}

/// Started by a double-click there is nowhere to see the Pillar running (or
/// to stop it): open a terminal window and run in that instead.
#[cfg(target_os = "linux")]
mod window {
    use std::io::IsTerminal;
    use std::process::{Command, Stdio};

    const MARK: &str = "SENTINEL_PILLAR_IN_TERMINAL";

    fn quote(a: &str) -> String {
        format!("'{}'", a.replace('\'', r"'\''"))
    }

    /// True if the Pillar now runs in a new terminal window (this process
    /// should exit).
    pub fn open() -> bool {
        let desktop = std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
        if std::env::var_os(MARK).is_some() || !desktop || std::io::stdin().is_terminal() || std::io::stderr().is_terminal() {
            return false;
        }
        let Ok(exe) = std::env::current_exe() else { return false };
        let mut line = quote(&exe.to_string_lossy());
        for a in std::env::args_os().skip(1) {
            line.push(' ');
            line.push_str(&quote(&a.to_string_lossy()));
        }
        // The window stays open after the Pillar stops, so its last words
        // can be read.
        let script = format!("{line}; s=$?; echo; echo \"The Pillar has stopped (exit code $s). Press Enter to close this window.\"; read _");
        let shell = format!("sh -c {}", quote(&script));
        // (terminal, arguments before the command, true: takes the command
        // as separate words; false: as one line)
        let terminals: [(&str, &[&str], bool); 13] = [
            ("x-terminal-emulator", &["-e"], false),
            ("gnome-terminal", &["--title=Sentinel Pillar", "--"], true),
            ("kgx", &["--"], true),
            ("ptyxis", &["--"], true),
            ("konsole", &["-e"], true),
            ("xfce4-terminal", &["--title=Sentinel Pillar", "-x"], true),
            ("mate-terminal", &["-x"], true),
            ("lxterminal", &["--title=Sentinel Pillar", "-e"], false),
            ("tilix", &["-e"], false),
            ("alacritty", &["--title", "Sentinel Pillar", "-e"], true),
            ("kitty", &["--title", "Sentinel Pillar"], true),
            ("foot", &["--title=Sentinel Pillar"], true),
            ("xterm", &["-T", "Sentinel Pillar", "-e"], true),
        ];
        for (term, pre, words) in terminals {
            let mut c = Command::new(term);
            c.args(pre);
            if words {
                c.args(["sh", "-c", &script]);
            } else {
                c.arg(&shell);
            }
            c.env(MARK, "1").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            if c.spawn().is_ok() {
                return true;
            }
        }
        false
    }
}
