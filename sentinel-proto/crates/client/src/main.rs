//! Sentinel client prototype.
//!
//! First launch (`sentinel init`) makes zero network connections (I17): it asks
//! for a network mode, creates an identity encrypted with a passphrase, and
//! Tor-locks it by default (I18).

mod config;

use std::io::Write;
use std::time::{Duration, Instant};

use sentinel_core::cell::{read_message, write_message};
use sentinel_core::identity;
use sentinel_core::object::{Address, Envelope};
use sentinel_core::wire::{self, Request, Response};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use config::{Mode, Settings, UNLOCK_DELAY_SECS};
use sentinel_net::transport::{check_onion, Io, Net, NetMode};

#[derive(Parser)]
#[command(about = "Sentinel client prototype (Tor built in)")]
struct Cli {
    /// Print redacted Tor diagnostics to stderr (never written to disk).
    #[arg(long, global = true)]
    debug_log: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// First-run setup: choose network mode and create an identity. No network is used.
    Init,
    /// Show or change the network mode.
    Mode {
        #[command(subcommand)]
        action: ModeCmd,
    },
    /// Sign and publish a post to a Pillar.
    Post {
        #[arg(long)]
        pillar: String,
        text: String,
    },
    /// Fetch and verify an object from a Pillar.
    Get {
        #[arg(long)]
        pillar: String,
        address: String,
        /// Read key printed by `post` (base32). Without it only the sealed
        /// envelope is shown.
        #[arg(long)]
        key: Option<String>,
    },
    /// Measure Tor latency to a Pillar. Uses a throwaway key, never your identity.
    Bench {
        #[arg(long)]
        pillar: String,
        /// Pings on one warm stream.
        #[arg(long, default_value_t = 10)]
        rounds: usize,
        /// Fresh isolated circuits to open.
        #[arg(long, default_value_t = 3)]
        fresh: usize,
    },
    /// Manage bridges (secret Tor entry points for censored networks). No network is used.
    Bridges {
        #[command(subcommand)]
        action: BridgesCmd,
    },
    /// Release signing: make a release key (keep the secret file offline).
    /// Prints the line to add to sentinel-core/data/release_keys.txt.
    ReleaseKeygen { secret_file: std::path::PathBuf },
    /// Sentinel Apps: sign an app (WebAssembly built with sentinel-app-sdk)
    /// into a file room admins can add. The key file is made if missing;
    /// keep it, since your later versions should be signed with it too.
    AppPack {
        #[arg(long)]
        key: std::path::PathBuf,
        #[arg(long)]
        wasm: std::path::PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: u32,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Release signing: build and sign an update bundle. Files are given as
    /// `<path in the install folder>=<file on disk>`, e.g.
    /// `Sentinel.exe=target/release/Sentinel.exe`.
    ReleasePack {
        #[arg(long)]
        secret: std::path::PathBuf,
        #[arg(long, default_value = "app")]
        product: String,
        #[arg(long, default_value = "windows-x64")]
        platform: String,
        #[arg(long)]
        version: String,
        #[arg(long, default_value = "")]
        notes: String,
        #[arg(long)]
        out: std::path::PathBuf,
        files: Vec<String>,
    },
    /// Release signing: add your signature to someone else's bundle (a
    /// majority of the release keys must sign).
    ReleaseCosign {
        #[arg(long)]
        secret: std::path::PathBuf,
        bundle: std::path::PathBuf,
    },
    /// Check a bundle: who signed it and whether this build would accept it.
    ReleaseCheck { bundle: std::path::PathBuf },
    /// Revoke a release: sign "never install this bundle". Run it once per
    /// key holder on the same output file; it counts once a majority signed.
    /// Put the file in a Pillar's update folder; it spreads from there.
    ReleaseRevoke {
        #[arg(long)]
        secret: std::path::PathBuf,
        #[arg(long)]
        bundle: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum BridgesCmd {
    /// Show which bridges will be used (addresses are masked).
    List,
    /// Add your own bridge line (from bridges.torproject.org or a trusted friend).
    /// Own bridges take priority over the built-in set.
    Add { line: String },
    /// Remove your own bridges (falls back to the built-in set).
    Clear,
    /// Choose the built-in bridge set: snowflake | obfs4
    Builtin { set: String },
}

#[derive(Subcommand)]
enum ModeCmd {
    Show,
    /// Switch mode: tor | tor-bridges | external-tor | direct
    Set { mode: String },
    /// Set the loopback SOCKS address for external-tor (e.g. 127.0.0.1:9150 for Tor Browser).
    Socks { addr: String },
    /// Request removal of Tor-lock (takes effect after 24h; cancel with `mode lock`).
    Unlock,
    /// Re-enable Tor-lock immediately.
    Lock,
}

/// Read a passphrase without echo; the buffer is wiped when dropped.
fn read_pass(q: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(q)?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.debug_log {
        sentinel_net::enable_debug_log();
    }
    match cli.cmd {
        Cmd::Init => init(),
        Cmd::Mode { action } => mode(action),
        Cmd::Post { pillar, text } => post(&pillar, text).await,
        Cmd::Get { pillar, address, key } => get(&pillar, &address, key.as_deref()).await,
        Cmd::Bench { pillar, rounds, fresh } => bench(&pillar, rounds, fresh).await,
        Cmd::Bridges { action } => bridges(action),
        Cmd::ReleaseKeygen { secret_file } => release_keygen(&secret_file),
        Cmd::AppPack { key, wasm, name, version, description, out } => app_pack(&key, &wasm, name, version, description, &out),
        Cmd::ReleasePack { secret, product, platform, version, notes, out, files } => release_pack(&secret, product, platform, version, notes, &out, &files),
        Cmd::ReleaseCosign { secret, bundle } => release_cosign(&secret, &bundle),
        Cmd::ReleaseCheck { bundle } => release_check(&bundle),
        Cmd::ReleaseRevoke { secret, bundle, out } => release_revoke(&secret, &bundle, &out),
    }
}

fn release_signer(path: &std::path::Path) -> Result<sentinel_core::pq::HybridSigner> {
    let b = zeroize::Zeroizing::new(std::fs::read(path)?);
    let secret: [u8; 32] = b.as_slice().try_into().map_err(|_| anyhow::anyhow!("not a release secret file"))?;
    Ok(sentinel_core::pq::HybridSigner::from_secret(&secret))
}

fn app_pack(key: &std::path::Path, wasm: &std::path::Path, name: String, version: u32, description: String, out: &std::path::Path) -> Result<()> {
    use sentinel_core::apps;
    let seed: zeroize::Zeroizing<[u8; 32]> = if key.exists() {
        let b = zeroize::Zeroizing::new(std::fs::read(key)?);
        zeroize::Zeroizing::new(b.as_slice().try_into().map_err(|_| anyhow::anyhow!("not an app key file"))?)
    } else {
        let s = zeroize::Zeroizing::new(sentinel_core::random_bytes::<32>());
        std::fs::write(key, s.as_slice())?;
        eprintln!("New app key written to {}. Keep it: sign your later versions with it.", key.display());
        s
    };
    let manifest = apps::Manifest { name, version, description, permissions: Vec::new() };
    let pkg = apps::pack(&seed, manifest, std::fs::read(wasm)?).map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(out, &pkg)?;
    let app = apps::open(&pkg).map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("Wrote {} ({} KB).", out.display(), pkg.len() / 1024);
    println!("app id {}", data_encoding::HEXLOWER.encode(&app.id));
    Ok(())
}

fn release_keygen(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        anyhow::bail!("{} already exists", path.display());
    }
    let secret = zeroize::Zeroizing::new(sentinel_core::random_bytes::<32>());
    std::fs::write(path, secret.as_slice())?;
    let p = sentinel_core::pq::HybridSigner::from_secret(&secret).public();
    eprintln!("Secret written to {}. Keep it offline (a USB stick in a safe place).", path.display());
    eprintln!("Add this line to sentinel-core/data/release_keys.txt:");
    println!("{}", sentinel_core::update::key_line(&p));
    Ok(())
}

fn release_pack(secret: &std::path::Path, product: String, platform: String, version: String, notes: String, out: &std::path::Path, files: &[String]) -> Result<()> {
    use sentinel_core::update::{self, FileEntry, Header, Manifest};
    if update::parse_version(&version).is_none() {
        anyhow::bail!("version must be major.minor.patch");
    }
    let mut entries = Vec::new();
    let mut datas = Vec::new();
    for f in files {
        let (name, disk) = f.split_once('=').ok_or_else(|| anyhow::anyhow!("use <path in install>=<file on disk>: {f}"))?;
        if !update::safe_path(name) {
            anyhow::bail!("not an allowed install path: {name}");
        }
        let data = std::fs::read(disk)?;
        entries.push(FileEntry { path: name.into(), size: data.len() as u64, hash: update::hash_file(&data) });
        datas.push(data);
    }
    let manifest = Manifest { product, platform, version, notes, files: entries };
    let signer = release_signer(secret)?;
    let header = Header { sigs: vec![update::sign(&signer, &manifest)], manifest };
    std::fs::write(out, update::pack(&header, &datas))?;
    eprintln!("Wrote {} (signed by 1 key).", out.display());
    release_check(out)
}

fn release_cosign(secret: &std::path::Path, bundle: &std::path::Path) -> Result<()> {
    use sentinel_core::update;
    let bytes = std::fs::read(bundle)?;
    let (mut h, start) = update::read_header(&bytes)?;
    let signer = release_signer(secret)?;
    let me = signer.public().ed;
    h.sigs.retain(|s| s.ed != me);
    h.sigs.push(update::sign(&signer, &h.manifest));
    let mut out = update::pack(&h, &[]);
    out.extend_from_slice(&bytes[start..]);
    let tmp = bundle.with_extension("tmp");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, bundle)?;
    eprintln!("Added your signature ({} now).", h.sigs.len());
    release_check(bundle)
}

fn release_revoke(secret: &std::path::Path, bundle: &std::path::Path, out: &std::path::Path) -> Result<()> {
    use sentinel_core::update;
    let bytes = std::fs::read(bundle)?;
    let (h, _) = update::read_header(&bytes)?;
    let r = update::Revocation { product: h.manifest.product.clone(), version: h.manifest.version.clone(), manifest: update::manifest_id(&h.manifest) };
    let mut doc = std::fs::read(out).ok().and_then(|b| update::decode_revocation(&b)).filter(|d| d.revocation == r).unwrap_or(update::RevocationDoc { revocation: r, sigs: Vec::new() });
    let signer = release_signer(secret)?;
    let me = signer.public().ed;
    doc.sigs.retain(|s| s.ed != me);
    doc.sigs.push(update::sign_revocation(&signer, &doc.revocation));
    std::fs::write(out, update::encode_revocation(&doc))?;
    let keys = update::release_keys();
    println!(
        "Revocation of {} {}: {} signature(s); {}.",
        doc.revocation.product,
        doc.revocation.version,
        doc.sigs.len(),
        if update::verify_revocation(&doc, &keys) { "valid now, put it in a Pillar's update folder" } else { "more release keys must sign it" }
    );
    Ok(())
}

fn release_check(bundle: &std::path::Path) -> Result<()> {
    use sentinel_core::update;
    let bytes = std::fs::read(bundle)?;
    let (h, _) = update::read_header(&bytes)?;
    let keys = update::release_keys();
    println!("{} {} for {}: {} file(s), {} signature(s); this build pins {} key(s), needs {}.", h.manifest.product, h.manifest.version, h.manifest.platform, h.manifest.files.len(), h.sigs.len(), keys.len(), update::threshold(keys.len()));
    match update::open_bundle(&bytes, &keys, &h.manifest.product, &h.manifest.platform, "0.0.0") {
        Ok(_) => println!("Valid: apps with these release keys will accept it."),
        Err(e) => println!("Not accepted: {e}"),
    }
    Ok(())
}

/// Mask a bridge line for display: bridge addresses are secrets, and terminal
/// scrollback or screenshots shouldn't leak them.
fn mask_bridge(line: &str) -> String {
    let transport = sentinel_net::bridge_transport(line).unwrap_or_else(|| "vanilla".into());
    let digest = blake3::hash(line.as_bytes()).to_hex();
    format!("{transport:<10} id {}", &digest[..12])
}

fn bridges(action: BridgesCmd) -> Result<()> {
    let mut s = Settings::load()?;
    let mut lines = config::load_bridges()?;
    match action {
        BridgesCmd::List => {
            if lines.is_empty() {
                let builtin = sentinel_net::builtin_pt::builtin_bridges(&s.builtin_bridges)?;
                println!("using built-in '{}' bridges ({}):", s.builtin_bridges, builtin.len());
                for l in &builtin {
                    println!("  {}", mask_bridge(l));
                }
            } else {
                println!("using your own bridges ({}):", lines.len());
                for l in &lines {
                    println!("  {}", mask_bridge(l));
                }
            }
        }
        BridgesCmd::Add { line } => {
            let line = line.trim().strip_prefix("Bridge ").unwrap_or(line.trim()).to_owned();
            // Validate now (offline) rather than at connect time.
            sentinel_net::tor_config_with_bridges_check(&line)?;
            if !lines.contains(&line) {
                lines.push(line.clone());
            }
            config::save_bridges(&lines)?;
            println!("added {}", mask_bridge(&line));
        }
        BridgesCmd::Clear => {
            config::save_bridges(&[])?;
            println!("own bridges cleared; built-in '{}' bridges will be used", s.builtin_bridges);
        }
        BridgesCmd::Builtin { set } => {
            sentinel_net::builtin_pt::builtin_bridges(&set)?; // validates the name
            s.builtin_bridges = set;
            s.save()?;
            println!("built-in bridge set: {}", s.builtin_bridges);
        }
    }
    Ok(())
}

fn prompt(q: &str) -> Result<String> {
    print!("{q}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_owned())
}

fn init() -> Result<()> {
    if Settings::exists()? {
        bail!("already initialised (settings exist). Delete the data folder to start over.");
    }
    println!("How do you want to connect? (nothing has been sent over the network yet)\n");
    println!("  1) Tor                (recommended — built in)");
    println!("  2) Tor with bridges   (Tor is blocked or dangerous where I am — hides that you use Tor)");
    println!("  3) External Tor       (Orbot / system tor / Tor Browser via SOCKS)");
    println!("  4) Direct             (fast, NOT anonymous — not available in this prototype)\n");
    let mode = match prompt("Choice [1]: ")?.as_str() {
        "" | "1" => Mode::Tor,
        "2" => Mode::TorBridges,
        "3" => Mode::ExternalTor,
        "4" => bail!("Direct mode is not implemented in this prototype."),
        other => bail!("invalid choice '{other}'"),
    };
    let mut builtin_bridges = "snowflake".to_owned();
    if mode == Mode::TorBridges {
        println!("\nBridge mode never contacts public Tor relays. Which disguise?\n");
        println!("  1) Snowflake  (recommended — looks like a video call, hardest to block)");
        println!("  2) obfs4      (looks like random noise)\n");
        builtin_bridges = match prompt("Choice [1]: ")?.as_str() {
            "" | "1" => "snowflake",
            "2" => "obfs4",
            other => bail!("invalid choice '{other}'"),
        }
        .to_owned();
        println!("You can also add private bridges later with `sentinel bridges add`.\n");
    }

    let pass = read_pass("New identity passphrase (min 12 chars): ")?;
    let again = read_pass("Repeat passphrase: ")?;
    if *pass != *again {
        bail!("passphrases do not match");
    }
    if pass.chars().count() < 12 {
        bail!("passphrase too short");
    }
    let key = identity::generate();
    let sealed = identity::seal(&key, pass.as_bytes(), None)?;
    std::fs::write(config::identity_path()?, sealed)?;

    let settings = Settings { mode, tor_lock: true, unlock_requested: None, socks: "127.0.0.1:9050".into(), pt_dir: None, builtin_bridges };
    settings.save()?;
    println!("\nIdentity created and Tor-locked. Mode: {}", mode.as_str());
    println!("Public key: {}", data_encoding::BASE32_NOPAD.encode(&key.verifying_key().to_bytes()).to_lowercase());
    Ok(())
}

fn mode(action: ModeCmd) -> Result<()> {
    let mut s = Settings::load()?;
    match action {
        ModeCmd::Show => {
            println!("mode={} tor_lock={} socks={}", s.mode.as_str(), s.tor_lock, s.socks);
            if let Some(t) = s.unlock_requested {
                let left = (t + UNLOCK_DELAY_SECS).saturating_sub(config::now());
                println!("Tor-lock removal pending: {}h {}m left", left / 3600, (left % 3600) / 60);
            }
        }
        ModeCmd::Set { mode } => {
            let m = Mode::parse(&mode)?;
            if !m.is_tor() {
                if s.tor_lock {
                    let ready = s.unlock_requested.is_some_and(|t| config::now() >= t + UNLOCK_DELAY_SECS);
                    if !ready {
                        bail!("This identity is Tor-locked. One direct connection can permanently link it to your location.\n\
                               To proceed anyway: `sentinel mode unlock`, wait 24 hours, then retry. Safer: create a new identity.");
                    }
                    let typed = prompt("Type 'I understand this can reveal my location' to continue: ")?;
                    if typed != "I understand this can reveal my location" {
                        bail!("not confirmed");
                    }
                    s.tor_lock = false;
                    s.unlock_requested = None;
                }
            } else if s.mode == Mode::Direct {
                println!("Warning: past direct connections may already link this identity to an IP. Consider a new identity.");
            }
            s.mode = m;
            s.save()?;
            println!("mode={}", s.mode.as_str());
        }
        ModeCmd::Socks { addr } => {
            let sa: std::net::SocketAddr = addr.parse().context("expected ip:port")?;
            if !sa.ip().is_loopback() {
                bail!("SOCKS proxy must be on loopback");
            }
            s.socks = addr;
            s.save()?;
        }
        ModeCmd::Unlock => {
            s.unlock_requested = Some(config::now());
            s.save()?;
            println!("Tor-lock removal requested; it can be completed in 24 hours. `sentinel mode lock` cancels.");
        }
        ModeCmd::Lock => {
            s.tor_lock = true;
            s.unlock_requested = None;
            if !s.mode.is_tor() {
                s.mode = Mode::Tor;
            }
            s.save()?;
            println!("Tor-lock enabled.");
        }
    }
    Ok(())
}

fn load_identity() -> Result<SigningKey> {
    let file = std::fs::read(config::identity_path()?).context("no identity — run `sentinel init`")?;
    let pass = read_pass("Identity passphrase: ")?;
    Ok(identity::open(&file, pass.as_bytes(), None)?)
}

async fn request(stream: &mut Box<dyn Io>, req: &Request) -> Result<Response> {
    write_message(stream, &wire::encode(req)).await?;
    let bytes = read_message(stream).await?;
    wire::decode(&bytes).context("malformed response")
}

async fn post(pillar: &str, text: String) -> Result<()> {
    let settings = Settings::load()?;
    check_onion(pillar)?;
    let key = load_identity()?;
    // Always sealed (spec §12.4): never send readable content to a Pillar.
    let read_key = sentinel_core::random_bytes::<32>();
    let env = sentinel_core::social::post_envelope(&key, &read_key, &text).map_err(|e| anyhow::anyhow!(e))?;
    let bytes = env.encode()?;
    eprintln!("read key (share only with readers): {}", data_encoding::BASE32_NOPAD.encode(&read_key).to_lowercase());
    let net = start_net(&settings).await?;
    let mut s = net.connect_hedged(pillar).await?;
    match request(&mut s, &Request::Put(bytes)).await? {
        Response::Stored(a) => println!("{}", a.to_text()),
        Response::Rejected(r) => bail!("rejected: {r}"),
        other => bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

async fn get(pillar: &str, address: &str, key: Option<&str>) -> Result<()> {
    let settings = Settings::load()?;
    check_onion(pillar)?;
    let addr = Address::from_text(address).context("bad address")?;
    let net = start_net(&settings).await?;
    let mut s = net.connect_hedged(pillar).await?;
    match request(&mut s, &Request::Get(addr)).await? {
        Response::Object(bytes) => {
            if Address::of(&bytes) != addr {
                bail!("Pillar returned bytes that don't match the address (tampering)");
            }
            let env = Envelope::decode_verified(&bytes)?;
            println!("type:   {}", env.kind);
            println!("author: {}", data_encoding::BASE32_NOPAD.encode(&env.author).to_lowercase());
            let k: Option<[u8; 32]> = key
                .and_then(|k| data_encoding::BASE32_NOPAD.decode(k.trim().to_uppercase().as_bytes()).ok())
                .and_then(|v| v.try_into().ok());
            match k.and_then(|k| sentinel_core::social::open_record(&env, &[k])) {
                Some(sentinel_core::social::Record::Post(p)) => println!("text:   {}", p.text),
                Some(_) => println!("(a sealed non-post record)"),
                None => println!("sealed: {} bytes (pass --key to read)", env.body.len()),
            }
        }
        Response::NotFound => bail!("not found"),
        other => bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn summary(label: &str, mut v: Vec<f64>) {
    if v.is_empty() {
        return;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
    println!("{label:<34} n={:<3} min={:>7.0}ms  median={:>7.0}ms  p90={:>7.0}ms  max={:>7.0}ms",
        v.len(), v[0], p(0.5), p(0.9), v[v.len() - 1]);
}

/// Per-operation limits so one failed Tor circuit can't stall the benchmark.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(200);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

async fn timed_connect(net: &Net, pillar: &str) -> Result<(Box<dyn Io>, f64)> {
    let t = Instant::now();
    let s = tokio::time::timeout(CONNECT_TIMEOUT, net.connect_hedged(pillar))
        .await
        .context("connect timed out")??;
    Ok((s, ms(t.elapsed())))
}

async fn timed_request(s: &mut Box<dyn Io>, req: &Request) -> Result<(Response, f64)> {
    let t = Instant::now();
    let r = tokio::time::timeout(REQUEST_TIMEOUT, request(s, req))
        .await
        .context("request timed out")??;
    Ok((r, ms(t.elapsed())))
}

async fn bench(pillar: &str, rounds: usize, fresh: usize) -> Result<()> {
    let settings = Settings::load()?;
    check_onion(pillar)?;
    println!("mode={}  (benchmark uses a throwaway key, not your identity)\n", settings.mode.as_str());

    let t = Instant::now();
    let net = start_net(&settings).await?;
    println!("Tor bootstrap:                         {:>7.0}ms", ms(t.elapsed()));

    let (mut s, first) = timed_connect(&net, pillar).await?;
    println!("First connect (descriptor+rendezvous): {first:>7.0}ms");

    let mut pings = Vec::new();
    for i in 0..rounds {
        match timed_request(&mut s, &Request::Ping).await? {
            (Response::Pong, d) => {
                println!("  ping {:>2}: {d:>6.0}ms", i + 1);
                pings.push(d);
            }
            (other, _) => bail!("unexpected: {other:?}"),
        }
    }

    let throwaway = identity::generate();
    let env = Envelope::sign(&throwaway, "post", vec![b'x'; 2000]);
    let (addr, put) = match timed_request(&mut s, &Request::Put(env.encode()?)).await? {
        (Response::Stored(a), d) => (a, d),
        (other, _) => bail!("unexpected: {other:?}"),
    };
    println!("Put 2 KB object:                       {put:>7.0}ms");
    let get = match timed_request(&mut s, &Request::Get(addr)).await? {
        (Response::Object(_), d) => d,
        (other, _) => bail!("unexpected: {other:?}"),
    };
    println!("Get 2 KB object:                       {get:>7.0}ms");

    let mut fresh_connects = Vec::new();
    let mut failures = 0;
    for i in 0..fresh {
        let t = Instant::now();
        let attempt = async {
            let (mut s2, _) = timed_connect(&net, pillar).await?;
            timed_request(&mut s2, &Request::Ping).await?;
            anyhow::Ok(())
        };
        match attempt.await {
            Ok(()) => {
                let d = ms(t.elapsed());
                println!("  fresh circuit {:>2}: {d:>6.0}ms", i + 1);
                fresh_connects.push(d);
            }
            Err(e) => {
                failures += 1;
                println!("  fresh circuit {:>2}: FAILED after {:.0}ms ({e})", i + 1, ms(t.elapsed()));
            }
        }
    }

    // Pre-warmed pool: what a real app sees for a new request group.
    let pool_size = 2;
    let pool = sentinel_net::pool::Pool::spawn(net.clone(), pillar.to_owned(), pool_size);
    let mut pooled = Vec::new();
    for i in 0..fresh {
        // Simulate a user acting after the pool has had time to refill.
        let wait = Instant::now();
        while pool.ready() < pool_size && wait.elapsed() < CONNECT_TIMEOUT {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let t = Instant::now();
        let attempt = async {
            let mut s3 = pool.take().await?;
            timed_request(&mut s3, &Request::Ping).await?;
            anyhow::Ok(())
        };
        match attempt.await {
            Ok(()) => {
                let d = ms(t.elapsed());
                println!("  pooled isolated stream {:>2}: {d:>6.0}ms", i + 1);
                pooled.push(d);
            }
            Err(e) => println!("  pooled isolated stream {:>2}: FAILED ({e})", i + 1),
        }
    }

    println!();
    summary("Request round trip (warm stream)", pings);
    summary("Fresh isolated circuit + ping", fresh_connects);
    summary("Pooled isolated stream + ping", pooled);
    if failures > 0 {
        println!("Fresh circuit failures: {failures}/{fresh}");
    }
    Ok(())
}

/// Map client settings to a network mode and start Tor. Tor-lock is enforced
/// by `Settings::load`; there is no non-Tor path here.
async fn start_net(settings: &Settings) -> Result<Net> {
    let mode = match settings.mode {
        Mode::Tor => NetMode::Tor,
        Mode::TorBridges => {
            // Own bridges take priority; otherwise use the built-in set.
            let mut bridges = config::load_bridges()?;
            if bridges.is_empty() {
                bridges = sentinel_net::builtin_pt::builtin_bridges(&settings.builtin_bridges)?;
            }
            NetMode::TorBridges { bridges, pt_dir: settings.pt_dir.clone() }
        }
        Mode::ExternalTor => NetMode::ExternalTor(settings.socks.parse().context("invalid SOCKS address")?),
        Mode::Direct => bail!("Direct mode is not implemented in this prototype (it is not anonymous; spec §9.2)"),
    };
    Net::start("client", mode, |_, _| {}).await
}
