//! Client settings: network mode, Tor-lock and bridges (spec §9.2).
//!
//! Stored as plain `key=value` lines in the local, non-synced data root.
//! Reading or writing settings never touches the network (I17).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

/// Delay between requesting a Tor-lock removal and it taking effect.
pub const UNLOCK_DELAY_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Embedded arti.
    Tor,
    /// Embedded arti entering Tor only through configured bridges.
    TorBridges,
    /// External Tor (Orbot, system tor, Tor Browser) via loopback SOCKS5.
    ExternalTor,
    /// Not anonymous. Not implemented in this prototype.
    Direct,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "tor" => Mode::Tor,
            "tor-bridges" => Mode::TorBridges,
            "external-tor" => Mode::ExternalTor,
            "direct" => Mode::Direct,
            _ => bail!("unknown mode '{s}' (expected tor | tor-bridges | external-tor | direct)"),
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Tor => "tor",
            Mode::TorBridges => "tor-bridges",
            Mode::ExternalTor => "external-tor",
            Mode::Direct => "direct",
        }
    }
    pub fn is_tor(self) -> bool {
        matches!(self, Mode::Tor | Mode::TorBridges | Mode::ExternalTor)
    }
}

#[derive(Debug)]
pub struct Settings {
    pub mode: Mode,
    pub tor_lock: bool,
    /// Unix time when the user requested Tor-lock removal, if any.
    pub unlock_requested: Option<u64>,
    /// Loopback SOCKS5 address for External Tor mode.
    pub socks: String,
    /// Override folder for pluggable-transport programs (default: built in).
    pub pt_dir: Option<PathBuf>,
    /// Built-in bridge set used when no own bridges are configured.
    pub builtin_bridges: String,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn path() -> Result<PathBuf> {
    Ok(sentinel_net::data_root("client")?.join("settings.txt"))
}

pub fn identity_path() -> Result<PathBuf> {
    Ok(sentinel_net::data_root("client")?.join("identity.key"))
}

/// Bridge lines, one per line. Kept in their own file because they are
/// secrets: a leaked private bridge gets blocked.
pub fn bridges_path() -> Result<PathBuf> {
    Ok(sentinel_net::data_root("client")?.join("bridges.txt"))
}

pub fn load_bridges() -> Result<Vec<String>> {
    let p = bridges_path()?;
    if !p.exists() {
        return Ok(Vec::new());
    }
    Ok(std::fs::read_to_string(p)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.strip_prefix("Bridge ").unwrap_or(l).to_owned())
        .collect())
}

pub fn save_bridges(lines: &[String]) -> Result<()> {
    let mut text = lines.join("\n");
    text.push('\n');
    std::fs::write(bridges_path()?, text)?;
    Ok(())
}

impl Settings {
    pub fn load() -> Result<Self> {
        let p = path()?;
        let text = std::fs::read_to_string(&p)
            .with_context(|| "not initialised — run `sentinel init` first (no network is used)")?;
        let mut s = Settings {
            mode: Mode::Tor,
            tor_lock: true,
            unlock_requested: None,
            socks: "127.0.0.1:9050".into(),
            pt_dir: None,
            builtin_bridges: "snowflake".into(),
        };
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            match k.trim() {
                "mode" => s.mode = Mode::parse(v.trim())?,
                "tor_lock" => s.tor_lock = v.trim() == "true",
                "unlock_requested" => s.unlock_requested = v.trim().parse().ok(),
                "socks" => s.socks = v.trim().to_owned(),
                "pt_dir" => s.pt_dir = Some(PathBuf::from(v.trim())),
                "builtin_bridges" => s.builtin_bridges = v.trim().to_owned(),
                _ => {}
            }
        }
        // Fail closed: a Tor-locked identity can never be in a non-Tor mode.
        if s.tor_lock && !s.mode.is_tor() {
            bail!("settings file is inconsistent (Tor-locked but mode={}); refusing to run", s.mode.as_str());
        }
        Ok(s)
    }

    pub fn save(&self) -> Result<()> {
        let mut text = format!(
            "mode={}\ntor_lock={}\nsocks={}\nbuiltin_bridges={}\n",
            self.mode.as_str(),
            self.tor_lock,
            self.socks,
            self.builtin_bridges
        );
        if let Some(d) = &self.pt_dir {
            text.push_str(&format!("pt_dir={}\n", d.display()));
        }
        if let Some(t) = self.unlock_requested {
            text.push_str(&format!("unlock_requested={t}\n"));
        }
        std::fs::write(path()?, text)?;
        Ok(())
    }

    pub fn exists() -> Result<bool> {
        Ok(path()?.exists())
    }
}
