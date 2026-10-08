//! A tiny SOCKS5 front for a Tor client running in its own process.
//!
//! The app runs its Tor client in a separate process (so locking or wiping
//! ends that process and frees every Tor file at once, and the process
//! that holds the account's keys never parses network data). This is the
//! door between the two. It is deliberately narrow:
//!
//! - listens on 127.0.0.1 only, on a random port;
//! - requires a secret password only the parent knows (other programs on
//!   the computer can't use it);
//! - accepts only CONNECT to a v3 `.onion` address on Sentinel's port:
//!   no clearnet, no DNS, no other ports;
//! - every connection gets its own isolated Tor circuit.

use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::transport::{check_onion, Net};

/// Start serving; returns the port.
pub async fn serve(net: Net, secret: String) -> Result<(u16, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let secret: Arc<[u8]> = Arc::from(secret.into_bytes());
    let task = tokio::spawn(async move {
        loop {
            let Ok((sock, peer)) = listener.accept().await else { continue };
            if !peer.ip().is_loopback() {
                continue;
            }
            let net = net.clone();
            let secret = Arc::clone(&secret);
            tokio::spawn(async move {
                let _ = session(sock, &net, &secret).await;
            });
        }
    });
    Ok((port, task))
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn reply(s: &mut TcpStream, code: u8) -> Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn session(mut s: TcpStream, net: &Net, secret: &[u8]) -> Result<()> {
    // Greeting: only username/password authentication.
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        bail!("not SOCKS5");
    }
    let mut methods = vec![0u8; h[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        s.write_all(&[5, 0xff]).await?;
        bail!("no password");
    }
    s.write_all(&[5, 2]).await?;
    // RFC 1929: version, username (any: a fresh one per request), password.
    let mut v = [0u8; 2];
    s.read_exact(&mut v).await?;
    let mut user = vec![0u8; v[1] as usize];
    s.read_exact(&mut user).await?;
    let mut pl = [0u8; 1];
    s.read_exact(&mut pl).await?;
    let mut pass = vec![0u8; pl[0] as usize];
    s.read_exact(&mut pass).await?;
    if v[0] != 1 || !same(&pass, secret) {
        s.write_all(&[1, 1]).await?;
        bail!("wrong password");
    }
    s.write_all(&[1, 0]).await?;
    // Request: CONNECT to a domain name only.
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != 5 || req[1] != 1 || req[3] != 3 {
        reply(&mut s, 7).await?;
        bail!("unsupported request");
    }
    let mut l = [0u8; 1];
    s.read_exact(&mut l).await?;
    let mut host = vec![0u8; l[0] as usize];
    s.read_exact(&mut host).await?;
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);
    let host = String::from_utf8(host).unwrap_or_default();
    if port != crate::SENTINEL_PORT || check_onion(&host).is_err() {
        reply(&mut s, 2).await?; // not allowed
        bail!("only Sentinel onion services");
    }
    match net.connect(&host).await {
        Ok(mut tor) => {
            reply(&mut s, 0).await?;
            let _ = tokio::io::copy_bidirectional(&mut s, &mut tor).await;
            Ok(())
        }
        Err(e) => {
            reply(&mut s, 4).await?;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_wrong_password_and_clearnet() {
        // A Net that would only ever be reached after the checks pass.
        let net = Net::ExternalTor("127.0.0.1:9".parse().unwrap());
        let (port, task) = serve(net, "right-secret".into()).await.unwrap();
        let addr = ("127.0.0.1", port);
        // Wrong password.
        let r = tokio_socks::tcp::Socks5Stream::connect_with_password(addr, ("a".repeat(56) + ".onion", crate::SENTINEL_PORT), "u", "wrong-secret").await;
        assert!(r.is_err());
        // Right password, clearnet target.
        let r = tokio_socks::tcp::Socks5Stream::connect_with_password(addr, ("example.com", 443), "u", "right-secret").await;
        assert!(r.is_err());
        // Right password, onion on another port.
        let r = tokio_socks::tcp::Socks5Stream::connect_with_password(addr, ("a".repeat(56) + ".onion", 22), "u", "right-secret").await;
        assert!(r.is_err());
        task.abort();
    }
}
