//! Pre-warmed pool of isolated streams (spec §13.1).
//!
//! Keeps up to `size` ready-to-use streams to one destination. Each stream is
//! built on its own isolation group, carries no data while pooled, and is
//! handed out exactly once — a used stream is never returned to the pool, so
//! two request groups never share a circuit (I13).
//!
//! Privacy gain over connecting on demand: circuits are built on a background
//! schedule rather than at the moment the user acts, so network activity no
//! longer reveals *when* the user did something. Stream lifetimes are
//! randomised so the refresh pattern is not a fixed-period fingerprint.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Notify;

use crate::transport::{Io, Net};

/// Pooled streams are retired after a random age in this range (must stay
/// below the Pillar's idle timeout).
const MIN_AGE: Duration = Duration::from_secs(5 * 60);
const MAX_AGE: Duration = Duration::from_secs(8 * 60);
/// How often the background task re-checks the pool when it is full.
const CHECK_EVERY: Duration = Duration::from_secs(15);

struct Entry {
    expires: Instant,
    stream: Box<dyn Io>,
}

struct Inner {
    ready: Mutex<VecDeque<Entry>>,
    wake: Notify,
}

pub struct Pool {
    inner: Arc<Inner>,
    net: Net,
    onion: String,
    task: tokio::task::JoinHandle<()>,
}

fn random_lifetime() -> Duration {
    let r = u64::from_le_bytes(sentinel_core::random_bytes::<8>());
    let span = (MAX_AGE - MIN_AGE).as_millis() as u64;
    MIN_AGE + Duration::from_millis(r % span.max(1))
}

impl Pool {
    pub fn spawn(net: Net, onion: String, size: usize) -> Self {
        let inner = Arc::new(Inner { ready: Mutex::new(VecDeque::new()), wake: Notify::new() });
        let task = {
            let (inner, net, onion) = (Arc::clone(&inner), net.clone(), onion.clone());
            tokio::spawn(async move {
                let mut backoff = Duration::from_secs(1);
                loop {
                    let need = {
                        let mut q = inner.ready.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        let now = Instant::now();
                        q.retain(|e| e.expires > now);
                        q.len() < size
                    };
                    if !need {
                        tokio::select! {
                            _ = tokio::time::sleep(CHECK_EVERY) => {}
                            _ = inner.wake.notified() => {}
                        }
                        continue;
                    }
                    match net.connect_hedged(&onion).await {
                        Ok(stream) => {
                            backoff = Duration::from_secs(1);
                            let expires = Instant::now() + random_lifetime();
                            inner.ready.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push_back(Entry { expires, stream });
                        }
                        Err(_) => {
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(60));
                        }
                    }
                }
            })
        };
        Pool { inner, net, onion, task }
    }

    /// Number of ready streams.
    pub fn ready(&self) -> usize {
        self.inner.ready.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }

    /// Take a ready isolated stream, or connect (hedged) if none is ready.
    pub async fn take(&self) -> Result<Box<dyn Io>> {
        let pooled = {
            let mut q = self.inner.ready.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = Instant::now();
            q.retain(|e| e.expires > now);
            q.pop_front()
        };
        self.inner.wake.notify_one();
        match pooled {
            Some(e) => Ok(e.stream),
            None => self.net.connect_hedged(&self.onion).await,
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.task.abort();
    }
}
