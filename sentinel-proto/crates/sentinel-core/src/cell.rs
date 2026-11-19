//! Fixed-size cell framing (spec §9.3).
//!
//! Every message is padded to a power-of-two number of `CELL_SIZE` cells
//! (1, 2, 4, 8 … KiB): `[u32 length][payload][zero padding]`.
//! An observer of the (already Tor-encrypted) stream learns only which
//! power-of-two size bucket a message falls in, never its length (spec §5.6).

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const CELL_SIZE: usize = 1024;
/// Upper bound on a framed message (DoS bound).
pub const MAX_MESSAGE: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CellError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large")]
    TooLarge,
    #[error("no memory free for this message now")]
    Busy,
}

/// The buffer grows by at most this much at a time, as the bytes arrive: a
/// peer that announces a big message and then stalls holds only what it sent.
const GROW_STEP: usize = 64 * 1024;

fn padded_len(payload: usize) -> usize {
    (4 + payload).div_ceil(CELL_SIZE).next_power_of_two() * CELL_SIZE
}

pub async fn write_message<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<(), CellError> {
    if payload.len() > MAX_MESSAGE {
        return Err(CellError::TooLarge);
    }
    let mut buf = vec![0u8; padded_len(payload.len())];
    buf[..4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    buf[4..4 + payload.len()].copy_from_slice(payload);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, CellError> {
    read_message_inner(r, None).await.map(|(msg, _)| msg)
}

/// Like [`read_message`], with every KiB of the buffer taken from `budget`
/// (one permit per KiB) as it grows. Shared by all of a server's streams, it
/// bounds the memory their messages in flight can take together. The permit
/// comes back with the message; drop it when done with the message. When the
/// budget is used up, the read stops with [`CellError::Busy`] at once (it
/// never waits, so streams can't wait on each other).
pub async fn read_message_budgeted<R: AsyncRead + Unpin>(
    r: &mut R,
    budget: &Arc<Semaphore>,
) -> Result<(Vec<u8>, OwnedSemaphorePermit), CellError> {
    let (msg, permit) = read_message_inner(r, Some(budget)).await?;
    Ok((msg, permit.expect("a budgeted read holds a permit")))
}

async fn read_message_inner<R: AsyncRead + Unpin>(
    r: &mut R,
    budget: Option<&Arc<Semaphore>>,
) -> Result<(Vec<u8>, Option<OwnedSemaphorePermit>), CellError> {
    let mut held: Option<OwnedSemaphorePermit> = None;
    let mut take = |bytes: usize| -> Result<(), CellError> {
        let Some(budget) = budget else { return Ok(()) };
        let kib = u32::try_from(bytes.div_ceil(1024)).map_err(|_| CellError::TooLarge)?;
        let permit = Arc::clone(budget).try_acquire_many_owned(kib).map_err(|_| CellError::Busy)?;
        match held.as_mut() {
            Some(h) => h.merge(permit),
            None => held = Some(permit),
        }
        Ok(())
    };

    take(CELL_SIZE)?;
    let mut buf = vec![0u8; CELL_SIZE];
    r.read_exact(&mut buf).await?;
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    if len > MAX_MESSAGE {
        return Err(CellError::TooLarge);
    }
    let total = padded_len(len);
    while buf.len() < total {
        let start = buf.len();
        let step = GROW_STEP.min(total - start);
        take(step)?;
        buf.resize(start + step, 0);
        r.read_exact(&mut buf[start..]).await?;
    }
    buf.truncate(4 + len);
    buf.drain(..4);
    Ok((buf, held))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn budget_bounds_messages_in_flight() {
        let msg = vec![7u8; 100 * 1024];
        let mut wire = Vec::new();
        write_message(&mut wire, &msg).await.unwrap();
        // 128 KiB on the wire: a 200 KiB budget takes one, not two.
        let budget = Arc::new(Semaphore::new(200));
        let (got, held) = read_message_budgeted(&mut wire.as_slice(), &budget).await.unwrap();
        assert_eq!(got, msg);
        assert!(matches!(read_message_budgeted(&mut wire.as_slice(), &budget).await, Err(CellError::Busy)));
        drop(held);
        assert!(read_message_budgeted(&mut wire.as_slice(), &budget).await.is_ok());
        assert_eq!(budget.available_permits(), 200);
    }

    #[tokio::test]
    async fn stalled_peer_holds_only_what_it_sent() {
        // Announces the biggest message, then sends one cell and stops.
        let mut wire = vec![0u8; CELL_SIZE];
        wire[..4].copy_from_slice(&(MAX_MESSAGE as u32).to_be_bytes());
        let budget = Arc::new(Semaphore::new(4096));
        assert!(read_message_budgeted(&mut wire.as_slice(), &budget).await.is_err());
        assert_eq!(budget.available_permits(), 4096);
    }

    #[tokio::test]
    async fn roundtrip_and_sizes() {
        for n in [0usize, 1, 1019, 1020, 1021, 3000, 5000, 9000] {
            let msg: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let mut wire = Vec::new();
            write_message(&mut wire, &msg).await.unwrap();
            assert_eq!(wire.len() % CELL_SIZE, 0);
            assert!((wire.len() / CELL_SIZE).is_power_of_two());
            let got = read_message(&mut wire.as_slice()).await.unwrap();
            assert_eq!(got, msg);
        }
    }
}
