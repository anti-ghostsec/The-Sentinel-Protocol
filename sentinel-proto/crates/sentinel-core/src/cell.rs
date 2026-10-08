//! Fixed-size cell framing (spec §9.3).
//!
//! Every message is padded to a power-of-two number of `CELL_SIZE` cells
//! (1, 2, 4, 8 … KiB): `[u32 length][payload][zero padding]`.
//! An observer of the (already Tor-encrypted) stream learns only which
//! power-of-two size bucket a message falls in, never its length (spec §5.6).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CELL_SIZE: usize = 1024;
/// Upper bound on a framed message (DoS bound).
pub const MAX_MESSAGE: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CellError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large")]
    TooLarge,
}

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
    let mut first = vec![0u8; CELL_SIZE];
    r.read_exact(&mut first).await?;
    let len = u32::from_be_bytes(first[..4].try_into().unwrap()) as usize;
    if len > MAX_MESSAGE {
        return Err(CellError::TooLarge);
    }
    let total = padded_len(len);
    let mut buf = first;
    buf.resize(total, 0);
    r.read_exact(&mut buf[CELL_SIZE..]).await?;
    buf.truncate(4 + len);
    buf.drain(..4);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

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
