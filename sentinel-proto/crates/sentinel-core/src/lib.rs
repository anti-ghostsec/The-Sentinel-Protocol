//! Sentinel prototype core: signed content-addressed objects, encrypted identity
//! storage, and fixed-size cell framing (spec §5, §8.3, §9.3).

pub mod apps;
pub mod cell;
pub mod credits;
pub mod dm;
pub mod erasure;
pub mod identity;
pub mod link;
pub mod media;
pub mod mix;
pub mod object;
pub mod seal;
pub mod pow;
pub mod pqcash;
pub mod pq;
pub mod recovery;
pub mod room;
pub mod room_auth;
pub mod sanitize;
pub mod update;
pub mod social;
pub mod wire;

/// Fill a buffer from the OS CSPRNG. Panics only if the OS RNG is unavailable,
/// in which case continuing would be unsafe.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    b
}
