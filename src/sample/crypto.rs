//! Thin SHA3/SHAKE wrappers used by the sampler and FO transform.
//!
//! ```
//! use jkem::sample::crypto::{sha3_256, shake256};
//!
//! let digest = sha3_256(b"jkem");
//! let stream: [u8; 64] = shake256(b"jkem");
//!
//! assert_eq!(digest.len(), 32);
//! assert_eq!(stream.len(), 64);
//! ```

use sha3::{
    Digest, Sha3_256, Sha3_512, Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    Sha3_256::digest(input).into()
}

pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    Sha3_512::digest(input).into()
}

pub fn shake128<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut hasher = Shake128::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = [0; N];
    reader.read(&mut out);
    out
}

pub fn shake128_reader(input: &[u8]) -> impl XofReader {
    let mut hasher = Shake128::default();
    hasher.update(input);
    hasher.finalize_xof()
}

pub fn shake256<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = [0; N];
    reader.read(&mut out);
    out
}
