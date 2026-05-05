//! Thin SHA3/SHAKE wrappers used by the sampler and FO transform.

use sha3::{
    Digest, Sha3_256, Sha3_512, Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub(crate) fn sha3_256(input: &[u8]) -> [u8; 32] {
    Sha3_256::digest(input).into()
}

pub(crate) fn sha3_512(input: &[u8]) -> [u8; 64] {
    Sha3_512::digest(input).into()
}

pub(crate) fn shake128_reader(input: &[u8]) -> impl XofReader {
    let mut hasher = Shake128::default();
    hasher.update(input);
    hasher.finalize_xof()
}

pub(crate) fn shake256<'a, const N: usize>(input: impl IntoIterator<Item = &'a [u8]>) -> [u8; N] {
    let mut hasher = Shake256::default();
    for i in input {
        hasher.update(i);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0; N];
    reader.read(&mut out);
    out
}
