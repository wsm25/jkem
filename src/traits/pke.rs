use crate::{error::Result, params::CIPHERTEXT_BYTES};

pub trait Pke<
    const EK: usize,
    const SK: usize,
    const CT: usize,
    const SEED: usize,
    const MSG: usize,
    const COINS: usize,
>
{
    /// Deterministic PKE key generation.
    ///
    /// # Safety
    ///
    /// This low-level primitive bypasses the KEM RNG wrapper. Callers must provide
    /// a uniformly random, single-use seed from an approved entropy source.
    unsafe fn keygen(seed: &[u8; SEED]) -> Result<([u8; EK], [u8; SK])>;

    /// Deterministic PKE encryption.
    ///
    /// # Safety
    ///
    /// This low-level primitive bypasses the KEM FO wrapper. `coins` must be
    /// uniformly random, single-use, and derived exactly as required by ML-KEM
    /// when used as part of the KEM.
    unsafe fn encrypt(pk: &[u8; EK], message: &[u8; MSG], coins: &[u8; COINS]) -> Result<[u8; CT]>;

    fn decrypt(sk: &[u8; SK], ct: &[u8; CT]) -> Result<[u8; MSG]>;
}

pub type MlKem512Ciphertext = [u8; CIPHERTEXT_BYTES];
