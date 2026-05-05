use crate::{error::Result, params::CIPHERTEXT_BYTES};

/// Deterministic public-key encryption primitive used underneath a KEM.
///
/// This trait is deliberately lower-level than the public KEM API. Implementers
/// should keep it IND-CPA-oriented and deterministic: randomness enters through
/// `keygen` seeds and encryption `coins`, while CCA security, public-key hash
/// binding, re-encryption checks, and implicit rejection are provided by the FO
/// wrapper in `crate::traits::fo`.
///
/// Do not expose these methods as the normal application-facing KEM API. In
/// particular, direct calls to `encrypt` must receive coins derived by the
/// concrete FO transform with whatever public-key binding and domain separation
/// that transform requires.
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
    /// Reusing a seed repeats the PKE key pair and can invalidate KEM security
    /// assumptions.
    unsafe fn keygen(seed: &[u8; SEED]) -> Result<([u8; EK], [u8; SK])>;

    /// Deterministic PKE encryption.
    ///
    /// # Safety
    ///
    /// This low-level primitive bypasses the KEM FO wrapper. `coins` must be
    /// uniformly random, single-use, and derived exactly as required by the
    /// concrete KEM. Deriving them without the transform's required key binding
    /// or domain separation can weaken the hardened construction.
    unsafe fn encrypt(pk: &[u8; EK], message: &[u8; MSG], coins: &[u8; COINS]) -> Result<[u8; CT]>;

    /// Deterministic PKE decryption.
    ///
    /// This returns a candidate plaintext for the FO wrapper. It should not make
    /// CCA validity decisions or branch into success/failure KEM secrets; the
    /// wrapper performs re-encryption and constant-time selection.
    fn decrypt(sk: &[u8; SK], ct: &[u8; CT]) -> Result<[u8; MSG]>;
}

pub type MlKem512Ciphertext = [u8; CIPHERTEXT_BYTES];
