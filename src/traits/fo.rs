//! Generic Fujisaki-Okamoto KEM orchestration.
//!
//! This module owns the reusable control flow: deterministic test hooks,
//! randomized public APIs, decapsulation re-encryption, and constant-time shared
//! secret selection. Concrete KEMs provide byte sizes, key layout, and
//! hash/KDF choices through `FoTransform`.

use crate::{error::Result, security::wipe::WipeBytes, traits::pke::Pke};
use subtle::{ConditionallySelectable, ConstantTimeEq};

pub struct DecapsulationKeyParts<'a, const EK: usize, const SK: usize, const Z: usize> {
    pub sk: &'a [u8; SK],
    pub ek: &'a [u8; EK],
    pub z: &'a [u8; Z],
}

pub struct FoDerivation<const SS: usize, const COINS: usize> {
    shared_secret: WipeBytes<SS>,
    coins: WipeBytes<COINS>,
}

impl<const SS: usize, const COINS: usize> FoDerivation<SS, COINS> {
    pub fn new(shared_secret: [u8; SS], coins: [u8; COINS]) -> Self {
        Self {
            shared_secret: WipeBytes::new(shared_secret),
            coins: WipeBytes::new(coins),
        }
    }
}

pub trait FoTransform<
    const EK: usize,
    const SK: usize,
    const CT: usize,
    const DK: usize,
    const SS: usize,
    const MSG: usize,
    const COINS: usize,
    const Z: usize,
>
{
    fn pack_decapsulation_key(sk: &[u8; SK], ek: &[u8; EK], z: &[u8; Z]) -> Result<[u8; DK]>;

    fn unpack_decapsulation_key(dk: &[u8; DK]) -> Result<DecapsulationKeyParts<'_, EK, SK, Z>>;

    fn derive_encapsulation(ek: &[u8; EK], message: &[u8; MSG]) -> Result<FoDerivation<SS, COINS>>;

    fn derive_decapsulation(
        parts: &DecapsulationKeyParts<'_, EK, SK, Z>,
        message: &[u8; MSG],
    ) -> Result<FoDerivation<SS, COINS>>;

    fn derive_decapsulation_failure(
        parts: &DecapsulationKeyParts<'_, EK, SK, Z>,
        ct: &[u8; CT],
    ) -> Result<[u8; SS]>;
}

pub trait Fo<
    const EK: usize,
    const SK: usize,
    const CT: usize,
    const DK: usize,
    const SS: usize,
    const SEED: usize,
    const MSG: usize,
    const COINS: usize,
    const Z: usize,
>: Pke<EK, SK, CT, SEED, MSG, COINS>
{
    type Transform: FoTransform<EK, SK, CT, DK, SS, MSG, COINS, Z>;

    /// Deterministic FO key generation.
    ///
    /// # Safety
    ///
    /// Callers must provide uniformly random, single-use `seed` and `z` values.
    /// This function is intended for test vectors and audited protocol
    /// integrations.
    unsafe fn keygen_with_seed(seed: &[u8; SEED], z: &[u8; Z]) -> Result<([u8; EK], [u8; DK])> {
        let (ek, sk) = unsafe { <Self as Pke<EK, SK, CT, SEED, MSG, COINS>>::keygen(seed)? };
        let sk_bytes = WipeBytes::new(sk);
        let dk = Self::Transform::pack_decapsulation_key(&sk_bytes, &ek, z)?;
        Ok((ek, dk))
    }

    /// Deterministic FO encapsulation.
    ///
    /// # Safety
    ///
    /// `message` must be uniformly random, single-use, and secret. External
    /// callers should use the randomized `encaps` method.
    unsafe fn encaps_with_message(
        ek: &[u8; EK],
        message: &[u8; MSG],
    ) -> Result<([u8; CT], [u8; SS])> {
        let derived = Self::Transform::derive_encapsulation(ek, message)?;
        let ct = unsafe { Self::encrypt(ek, message, &derived.coins)? };
        let mut ss = [0u8; SS];
        ss.copy_from_slice(&derived.shared_secret[..]);
        Ok((ct, ss))
    }

    fn keygen() -> Result<([u8; EK], [u8; DK])> {
        let mut seed = WipeBytes::<SEED>::zeroed();
        let mut z = WipeBytes::<Z>::zeroed();
        getrandom::fill(&mut seed[..])?;
        getrandom::fill(&mut z[..])?;
        // Fresh RNG output satisfies the deterministic hook's seed requirements.
        unsafe { Self::keygen_with_seed(&seed, &z) }
    }

    fn encaps(ek: &[u8; EK]) -> Result<([u8; CT], [u8; SS])> {
        let mut message = WipeBytes::<MSG>::zeroed();
        getrandom::fill(&mut message[..])?;
        // Fresh RNG output satisfies the deterministic hook's message requirement.
        unsafe { Self::encaps_with_message(ek, &message) }
    }

    fn decaps(dk: &[u8; DK], ct: &[u8; CT]) -> Result<[u8; SS]> {
        let parts = Self::Transform::unpack_decapsulation_key(dk)?;
        let message = WipeBytes::new(Self::decrypt(parts.sk, ct)?);
        let derived = Self::Transform::derive_decapsulation(&parts, &message)?;
        let expected = unsafe { Self::encrypt(parts.ek, &message, &derived.coins)? };

        let valid = expected.ct_eq(ct);
        let fallback_ss =
            WipeBytes::new(Self::Transform::derive_decapsulation_failure(&parts, ct)?);

        let mut ss = [0u8; SS];
        for i in 0..SS {
            ss[i] = u8::conditional_select(&fallback_ss[i], &derived.shared_secret[i], valid);
        }
        Ok(ss)
    }
}
