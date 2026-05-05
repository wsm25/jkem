//! Generic Fujisaki-Okamoto KEM orchestration.
//!
//! This module owns the reusable control flow: deterministic test hooks,
//! randomized public APIs, decapsulation re-encryption, and constant-time shared
//! secret selection. Concrete KEMs provide byte sizes, key layout, and
//! hash/KDF choices through `FoTransform`.
//!
//! # Implementation guide
//!
//! `Fo` is intentionally only the orchestration layer. The concrete
//! `FoTransform` implementation is responsible for matching the scheme's
//! hardened FO variant exactly. A hardened transform normally must:
//!
//! - store every value needed for decapsulation in an authenticated,
//!   self-consistent decapsulation key;
//! - bind the encapsulated message to the intended public key or public-key
//!   digest before deriving shared secrets and encryption coins;
//! - use domain-separated KDF inputs for success and failure paths;
//! - mirror encapsulation derivation during decapsulation, re-encrypt with the
//!   candidate coins, and select the failure secret on mismatch without
//!   exposing whether rejection occurred.
//!
//! These requirements are what bind the random message to the public key and
//! avoid multi-target weaknesses in QROM-hardened FO variants. Do not replace
//! them with a simplified derivation unless that is the exact transform
//! specified for the concrete KEM and backed by tests.

use crate::{error::Result, security::wipe::WipeBytes, traits::pke::Pke};
use subtle::{ConditionallySelectable, ConstantTimeEq};

pub struct DecapsulationKeyParts<'a, const EK: usize, const SK: usize, const Z: usize> {
    /// PKE decryption key bytes embedded in the KEM decapsulation key.
    pub sk: &'a [u8; SK],
    /// PKE encapsulation key bytes embedded in the KEM decapsulation key.
    ///
    /// Implementations should validate any companion public-key hash before
    /// returning these parts, so decapsulation cannot mix an `ek` with a stale
    /// or attacker-modified hash.
    pub ek: &'a [u8; EK],
    /// Secret implicit-rejection value used to derive the fallback shared secret.
    pub z: &'a [u8; Z],
}

/// Shared secret and PKE coins derived by a concrete FO transform.
///
/// Both fields are wiped on drop. A transform must return exactly the values
/// required by its KEM specification, with clear separation between the bytes
/// used as the shared secret and the bytes used as PKE encryption coins.
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
    /// Assemble the KEM decapsulation key from PKE key material and rejection
    /// randomness.
    ///
    /// Implementations should store all values required to decapsulate without
    /// looking up external state. If the transform derives secrets from a public
    /// key digest, that digest should be stored or recomputable from
    /// authenticated key material so decapsulation cannot mix inconsistent
    /// inputs.
    fn pack_decapsulation_key(sk: &[u8; SK], ek: &[u8; EK], z: &[u8; Z]) -> Result<[u8; DK]>;

    /// Parse and validate a KEM decapsulation key.
    ///
    /// This method is the last scheme-specific checkpoint before the generic
    /// decapsulation flow uses the embedded parts. It should reject malformed
    /// key material, including mismatches between embedded public data and any
    /// stored digest or binding value. Validate those relationships before
    /// returning `DecapsulationKeyParts`.
    fn unpack_decapsulation_key(dk: &[u8; DK]) -> Result<DecapsulationKeyParts<'_, EK, SK, Z>>;

    /// Derive the success shared secret and PKE encryption coins for
    /// encapsulation.
    ///
    /// The derivation must bind the random message to the intended
    /// encapsulation key in the exact order required by the concrete KEM. Split
    /// the KDF output into the success shared secret and deterministic
    /// encryption coins according to that specification. This public-key binding
    /// is part of hardened FO constructions and helps prevent multi-target
    /// attacks.
    fn derive_encapsulation(ek: &[u8; EK], message: &[u8; MSG]) -> Result<FoDerivation<SS, COINS>>;

    /// Derive the candidate success shared secret and re-encryption coins during
    /// decapsulation.
    ///
    /// This must mirror `derive_encapsulation` exactly, but using authenticated
    /// key parts from `unpack_decapsulation_key`. If encapsulation uses a
    /// public-key digest or other binding value, decapsulation must use the same
    /// validated value. Divergence between encapsulation and decapsulation
    /// derivations will break correctness and can weaken the FO transform.
    fn derive_decapsulation(
        parts: &DecapsulationKeyParts<'_, EK, SK, Z>,
        message: &[u8; MSG],
    ) -> Result<FoDerivation<SS, COINS>>;

    /// Derive the implicit-rejection fallback shared secret.
    ///
    /// This value is selected when re-encryption does not reproduce the input
    /// ciphertext. It must depend on secret rejection material from the
    /// decapsulation key and the full ciphertext, using the KDF and
    /// domain-separation rules specified by the concrete KEM. It must not
    /// reveal, directly or indirectly, whether the ciphertext was valid.
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
    /// Scheme-specific FO transform.
    ///
    /// Implementers should treat this associated type as security-critical API
    /// surface: it fixes key layout, KDF input order, public-key hash binding,
    /// and implicit-rejection derivation.
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
        // Derandomization r
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
        // binding property
        let derived = Self::Transform::derive_decapsulation(&parts, &message)?;
        // re-encryption check && implicit rejection
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
