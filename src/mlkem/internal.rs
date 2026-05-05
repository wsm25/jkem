//! ML-KEM-512 internal orchestration.
//!
//! This module owns the reusable ML-KEM flow from FIPS 203: deterministic test
//! hooks, randomized public APIs, K-PKE seed expansion, public-key hash binding,
//! decapsulation re-encryption, and implicit rejection.

use crate::{
    error::Result,
    mlkem::{
        MlKem512,
        control::{MlKem512ControlPlane, MlKemControlPlane},
        kpke::KpkeCore,
    },
    params::*,
    security::wipe::WipeBytes,
};
use subtle::{ConditionallySelectable, ConstantTimeEq};

pub trait MlKemInterface: KpkeCore {
    type Control: MlKemControlPlane;

    /// FIPS 203 ML-KEM.KeyGen_internal.
    ///
    /// # Safety
    ///
    /// Callers must provide uniformly random, single-use `d` and `z`. This
    /// method is intended for KATs and audited deterministic integrations.
    #[doc(hidden)]
    unsafe fn keygen_internal(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<([u8; ENCAPSULATION_KEY_BYTES], [u8; DECAPSULATION_KEY_BYTES])> {
        let seeds = Self::Control::expand_keygen_seed(d)?;
        let (ek, dk_pke) = unsafe { Self::keygen_from_expanded(seeds.rho(), seeds.sigma())? };
        let dk_pke = WipeBytes::new(dk_pke);
        let dk = Self::Control::pack_decapsulation_key(&dk_pke, &ek, z)?;
        Ok((ek, dk))
    }

    /// FIPS 203 ML-KEM.Encaps_internal.
    ///
    /// # Safety
    ///
    /// `message` must be uniformly random, single-use, and secret.
    #[doc(hidden)]
    unsafe fn encaps_internal(
        ek: &[u8; ENCAPSULATION_KEY_BYTES],
        message: &[u8; 32],
    ) -> Result<([u8; CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES])> {
        let derived = Self::Control::derive_encapsulation(ek, message)?;
        let ct = unsafe { Self::encrypt(ek, message, &derived.coins)? };
        let mut ss = [0u8; SHARED_SECRET_BYTES];
        ss.copy_from_slice(&derived.shared_secret[..]);
        Ok((ct, ss))
    }

    fn keygen() -> Result<([u8; ENCAPSULATION_KEY_BYTES], [u8; DECAPSULATION_KEY_BYTES])> {
        let mut d = WipeBytes::<32>::zeroed();
        let mut z = WipeBytes::<32>::zeroed();
        getrandom::fill(&mut d[..])?;
        getrandom::fill(&mut z[..])?;
        // Fresh RNG output satisfies the deterministic hook's requirements.
        unsafe { Self::keygen_internal(&d, &z) }
    }

    fn encaps(
        ek: &[u8; ENCAPSULATION_KEY_BYTES],
    ) -> Result<([u8; CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES])> {
        let mut message = WipeBytes::<32>::zeroed();
        getrandom::fill(&mut message[..])?;
        // Fresh RNG output satisfies the deterministic hook's message requirement.
        unsafe { Self::encaps_internal(ek, &message) }
    }

    fn decaps(
        dk: &[u8; DECAPSULATION_KEY_BYTES],
        ct: &[u8; CIPHERTEXT_BYTES],
    ) -> Result<[u8; SHARED_SECRET_BYTES]> {
        let parts = Self::Control::unpack_decapsulation_key(dk)?;
        let message = WipeBytes::new(Self::decrypt(parts.dk_pke, ct)?);
        let derived = Self::Control::derive_decapsulation(parts.h, &message)?;
        let expected = unsafe { Self::encrypt(parts.ek, &message, &derived.coins)? };
        let valid = expected.ct_eq(ct);
        let fallback_ss = WipeBytes::new(Self::Control::derive_implicit_rejection(parts.z, ct)?);

        let mut ss = [0u8; SHARED_SECRET_BYTES];
        for i in 0..SHARED_SECRET_BYTES {
            ss[i] = u8::conditional_select(&fallback_ss[i], &derived.shared_secret[i], valid);
        }
        Ok(ss)
    }
}

impl MlKemInterface for MlKem512 {
    type Control = MlKem512ControlPlane;
}
