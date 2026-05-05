pub mod control;
pub mod kpke;
pub mod params;
mod serialize;

use core::marker::PhantomData;

use crate::{
    Result,
    mlkem::{
        control::MlKemControlPlane,
        kpke::KpkeCore,
    },
    params::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKemParams, SharedSecret},
    security::wipe::WipeBytes,
};
use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Public ML-KEM API for a parameter set `P`.
///
/// `P` is one of the parameter marker types in [`params`], such as
/// [`params::MlKem512`]. Most callers should use the convenience aliases
/// [`MlKem512`], [`MlKem768`], or [`MlKem1024`].
pub struct MlKem<P>(PhantomData<P>);

/// ML-KEM-512 public API.
pub type MlKem512 = MlKem<params::MlKem512>;

/// ML-KEM-768 public API.
pub type MlKem768 = MlKem<params::MlKem768>;

/// ML-KEM-1024 public API.
pub type MlKem1024 = MlKem<params::MlKem1024>;

impl<P> MlKem<P>
where
    P: MlKemParams,
{
    /// Generate a fresh ML-KEM encapsulation key and decapsulation key.
    ///
    /// The returned tuple is `(encapsulation_key, decapsulation_key)`.
    /// Share the encapsulation key with senders and keep the decapsulation key
    /// secret. Randomness is obtained from the operating system RNG.
    pub fn keygen() -> Result<(EncapsulationKey<P>, DecapsulationKey<P>)> {
        let mut d = WipeBytes::<32>::zeroed();
        let mut z = WipeBytes::<32>::zeroed();
        getrandom::fill(&mut d[..])?;
        getrandom::fill(&mut z[..])?;
        // Fresh RNG output satisfies the deterministic hook's requirements.
        unsafe { Self::keygen_internal(&d, &z) }
    }

    /// Encapsulate a fresh shared secret to an ML-KEM encapsulation key.
    ///
    /// The returned tuple is `(ciphertext, shared_secret)`. Send the ciphertext
    /// to the decapsulating party and use the shared secret only with a protocol
    /// that expects an ML-KEM shared secret.
    pub fn encaps(ek: &EncapsulationKey<P>) -> Result<(Ciphertext<P>, SharedSecret)> {
        let mut message = WipeBytes::<32>::zeroed();
        getrandom::fill(&mut message[..])?;
        // Fresh RNG output satisfies the deterministic hook's message requirement.
        unsafe { Self::encaps_internal(ek, &message) }
    }

    /// Decapsulate an ML-KEM ciphertext with a decapsulation key.
    ///
    /// Returns the receiver's shared secret. Invalid or modified ciphertexts are
    /// handled with ML-KEM implicit rejection, returning a pseudorandom fallback
    /// secret instead of an error that would reveal ciphertext validity.
    pub fn decaps(dk: &DecapsulationKey<P>, ct: &Ciphertext<P>) -> Result<SharedSecret> {
        let parts = MlKemControlPlane::<P>::unpack_decapsulation_key(dk)?;
        let message = WipeBytes::new(KpkeCore::<P>::decrypt(parts.dk_pke, ct)?);
        let derived = MlKemControlPlane::<P>::derive_decapsulation(parts.h, &message)?;
        let expected = unsafe { KpkeCore::<P>::encrypt(parts.ek, &message, &derived.coins)? };
        let valid = expected.ct_eq(ct);
        let fallback_ss =
            WipeBytes::new(MlKemControlPlane::<P>::derive_implicit_rejection(parts.z, ct)?);

        let mut ss = [0u8; 32];
        for i in 0..32 {
            ss[i] = u8::conditional_select(&fallback_ss[i], &derived.shared_secret[i], valid);
        }
        Ok(ss)
    }

    /// FIPS 203 ML-KEM.KeyGen_internal.
    ///
    /// # Safety
    ///
    /// Callers must provide uniformly random, single-use `d` and `z`. This
    /// method is intended for crate-internal tests and deterministic analysis.
    #[doc(hidden)]
    pub unsafe fn keygen_internal(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(EncapsulationKey<P>, DecapsulationKey<P>)> {
        let seeds = MlKemControlPlane::<P>::expand_keygen_seed(d)?;
        let (ek, dk_pke) =
            unsafe { KpkeCore::<P>::keygen_from_expanded(seeds.rho(), seeds.sigma())? };
        let dk = MlKemControlPlane::<P>::pack_decapsulation_key(&dk_pke, &ek, z)?;
        Ok((ek, dk))
    }

    /// FIPS 203 ML-KEM.Encaps_internal.
    ///
    /// # Safety
    ///
    /// `message` must be uniformly random, single-use, and secret.
    #[doc(hidden)]
    pub unsafe fn encaps_internal(
        ek: &EncapsulationKey<P>,
        message: &[u8; 32],
    ) -> Result<(Ciphertext<P>, SharedSecret)> {
        let derived = MlKemControlPlane::<P>::derive_encapsulation(ek, message)?;
        let ct = unsafe { KpkeCore::<P>::encrypt(ek, message, &derived.coins)? };
        let mut ss = [0u8; 32];
        ss.copy_from_slice(&derived.shared_secret[..]);
        Ok((ct, ss))
    }
}
