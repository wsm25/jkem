//! ML-KEM control-plane implementation.
//!
//! This module contains the ML-KEM-specific pieces from FIPS 203 that sit above
//! the algebraic K-PKE core: key-generation seed expansion, decapsulation-key
//! layout and validation, public-key hash binding, and implicit rejection.

use crate::{
    error::{JkemError, Result},
    mlkem::kpke::derive_ml_kem_success,
    params::*,
    security::{crypto, wipe::WipeBytes},
};
use core::marker::PhantomData;
use hybrid_array::{Array, SliceExt, typenum::Unsigned};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub(crate) struct MlKemControlPlane<P>(PhantomData<P>);

pub(crate) struct KpkeKeygenSeeds {
    rho: [u8; 32],
    sigma: WipeBytes<32>,
}

impl KpkeKeygenSeeds {
    pub(crate) fn new(rho: [u8; 32], sigma: [u8; 32]) -> Self {
        Self {
            rho,
            sigma: WipeBytes::new(sigma),
        }
    }

    pub(crate) fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    pub(crate) fn sigma(&self) -> &[u8; 32] {
        &self.sigma
    }
}

pub(crate) struct CheckedDecapsulationKeyParts<'a, P>
where
    P: MlKemParams,
{
    /// K-PKE decryption key bytes embedded in the ML-KEM decapsulation key.
    pub(crate) dk_pke: &'a PolyVectorBytes<P>,
    /// Encapsulation key bytes embedded in the ML-KEM decapsulation key.
    pub(crate) ek: &'a EncapsulationKey<P>,
    /// Validated public-key hash stored in the ML-KEM decapsulation key.
    pub(crate) h: &'a [u8; 32],
    /// Secret implicit-rejection value.
    pub(crate) z: &'a [u8; 32],
}

/// ML-KEM success shared secret and deterministic K-PKE coins.
pub(crate) struct MlKemDerivation {
    pub(crate) shared_secret: WipeBytes<32>,
    pub(crate) coins: WipeBytes<32>,
}

impl MlKemDerivation {
    pub(crate) fn new(shared_secret: SharedSecret, coins: [u8; 32]) -> Self {
        Self {
            shared_secret: WipeBytes::new(shared_secret),
            coins: WipeBytes::new(coins),
        }
    }
}

impl<P> MlKemControlPlane<P>
where
    P: MlKemParams,
{
    /// Expand FIPS 203 ML-KEM key generation seed `d` into K-PKE seeds.
    pub(crate) fn expand_keygen_seed(d: &[u8; 32]) -> Result<KpkeKeygenSeeds> {
        // FIPS 203 ML-KEM expands d with the parameter k before K-PKE sampling.
        let mut seed_input = WipeBytes::<33>::zeroed();
        seed_input[..32].copy_from_slice(d);
        seed_input[32] = P::k() as u8;
        let mut expanded = crypto::sha3_512(&seed_input[..]);
        let mut rho = [0u8; 32];
        let mut sigma = [0u8; 32];
        rho.copy_from_slice(&expanded[..32]);
        sigma.copy_from_slice(&expanded[32..]);
        expanded.zeroize();
        Ok(KpkeKeygenSeeds::new(rho, sigma))
    }

    /// Assemble `dk = dkPKE || ek || H(ek) || z`.
    pub(crate) fn pack_decapsulation_key(
        dk_pke: &PolyVectorBytes<P>,
        ek: &EncapsulationKey<P>,
        z: &[u8; 32],
    ) -> Result<DecapsulationKey<P>> {
        let h = crypto::sha3_256(ek);
        let mut dk = Array::default();
        let sk_end = P::PolyVectorBytes::USIZE;
        let ek_end = sk_end + P::EncapsulationKeyBytes::USIZE;
        let h_end = ek_end + 32;
        dk[..sk_end].copy_from_slice(dk_pke);
        dk[sk_end..ek_end].copy_from_slice(ek);
        dk[ek_end..h_end].copy_from_slice(&h);
        dk[h_end..].copy_from_slice(z);
        Ok(dk)
    }

    /// Parse and validate an ML-KEM decapsulation key.
    pub(crate) fn unpack_decapsulation_key(
        dk: &DecapsulationKey<P>,
    ) -> Result<CheckedDecapsulationKeyParts<'_, P>> {
        let sk_end = P::PolyVectorBytes::USIZE;
        let ek_end = sk_end + P::EncapsulationKeyBytes::USIZE;
        let h_end = ek_end + 32;
        let dk_pke = dk[..sk_end]
            .as_hybrid_array()
            .expect("fixed-layout decapsulation key contains a PKE secret key");
        let ek = dk[sk_end..ek_end]
            .as_hybrid_array()
            .expect("fixed-layout decapsulation key contains an encapsulation key");
        let h: &[u8; 32] = (&dk[ek_end..h_end])
            .try_into()
            .expect("fixed-layout decapsulation key contains H(ek)");
        if crypto::sha3_256(ek).ct_ne(h).into() {
            return Err(JkemError::InvalidParameter {
                name: "decapsulation key",
                message: "stored H(ek) does not match ek",
            });
        }
        let z: &[u8; 32] = (&dk[h_end..])
            .try_into()
            .expect("fixed-layout decapsulation key contains z");

        Ok(CheckedDecapsulationKeyParts { dk_pke, ek, h, z })
    }

    /// Derive `(K, r) = G(m || H(ek))` for encapsulation.
    pub(crate) fn derive_encapsulation(
        ek: &EncapsulationKey<P>,
        message: &[u8; 32],
    ) -> Result<MlKemDerivation> {
        let h = crypto::sha3_256(ek);
        derive_ml_kem_success(&h, message)
    }

    /// Mirror encapsulation derivation using the validated stored `H(ek)`.
    pub(crate) fn derive_decapsulation(
        h: &[u8; 32],
        message: &[u8; 32],
    ) -> Result<MlKemDerivation> {
        derive_ml_kem_success(h, message)
    }

    /// Derive implicit rejection secret `J(z || c)`.
    pub(crate) fn derive_implicit_rejection(
        z: &[u8; 32],
        ct: &Ciphertext<P>,
    ) -> Result<SharedSecret>
    {
        Ok(crypto::shake256([&z[..], &ct[..]]))
    }
}
