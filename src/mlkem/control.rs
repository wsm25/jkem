//! ML-KEM-512 control-plane contract and implementation.
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
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub struct MlKem512ControlPlane;

pub struct KpkeKeygenSeeds {
    rho: [u8; 32],
    sigma: WipeBytes<32>,
}

impl KpkeKeygenSeeds {
    pub fn new(rho: [u8; 32], sigma: [u8; 32]) -> Self {
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

pub struct CheckedDecapsulationKeyParts<'a> {
    /// K-PKE decryption key bytes embedded in the ML-KEM decapsulation key.
    pub dk_pke: &'a [u8; POLY_VECTOR_BYTES],
    /// Encapsulation key bytes embedded in the ML-KEM decapsulation key.
    pub ek: &'a [u8; ENCAPSULATION_KEY_BYTES],
    /// Validated public-key hash stored in the ML-KEM decapsulation key.
    pub h: &'a [u8; 32],
    /// Secret implicit-rejection value.
    pub z: &'a [u8; 32],
}

/// ML-KEM success shared secret and deterministic K-PKE coins.
pub struct MlKemDerivation {
    pub(crate) shared_secret: WipeBytes<SHARED_SECRET_BYTES>,
    pub(crate) coins: WipeBytes<32>,
}

impl MlKemDerivation {
    pub fn new(shared_secret: [u8; SHARED_SECRET_BYTES], coins: [u8; 32]) -> Self {
        Self {
            shared_secret: WipeBytes::new(shared_secret),
            coins: WipeBytes::new(coins),
        }
    }
}

pub trait MlKemControlPlane {
    /// Expand FIPS 203 ML-KEM key generation seed `d` into K-PKE seeds.
    fn expand_keygen_seed(d: &[u8; 32]) -> Result<KpkeKeygenSeeds>;

    /// Assemble `dk = dkPKE || ek || H(ek) || z`.
    fn pack_decapsulation_key(
        dk_pke: &[u8; POLY_VECTOR_BYTES],
        ek: &[u8; ENCAPSULATION_KEY_BYTES],
        z: &[u8; 32],
    ) -> Result<[u8; DECAPSULATION_KEY_BYTES]>;

    /// Parse and validate an ML-KEM decapsulation key.
    fn unpack_decapsulation_key(
        dk: &[u8; DECAPSULATION_KEY_BYTES],
    ) -> Result<CheckedDecapsulationKeyParts<'_>>;

    /// Derive `(K, r) = G(m || H(ek))` for encapsulation.
    fn derive_encapsulation(
        ek: &[u8; ENCAPSULATION_KEY_BYTES],
        message: &[u8; 32],
    ) -> Result<MlKemDerivation>;

    /// Mirror encapsulation derivation using the validated stored `H(ek)`.
    fn derive_decapsulation(h: &[u8; 32], message: &[u8; 32]) -> Result<MlKemDerivation>;

    /// Derive implicit rejection secret `J(z || c)`.
    fn derive_implicit_rejection(
        z: &[u8; 32],
        ct: &[u8; CIPHERTEXT_BYTES],
    ) -> Result<[u8; SHARED_SECRET_BYTES]>;
}

impl MlKemControlPlane for MlKem512ControlPlane {
    fn expand_keygen_seed(d: &[u8; 32]) -> Result<KpkeKeygenSeeds> {
        // FIPS 203 ML-KEM expands d with the parameter k before K-PKE sampling.
        let mut seed_input = WipeBytes::<33>::zeroed();
        seed_input[..32].copy_from_slice(d);
        seed_input[32] = K as u8;
        let mut expanded = crypto::sha3_512(&seed_input[..]);
        let mut rho = [0u8; 32];
        let mut sigma = [0u8; 32];
        rho.copy_from_slice(&expanded[..32]);
        sigma.copy_from_slice(&expanded[32..]);
        expanded.zeroize();
        Ok(KpkeKeygenSeeds::new(rho, sigma))
    }

    fn pack_decapsulation_key(
        dk_pke: &[u8; POLY_VECTOR_BYTES],
        ek: &[u8; ENCAPSULATION_KEY_BYTES],
        z: &[u8; 32],
    ) -> Result<[u8; DECAPSULATION_KEY_BYTES]> {
        let h = crypto::sha3_256(ek);
        let mut dk = [0u8; DECAPSULATION_KEY_BYTES];
        dk[..POLY_VECTOR_BYTES].copy_from_slice(dk_pke);
        dk[POLY_VECTOR_BYTES..POLY_VECTOR_BYTES + ENCAPSULATION_KEY_BYTES].copy_from_slice(ek);
        dk[POLY_VECTOR_BYTES + ENCAPSULATION_KEY_BYTES
            ..POLY_VECTOR_BYTES + ENCAPSULATION_KEY_BYTES + 32]
            .copy_from_slice(&h);
        dk[POLY_VECTOR_BYTES + ENCAPSULATION_KEY_BYTES + 32..].copy_from_slice(z);
        Ok(dk)
    }

    fn unpack_decapsulation_key(
        dk: &[u8; DECAPSULATION_KEY_BYTES],
    ) -> Result<CheckedDecapsulationKeyParts<'_>> {
        let dk_pke: &[u8; POLY_VECTOR_BYTES] = (&dk[..POLY_VECTOR_BYTES])
            .try_into()
            .expect("fixed-layout decapsulation key contains a PKE secret key");
        let ek: &[u8; ENCAPSULATION_KEY_BYTES] = (&dk
            [POLY_VECTOR_BYTES..POLY_VECTOR_BYTES + ENCAPSULATION_KEY_BYTES])
            .try_into()
            .expect("fixed-layout decapsulation key contains an encapsulation key");
        let h: &[u8; 32] = (&dk[POLY_VECTOR_BYTES + ENCAPSULATION_KEY_BYTES
            ..POLY_VECTOR_BYTES + ENCAPSULATION_KEY_BYTES + 32])
            .try_into()
            .expect("fixed-layout decapsulation key contains H(ek)");
        if crypto::sha3_256(ek).ct_ne(h).into() {
            return Err(JkemError::InvalidParameter {
                name: "decapsulation key",
                message: "stored H(ek) does not match ek",
            });
        }
        let z: &[u8; 32] = (&dk[POLY_VECTOR_BYTES + ENCAPSULATION_KEY_BYTES + 32..])
            .try_into()
            .expect("fixed-layout decapsulation key contains z");

        Ok(CheckedDecapsulationKeyParts { dk_pke, ek, h, z })
    }

    fn derive_encapsulation(
        ek: &[u8; ENCAPSULATION_KEY_BYTES],
        message: &[u8; 32],
    ) -> Result<MlKemDerivation> {
        let h = crypto::sha3_256(ek);
        derive_ml_kem_success(&h, message)
    }

    fn derive_decapsulation(h: &[u8; 32], message: &[u8; 32]) -> Result<MlKemDerivation> {
        derive_ml_kem_success(h, message)
    }

    fn derive_implicit_rejection(
        z: &[u8; 32],
        ct: &[u8; CIPHERTEXT_BYTES],
    ) -> Result<[u8; SHARED_SECRET_BYTES]> {
        let mut input = WipeBytes::<{ 32 + CIPHERTEXT_BYTES }>::zeroed();
        input[..32].copy_from_slice(z);
        input[32..].copy_from_slice(ct);
        Ok(crypto::shake256(&input[..]))
    }
}
