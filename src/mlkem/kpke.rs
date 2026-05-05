//! Algebraic K-PKE core for ML-KEM-512.

use super::{
    MlKem512,
    control::MlKemDerivation,
    serialize::{
        decode_ciphertext, decode_poly_vector, decode_public_key, encode_ciphertext,
        encode_public_key, encode_secret_key,
    },
};
use crate::{
    error::Result,
    math::{
        ntt::{basemul, from_ntt, to_mont, to_ntt},
        ring::{Poly, PolyVector, add, add_vector, sub},
    },
    params::*,
    security::{
        crypto,
        sample::{sample_matrix, sample_noise},
        wipe::WipeBytes,
    },
};
use zeroize::Zeroize;

/// Algebraic K-PKE core used underneath ML-KEM.
///
/// This trait deliberately starts after the ML-KEM seed expansion step. FIPS
/// 203's K-PKE.KeyGen takes `d` and expands it as `G(d || k)`, but this core
/// interface receives the already-expanded `rho` and `sigma` so the polynomial
/// encryption layer stays separated from ML-KEM's hash/KDF control plane.
pub trait KpkeCore {
    /// Deterministic algebraic K-PKE key generation from expanded seeds.
    ///
    /// # Safety
    ///
    /// `rho` and `sigma` must come from ML-KEM's approved seed expansion.
    /// Reusing the same pair repeats the PKE key pair.
    unsafe fn keygen_from_expanded(
        rho: &[u8; 32],
        sigma: &[u8; 32],
    ) -> Result<([u8; ENCAPSULATION_KEY_BYTES], [u8; POLY_VECTOR_BYTES])>;

    /// Deterministic K-PKE encryption.
    ///
    /// # Safety
    ///
    /// `coins` must be uniformly random, single-use, and derived exactly as the
    /// ML-KEM control plane requires.
    unsafe fn encrypt(
        ek: &[u8; ENCAPSULATION_KEY_BYTES],
        message: &[u8; 32],
        coins: &[u8; 32],
    ) -> Result<[u8; CIPHERTEXT_BYTES]>;

    /// Deterministic K-PKE decryption.
    fn decrypt(dk_pke: &[u8; POLY_VECTOR_BYTES], ct: &[u8; CIPHERTEXT_BYTES]) -> Result<[u8; 32]>;
}

impl KpkeCore for MlKem512 {
    unsafe fn keygen_from_expanded(
        rho: &[u8; 32],
        sigma: &[u8; 32],
    ) -> Result<([u8; ENCAPSULATION_KEY_BYTES], [u8; POLY_VECTOR_BYTES])> {
        fn mont_vector(vector: &PolyVector) -> PolyVector {
            core::array::from_fn(|i| to_mont(&vector[i]))
        }

        // sample_matrix already returns the public matrix in the NTT domain, as
        // in the ML-KEM reference implementation.
        let a = sample_matrix(rho, false)?;
        let s: PolyVector = [sample_noise(sigma, 0, ETA1)?, sample_noise(sigma, 1, ETA1)?];
        let e: PolyVector = [
            sample_noise(sigma, K as u8, ETA1)?,
            sample_noise(sigma, (K + 1) as u8, ETA1)?,
        ];
        let s_hat = ntt_vector(&s)?;
        let e_hat = ntt_vector(&e)?;
        // The reference code converts the NTT product into Montgomery form
        // before adding e_hat.
        let product_hat = mont_vector(&matrix_vector_mul_ntt(&a, &s_hat));
        let t_hat = add_vector(&product_hat, &e_hat);

        Ok((encode_public_key(&t_hat, rho), encode_secret_key(&s_hat)))
    }

    unsafe fn encrypt(
        pk: &[u8; ENCAPSULATION_KEY_BYTES],
        message: &[u8; 32],
        coins: &[u8; 32],
    ) -> Result<[u8; CIPHERTEXT_BYTES]> {
        fn from_ntt_vector(vector: &PolyVector) -> Result<PolyVector> {
            Ok([from_ntt(&vector[0])?, from_ntt(&vector[1])?])
        }

        fn message_to_poly(message: &[u8; 32]) -> Poly {
            let mut coeffs = [0i16; crate::params::N];
            for (i, coeff) in coeffs.iter_mut().enumerate() {
                // Secret bit: arithmetic select.
                let bit = (message[i / 8] >> (i % 8)) & 1;
                *coeff = i16::from(bit) * ((Q + 1) / 2);
            }
            Poly::new(coeffs)
        }

        let (t_hat, rho) = decode_public_key(pk)?;
        let a = sample_matrix(&rho, true)?;
        let r: PolyVector = [sample_noise(coins, 0, ETA1)?, sample_noise(coins, 1, ETA1)?];
        let e1: PolyVector = [
            sample_noise(coins, K as u8, ETA2)?,
            sample_noise(coins, (K + 1) as u8, ETA2)?,
        ];
        let e2 = sample_noise(coins, (2 * K) as u8, ETA2)?;

        let r_hat = ntt_vector(&r)?;
        let u_hat = matrix_vector_mul_ntt(&a, &r_hat);
        let u = add_vector(&from_ntt_vector(&u_hat)?, &e1);
        let mut v = add(&from_ntt(&dot_ntt(&t_hat, &r_hat))?, &e2);
        v = add(&v, &message_to_poly(message));

        Ok(encode_ciphertext(&u, &v))
    }

    fn decrypt(sk: &[u8; POLY_VECTOR_BYTES], ct: &[u8; CIPHERTEXT_BYTES]) -> Result<[u8; 32]> {
        fn poly_to_message(poly: &Poly) -> [u8; 32] {
            fn ge_mask_u16(lhs: u16, rhs: u16) -> u16 {
                // Branchless lhs >= rhs mask.
                let diff = i32::from(lhs) - i32::from(rhs);
                (!(diff >> 31) as u16).wrapping_neg()
            }

            let mut message = [0u8; 32];
            for (i, &coeff) in poly.coeffs().iter().enumerate() {
                // Equivalent to round(2*coeff/q) & 1, without division.
                let coeff = coeff as u16;
                let in_lower_bound = ge_mask_u16(coeff, 833);
                let in_upper_bound = ge_mask_u16(2496, coeff);
                let bit = (in_lower_bound & in_upper_bound) & 1;
                message[i / 8] |= (bit as u8) << (i % 8);
            }
            message
        }

        let s_hat = decode_poly_vector(sk, 12)?;
        let (u, v) = decode_ciphertext(ct)?;
        let u_hat = ntt_vector(&u)?;
        let m_poly = sub(&v, &from_ntt(&dot_ntt(&s_hat, &u_hat))?);
        Ok(poly_to_message(&m_poly))
    }
}

pub(crate) fn derive_ml_kem_success(h: &[u8; 32], message: &[u8; 32]) -> Result<MlKemDerivation> {
    // ML-KEM.Encaps derives both K and the encryption coins from
    // G(m || H(ek)); the public randomized API supplies m randomly.
    let mut preimage = WipeBytes::<64>::zeroed();
    preimage[..32].copy_from_slice(message);
    preimage[32..].copy_from_slice(h);
    let mut kr = crypto::sha3_512(&preimage[..]);
    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];
    let mut coins = [0u8; 32];
    shared_secret.copy_from_slice(&kr[..SHARED_SECRET_BYTES]);
    coins.copy_from_slice(&kr[SHARED_SECRET_BYTES..SHARED_SECRET_BYTES + 32]);
    kr.zeroize();
    Ok(MlKemDerivation::new(shared_secret, coins))
}

fn ntt_vector(vector: &PolyVector) -> Result<PolyVector> {
    Ok([to_ntt(&vector[0])?, to_ntt(&vector[1])?])
}

fn matrix_vector_mul_ntt(
    matrix: &crate::math::ring::PolyMatrix,
    vector: &PolyVector,
) -> PolyVector {
    core::array::from_fn(|i| dot_ntt(&matrix[i], vector))
}

fn dot_ntt(a: &PolyVector, b: &PolyVector) -> Poly {
    let mut acc = Poly::ZERO;
    for (lhs, rhs) in a.iter().zip(b) {
        acc = add(&acc, &basemul(lhs, rhs));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlKem512, MlKemInterface};

    #[test]
    fn pke_round_trips_fixed_message() {
        let seed = [1u8; 32];
        let coins = [2u8; 32];
        let message = [0xa5u8; 32];

        let (pk, sk) = unsafe { MlKem512::keygen_from_expanded(&seed, &seed) }.unwrap();
        let ct = unsafe { MlKem512::encrypt(&pk, &message, &coins) }.unwrap();
        let decrypted = MlKem512::decrypt(&sk, &ct).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn ml_kem_internal_round_trips_fixed_message() {
        let d = [3u8; 32];
        let z = [4u8; 32];
        let message = [0x5au8; 32];

        let (ek, dk) = unsafe { MlKem512::keygen_internal(&d, &z) }.unwrap();
        let (ct, ss) = unsafe { MlKem512::encaps_internal(&ek, &message) }.unwrap();
        let decapsulated = MlKem512::decaps(&dk, &ct).unwrap();

        assert_eq!(decapsulated, ss);
    }
}
