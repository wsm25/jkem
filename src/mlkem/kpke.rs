//! Algebraic K-PKE core for ML-KEM-512.

use super::{
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
use core::marker::PhantomData;
use zeroize::Zeroize;

/// Algebraic K-PKE core used underneath ML-KEM.
pub struct KpkeCore<P>(PhantomData<P>);

impl<P> KpkeCore<P>
where
    P: MlKemParams,
{
    /// Deterministic algebraic K-PKE key generation from expanded seeds.
    ///
    /// # Safety
    ///
    /// `rho` and `sigma` must come from ML-KEM's approved seed expansion.
    /// Reusing the same pair repeats the PKE key pair.
    pub(crate) unsafe fn keygen_from_expanded(
        rho: &[u8; 32],
        sigma: &[u8; 32],
    ) -> Result<(EncapsulationKey<P>, PolyVectorBytes<P>)> {
        fn mont_vector<P>(vector: &PolyVector<P>) -> PolyVector<P>
        where
            P: MlKemParams,
        {
            hybrid_array::Array::from_fn(|i| to_mont(&vector[i]))
        }

        // sample_matrix already returns the public matrix in the NTT domain, as
        // in the ML-KEM reference implementation.
        let a = sample_matrix::<P>(rho, false)?;
        let s: PolyVector<P> =
            hybrid_array::Array::try_from_fn(|i| sample_noise(sigma, i as u8, P::eta1()))?;
        let e: PolyVector<P> = hybrid_array::Array::try_from_fn(|i| {
            sample_noise(sigma, (P::k() + i) as u8, P::eta1())
        })?;
        let s_hat = ntt_vector::<P>(&s)?;
        let e_hat = ntt_vector::<P>(&e)?;
        // The reference code converts the NTT product into Montgomery form
        // before adding e_hat.
        let product_hat = mont_vector::<P>(&matrix_vector_mul_ntt::<P>(&a, &s_hat));
        let t_hat = add_vector::<P>(&product_hat, &e_hat);

        Ok((
            encode_public_key::<P>(&t_hat, rho),
            encode_secret_key::<P>(&s_hat),
        ))
    }

    /// Deterministic K-PKE encryption.
    ///
    /// # Safety
    ///
    /// `coins` must be uniformly random, single-use, and derived exactly as the
    /// ML-KEM control plane requires.
    pub(crate) unsafe fn encrypt(
        ek: &EncapsulationKey<P>,
        message: &[u8; 32],
        coins: &[u8; 32],
    ) -> Result<Ciphertext<P>> {
        fn from_ntt_vector<P>(vector: &PolyVector<P>) -> Result<PolyVector<P>>
        where
            P: MlKemParams,
        {
            hybrid_array::Array::try_from_fn(|i| from_ntt(&vector[i]))
        }

        fn message_to_poly(message: &[u8; 32]) -> Poly {
            let mut coeffs = [0i16; crate::params::N];
            for (i, coeff) in coeffs.iter_mut().enumerate() {
                // Secret bit: arithmetic select.
                let bit = (message[i / 8] >> (i % 8)) & 1;
                *coeff = i16::from(bit) * ((Q as i16 + 1) / 2);
            }
            Poly::new(coeffs)
        }

        let (t_hat, rho) = decode_public_key::<P>(ek)?;
        let a = sample_matrix::<P>(&rho, true)?;
        let r: PolyVector<P> =
            hybrid_array::Array::try_from_fn(|i| sample_noise(coins, i as u8, P::eta1()))?;
        let e1: PolyVector<P> = hybrid_array::Array::try_from_fn(|i| {
            sample_noise(coins, (P::k() + i) as u8, P::eta2())
        })?;
        let e2 = sample_noise(coins, (2 * P::k()) as u8, P::eta2())?;

        let r_hat = ntt_vector::<P>(&r)?;
        let u_hat = matrix_vector_mul_ntt::<P>(&a, &r_hat);
        let u = add_vector::<P>(&from_ntt_vector::<P>(&u_hat)?, &e1);
        let mut v = add(&from_ntt(&dot_ntt::<P>(&t_hat, &r_hat))?, &e2);
        v = add(&v, &message_to_poly(message));

        Ok(encode_ciphertext::<P>(&u, &v))
    }

    /// Deterministic K-PKE decryption.
    pub(crate) fn decrypt(sk: &PolyVectorBytes<P>, ct: &Ciphertext<P>) -> Result<[u8; 32]> {
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

        let s_hat = decode_poly_vector::<P>(sk, 12)?;
        let (u, v) = decode_ciphertext::<P>(ct)?;
        let u_hat = ntt_vector::<P>(&u)?;
        let m_poly = sub(&v, &from_ntt(&dot_ntt::<P>(&s_hat, &u_hat))?);
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
    let mut shared_secret = [0u8; 32];
    let mut coins = [0u8; 32];
    shared_secret.copy_from_slice(&kr[..32]);
    coins.copy_from_slice(&kr[32..64]);
    kr.zeroize();
    Ok(MlKemDerivation::new(shared_secret, coins))
}

fn ntt_vector<P>(vector: &PolyVector<P>) -> Result<PolyVector<P>>
where
    P: MlKemParams,
{
    hybrid_array::Array::try_from_fn(|i| to_ntt(&vector[i]))
}

fn matrix_vector_mul_ntt<P>(
    matrix: &crate::math::ring::PolyMatrix<P>,
    vector: &PolyVector<P>,
) -> PolyVector<P>
where
    P: MlKemParams,
{
    hybrid_array::Array::from_fn(|i| dot_ntt::<P>(&matrix[i], vector))
}

fn dot_ntt<P>(a: &PolyVector<P>, b: &PolyVector<P>) -> Poly
where
    P: MlKemParams,
{
    let mut acc = Poly::ZERO;
    for (lhs, rhs) in a.iter().zip(b) {
        acc = add(&acc, &basemul(lhs, rhs));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MlKem512;

    #[test]
    fn pke_round_trips_fixed_message() {
        let seed = [1u8; 32];
        let coins = [2u8; 32];
        let message = [0xa5u8; 32];

        let (pk, sk) =
            unsafe { KpkeCore::<crate::params::MlKem512>::keygen_from_expanded(&seed, &seed) }
                .unwrap();
        let ct =
            unsafe { KpkeCore::<crate::params::MlKem512>::encrypt(&pk, &message, &coins) }.unwrap();
        let decrypted = KpkeCore::<crate::params::MlKem512>::decrypt(&sk, &ct).unwrap();

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
