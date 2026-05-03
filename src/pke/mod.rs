//! IND-CPA public-key encryption layer for ML-KEM-512.
//!
//! The KEM wrapper uses this module through the `FoPke` trait, while tests can
//! still exercise deterministic PKE key generation, encryption, and decryption.
//!
//! ```
//! use jkem::pke::{MlKem512Pke, Pke};
//!
//! let seed = [1u8; 32];
//! let coins = [2u8; 32];
//! let message = [0xa5u8; 32];
//!
//! let (pk, sk) = MlKem512Pke::keygen(&seed)?;
//! let ct = MlKem512Pke::encrypt(&pk, &message, &coins)?;
//! assert_eq!(MlKem512Pke::decrypt(&sk, &ct)?, message);
//!
//! # Ok::<(), jkem::JkemError>(())
//! ```

use crate::{
    error::Result,
    math::{
        ntt::{basemul, from_ntt, to_mont, to_ntt},
        ring::{Poly, PolyVector, add, add_vector, sub},
    },
    params::{
        CIPHERTEXT_BYTES, DECAPSULATION_KEY_BYTES, ENCAPSULATION_KEY_BYTES, ETA1, ETA2, K, Q,
        SHARED_SECRET_BYTES,
    },
    sample::{crypto, sample_matrix, sample_noise},
    serialize::{decode_ciphertext, decode_public_key, encode_ciphertext, encode_public_key},
};

pub trait Pke {
    type PublicKey;
    type SecretKey;
    type Ciphertext;

    fn keygen(seed: &[u8; 32]) -> Result<(Self::PublicKey, Self::SecretKey)>;

    fn encrypt(
        pk: &Self::PublicKey,
        message: &[u8; 32],
        coins: &[u8; 32],
    ) -> Result<Self::Ciphertext>;

    fn decrypt(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<[u8; 32]>;
}

pub trait FoPke: Pke {
    type EncapsulationKey;
    type DecapsulationKey;
    type SharedSecret;

    fn pke_keygen_from_dz(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey)>;

    fn pke_encrypt_for_fo(
        ek: &Self::EncapsulationKey,
        message: &[u8; 32],
        coins: &[u8; 32],
    ) -> Result<Self::Ciphertext>;

    fn pke_decrypt_for_fo(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<[u8; 32]>;

    fn ciphertext_bytes(ct: &Self::Ciphertext) -> &[u8];

    fn encaps_with_message_fo(
        ek: &Self::EncapsulationKey,
        message: &[u8; 32],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)>;

    fn decaps_fo(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret>;
}

pub struct MlKem512Pke;

pub struct MlKem512PublicKey(pub [u8; ENCAPSULATION_KEY_BYTES]);

pub struct MlKem512SecretKey(pub Vec<u8>);

pub struct MlKem512Ciphertext(pub [u8; CIPHERTEXT_BYTES]);

impl Pke for MlKem512Pke {
    type PublicKey = MlKem512PublicKey;
    type SecretKey = MlKem512SecretKey;
    type Ciphertext = MlKem512Ciphertext;

    fn keygen(seed: &[u8; 32]) -> Result<(Self::PublicKey, Self::SecretKey)> {
        fn mont_vector(vector: &PolyVector) -> PolyVector {
            core::array::from_fn(|i| to_mont(&vector[i]))
        }

        // FIPS 203 expands d with the parameter k before sampling A, s, and e.
        let mut seed_input = [0u8; 33];
        seed_input[..32].copy_from_slice(seed);
        seed_input[32] = K as u8;
        let expanded = crypto::sha3_512(&seed_input);
        let mut rho = [0u8; 32];
        let mut sigma = [0u8; 32];
        rho.copy_from_slice(&expanded[..32]);
        sigma.copy_from_slice(&expanded[32..]);

        // sample_matrix already returns the public matrix in the NTT domain, as
        // in the ML-KEM reference implementation.
        let a = sample_matrix(&rho, false)?;
        let s: PolyVector = [
            sample_noise(&sigma, 0, ETA1)?,
            sample_noise(&sigma, 1, ETA1)?,
        ];
        let e: PolyVector = [
            sample_noise(&sigma, K as u8, ETA1)?,
            sample_noise(&sigma, (K + 1) as u8, ETA1)?,
        ];
        let s_hat = ntt_vector(&s)?;
        let e_hat = ntt_vector(&e)?;
        // The reference code converts the NTT product into Montgomery form
        // before adding e_hat.
        let product_hat = mont_vector(&matrix_vector_mul_ntt(&a, &s_hat));
        let t_hat = add_vector(&product_hat, &e_hat);

        Ok((
            MlKem512PublicKey(encode_public_key(&t_hat, &rho)),
            MlKem512SecretKey(crate::serialize::encode_poly_vector(&s_hat, 12)),
        ))
    }

    fn encrypt(
        pk: &Self::PublicKey,
        message: &[u8; 32],
        coins: &[u8; 32],
    ) -> Result<Self::Ciphertext> {
        fn from_ntt_vector(vector: &PolyVector) -> Result<PolyVector> {
            Ok([from_ntt(&vector[0])?, from_ntt(&vector[1])?])
        }

        fn message_to_poly(message: &[u8; 32]) -> Poly {
            let mut coeffs = [0i16; crate::params::N];
            for (i, coeff) in coeffs.iter_mut().enumerate() {
                let bit = (message[i / 8] >> (i % 8)) & 1;
                *coeff = if bit == 1 { (Q + 1) / 2 } else { 0 };
            }
            Poly::new(coeffs)
        }

        let (t_hat, rho) = decode_public_key(&pk.0)?;
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

        Ok(MlKem512Ciphertext(encode_ciphertext(&u, &v)))
    }

    fn decrypt(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<[u8; 32]> {
        fn poly_to_message(poly: &Poly) -> [u8; 32] {
            let mut message = [0u8; 32];
            for (i, &coeff) in poly.coeffs().iter().enumerate() {
                let normalized = if coeff < 0 { coeff + Q } else { coeff };
                let bit = (((i32::from(normalized) << 1) + i32::from(Q) / 2) / i32::from(Q)) & 1;
                message[i / 8] |= (bit as u8) << (i % 8);
            }
            message
        }

        let s_hat = crate::serialize::decode_poly_vector(&sk.0, 12)?;
        let (u, v) = decode_ciphertext(&ct.0)?;
        let u_hat = ntt_vector(&u)?;
        let m_poly = sub(&v, &from_ntt(&dot_ntt(&s_hat, &u_hat))?);
        Ok(poly_to_message(&m_poly))
    }
}

impl FoPke for MlKem512Pke {
    type EncapsulationKey = [u8; ENCAPSULATION_KEY_BYTES];
    type DecapsulationKey = [u8; DECAPSULATION_KEY_BYTES];
    type SharedSecret = [u8; SHARED_SECRET_BYTES];

    fn pke_keygen_from_dz(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey)> {
        let (pk, sk) = Self::keygen(d)?;
        let h_pk = crypto::sha3_256(&pk.0);
        let mut dk = [0u8; DECAPSULATION_KEY_BYTES];
        dk[..768].copy_from_slice(&sk.0);
        dk[768..1568].copy_from_slice(&pk.0);
        dk[1568..1600].copy_from_slice(&h_pk);
        dk[1600..].copy_from_slice(z);
        Ok((pk.0, dk))
    }

    fn pke_encrypt_for_fo(
        ek: &Self::EncapsulationKey,
        message: &[u8; 32],
        coins: &[u8; 32],
    ) -> Result<Self::Ciphertext> {
        Self::encrypt(&MlKem512PublicKey(*ek), message, coins)
    }

    fn pke_decrypt_for_fo(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<[u8; 32]> {
        let mut sk = Vec::with_capacity(768);
        sk.extend_from_slice(&dk[..768]);
        Self::decrypt(&MlKem512SecretKey(sk), ct)
    }

    fn ciphertext_bytes(ct: &Self::Ciphertext) -> &[u8] {
        &ct.0
    }

    fn encaps_with_message_fo(
        ek: &Self::EncapsulationKey,
        message: &[u8; 32],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        // ML-KEM.Encaps derives both K and the encryption coins from
        // H(m || H(ek)); the public randomized API supplies m randomly.
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(message);
        preimage[32..].copy_from_slice(&crypto::sha3_256(ek));
        let kr = crypto::sha3_512(&preimage);
        let mut coins = [0u8; 32];
        coins.copy_from_slice(&kr[32..]);
        let ct = Self::pke_encrypt_for_fo(ek, message, &coins)?;
        let mut ss = [0u8; 32];
        ss.copy_from_slice(&kr[..32]);
        Ok((ct, ss))
    }

    fn decaps_fo(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret> {
        // The ML-KEM decapsulation key layout is dkPKE || ek || H(ek) || z.
        let mut ek = [0u8; ENCAPSULATION_KEY_BYTES];
        ek.copy_from_slice(&dk[768..1568]);
        let mut h = [0u8; 32];
        h.copy_from_slice(&dk[1568..1600]);
        let mut z = [0u8; 32];
        z.copy_from_slice(&dk[1600..]);

        let message = Self::pke_decrypt_for_fo(dk, ct)?;
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&message);
        preimage[32..].copy_from_slice(&h);
        let kr = crypto::sha3_512(&preimage);
        let mut coins = [0u8; 32];
        coins.copy_from_slice(&kr[32..]);
        let expected = Self::pke_encrypt_for_fo(&ek, &message, &coins)?;

        let expected_bytes = Self::ciphertext_bytes(&expected);
        let ct_bytes = Self::ciphertext_bytes(ct);

        if expected_bytes == ct_bytes {
            let mut ss = [0u8; 32];
            ss.copy_from_slice(&kr[..32]);
            Ok(ss)
        } else {
            let mut fallback_input = Vec::with_capacity(32 + ct_bytes.len());
            fallback_input.extend_from_slice(&z);
            fallback_input.extend_from_slice(ct_bytes);
            Ok(crypto::shake256(&fallback_input))
        }
    }
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

    #[test]
    fn pke_round_trips_fixed_message() {
        let seed = [1u8; 32];
        let coins = [2u8; 32];
        let message = [0xa5u8; 32];

        let (pk, sk) = MlKem512Pke::keygen(&seed).unwrap();
        let ct = MlKem512Pke::encrypt(&pk, &message, &coins).unwrap();
        let decrypted = MlKem512Pke::decrypt(&sk, &ct).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn fo_round_trips_fixed_message() {
        let d = [3u8; 32];
        let z = [4u8; 32];
        let message = [0x5au8; 32];

        let (ek, dk) = <MlKem512Pke as FoPke>::pke_keygen_from_dz(&d, &z).unwrap();
        let (ct, ss) = <MlKem512Pke as FoPke>::encaps_with_message_fo(&ek, &message).unwrap();
        let decapsulated = <MlKem512Pke as FoPke>::decaps_fo(&dk, &ct).unwrap();

        assert_eq!(decapsulated, ss);
    }
}
