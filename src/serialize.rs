//! ML-KEM byte encoding, decoding, compression, and key/ciphertext layouts.
//!
//! This module implements the standard bit packing used for polynomials and
//! the fixed byte layouts for ML-KEM-512 public keys and ciphertexts.
//!
//! ```
//! use jkem::serialize::{decode, encode};
//!
//! let values = [0u16, 1, 255, 256, 3328, 4095];
//! let encoded = encode(&values, 12);
//! assert_eq!(decode(&encoded, 12, values.len())?, values);
//!
//! # Ok::<(), jkem::JkemError>(())
//! ```

use crate::{
    error::{JkemError, Result},
    math::ring::{Poly, PolyVector},
    params::{CIPHERTEXT_BYTES, DU, DV, K, N, POLY_VECTOR_BYTES, Q},
};

pub fn compress(value: i16, bits: usize) -> u16 {
    assert!((1..=12).contains(&bits));
    let modulus = 1u32 << bits;
    (((u32::from(reduce_to_u16(value)) << bits) + (u32::from(Q as u16) / 2)) / u32::from(Q as u16)
        % modulus) as u16
}

pub fn decompress(value: u16, bits: usize) -> i16 {
    assert!((1..=12).contains(&bits));
    let modulus = 1u32 << bits;
    (((u32::from(value) * u32::from(Q as u16)) + (modulus / 2)) / modulus) as i16
}

pub fn encode(values: &[u16], bits: usize) -> Vec<u8> {
    assert!((1..=16).contains(&bits));
    let mut out = vec![0u8; (values.len() * bits).div_ceil(8)];

    for (i, &value) in values.iter().enumerate() {
        let masked = value & ((1u32 << bits) - 1) as u16;
        for j in 0..bits {
            if ((masked >> j) & 1) != 0 {
                let bit_index = i * bits + j;
                out[bit_index / 8] |= 1 << (bit_index % 8);
            }
        }
    }

    out
}

pub fn decode(bytes: &[u8], bits: usize, count: usize) -> Result<Vec<u16>> {
    assert!((1..=16).contains(&bits));
    let expected = (count * bits).div_ceil(8);
    if bytes.len() != expected {
        return Err(JkemError::InvalidLength {
            name: "encoded values",
            expected,
            actual: bytes.len(),
        });
    }

    let mut out = vec![0u16; count];
    for (i, value) in out.iter_mut().enumerate() {
        let mut decoded = 0u16;
        for j in 0..bits {
            let bit_index = i * bits + j;
            let bit = (bytes[bit_index / 8] >> (bit_index % 8)) & 1;
            decoded |= u16::from(bit) << j;
        }
        *value = decoded;
    }

    Ok(out)
}

pub fn encode_poly(poly: &Poly, bits: usize) -> Vec<u8> {
    let values: Vec<u16> = poly
        .coeffs()
        .iter()
        .map(|&coeff| reduce_to_u16(coeff) & ((1u32 << bits) - 1) as u16)
        .collect();
    encode(&values, bits)
}

pub fn decode_poly(bytes: &[u8], bits: usize) -> Result<Poly> {
    let values = decode(bytes, bits, N)?;
    let mut coeffs = [0i16; N];
    for (dst, src) in coeffs.iter_mut().zip(values) {
        *dst = (src % Q as u16) as i16;
    }
    Ok(Poly::new(coeffs))
}

pub fn encode_poly_vector(vector: &PolyVector, bits: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * (N * bits).div_ceil(8));
    for poly in vector {
        out.extend_from_slice(&encode_poly(poly, bits));
    }
    out
}

pub fn decode_poly_vector(bytes: &[u8], bits: usize) -> Result<PolyVector> {
    let poly_bytes = (N * bits).div_ceil(8);
    let expected = K * poly_bytes;
    if bytes.len() != expected {
        return Err(JkemError::InvalidLength {
            name: "encoded polyvec",
            expected,
            actual: bytes.len(),
        });
    }

    Ok([
        decode_poly(&bytes[..poly_bytes], bits)?,
        decode_poly(&bytes[poly_bytes..], bits)?,
    ])
}

pub fn encode_public_key(t_hat: &PolyVector, rho: &[u8; 32]) -> [u8; POLY_VECTOR_BYTES + 32] {
    let mut out = [0u8; POLY_VECTOR_BYTES + 32];
    out[..POLY_VECTOR_BYTES].copy_from_slice(&encode_poly_vector(t_hat, 12));
    out[POLY_VECTOR_BYTES..].copy_from_slice(rho);
    out
}

pub fn decode_public_key(bytes: &[u8; POLY_VECTOR_BYTES + 32]) -> Result<(PolyVector, [u8; 32])> {
    let t_hat = decode_poly_vector(&bytes[..POLY_VECTOR_BYTES], 12)?;
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[POLY_VECTOR_BYTES..]);
    Ok((t_hat, rho))
}

pub fn encode_ciphertext(u: &PolyVector, v: &Poly) -> [u8; CIPHERTEXT_BYTES] {
    fn compress_poly(poly: &Poly, bits: usize) -> Poly {
        let mut out = [0i16; N];
        for (dst, &coeff) in out.iter_mut().zip(poly.coeffs()) {
            *dst = compress(coeff, bits) as i16;
        }
        Poly::new(out)
    }

    let mut out = [0u8; CIPHERTEXT_BYTES];
    let compressed_u: PolyVector = core::array::from_fn(|i| compress_poly(&u[i], DU));
    let compressed_v = compress_poly(v, DV);
    let u_bytes = encode_poly_vector(&compressed_u, DU);
    let v_bytes = encode_poly(&compressed_v, DV);
    out[..K * 320].copy_from_slice(&u_bytes);
    out[K * 320..].copy_from_slice(&v_bytes);
    out
}

pub fn decode_ciphertext(bytes: &[u8; CIPHERTEXT_BYTES]) -> Result<(PolyVector, Poly)> {
    fn decompress_poly(poly: &Poly, bits: usize) -> Poly {
        let mut out = [0i16; N];
        for (dst, &coeff) in out.iter_mut().zip(poly.coeffs()) {
            *dst = decompress(coeff as u16, bits);
        }
        Poly::new(out)
    }

    let u = decode_poly_vector(&bytes[..K * 320], DU)?;
    let v = decode_poly(&bytes[K * 320..], DV)?;
    Ok((
        core::array::from_fn(|i| decompress_poly(&u[i], DU)),
        decompress_poly(&v, DV),
    ))
}

fn reduce_to_u16(value: i16) -> u16 {
    let mut reduced = value % Q;
    if reduced < 0 {
        reduced += Q;
    }
    reduced as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trips_12_bit_values() {
        let values = [0, 1, 255, 256, 3328, 4095];
        let encoded = encode(&values, 12);
        let decoded = decode(&encoded, 12, values.len()).unwrap();
        assert_eq!(decoded, values);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let err = decode(&[0; 2], 12, 2).unwrap_err();
        assert_eq!(
            err,
            JkemError::InvalidLength {
                name: "encoded values",
                expected: 3,
                actual: 2
            }
        );
    }

    #[test]
    fn compress_handles_boundaries() {
        assert_eq!(compress(0, 1), 0);
        assert_eq!(compress(Q / 2, 1), 1);
        assert_eq!(compress(Q - 1, 1), 0);
    }

    #[test]
    fn poly_encode_decode_round_trips_mod_q_coefficients() {
        let mut coeffs = [0i16; N];
        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = (i as i16 * 13) % Q;
        }
        let poly = Poly::new(coeffs);
        let encoded = encode_poly(&poly, 12);
        let decoded = decode_poly(&encoded, 12).unwrap();
        assert_eq!(decoded, poly);
    }

    #[test]
    fn poly_vector_encode_decode_round_trips_12_bit_polys() {
        let vector: PolyVector = core::array::from_fn(|k| {
            let mut coeffs = [0i16; N];
            for (i, coeff) in coeffs.iter_mut().enumerate() {
                *coeff = ((i + k) as i16 * 17) % Q;
            }
            Poly::new(coeffs)
        });

        let encoded = encode_poly_vector(&vector, 12);
        assert_eq!(encoded.len(), POLY_VECTOR_BYTES);
        let decoded = decode_poly_vector(&encoded, 12).unwrap();
        assert_eq!(decoded, vector);
    }
}
