//! ML-KEM byte encoding, decoding, compression, and key/ciphertext layouts.

use crate::{
    error::{JkemError, Result},
    math::ring::{Poly, PolyVector, reduce},
    params::*,
};
use hybrid_array::{Array, typenum::Unsigned};

pub(crate) fn compress(value: i16, bits: usize) -> u16 {
    assert!((1..=12).contains(&bits));
    let modulus = 1u32 << bits;
    // Secret path: avoid hardware division by q.
    let numerator = (u32::from(reduce_to_u16(value)) << bits) + (u32::from(Q) / 2);
    (div_u32_by_q(numerator) & (modulus - 1)) as u16
}

pub(crate) fn decompress(value: u16, bits: usize) -> i16 {
    assert!((1..=12).contains(&bits));
    // Division by public 2^d is a shift.
    (((u32::from(value) * u32::from(Q)) + (1 << (bits - 1))) >> bits) as i16
}

pub(crate) fn encode_into(values: &[u16], bits: usize, out: &mut [u8]) {
    assert!((1..=16).contains(&bits));
    assert_eq!(out.len(), (values.len() * bits).div_ceil(8));
    out.fill(0);

    for (i, &value) in values.iter().enumerate() {
        let masked = value & ((1u32 << bits) - 1) as u16;
        for j in 0..bits {
            let bit_index = i * bits + j;
            let bit = ((masked >> j) & 1) as u8;
            out[bit_index / 8] |= bit << (bit_index % 8);
        }
    }
}

pub(crate) fn decode_into(bytes: &[u8], bits: usize, out: &mut [u16]) -> Result<()> {
    assert!((1..=16).contains(&bits));
    let expected = (out.len() * bits).div_ceil(8);
    // Public length check.
    if bytes.len() != expected {
        return Err(JkemError::InvalidLength {
            name: "encoded values",
            expected,
            actual: bytes.len(),
        });
    }

    for (i, value) in out.iter_mut().enumerate() {
        let mut decoded = 0u16;
        for j in 0..bits {
            let bit_index = i * bits + j;
            let bit = (bytes[bit_index / 8] >> (bit_index % 8)) & 1;
            decoded |= u16::from(bit) << j;
        }
        *value = decoded;
    }

    Ok(())
}

pub(crate) fn encode_poly_into(poly: &Poly, bits: usize, out: &mut [u8]) {
    let mut values = [0u16; N];
    for (dst, &coeff) in values.iter_mut().zip(poly.coeffs()) {
        *dst = reduce_to_u16(coeff) & ((1u32 << bits) - 1) as u16;
    }
    encode_into(&values, bits, out);
}

pub(crate) fn decode_poly(bytes: &[u8], bits: usize) -> Result<Poly> {
    let mut values = [0u16; N];
    decode_into(bytes, bits, &mut values)?;
    let mut coeffs = [0i16; N];
    for (dst, &src) in coeffs.iter_mut().zip(values.iter()) {
        *dst = reduce(src as i16);
    }
    Ok(Poly::new(coeffs))
}

pub(crate) fn decode_poly_mod_q(bytes: &[u8], bits: usize, name: &'static str) -> Result<Poly> {
    let mut values = [0u16; N];
    decode_into(bytes, bits, &mut values)?;
    let mut coeffs = [0i16; N];
    for (dst, &src) in coeffs.iter_mut().zip(values.iter()) {
        if src >= Q {
            return Err(JkemError::InvalidParameter {
                name,
                message: "encoded coefficient is not in [0, q)",
            });
        }
        *dst = src as i16;
    }
    Ok(Poly::new(coeffs))
}

pub(crate) fn encode_poly_vector_into<P>(vector: &PolyVector<P>, bits: usize, out: &mut [u8])
where
    P: MlKemParams,
{
    let poly_bytes = (N * bits).div_ceil(8);
    assert_eq!(out.len(), P::k() * poly_bytes);
    for (i, poly) in vector.iter().enumerate() {
        encode_poly_into(poly, bits, &mut out[i * poly_bytes..(i + 1) * poly_bytes]);
    }
}

pub(crate) fn encode_secret_key<P>(vector: &PolyVector<P>) -> PolyVectorBytes<P>
where
    P: MlKemParams,
{
    let mut out = Array::default();
    encode_poly_vector_into::<P>(vector, 12, &mut out);
    out
}

pub(crate) fn decode_poly_vector<P>(bytes: &[u8], bits: usize) -> Result<PolyVector<P>>
where
    P: MlKemParams,
{
    let poly_bytes = (N * bits).div_ceil(8);
    let expected = P::k() * poly_bytes;
    // Public length check.
    if bytes.len() != expected {
        return Err(JkemError::InvalidLength {
            name: "encoded polyvec",
            expected,
            actual: bytes.len(),
        });
    }

    Array::try_from_fn(|i| decode_poly(&bytes[i * poly_bytes..(i + 1) * poly_bytes], bits))
}

pub(crate) fn decode_poly_vector_mod_q<P>(
    bytes: &[u8],
    bits: usize,
    name: &'static str,
) -> Result<PolyVector<P>>
where
    P: MlKemParams,
{
    let poly_bytes = (N * bits).div_ceil(8);
    let expected = P::k() * poly_bytes;
    // Public length check.
    if bytes.len() != expected {
        return Err(JkemError::InvalidLength {
            name: "encoded polyvec",
            expected,
            actual: bytes.len(),
        });
    }

    Array::try_from_fn(|i| {
        decode_poly_mod_q(&bytes[i * poly_bytes..(i + 1) * poly_bytes], bits, name)
    })
}

pub(crate) fn encode_public_key<P>(t_hat: &PolyVector<P>, rho: &[u8; 32]) -> EncapsulationKey<P>
where
    P: MlKemParams,
{
    let mut out = Array::default();
    encode_poly_vector_into::<P>(t_hat, 12, &mut out[..P::PolyVectorBytes::USIZE]);
    out[P::PolyVectorBytes::USIZE..].copy_from_slice(rho);
    out
}

pub(crate) fn decode_public_key<P>(bytes: &EncapsulationKey<P>) -> Result<(PolyVector<P>, [u8; 32])>
where
    P: MlKemParams,
{
    let t_hat = decode_poly_vector_mod_q::<P>(
        &bytes[..P::PolyVectorBytes::USIZE],
        12,
        "encapsulation key",
    )?;
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[P::PolyVectorBytes::USIZE..]);
    Ok((t_hat, rho))
}

pub(crate) fn encode_ciphertext<P>(u: &PolyVector<P>, v: &Poly) -> Ciphertext<P>
where
    P: MlKemParams,
{
    fn compress_poly(poly: &Poly, bits: usize) -> Poly {
        let mut out = [0i16; N];
        for (dst, &coeff) in out.iter_mut().zip(poly.coeffs()) {
            *dst = compress(coeff, bits) as i16;
        }
        Poly::new(out)
    }

    let mut out = Array::default();
    let compressed_u: PolyVector<P> = Array::from_fn(|i| compress_poly(&u[i], P::du()));
    let compressed_v = compress_poly(v, P::dv());
    let u_len = P::k() * (N * P::du()).div_ceil(8);
    encode_poly_vector_into::<P>(&compressed_u, P::du(), &mut out[..u_len]);
    encode_poly_into(&compressed_v, P::dv(), &mut out[u_len..]);
    out
}

pub(crate) fn decode_ciphertext<P>(bytes: &Ciphertext<P>) -> Result<(PolyVector<P>, Poly)>
where
    P: MlKemParams,
{
    fn decompress_poly(poly: &Poly, bits: usize) -> Poly {
        let mut out = [0i16; N];
        for (dst, &coeff) in out.iter_mut().zip(poly.coeffs()) {
            *dst = decompress(coeff as u16, bits);
        }
        Poly::new(out)
    }

    let u_len = P::k() * (N * P::du()).div_ceil(8);
    let u = decode_poly_vector::<P>(&bytes[..u_len], P::du())?;
    let v = decode_poly(&bytes[u_len..], P::dv())?;
    Ok((
        Array::from_fn(|i| decompress_poly(&u[i], P::du())),
        decompress_poly(&v, P::dv()),
    ))
}

fn reduce_to_u16(value: i16) -> u16 {
    // Secret path: reduce avoids `%` and sign branches.
    reduce(value) as u16
}

fn div_u32_by_q(numerator: u32) -> u32 {
    let mut quotient = 0u32;
    let mut remainder = 0u32;

    // Fixed-iteration division by q for Compress.
    for shift in (0..24).rev() {
        remainder = (remainder << 1) | ((numerator >> shift) & 1);
        let candidate = remainder.wrapping_sub(u32::from(Q));
        let ge_q = ((candidate >> 31) ^ 1).wrapping_neg();
        remainder = (candidate & ge_q) | (remainder & !ge_q);
        quotient |= (ge_q & 1) << shift;
    }

    quotient
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MlKem512;
    use hybrid_array::Array;

    #[test]
    fn encode_decode_round_trips_12_bit_values() {
        let values = [0, 1, 255, 256, 3328, 4095];
        let mut encoded = [0u8; 9];
        let mut decoded = [0u16; 6];
        encode_into(&values, 12, &mut encoded);
        decode_into(&encoded, 12, &mut decoded).unwrap();
        assert_eq!(decoded, values);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let mut decoded = [0u16; 2];
        let err = decode_into(&[0; 2], 12, &mut decoded).unwrap_err();
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
        assert_eq!(compress(Q as i16 / 2, 1), 1);
        assert_eq!(compress(Q as i16 - 1, 1), 0);
    }

    #[test]
    fn compression_matches_reference_formula() {
        for bits in [1, 4, 5, 10, 11, 12] {
            let modulus = 1u32 << bits;
            for value in 0..Q {
                let expected = (((u32::from(value) << bits) + (u32::from(Q) / 2)) / u32::from(Q)
                    % modulus) as u16;
                assert_eq!(
                    compress(value as i16, bits),
                    expected,
                    "value={value} bits={bits}"
                );
            }

            for value in 0..(1u16 << bits) {
                let expected =
                    (((u32::from(value) * u32::from(Q)) + (modulus / 2)) / modulus) as i16;
                assert_eq!(
                    decompress(value, bits),
                    expected,
                    "value={value} bits={bits}"
                );
            }
        }
    }

    #[test]
    fn poly_encode_decode_round_trips_mod_q_coefficients() {
        let mut coeffs = [0i16; N];
        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = (i as i16 * 13) % Q as i16;
        }
        let poly = Poly::new(coeffs);
        let mut encoded = [0u8; 384];
        encode_poly_into(&poly, 12, &mut encoded);
        let decoded = decode_poly(&encoded, 12).unwrap();
        assert_eq!(decoded.coeffs(), poly.coeffs());
    }

    #[test]
    fn poly_vector_encode_decode_round_trips_12_bit_polys() {
        let vector: PolyVector<MlKem512> = Array::from_fn(|k| {
            let mut coeffs = [0i16; N];
            for (i, coeff) in coeffs.iter_mut().enumerate() {
                *coeff = ((i + k) as i16 * 17) % Q as i16;
            }
            Poly::new(coeffs)
        });

        let mut encoded: PolyVectorBytes<MlKem512> = Array::default();
        encode_poly_vector_into::<MlKem512>(&vector, 12, &mut encoded);
        assert_eq!(
            encoded.len(),
            <MlKem512 as MlKemParams>::PolyVectorBytes::USIZE
        );
        let decoded = decode_poly_vector::<MlKem512>(&encoded, 12).unwrap();
        for (lhs, rhs) in decoded.iter().zip(vector.iter()) {
            assert_eq!(lhs.coeffs(), rhs.coeffs());
        }
    }
}
