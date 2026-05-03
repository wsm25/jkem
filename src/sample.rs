//! SHAKE-based matrix and noise sampling for ML-KEM-512.

use crate::{
    crypto,
    error::{JkemError, Result},
    math::ring::{Poly, PolyMatrix},
    params::{N, Q},
};

pub(crate) fn sample_matrix(rho: &[u8; 32], transpose: bool) -> Result<PolyMatrix> {
    // Public algorithm branch: A vs A^T.
    Ok(core::array::from_fn(|i| {
        core::array::from_fn(|j| {
            if transpose {
                sample_uniform(rho, i as u8, j as u8)
            } else {
                sample_uniform(rho, j as u8, i as u8)
            }
        })
    }))
}

pub(crate) fn sample_noise(_seed: &[u8; 32], _nonce: u8, _eta: usize) -> Result<Poly> {
    // Public parameter branch.
    match _eta {
        2 => Ok(cbd::<2>(&noise_bytes::<128>(_seed, _nonce))),
        3 => Ok(cbd::<3>(&noise_bytes::<192>(_seed, _nonce))),
        _ => Err(JkemError::InvalidParameter {
            name: "eta",
            message: "expected 2 or 3",
        }),
    }
}

fn noise_bytes<const LEN: usize>(seed: &[u8; 32], nonce: u8) -> [u8; LEN] {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    input[32] = nonce;
    crypto::shake256(&input)
}

fn cbd<const ETA: usize>(bytes: &[u8]) -> Poly {
    debug_assert_eq!(bytes.len(), 64 * ETA);
    let mut coeffs = [0i16; N];

    for (i, coeff) in coeffs.iter_mut().enumerate() {
        let mut a = 0i16;
        let mut b = 0i16;
        for j in 0..ETA {
            a += bit(bytes, 2 * ETA * i + j) as i16;
            b += bit(bytes, 2 * ETA * i + ETA + j) as i16;
        }

        let value = a - b;
        // Secret sign: mask instead of branch.
        *coeff = value + ((value >> 15) & Q);
    }

    Poly::new(coeffs)
}

fn bit(bytes: &[u8], bit_index: usize) -> u8 {
    (bytes[bit_index / 8] >> (bit_index % 8)) & 1
}

fn sample_uniform(rho: &[u8; 32], x: u8, y: u8) -> Poly {
    // Public rejection sampler; rho is not secret.
    let mut input = [0u8; 34];
    input[..32].copy_from_slice(rho);
    input[32] = x;
    input[33] = y;

    let mut coeffs = [0i16; N];
    let mut filled = 0;
    let mut reader = crypto::shake128_reader(&input);
    while filled < N {
        let mut buf = [0u8; 504];
        use sha3::digest::XofReader;
        reader.read(&mut buf);

        // Reference rejection sampler: parse each 3-byte chunk into two
        // little-endian 12-bit candidates and keep candidates below q.
        // FIPS/ref code streams SHAKE128(rho || column || row), so additional
        // blocks are read from the same XOF reader rather than rehashing.
        for chunk in buf.chunks_exact(3) {
            let d1 = u16::from(chunk[0]) | ((u16::from(chunk[1]) & 0x0f) << 8);
            let d2 = (u16::from(chunk[1]) >> 4) | (u16::from(chunk[2]) << 4);
            if d1 < Q as u16 {
                coeffs[filled] = d1 as i16;
                filled += 1;
                if filled == N {
                    break;
                }
            }
            if d2 < Q as u16 {
                coeffs[filled] = d2 as i16;
                filled += 1;
                if filled == N {
                    break;
                }
            }
        }
    }

    Poly::new(coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_noise_is_deterministic_for_same_seed_nonce_eta() {
        let seed = [7u8; 32];
        let lhs = sample_noise(&seed, 3, 2).unwrap();
        let rhs = sample_noise(&seed, 3, 2).unwrap();
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn sample_noise_depends_on_nonce() {
        let seed = [7u8; 32];
        let lhs = sample_noise(&seed, 3, 2).unwrap();
        let rhs = sample_noise(&seed, 4, 2).unwrap();
        assert_ne!(lhs, rhs);
    }

    #[test]
    fn sample_noise_coefficients_are_small_mod_q() {
        let seed = [11u8; 32];
        let poly = sample_noise(&seed, 0, 3).unwrap();
        for &coeff in poly.coeffs() {
            assert!(matches!(coeff, 0..=3 | 3326..=3328));
        }
    }

    #[test]
    fn sample_noise_rejects_invalid_eta() {
        let seed = [0u8; 32];
        let err = sample_noise(&seed, 0, 4).unwrap_err();
        assert_eq!(
            err,
            JkemError::InvalidParameter {
                name: "eta",
                message: "expected 2 or 3"
            }
        );
    }

    #[test]
    fn sample_matrix_is_deterministic_and_uses_transpose_flag() {
        let rho = [9u8; 32];
        let matrix = sample_matrix(&rho, false).unwrap();
        let again = sample_matrix(&rho, false).unwrap();
        let transposed = sample_matrix(&rho, true).unwrap();

        for i in 0..crate::params::K {
            for j in 0..crate::params::K {
                assert_eq!(matrix[i][j], again[i][j]);
                assert_eq!(matrix[i][j], transposed[j][i]);
            }
        }
    }

    #[test]
    fn sample_matrix_coefficients_are_mod_q() {
        let rho = [3u8; 32];
        let matrix = sample_matrix(&rho, false).unwrap();
        for row in matrix {
            for poly in row {
                for &coeff in poly.coeffs() {
                    assert!((0..Q).contains(&coeff));
                }
            }
        }
    }
}
