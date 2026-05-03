//! Number theoretic transform helpers for ML-KEM polynomial multiplication.
//!
//! ```
//! use jkem::math::{Poly, mul_naive};
//! use jkem::math::ntt::multiply;
//! use jkem::params::N;
//!
//! let mut a = [0i16; N];
//! let mut b = [0i16; N];
//! a[0] = 7;
//! b[0] = 11;
//!
//! let a = Poly::new(a);
//! let b = Poly::new(b);
//! assert_eq!(multiply(&a, &b)?, mul_naive(&a, &b));
//!
//! # Ok::<(), jkem::JkemError>(())
//! ```

use crate::{
    error::Result,
    math::ring::Poly,
    params::{N, Q},
};

const QINV: i16 = -3327;

// Kyber/ML-KEM reference NTT twiddle factors in Montgomery representation.
// The ordering matches the reference implementation's in-place Cooley-Tukey
// forward NTT and Gentleman-Sande inverse NTT; changing this ordering changes
// serialized public keys and ciphertexts, so it is intentionally kept as data.
const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

pub fn ntt(_poly: &mut Poly) -> Result<()> {
    let r = _poly.coeffs_mut();
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            // Reference forward NTT butterfly. Coefficients are left in the
            // NTT/Montgomery domain expected by ML-KEM base multiplication.
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    for coeff in r {
        *coeff = reduce_to_field(*coeff);
    }
    Ok(())
}

pub fn inverse_ntt(_poly: &mut Poly) -> Result<()> {
    let r = _poly.coeffs_mut();
    let mut k = 127usize;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            // Reference inverse butterfly. The final multiplication by 1441
            // below folds in Montgomery conversion and the 1/256 scale factor.
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] -= t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    for coeff in r {
        *coeff = fqmul(*coeff, 1441);
        *coeff = reduce_to_field(*coeff);
    }
    Ok(())
}

pub fn multiply(lhs: &Poly, rhs: &Poly) -> Result<Poly> {
    let mut lhs_hat = lhs.clone();
    let mut rhs_hat = rhs.clone();
    ntt(&mut lhs_hat)?;
    ntt(&mut rhs_hat)?;
    let mut product = basemul(&lhs_hat, &rhs_hat);
    inverse_ntt(&mut product)?;
    Ok(Poly::new(*product.coeffs()))
}

pub fn to_ntt(poly: &Poly) -> Result<Poly> {
    let mut out = poly.clone();
    ntt(&mut out)?;
    Ok(out)
}

pub fn from_ntt(poly: &Poly) -> Result<Poly> {
    let mut out = poly.clone();
    inverse_ntt(&mut out)?;
    Ok(Poly::new(*out.coeffs()))
}

pub fn basemul(lhs: &Poly, rhs: &Poly) -> Poly {
    let mut out = [0i16; N];
    let a = lhs.coeffs();
    let b = rhs.coeffs();
    for i in 0..N / 4 {
        // ML-KEM multiplies degree-1 factors modulo x^2 - zeta in the NTT
        // domain; adjacent pairs use zeta and -zeta from the second half of
        // the reference zeta table.
        basemul_pair(
            &mut out[4 * i..4 * i + 2],
            &a[4 * i..4 * i + 2],
            &b[4 * i..4 * i + 2],
            ZETAS[64 + i],
        );
        basemul_pair(
            &mut out[4 * i + 2..4 * i + 4],
            &a[4 * i + 2..4 * i + 4],
            &b[4 * i + 2..4 * i + 4],
            -ZETAS[64 + i],
        );
    }
    Poly::new(out)
}

pub fn to_mont(poly: &Poly) -> Poly {
    let mut out = [0i16; N];
    for (dst, &coeff) in out.iter_mut().zip(poly.coeffs()) {
        *dst = reduce_to_field(fqmul(coeff, 1353));
    }
    Poly::new(out)
}

fn basemul_pair(out: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    out[0] = fqmul(a[1], b[1]);
    out[0] = fqmul(out[0], zeta);
    out[0] += fqmul(a[0], b[0]);
    out[1] = fqmul(a[0], b[1]) + fqmul(a[1], b[0]);
}

fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(i32::from(a) * i32::from(b))
}

fn montgomery_reduce(a: i32) -> i16 {
    let t = i32::from((a as i16).wrapping_mul(QINV));
    ((a - t * i32::from(Q)) >> 16) as i16
}

fn barrett_reduce(a: i16) -> i16 {
    let v = ((1i32 << 26) + i32::from(Q) / 2) / i32::from(Q);
    let t = (v * i32::from(a) + (1 << 25)) >> 26;
    (i32::from(a) - t * i32::from(Q)) as i16
}

fn reduce_to_field(a: i16) -> i16 {
    let mut r = a % Q;
    if r < 0 {
        r += Q;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{math::mul_naive, params::N};

    #[test]
    fn multiply_matches_naive_oracle() {
        let mut lhs = [0i16; N];
        let mut rhs = [0i16; N];
        for i in 0..N {
            lhs[i] = (i as i16 * 7) % 3329;
            rhs[i] = (i as i16 * 11 + 3) % 3329;
        }

        let lhs = Poly::new(lhs);
        let rhs = Poly::new(rhs);

        assert_eq!(multiply(&lhs, &rhs).unwrap(), mul_naive(&lhs, &rhs));
    }
}
