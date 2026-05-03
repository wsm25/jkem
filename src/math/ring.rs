//! Arithmetic in `R_q = Z_q[X] / (X^256 + 1)`.

use crate::params::{K, N, Q};

#[derive(Clone)]
pub(crate) struct Poly {
    coeffs: [i16; N],
}

impl Poly {
    pub(crate) const ZERO: Self = Self { coeffs: [0; N] };

    pub(crate) fn new(coeffs: [i16; N]) -> Self {
        let mut reduced = [0; N];
        for (dst, src) in reduced.iter_mut().zip(coeffs) {
            *dst = reduce(src);
        }
        Self { coeffs: reduced }
    }

    pub(crate) fn coeffs(&self) -> &[i16; N] {
        &self.coeffs
    }

    pub(crate) fn coeffs_mut(&mut self) -> &mut [i16; N] {
        &mut self.coeffs
    }
}

pub(crate) type PolyVector = [Poly; K];
pub(crate) type PolyMatrix = [[Poly; K]; K];

pub(crate) fn reduce(x: i16) -> i16 {
    let q = i32::from(Q);
    let mut r = i32::from(x);

    // Fixed-iteration canonicalization for secret coefficients.
    for _ in 0..10 {
        r += (r >> 31) & q;
    }
    for _ in 0..10 {
        let candidate = r - q;
        let ge_q = !(candidate >> 31);
        r = (candidate & ge_q) | (r & !ge_q);
    }

    r as i16
}

pub(crate) fn add(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0; N];
    for ((dst, lhs), rhs) in out.iter_mut().zip(a.coeffs()).zip(b.coeffs()) {
        *dst = reduce(lhs + rhs);
    }
    Poly::new(out)
}

pub(crate) fn sub(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0; N];
    for ((dst, lhs), rhs) in out.iter_mut().zip(a.coeffs()).zip(b.coeffs()) {
        *dst = reduce(lhs - rhs);
    }
    Poly::new(out)
}

#[cfg(test)]
pub(crate) fn mul_naive(a: &Poly, b: &Poly) -> Poly {
    fn reduce_i32(x: i32) -> i16 {
        let q = i32::from(Q);
        let r = x % q;
        let r = r + ((r >> 31) & q);
        r as i16
    }

    let mut acc = [0i32; N];
    for (i, &lhs) in a.coeffs().iter().enumerate() {
        for (j, &rhs) in b.coeffs().iter().enumerate() {
            let product = i32::from(lhs) * i32::from(rhs);
            let degree = i + j;
            if degree < N {
                acc[degree] += product;
            } else {
                acc[degree - N] -= product;
            }
        }
    }

    let mut out = [0i16; N];
    for (dst, src) in out.iter_mut().zip(acc) {
        *dst = reduce_i32(src);
    }
    Poly::new(out)
}

pub(crate) fn add_vector(a: &PolyVector, b: &PolyVector) -> PolyVector {
    core::array::from_fn(|i| add(&a[i], &b[i]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_maps_coefficients_into_field_range() {
        assert_eq!(reduce(-1), Q - 1);
        assert_eq!(reduce(Q), 0);
        assert_eq!(reduce(Q + 7), 7);
        assert_eq!(reduce(i16::MIN), 522);
        assert_eq!(reduce(i16::MAX), 2806);
    }

    #[test]
    fn mul_naive_reduces_mod_x_256_plus_one() {
        let mut lhs = [0; N];
        let mut rhs = [0; N];
        lhs[N - 1] = 1;
        rhs[1] = 1;

        let product = mul_naive(&Poly::new(lhs), &Poly::new(rhs));

        assert_eq!(product.coeffs()[0], Q - 1);
        assert!(product.coeffs()[1..].iter().all(|&coeff| coeff == 0));
    }
}
