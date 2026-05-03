//! Polynomial arithmetic used by ML-KEM-512.
//!
//! ```
//! use jkem::math::{Poly, mul_naive};
//! use jkem::params::{N, Q};
//!
//! let mut lhs = [0i16; N];
//! let mut rhs = [0i16; N];
//! lhs[N - 1] = 1;
//! rhs[1] = 1;
//!
//! let product = mul_naive(&Poly::new(lhs), &Poly::new(rhs));
//! assert_eq!(product.coeffs()[0], Q - 1);
//! ```

pub mod ntt;
pub mod ring;

pub use ring::{Poly, PolyMatrix, PolyVector, mul_naive};
