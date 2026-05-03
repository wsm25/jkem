//! ML-KEM-512 parameter constants.
//!
//! ```
//! use jkem::params::{
//!     CIPHERTEXT_BYTES, DECAPSULATION_KEY_BYTES, ENCAPSULATION_KEY_BYTES,
//!     POLY_BYTES, POLY_VECTOR_BYTES,
//! };
//!
//! assert_eq!(POLY_BYTES, 384);
//! assert_eq!(POLY_VECTOR_BYTES, 768);
//! assert_eq!(ENCAPSULATION_KEY_BYTES, 800);
//! assert_eq!(DECAPSULATION_KEY_BYTES, 1_632);
//! assert_eq!(CIPHERTEXT_BYTES, 768);
//! ```

pub const N: usize = 256;
pub const Q: i16 = 3329;
pub const K: usize = 2;

pub const ETA1: usize = 3;
pub const ETA2: usize = 2;
pub const DU: usize = 10;
pub const DV: usize = 4;

pub const SEED_BYTES: usize = 32;
pub const SHARED_SECRET_BYTES: usize = 32;

pub const POLY_BYTES: usize = 384;
pub const POLY_VECTOR_BYTES: usize = K * POLY_BYTES;

pub const ENCAPSULATION_KEY_BYTES: usize = 800;
pub const DECAPSULATION_KEY_BYTES: usize = 1_632;
pub const CIPHERTEXT_BYTES: usize = 768;
