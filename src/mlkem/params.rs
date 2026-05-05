//! ML-KEM-512 parameter constants.

/// Number of coefficients in each polynomial.
pub const N: usize = 256;
/// Prime modulus for polynomial coefficients.
pub const Q: i16 = 3329;
/// Module rank for the ML-KEM-512 parameter set.
pub const K: usize = 2;

/// Noise parameter for secret and error sampling during key generation.
pub const ETA1: usize = 3;
/// Noise parameter for error sampling during encryption.
pub const ETA2: usize = 2;
/// Compression bit width for the ciphertext vector component.
pub const DU: usize = 10;
/// Compression bit width for the ciphertext scalar component.
pub const DV: usize = 4;

/// Length in bytes of ML-KEM seeds.
pub const SEED_BYTES: usize = 32;
/// Length in bytes of an ML-KEM shared secret.
pub const SHARED_SECRET_BYTES: usize = 32;

/// Length in bytes of an encoded polynomial.
pub const POLY_BYTES: usize = 384;
/// Length in bytes of an encoded polynomial vector.
pub const POLY_VECTOR_BYTES: usize = K * POLY_BYTES;

/// Length in bytes of an ML-KEM-512 encapsulation key.
pub const ENCAPSULATION_KEY_BYTES: usize = 800;
/// Length in bytes of an ML-KEM-512 decapsulation key.
pub const DECAPSULATION_KEY_BYTES: usize = 1_632;
/// Length in bytes of an ML-KEM-512 ciphertext.
pub const CIPHERTEXT_BYTES: usize = 768;
