pub mod control;
pub mod internal;
pub mod kpke;
pub mod params;
mod serialize;

/// Marker type for the ML-KEM-512 algorithm.
///
/// Import [`MlKemInterface`](crate::MlKemInterface) to call the public
/// key-generation, encapsulation, and decapsulation methods. See the [`crate`]
/// documentation for a complete usage example.
pub struct MlKem512;
