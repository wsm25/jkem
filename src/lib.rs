//! Teaching-oriented ML-KEM-512 implementation.
//!
//! This crate is structured to mirror the standard construction:
//! polynomial-ring arithmetic, SHA3/SHAKE based sampling, IND-CPA PKE,
//! then the FO-style KEM wrapper.
//!
//! ```
//! use jkem::MlKem512;
//!
//! let d = [0u8; 32];
//! let z = [1u8; 32];
//! let message = [2u8; 32];
//!
//! let (ek, dk) = MlKem512::keygen_with_seed(&d, &z)?;
//! let (ct, ss) = MlKem512::encaps_with_message(&ek, &message)?;
//! assert_eq!(MlKem512::decaps(&dk, &ct)?, ss);
//!
//! # Ok::<(), jkem::JkemError>(())
//! ```

pub mod error;
pub mod fo;
pub mod math;
pub mod params;
pub mod pke;
pub mod sample;
pub mod serialize;

pub use error::{JkemError, Result};
pub use fo::MlKem512;
