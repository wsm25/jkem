//! Teaching-oriented ML-KEM-512 implementation.
//!
//! This crate is structured to mirror the standard construction:
//! polynomial-ring arithmetic, SHA3/SHAKE based sampling, IND-CPA PKE,
//! then the FO-style KEM wrapper.
//!
//! The implementation avoids the main secret-dependent branches in
//! decapsulation and secret polynomial handling, but it is still
//! teaching-oriented and has not been production-audited for constant-time
//! behavior.
//!
//! ```
//! use jkem::MlKem512;
//!
//! let (ek, dk) = MlKem512::keygen()?;
//! let (ct, ss) = MlKem512::encaps(&ek)?;
//! assert_eq!(MlKem512::decaps(&dk, &ct)?, ss);
//!
//! # Ok::<(), jkem::JkemError>(())
//! ```

mod crypto;
pub mod error;
pub mod fo;
mod math;
pub mod params;
pub mod pke;
mod sample;
mod serialize;

pub use error::{JkemError, Result};
pub use fo::MlKem512;
