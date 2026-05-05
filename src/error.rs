//! Crate-wide error and result types.
//!
//! ```
//! use jkem::{JkemError, Result};
//!
//! fn reject_short_input(input: &[u8]) -> Result<()> {
//!     if input.len() != 32 {
//!         return Err(JkemError::InvalidLength {
//!             name: "seed",
//!             expected: 32,
//!             actual: input.len(),
//!         });
//!     }
//!     Ok(())
//! }
//!
//! assert!(reject_short_input(&[0u8; 31]).is_err());
//! ```

use thiserror::Error;

/// Crate-local result type returned by fallible JKEM operations.
///
/// The error type is [`JkemError`].
pub type Result<T> = core::result::Result<T, JkemError>;

/// JKEM Errors.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum JkemError {
    #[error("invalid {name} length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("invalid {name}: {message}")]
    InvalidParameter {
        name: &'static str,
        message: &'static str,
    },

    #[error("random source failed")]
    Random(#[from] getrandom::Error),
}
