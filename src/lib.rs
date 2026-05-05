//! Teaching-oriented ML-KEM-512 implementation.
//!
//! This crate mirrors the standard construction: polynomial-ring arithmetic,
//! SHA3/SHAKE sampling, K-PKE core arithmetic, then the ML-KEM control plane.
//!
//! Security scope: this implementation is for learning and testing, not
//! production deployment. It avoids the main secret-dependent branches in
//! decapsulation and secret polynomial handling, but has not been
//! production-audited for constant-time behavior.
//!
//! Constant-time dependencies: `subtle` is used for ciphertext equality and
//! shared-secret selection; `sha3` provides SHA3/SHAKE; `zeroize` wipes selected
//! internal byte temporaries; and Rust core/std code generation is relied on for
//! fixed-size copies, integer arithmetic, and iterator lowering. These still need
//! target-specific assembly review and dudect/ctgrind-style timing tests.
//!
//! Key hygiene: returned decapsulation keys, ciphertexts, shared secrets, and any
//! caller-owned copies are plain byte arrays/newtypes. Callers are responsible for
//! wiping them when no longer needed.
//!
//! The main public entry point is [`MlKem512`]. Import [`MlKemInterface`] to use
//! its key generation, encapsulation, and decapsulation methods.
//!
//! ```
//! use jkem::{MlKem512, MlKemInterface};
//!
//! let (encapsulation_key, decapsulation_key) = MlKem512::keygen()?;
//! let (cipher_text, sender_shared_secret) = MlKem512::encaps(&encapsulation_key)?;
//! let receiver_shared_secret = MlKem512::decaps(&decapsulation_key, &cipher_text)?;
//!
//! assert_eq!(receiver_shared_secret, sender_shared_secret);
//!
//! # Ok::<(), jkem::JkemError>(())
//! ```

mod error;
mod math;
mod mlkem;
mod security;

pub use error::{JkemError, Result};
pub use mlkem::params;
pub use mlkem::{MlKem512, internal::MlKemInterface};
