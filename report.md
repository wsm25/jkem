# Technical Report: ML-KEM-512 Implementation

## Overview

This project implements a teaching-oriented ML-KEM-512 key encapsulation mechanism in Rust. ML-KEM is the standardized form of Kyber selected for post-quantum key establishment. The implementation follows the usual layered construction: polynomial-ring arithmetic, NTT-based module-lattice operations, SHA3/SHAKE-based sampling, an IND-CPA public-key encryption primitive, and a Fujisaki-Okamoto (FO) transform that turns the encryption primitive into a CCA-secure KEM.

The implementation target is correctness, readability, and a clear mapping from the standard construction to code. It is not presented as a production-audited constant-time cryptographic library.

## Implemented Algorithm and Hard Problem

The underlying hardness assumption is the Module Learning With Errors problem over the polynomial ring used by ML-KEM:

```text
R_q = Z_q[X] / (X^256 + 1), q = 3329
```

For ML-KEM-512, vectors have module rank `k = 2`. Public keys encode a matrix-vector product over this ring with small secret and error polynomials. Recovering the secret vector from the public value is intended to be hard because it corresponds to solving a noisy linear system over the module lattice.

The implementation includes the following components:

- Polynomial arithmetic in `src/math/ring.rs`
- Number theoretic transform operations in `src/math/ntt.rs`
- ML-KEM parameters in `src/mlkem/params.rs`
- Byte encoding, compression, decompression, and key/ciphertext layouts in `src/mlkem/serialize.rs`
- SHA3/SHAKE wrappers and sampling in `src/security/crypto.rs` and `src/security/sample.rs`
- IND-CPA ML-KEM-512 encryption in `src/mlkem/pke512.rs`
- Generic `Pke` and `Fo` traits in `src/traits/`

The public KEM workflow is:

1. `keygen()` samples fresh randomness and produces an encapsulation key and decapsulation key.
2. `encaps(ek)` samples a random message, derives encryption coins and a shared secret, and encrypts the message.
3. `decaps(dk, ct)` decrypts, re-encrypts to validate the ciphertext, and selects either the success shared secret or the fallback shared secret.

## Design Thoughts

The implementation is split by responsibility rather than by call order. The `math` module contains only arithmetic, `security` contains hashing, sampling, and byte-wiping helpers, `traits` contains reusable PKE/FO abstractions, and `mlkem` contains concrete ML-KEM-512 logic. This keeps the implementation close to the standard while avoiding a single large file that mixes algebra, encoding, randomness, and KEM orchestration.

The deterministic hooks, such as `keygen_with_seed` and `encaps_with_message`, are marked `unsafe` because they bypass the normal randomized API. They are useful for known-answer tests and reproducible protocol integration, but misuse could repeat seeds or messages. The safe public methods call the operating-system random source through `getrandom`.

The decapsulation path uses `subtle` for ciphertext equality and shared-secret selection. This avoids branching directly on the re-encryption result. Temporary byte arrays that hold seeds, coins, and derived material are wrapped with `WipeBytes` where practical, using `zeroize` on drop. However, returned keys, ciphertexts, and shared secrets are plain byte arrays, so caller-owned copies remain the caller's responsibility.

The implementation also validates two important input conditions: encapsulation rejects non-canonical public-key coefficients, and decapsulation rejects a decapsulation key whose stored `H(ek)` does not match the embedded public key. These checks make malformed inputs fail explicitly instead of silently entering the arithmetic path.

## Experimental Results and Observations

Correctness was evaluated using the bundled ML-KEM-512 known-answer test file. The test suite verifies that the KAT file is unchanged by checking its SHA-256 digest:

```text
ff4efa2b73bafc459d6fb0557d90b05c4bc50cf5d02e30b383edf2e88fa969d8
```

The test file contains 100 cases. For each case, the implementation checks:

- deterministic key generation against the expected public and secret keys
- deterministic encapsulation against the expected ciphertext and shared secret
- decapsulation against the expected shared secret

Additional tests check FO round trips, fallback shared-secret behavior for modified ciphertexts, rejection of non-canonical public keys, and rejection of decapsulation keys with an invalid embedded public-key hash.

The latest local run of `cargo test` passed:

```text
17 unit tests passed
8 ML-KEM-512 KAT/integration tests passed
3 doctests passed
```

Performance was not benchmarked with a dedicated criterion-style benchmark suite, so the current observations are qualitative. The implementation uses NTT multiplication for the core polynomial products, fixed-size arrays for keys and ciphertexts, and avoids heap allocation on the main fixed-size key and ciphertext interfaces. Some helper routines still allocate temporary vectors, especially in encoding/decoding and fallback derivation, so further optimization would focus on replacing those with fixed-size buffers and adding a benchmark harness for `keygen`, `encaps`, and `decaps`.

## Limitations and Future Work

The implementation has not undergone assembly-level constant-time review, dudect testing, ctgrind-style analysis, or formal verification. The current code avoids the most obvious secret-dependent branch in FO decapsulation, but Rust compiler lowering, target-specific code generation, and library dependencies still need independent review before any production use.

Future work should add:

- microbenchmarks for `keygen`, `encaps`, and `decaps`
- constant-time leakage tests
- broader malformed-input tests
- no-heap variants for remaining temporary buffers
- documentation mapping each function more directly to FIPS 203 pseudocode
