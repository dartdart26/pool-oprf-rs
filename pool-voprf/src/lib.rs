//! Verifiable Pool OPRF: server proofs as described in `docs/voprf.md`.

pub mod constraints;
pub mod statements;
pub mod traits;

#[cfg(feature = "plonky3")]
pub mod plonky3;

/// What a commitment hashes in with its value to hide it.
pub type CommitmentRandomness = u128;
