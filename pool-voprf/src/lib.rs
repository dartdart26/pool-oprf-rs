//! Verifiable Pool OPRF: server proofs as described in `docs/voprf.md`.

pub mod constraints;
pub mod statements;
pub mod traits;

#[cfg(feature = "plonky3")]
pub mod plonky3;

/// What a commitment hashes in with its value to hide it.
pub type CommitmentRandomness = u128;

/// How many runs one evaluation is: one per output element. The online
/// statement covers an evaluation, and `m` commits to the `r̃_Σ` of all
/// its runs.
pub const RUNS: usize = pool_prf::params::OUTPUT_ELEMENTS;
