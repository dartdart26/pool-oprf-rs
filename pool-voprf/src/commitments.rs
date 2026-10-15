//! What each commitment commits to.

use pool_prf::params::{RUNS_PER_EVALUATION, Zp, Zq};

/// What a commitment hashes in with its value to hide it.
pub type CommitmentRandomness = u128;

/// The input of `c_{0, i}` and `c_{1, i}`, see constraint (S).
pub struct MasksInput {
    pub masks: [Zq; RUNS_PER_EVALUATION],
    pub randomness: CommitmentRandomness,
}

/// The input of `m`, see constraint (M).
pub struct MaskSumsInput {
    /// `r̃_Σ` of each run of an evaluation.
    pub r_sigma_sums: [Zq; RUNS_PER_EVALUATION],
    pub randomness: CommitmentRandomness,
}

/// The input of `d_j`, see constraint (P).
pub struct PadInput {
    /// `r′_j`.
    pub pad: Zp,
    pub randomness: CommitmentRandomness,
}
