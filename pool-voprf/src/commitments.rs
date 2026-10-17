//! What each commitment commits to.

use pool_prf::params::{RUNS_PER_EVALUATION, Zp, Zq};

/// What a commitment hashes in with its value to hide it.
pub type CommitmentRandomness = u128;

/// The input of `c^v_{0, i}` and `c^v_{1, i}`, see constraint (S).
pub struct MasksInput {
    pub masks: [Zq; RUNS_PER_EVALUATION],
    pub randomness: CommitmentRandomness,
}

/// The input of `m^v`, see constraint (M).
pub struct MaskSumsInput {
    /// `r̃^{v, k}_Σ` of each run `k`.
    pub r_sigma_sums: [Zq; RUNS_PER_EVALUATION],
    pub randomness: CommitmentRandomness,
}

/// The input of `d^{v, k}_j`, see constraint (P).
pub struct PadInput {
    /// `r′^{v, k}_j`.
    pub pad: Zp,
    pub randomness: CommitmentRandomness,
}
