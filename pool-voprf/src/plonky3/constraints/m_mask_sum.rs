//! Constraint (M) on Plonky3:
//!
//! ```text
//! m = Commit(Domain::MaskSum, r̃^0_Σ .. r̃^{RUNS_PER_EVALUATION-1}_Σ, randomness)
//! ```
//!
//! One row holds all of (M) and every row is the same. Domain, sums,
//! random and rest are Poseidon2's input.
//!
//! | row      | domain (1)        | sums (`RUNS_PER_EVALUATION`) | random (`RANDOMNESS_ELEMENTS`) | rest  | rounds     |
//! |----------|-------------------|------------------------------|--------------------------------|-------|------------|
//! | `0`      | `Domain::MaskSum` | `r̃_Σ` of each run            | `randomness`                   | zeros | end in `m` |
//! | `1`      | `Domain::MaskSum` | `r̃_Σ` of each run            | `randomness`                   | zeros | end in `m` |
//! | …        | …                 | …                            | …                              | …     | …          |
//! | `ROWS-1` | `Domain::MaskSum` | `r̃_Σ` of each run            | `randomness`                   | zeros | end in `m` |
//!
//! Plonky3 checks Poseidon2's rounds itself. We add these rules for (M):
//!
//! - the input starts with `Domain::MaskSum` and ends in zeros
//! - the rounds end in `m`
//!
//! No rule checks the random value. It is there to hide the `r̃_Σ`, so a
//! bad one only harms the server.
//!
//! No rule checks that an `r̃_Σ` is in `ℤ_q` either. (T) has to check it,
//! in the preprocessing proof. Online, (M) opens the same `m`, so each
//! `r̃_Σ` is the value (T) checked.

use crate::commitments::CommitmentRandomness;
use crate::plonky3::commitments::DIGEST_ELEMENTS;
use crate::plonky3::commitments::mask_sum::{MaskSumCommitment, VALUE_ELEMENTS, elements};
use crate::plonky3::sponge::{PERMUTATION, PERMUTATION_COLS, eval_commitment, sponge_trace};
use crate::plonky3::{ROWS, Val};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::params::{RUNS_PER_EVALUATION, Zq};

/// Where each part of the row starts. Poseidon2's input is the domain, the
/// sums, the random value, then zeros.
const SPONGE: usize = 0;
pub(crate) const R_SIGMA: usize = SPONGE + 1;
pub(crate) const RANDOMNESS: usize = R_SIGMA + RUNS_PER_EVALUATION;
pub(crate) const NUM_COLS: usize = SPONGE + PERMUTATION_COLS;

/// The rules for (M).
pub struct MaskSumAir;

impl MaskSumAir {
    /// The row for the `r̃_Σ` of each run and their random value.
    pub fn row(
        r_sigma_sum: &[Zq; RUNS_PER_EVALUATION],
        randomness: CommitmentRandomness,
    ) -> Vec<Val> {
        sponge_trace(MaskSumCommitment::input(elements(r_sigma_sum, randomness)))
    }

    /// The table - `ROWS` copies of the row.
    pub fn trace(
        r_sigma_sum: &[Zq; RUNS_PER_EVALUATION],
        randomness: CommitmentRandomness,
    ) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(Self::row(r_sigma_sum, randomness).repeat(ROWS), NUM_COLS)
    }

    /// The rules for (M) on the row, for `m`.
    pub fn rules<AB: AirBuilder<F = Val>>(builder: &mut AB, m: [AB::Expr; DIGEST_ELEMENTS]) {
        let domain = MaskSumCommitment::domain();
        eval_commitment(builder, SPONGE, domain, VALUE_ELEMENTS, m);
    }
}

impl BaseAir<Val> for MaskSumAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// A row holds all of (M), so no rule reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        PERMUTATION.max_constraint_degree()
    }

    fn num_public_values(&self) -> usize {
        DIGEST_ELEMENTS
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for MaskSumAir {
    fn eval(&self, builder: &mut AB) {
        let m: [AB::PublicVar; DIGEST_ELEMENTS] = builder.public_values().try_into().expect("m");
        Self::rules(builder, m.map(Into::into));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::commitments::mask_sum::commit;
    use crate::plonky3::sponge::{output, permutation};
    use core::array;
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Matrix;
    use pool_prf::params::Q;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// Random `r̃_Σ` and a random value, from `seed`.
    fn random(seed: u64) -> ([Zq; RUNS_PER_EVALUATION], CommitmentRandomness) {
        let mut rng = StdRng::seed_from_u64(seed);
        (array::from_fn(|_| rng.random_range(0..Q)), rng.random())
    }

    #[test]
    fn the_trace_ends_in_the_commitment() {
        let (r_sigma_sum, randomness) = random(1);
        let trace = MaskSumAir::trace(&r_sigma_sum, randomness);
        let row = trace.row_slice(0).expect("a row");
        assert_eq!(
            output(permutation(&row[SPONGE..]))[..DIGEST_ELEMENTS],
            commit(&r_sigma_sum, randomness).0
        );
    }

    #[test]
    fn the_rules_hold() {
        let (r_sigma_sum, randomness) = random(2);
        let trace = MaskSumAir::trace(&r_sigma_sum, randomness);
        let m = commit(&r_sigma_sum, randomness);
        assert!(check_all_constraints(&MaskSumAir, &trace, &m.0, None).is_ok());
    }

    #[test]
    fn another_random_value_is_refused() {
        let (r_sigma_sum, randomness) = random(3);
        let trace = MaskSumAir::trace(&r_sigma_sum, randomness);
        let m = commit(&r_sigma_sum, randomness ^ 1);
        assert!(!check_all_constraints(&MaskSumAir, &trace, &m.0, None).is_ok());
    }

    /// Another `r̃_Σ` in any run does not hash to `m`.
    #[test]
    fn every_run_is_checked() {
        let (r_sigma_sum, randomness) = random(4);
        let m = commit(&r_sigma_sum, randomness);
        for k in 0..RUNS_PER_EVALUATION {
            let mut trace = MaskSumAir::trace(&r_sigma_sum, randomness);
            for row in trace.values.chunks_mut(NUM_COLS) {
                row[R_SIGMA + k] += Val::ONE;
            }
            assert!(
                !check_all_constraints(&MaskSumAir, &trace, &m.0, None).is_ok(),
                "run {k} is not checked"
            );
        }
    }
}
