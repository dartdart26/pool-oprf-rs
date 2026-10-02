//! Constraint (M) on Plonky3: the `r̃_Σ` of every run open `m`.
//!
//! # Layout
//!
//! One row holds all of (M). Its columns, in order:
//!
//! | columns               | content                             |
//! |-----------------------|-------------------------------------|
//! | `RUNS`                | `r̃_Σ` of each run, one column each  |
//! | `RANDOMNESS_ELEMENTS` | the random value                    |
//! | the rest              | Poseidon2's columns                 |
//!
//! # 1. The hash
//!
//! In order, Poseidon2 takes `WIDTH` slots:
//!
//! | slots                 | content                                 |
//! |-----------------------|-----------------------------------------|
//! | 1                     | the domain                              |
//! | `RUNS`                | `r̃_Σ` of each run, one column per slot  |
//! | `RANDOMNESS_ELEMENTS` | the random value, one column per slot   |
//! | the rest              | zero                                    |
//!
//! No rule checks the random value. It is there to hide the `r̃_Σ`, so a
//! bad one only harms the server. No rule checks that an `r̃_Σ` is in `ℤ_q`
//! either: (T) computes it mod `q`, and (A) takes it as given.
//!
//! [`MaskSumAir::rules`] takes `m` from its caller. Alone, that is the
//! public values. In the online statement, it is the `m` of the evaluation.

use crate::plonky3::commitments::mask_sum::{INPUT_ELEMENTS, MaskSumCommitment, elements, values};
use crate::plonky3::commitments::{DIGEST_ELEMENTS, RANDOMNESS_ELEMENTS, pack_randomness};
use crate::plonky3::sponge::{
    PERMUTATION, PERMUTATION_COLS, eval_sponge, permutations, sponge_trace,
};
use crate::plonky3::{ROWS, Val};
use crate::{CommitmentRandomness, RUNS};
use core::array;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::integers::QuotientMap;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::params::Zq;

const PERMUTATIONS: usize = permutations(INPUT_ELEMENTS);

/// Where each part of the row starts.
pub(crate) const R_SIGMA: usize = 0;
pub(crate) const RANDOMNESS: usize = R_SIGMA + RUNS;
const SPONGE: usize = RANDOMNESS + RANDOMNESS_ELEMENTS;
pub(crate) const NUM_COLS: usize = SPONGE + PERMUTATIONS * PERMUTATION_COLS;

/// The rules for (M).
pub struct MaskSumAir;

impl MaskSumAir {
    /// The row for the `r̃_Σ` of each run and their random value.
    pub fn row(r_sigma_sum: &[Zq; RUNS], randomness: CommitmentRandomness) -> Vec<Val> {
        let sums = r_sigma_sum.iter().map(|&r| Val::from_int(r));
        let hash = sponge_trace(MaskSumCommitment::input(elements(r_sigma_sum, randomness)));
        sums.chain(pack_randomness(randomness))
            .chain(hash)
            .collect()
    }

    /// The table - `ROWS` copies of the row.
    pub fn trace(
        r_sigma_sum: &[Zq; RUNS],
        randomness: CommitmentRandomness,
    ) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(Self::row(r_sigma_sum, randomness).repeat(ROWS), NUM_COLS)
    }

    /// The rules for (M) on the row, for `m`.
    pub fn rules<AB: AirBuilder<F = Val>>(builder: &mut AB, m: [AB::Expr; DIGEST_ELEMENTS]) {
        let main = builder.main();
        let row = main.current_slice();
        let r_sigma_sum = array::from_fn(|k| row[R_SIGMA + k].into());
        let randomness = array::from_fn(|k| row[RANDOMNESS + k].into());
        let input = MaskSumCommitment::input(values(r_sigma_sum, randomness));
        eval_sponge(builder, SPONGE, input, m);
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
    use crate::plonky3::sponge::{last_run, output};
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Matrix;
    use pool_prf::params::Q;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// Random `r̃_Σ` and a random value, from `seed`.
    fn random(seed: u64) -> ([Zq; RUNS], CommitmentRandomness) {
        let mut rng = StdRng::seed_from_u64(seed);
        (array::from_fn(|_| rng.random_range(0..Q)), rng.random())
    }

    #[test]
    fn the_trace_ends_in_the_commitment() {
        let (r_sigma_sum, randomness) = random(1);
        let trace = MaskSumAir::trace(&r_sigma_sum, randomness);
        let row = trace.row_slice(0).expect("a row");
        assert_eq!(
            output(last_run(&row[SPONGE..]))[..DIGEST_ELEMENTS],
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
        for k in 0..RUNS {
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
