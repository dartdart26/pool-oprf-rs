//! The preprocessing statement on Plonky3. Its constraints are (K), (S), (T)
//! and (M).
//!
//! # Layout
//!
//! Each evaluation `v` gets `N_TABLE_ROWS` consecutive rows. Row
//! `v·N_TABLE_ROWS + i` is for binary OT block `i` in evaluation `v`,
//! `i = 0 .. n-1`. The rows after block `n-1`, up to `N_TABLE_ROWS`,
//! repeat the row of block `n-1`.
//!
//! | row                  | (K)          | (M)           |
//! |----------------------|--------------|---------------|
//! | `0`                  | (K) for `sk` | (M) for `m^0` |
//! | `1`                  | (K) for `sk` | (M) for `m^0` |
//! | …                    | …            | …             |
//! | `N_TABLE_ROWS-1`     | (K) for `sk` | (M) for `m^0` |
//! | `N_TABLE_ROWS`       | (K) for `sk` | (M) for `m^1` |
//! | …                    | …            | …             |
//! | `v·N_TABLE_ROWS + i` | (K) for `sk` | (M) for `m^v` |
//! | …                    | …            | …             |
//!
//! (K) is the same on every row. (M) is the same on the rows of an
//! evaluation.
//!
//! The public values are `pk` and each `m^v`. On the rows of evaluation `v`,
//! (M) takes `m^v` from periodic columns.
//!
//! TODO: share one Poseidon2 block between (K), (M) and (S), with (K) and
//! (M) on rows after the last block of each evaluation.

use crate::plonky3::commitments::DIGEST_ELEMENTS;
use crate::plonky3::commitments::key::KeyCommitment;
use crate::plonky3::commitments::mask_sum::MaskSumCommitment;
use crate::plonky3::commitments::masks::MasksCommitment;
use crate::plonky3::constraints::k_key;
use crate::plonky3::{
    KeyAir, MaskSumAir, N_TABLE_ROWS, Plonky3, Proof, ProveError, Val, VerifyError,
};
use crate::statements::preprocessing::{PreprocessingStatement, PreprocessingWitness};
use crate::traits::{ProofSystem, Statement};
use core::array;
use core::ops::Range;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SubAirBuilder, prove, verify};
use std::borrow::Cow;

type Preprocessing = PreprocessingStatement<KeyCommitment, MasksCommitment, MaskSumCommitment>;

/// Where the columns of each constraint start.
const KEY: usize = 0;
const MASK_SUM: usize = KEY + k_key::NUM_COLS;
const NUM_COLS: usize = MASK_SUM + crate::plonky3::constraints::m_mask_sum::NUM_COLS;

/// Where the public values start: `pk`, then each `m^v`.
const PK: usize = 0;
const FIRST_M: usize = PK + DIGEST_ELEMENTS;

/// The periodic columns: `m^v`, one column per element.
const M: usize = 0;
const NUM_PERIODIC_COLUMNS: usize = M + DIGEST_ELEMENTS;

/// The rows of a table for `evaluations` evaluations.
fn rows(evaluations: usize) -> usize {
    (evaluations * N_TABLE_ROWS).next_power_of_two()
}

/// The evaluation `row` is in, out of `evaluations`. The rows after the last
/// evaluation count as the last one.
fn evaluation(row: usize, evaluations: usize) -> usize {
    (row / N_TABLE_ROWS).min(evaluations - 1)
}

/// The circuit of the whole preprocessing statement.
struct PreprocessingAir {
    /// Plonky3 requires the periodic columns to be in the Fiat–Shamir
    /// transcript and only the public values go into it. The periodic
    /// columns are, therefore, built from the public values.
    public: Vec<Val>,
    evaluations: usize,
}

impl PreprocessingAir {
    fn new(statement: &Preprocessing) -> Self {
        Self {
            public: public_values(statement),
            evaluations: statement.evaluations.len(),
        }
    }

    /// `m^v`.
    fn m(&self, v: usize) -> &[Val] {
        &self.public[FIRST_M + v * DIGEST_ELEMENTS..][..DIGEST_ELEMENTS]
    }

    fn trace(witness: &PreprocessingWitness) -> RowMajorMatrix<Val> {
        let key = KeyAir::row(&witness.sk);
        let mask_sums: Vec<Vec<Val>> = witness
            .evaluations
            .iter()
            .map(|v| MaskSumAir::row(&v.r_sigma_sums, v.m_randomness))
            .collect();
        Self::table(&key, &mask_sums)
    }

    fn table(key: &[Val], mask_sums: &[Vec<Val>]) -> RowMajorMatrix<Val> {
        let evaluations = mask_sums.len();
        let mut values = Vec::with_capacity(rows(evaluations) * NUM_COLS);
        for row in 0..rows(evaluations) {
            values.extend_from_slice(key);
            values.extend_from_slice(&mask_sums[evaluation(row, evaluations)]);
        }
        RowMajorMatrix::new(values, NUM_COLS)
    }
}

impl BaseAir<Val> for PreprocessingAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn num_public_values(&self) -> usize {
        self.public.len()
    }

    fn num_periodic_columns(&self) -> usize {
        NUM_PERIODIC_COLUMNS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        let column = |element: usize| -> Vec<Val> {
            (0..rows(self.evaluations))
                .map(|row| self.m(evaluation(row, self.evaluations))[element])
                .collect()
        };
        Cow::Owned((0..DIGEST_ELEMENTS).map(column).collect())
    }
}

fn columns<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    columns: Range<usize>,
) -> SubAirBuilder<'_, AB, PreprocessingAir, AB::Var> {
    SubAirBuilder::new(builder, columns)
}

impl<AB: AirBuilder<F = Val>> Air<AB> for PreprocessingAir {
    fn eval(&self, builder: &mut AB) {
        let public = builder.public_values();
        let pk: [AB::Expr; DIGEST_ELEMENTS] = array::from_fn(|i| public[PK + i].into());
        // `m^v` of the row's evaluation `v`.
        let periodic = builder.periodic_values();
        let m: [AB::Expr; DIGEST_ELEMENTS] = array::from_fn(|i| periodic[M + i].into());

        KeyAir::rules(&mut columns(builder, KEY..MASK_SUM), pk);
        MaskSumAir::rules(&mut columns(builder, MASK_SUM..NUM_COLS), m);
    }
}

fn public_values(statement: &Preprocessing) -> Vec<Val> {
    let mut values = statement.pk.0.to_vec();
    for evaluation in &statement.evaluations {
        values.extend(evaluation.m.0);
    }
    values
}

impl ProofSystem<Preprocessing> for Plonky3 {
    type Proof = Proof;
    type ProveError = ProveError;
    type VerifyError = VerifyError;

    fn prove(
        &self,
        statement: &Preprocessing,
        witness: &PreprocessingWitness,
    ) -> Result<Proof, ProveError> {
        if !statement.holds_for(witness) {
            return Err(ProveError::WrongWitness);
        }
        let air = PreprocessingAir::new(statement);
        let trace = PreprocessingAir::trace(witness);
        prove(&self.config, &air, trace, &air.public).map_err(ProveError::Prover)
    }

    fn verify(&self, statement: &Preprocessing, proof: &Proof) -> Result<(), VerifyError> {
        if statement.evaluations.is_empty() {
            return Err(VerifyError::NoEvaluation);
        }
        let air = PreprocessingAir::new(statement);
        Plonky3::verified(|| verify(&self.config, &air, proof, &air.public))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing::random_preprocessing;
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;

    /// Not a power of two, such that the table has rows past the last
    /// evaluation.
    const EVALUATIONS: usize = 3;

    /// A random witness and the honest statement for it, from `seed`.
    fn random(seed: u64) -> (Preprocessing, PreprocessingWitness) {
        random_preprocessing(seed, EVALUATIONS)
    }

    /// Runs the rules over `trace` for `statement`.
    fn report(trace: &RowMajorMatrix<Val>, statement: &Preprocessing) -> ConstraintReport {
        let air = PreprocessingAir::new(statement);
        check_all_constraints(&air, trace, &air.public, None)
    }

    #[test]
    fn the_rules_hold() {
        let (statement, witness) = random(1);
        assert!(statement.holds_for(&witness));
        let trace = PreprocessingAir::trace(&witness);
        assert!(report(&trace, &statement).is_ok());
    }

    #[test]
    fn every_evaluation_is_checked() {
        let (statement, witness) = random(2);
        let trace = PreprocessingAir::trace(&witness);
        for v in 0..EVALUATIONS {
            let mut wrong = statement.clone();
            wrong.evaluations[v].m.0[0] += Val::ONE;
            assert!(!report(&trace, &wrong).is_ok(), "evaluation {v}");
        }
    }
}
