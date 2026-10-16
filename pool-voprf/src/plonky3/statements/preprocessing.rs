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
//! | row                  | (K)          | (M)           | (T)                                        |
//! |----------------------|--------------|---------------|--------------------------------------------|
//! | `0`                  | (K) for `sk` | (M) for `m^0` | (T) for evaluation 0, row `0`              |
//! | `1`                  | (K) for `sk` | (M) for `m^0` | (T) for evaluation 0, row `1`              |
//! | …                    | …            | …             | …                                          |
//! | `N_TABLE_ROWS-1`     | (K) for `sk` | (M) for `m^0` | (T) for evaluation 0, row `N_TABLE_ROWS-1` |
//! | `N_TABLE_ROWS`       | (K) for `sk` | (M) for `m^1` | (T) for evaluation 1, row `0`              |
//! | …                    | …            | …             | …                                          |
//! | `v·N_TABLE_ROWS + i` | (K) for `sk` | (M) for `m^v` | (T) for evaluation `v`, row `i`            |
//! | …                    | …            | …             | …                                          |
//!
//! (K) is the same on every row. (M) is the same on the rows of an
//! evaluation. (T) changes on every row.
//!
//! The public values are `pk` and each `m^v`.
//!
//! # The values they share
//!
//! (T) keeps its own copy of `sk_i` and of each `r̃^k_Σ`. Rules make the
//! copies equal:
//!
//! - `sk_i` of (T) is bit `i` of (K).
//! - `r̃^k_Σ` is bits in (T) and one column of (M), on every row.
//!
//! TODO: share one Poseidon2 block between (K), (M) and (S), with (K) and
//! (M) on rows after the last block of each evaluation.

use crate::plonky3::commitments::DIGEST_ELEMENTS;
use crate::plonky3::commitments::key::KeyCommitment;
use crate::plonky3::commitments::mask_sum::MaskSumCommitment;
use crate::plonky3::commitments::masks::MasksCommitment;
use crate::plonky3::constraints::{k_key, m_mask_sum, t_sum_of_masks};
use crate::plonky3::selectors::select;
use crate::plonky3::{
    KeyAir, MaskSumAir, N_TABLE_ROWS, Plonky3, Proof, ProveError, SumOfMasksAir, Val, VerifyError,
};
use crate::statements::preprocessing::{PreprocessingStatement, PreprocessingWitness};
use crate::traits::{ProofSystem, Statement};
use core::array;
use core::ops::Range;
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SubAirBuilder, prove, verify};
use pool_prf::params::N;
use std::borrow::Cow;

type Preprocessing = PreprocessingStatement<KeyCommitment, MasksCommitment, MaskSumCommitment>;

/// Where the columns of each constraint start.
const KEY: usize = 0;
const MASK_SUM: usize = KEY + k_key::NUM_COLS;
const SUM_OF_MASKS: usize = MASK_SUM + m_mask_sum::NUM_COLS;
const NUM_COLS: usize = SUM_OF_MASKS + t_sum_of_masks::NUM_COLS;

/// Where the public values start: `pk`, then each `m^v`.
const PK: usize = 0;
const FIRST_M: usize = PK + DIGEST_ELEMENTS;

/// Where the periodic columns start: `m^v` (one column per element), (T)'s,
/// then `sel_i`.
const M: usize = 0;
const T: usize = M + DIGEST_ELEMENTS;
const SEL: usize = T + t_sum_of_masks::NUM_PERIODIC_COLUMNS;
const NUM_PERIODIC_COLUMNS: usize = SEL + N;

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
        Self::table(&KeyAir::row(&witness.sk), witness)
    }

    fn table(k_row: &[Val], witness: &PreprocessingWitness) -> RowMajorMatrix<Val> {
        let evaluations = witness.evaluations.len();
        let m_rows: Vec<Vec<Val>> = witness
            .evaluations
            .iter()
            .map(|v| MaskSumAir::row(&v.r_sigma_sums, v.m_randomness))
            .collect();
        let t_tables: Vec<RowMajorMatrix<Val>> = witness
            .evaluations
            .iter()
            .map(|v| SumOfMasksAir::trace(&witness.sk, &v.masks))
            .collect();
        let mut values = Vec::with_capacity(rows(evaluations) * NUM_COLS);
        for row in 0..rows(evaluations) {
            let v = evaluation(row, evaluations);
            let i = row % N_TABLE_ROWS;
            values.extend_from_slice(k_row);
            values.extend_from_slice(&m_rows[v]);
            values.extend_from_slice(&t_tables[v].row_slice(i).expect("a row"));
        }
        RowMajorMatrix::new(values, NUM_COLS)
    }
}

impl BaseAir<Val> for PreprocessingAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// Only (T) reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (SUM_OF_MASKS..NUM_COLS).collect()
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
        let m = (0..DIGEST_ELEMENTS).map(column);
        let sel = (0..N).map(|i| {
            (0..N_TABLE_ROWS)
                .map(|row| Val::from_bool(row == i))
                .collect()
        });
        Cow::Owned(
            m.chain(t_sum_of_masks::periodic_columns())
                .chain(sel)
                .collect(),
        )
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
        let [first_block, has_next_block, last_block] = array::from_fn(|i| periodic[T + i].into());
        let sel: [AB::PeriodicVar; N] = periodic[SEL..NUM_PERIODIC_COLUMNS]
            .try_into()
            .expect("sel_i");

        KeyAir::rules(&mut columns(builder, KEY..MASK_SUM), pk);
        MaskSumAir::rules(&mut columns(builder, MASK_SUM..SUM_OF_MASKS), m);
        SumOfMasksAir::rules(
            &mut columns(builder, SUM_OF_MASKS..NUM_COLS),
            first_block,
            has_next_block,
            last_block,
        );

        // The values they share
        let main = builder.main();
        let row = main.current_slice();
        let key_bits = &row[KEY..KEY + N];
        let m_columns = &row[MASK_SUM..SUM_OF_MASKS];
        let t_columns = &row[SUM_OF_MASKS..NUM_COLS];

        // `sk_i` of (T) is bit `i` of (K): `Σ_i sel_i·(sk_i - bit_i) = 0`.
        let sk_i = t_columns[t_sum_of_masks::SK];
        let differences = array::from_fn(|i| sk_i - key_bits[i]);
        builder.assert_zero(select::<AB, N>(&sel, differences));

        // `r̃^k_Σ` is bits in (T) and one column of (M).
        let r_sigma_bits = &t_columns[t_sum_of_masks::R_SIGMA..t_sum_of_masks::QUOTIENT];
        let r_sigma_sums = &m_columns[m_mask_sum::R_SIGMA..m_mask_sum::RANDOMNESS];
        let runs = r_sigma_bits
            .chunks(t_sum_of_masks::R_SIGMA_BITS)
            .zip(r_sigma_sums);
        for (bits, &r_sigma_sum) in runs {
            let packed = pack_bits_le::<AB::Expr, _, _>(bits.iter().copied());
            builder.assert_eq(packed, r_sigma_sum);
        }
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

    use crate::plonky3::commitments::{key, mask_sum};
    use crate::testing::random_preprocessing;
    use p3_air::{ConstraintReport, check_all_constraints};
    use pool_prf::modular::reduce_q;
    use pool_prf::params::RUNS_PER_EVALUATION;
    use pool_prf::prf::SecretKey;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

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

    /// (K) for another key and its `pk`. (K), (M) and (T) each hold. Only the
    /// rule that `sk_i` of (T) is bit `i` of (K) fails.
    #[test]
    fn another_key_in_k_is_refused() {
        let (mut statement, witness) = random(3);
        let other = SecretKey::random(&mut StdRng::seed_from_u64(4));
        statement.pk = key::commit(&other);
        let trace = PreprocessingAir::table(&KeyAir::row(&other), &witness);
        assert!(!report(&trace, &statement).is_ok());
    }

    /// Evaluation `v`'s (M) with another `r̃_Σ` for run `k`, and its `m^v`.
    /// (K), (M) and (T) each hold. Only the rule that (T) and (M) have the
    /// same `r̃_Σ` fails.
    #[test]
    fn another_r_sigma_sum_in_m_is_refused() {
        let (statement, witness) = random(5);
        for v in 0..EVALUATIONS {
            for k in 0..RUNS_PER_EVALUATION {
                let (mut statement, mut witness) = (statement.clone(), witness.clone());
                let evaluation = &mut witness.evaluations[v];
                evaluation.r_sigma_sums[k] = reduce_q(evaluation.r_sigma_sums[k] + 1);
                statement.evaluations[v].m =
                    mask_sum::commit(&evaluation.r_sigma_sums, evaluation.m_randomness);
                let trace = PreprocessingAir::trace(&witness);
                assert!(
                    !report(&trace, &statement).is_ok(),
                    "evaluation {v}, run {k}"
                );
            }
        }
    }
}
