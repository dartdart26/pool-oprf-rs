//! The online statement on Plonky3.
//!
//! # Layout
//!
//! One proof covers one evaluation i.e. `RUNS_PER_EVALUATION` runs. Each run
//! gets `Δ` consecutive rows, one per entry `j` of its response `y_j`:
//! run 0 is rows `0 .. Δ-1`, run 1 is rows `Δ .. 2Δ-1`, and so
//! on. Entry `j` of run `k` is on row `Δ·k + j`, and the table has
//! `RUNS_PER_EVALUATION·Δ = ROWS` rows.
//!
//! Each row holds the columns of all constraints side by side.
//!
//! | row       | (K)          | (M)           | (A)                      | (R)                          | (P)                            |
//! |-----------|--------------|---------------|--------------------------|------------------------------|--------------------------------|
//! | `0`       | (K) for `sk` | (M) for `r̃_Σ` | (A) for run 0's `ã_Σ`    | (R) for run 0's `y_0`        | (P) for run 0's `pad_0`        |
//! | `1`       | (K) for `sk` | (M) for `r̃_Σ` | (A) for run 0's `ã_Σ`    | (R) for run 0's `y_1`        | (P) for run 0's `pad_1`        |
//! | …         | …            | …             | …                        | …                            | …                              |
//! | `Δ-1`     | (K) for `sk` | (M) for `r̃_Σ` | (A) for run 0's `ã_Σ`    | (R) for run 0's `y_{Δ-1}`    | (P) for run 0's `pad_{Δ-1}`    |
//! | `Δ`       | (K) for `sk` | (M) for `r̃_Σ` | (A) for run 1's `ã_Σ`    | (R) for run 1's `y_0`        | (P) for run 1's `pad_0`        |
//! | …         | …            | …             | …                        | …                            | …                              |
//! | `Δ·k + j` | (K) for `sk` | (M) for `r̃_Σ` | (A) for run k's `ã_Σ`    | (R) for run k's `y_j`        | (P) for run k's `pad_j`        |
//! | …         | …            | …             | …                        | …                            | …                              |
//! | `ROWS-1`  | (K) for `sk` | (M) for `r̃_Σ` | (A) for last run's `ã_Σ` | (R) for last run's `y_{Δ-1}` | (P) for last run's `pad_{Δ-1}` |
//!
//! (K) and (M) are the same on every row, because `sk` is the same in every run
//! and (M) holds the `r̃_Σ` of all runs at once.
//!
//! (A) is the same on the `Δ` rows of a run, because `ã_Σ` does not depend on `j`.
//!
//! (R) and (P) change on every row.
//!
//! The public values are `pk` and `m`, `e`, `y` and `d`.
//!
//! # 1. The constraints
//!
//! Each constraint checks its own block of columns on every row. Some of
//! its rules compare the block with a public value, and which public value
//! that is depends on the row:
//!
//! - (K) and (M) use `pk` and `m`, the same on every row.
//! - (A) uses the request `e`: on the rows of run `k`, run `k`'s `e`.
//! - (R) uses the response: on row `Δ·k + j`, run `k`'s `y_j`.
//! - (P) uses the pad commitments: on row `Δ·k + j` (run `k`),
//!   `d_{(j - b̄′) mod Δ}` as (R) uses pad `r′_{(j - b̄′) mod Δ}` there. The
//!   circuit gives (P) the pads and `d` in that order, see
//!   [`in_response_order`].
//!
//! The selectors pick these out, see [`selectors`]: `u_k` is 1 on the rows
//! of run `k`, and `s_j` is 1 on the rows of entry `j`.
//!
//! # 2. The values they share
//!
//! Some constraints share a value. Each keeps it in its own columns, so a
//! rule makes the copies equal.

use crate::plonky3::commitments::DIGEST_ELEMENTS;
use crate::plonky3::commitments::key::KeyCommitment;
use crate::plonky3::commitments::mask_sum::MaskSumCommitment;
use crate::plonky3::commitments::pad::PadCommitment;
use crate::plonky3::constraints::common::KEY_BITS;
use crate::plonky3::constraints::{a_sum, k_key, m_mask_sum, p_pads, r_response};
use crate::plonky3::selectors::{index, select, selectors};
use crate::plonky3::{
    KeyAir, MaskSumAir, PadsAir, Plonky3, Proof, ProveError, ROWS, ResponseAir, SumAir, Val,
    VerifyError,
};
use crate::statements::online::{OnlineStatement, OnlineWitness, RunStatement, RunWitness};
use crate::traits::{ProofSystem, Statement};
use core::array;
use core::ops::Range;
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SubAirBuilder, prove, verify};
use pool_prf::modular::sub_delta;
use pool_prf::params::{DELTA, N, RUNS_PER_EVALUATION, Zdelta};
use pool_prf::prf::SecretKey;
use std::borrow::Cow;

type Online = OnlineStatement<KeyCommitment, MaskSumCommitment, PadCommitment>;

const _: () = assert!(
    ROWS == RUNS_PER_EVALUATION * DELTA,
    "one row per run and entry"
);

/// Where the columns of each constraint start.
const KEY: usize = 0;
const MASK_SUM: usize = KEY + k_key::NUM_COLS;
const SUM: usize = MASK_SUM + m_mask_sum::NUM_COLS;
const RESPONSE: usize = SUM + a_sum::NUM_COLS;
const PADS: usize = RESPONSE + r_response::NUM_COLS;
const NUM_COLS: usize = PADS + p_pads::NUM_COLS;

/// Where the public values start: `pk`, `m`, then the runs.
const PK: usize = 0;
const M: usize = PK + DIGEST_ELEMENTS;
const FIRST_RUN: usize = M + DIGEST_ELEMENTS;
/// Where the public values of each constraint start, within a run's.
const E: usize = 0;
const Y: usize = E + N;
const D: usize = Y + DELTA;
const RUN_PUBLIC_VALUES: usize = D + p_pads::NUM_PUBLIC_VALUES;
const NUM_PUBLIC_VALUES: usize = FIRST_RUN + RUNS_PER_EVALUATION * RUN_PUBLIC_VALUES;

/// Where the periodic columns start: `s`, then `u`.
const S: usize = 0;
const U: usize = S + DELTA;
const NUM_PERIODIC_COLUMNS: usize = U + RUNS_PER_EVALUATION;

/// `values` in the order (R) uses the pads: entry `j` is value
/// `(j - b̄′) mod Δ`.
fn in_response_order<T: Copy>(values: &[T; DELTA], b_bar_prime: Zdelta) -> [T; DELTA] {
    array::from_fn(|j| values[usize::from(sub_delta(j as Zdelta, b_bar_prime))])
}

/// The rows of one run: one of (A), the `Δ` entries of (R) and of (P).
struct RunRows {
    sum: Vec<Val>,
    response: Vec<Val>,
    pads: Vec<Val>,
}

impl RunRows {
    fn honest(sk: &SecretKey, run: &RunStatement<PadCommitment>, witness: &RunWitness) -> Self {
        let a_sigma_sum = pool_eval::a_sigma_sum(sk, witness.r_sigma_sum, &run.e);
        Self {
            sum: SumAir::row(sk, witness.r_sigma_sum, &run.e),
            response: ResponseAir::entries(a_sigma_sum, &witness.pads, run.b_bar_prime),
            pads: PadsAir::entries(
                &in_response_order(&witness.pads, run.b_bar_prime),
                &in_response_order(&witness.d_randomness, run.b_bar_prime),
            ),
        }
    }
}

struct OnlineAir;

impl OnlineAir {
    fn trace(statement: &Online, witness: &OnlineWitness) -> RowMajorMatrix<Val> {
        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sums(), witness.m_randomness);
        let runs =
            array::from_fn(|k| RunRows::honest(&witness.sk, &statement.runs[k], &witness.runs[k]));
        Self::table(&key, &mask_sum, &runs)
    }

    /// Row `Δ·k + j` is the rows of (K) and (M), then run `k`'s row of (A),
    /// then its entry `j` of (R) and of (P).
    fn table(
        key: &[Val],
        mask_sum: &[Val],
        runs: &[RunRows; RUNS_PER_EVALUATION],
    ) -> RowMajorMatrix<Val> {
        let mut values = Vec::with_capacity(ROWS * NUM_COLS);
        for run in runs {
            let responses = run.response.chunks(r_response::NUM_COLS);
            let pads = run.pads.chunks(p_pads::NUM_COLS);
            for (response, pad) in responses.zip(pads) {
                values.extend_from_slice(key);
                values.extend_from_slice(mask_sum);
                values.extend_from_slice(&run.sum);
                values.extend_from_slice(response);
                values.extend_from_slice(pad);
            }
        }
        RowMajorMatrix::new(values, NUM_COLS)
    }
}

impl BaseAir<Val> for OnlineAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// No constraint reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn num_periodic_columns(&self) -> usize {
        NUM_PERIODIC_COLUMNS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        let s = selectors::<DELTA>(1);
        let u = selectors::<RUNS_PER_EVALUATION>(DELTA);
        Cow::Owned(s.into_iter().chain(u).collect())
    }
}

/// The builder of `columns` only.
fn columns<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    columns: Range<usize>,
) -> SubAirBuilder<'_, AB, OnlineAir, AB::Var> {
    SubAirBuilder::new(builder, columns)
}

/// `value` of the row's run: `Σ_k u_k·value(run k)`.
fn of_run<AB: AirBuilder>(
    u: &[AB::PeriodicVar; RUNS_PER_EVALUATION],
    public_values: &[AB::PublicVar],
    value: impl Fn(&[AB::PublicVar]) -> AB::Expr,
) -> AB::Expr {
    let run = |k: usize| &public_values[FIRST_RUN + k * RUN_PUBLIC_VALUES..][..RUN_PUBLIC_VALUES];
    select::<AB, RUNS_PER_EVALUATION>(u, array::from_fn(|k| value(run(k))))
}

impl<AB: AirBuilder<F = Val>> Air<AB> for OnlineAir {
    fn eval(&self, builder: &mut AB) {
        // The row's entry and run.
        let periodic = builder.periodic_values();
        let s: [AB::PeriodicVar; DELTA] = periodic[S..U].try_into().expect("s_j");
        let u: [AB::PeriodicVar; RUNS_PER_EVALUATION] =
            periodic[U..NUM_PERIODIC_COLUMNS].try_into().expect("u_k");

        // The public values of the row's run.
        let public = builder.public_values();
        let pk: [AB::Expr; DIGEST_ELEMENTS] = array::from_fn(|i| public[PK + i].into());
        let m: [AB::Expr; DIGEST_ELEMENTS] = array::from_fn(|i| public[M + i].into());
        let e: [AB::Expr; N] =
            array::from_fn(|i| of_run::<AB>(&u, public, |run| run[E + i].into()));
        // The row's entry `j`, and its `y_j` out of the run's Δ.
        let j = index::<AB, DELTA>(&s);
        let y_j = of_run::<AB>(&u, public, |run| {
            select::<AB, DELTA>(&s, array::from_fn(|j| run[Y + j].into()))
        });
        // The `d` of the row's entry, out of the run's Δ.
        let d: [AB::Expr; DIGEST_ELEMENTS] = array::from_fn(|i| {
            of_run::<AB>(&u, public, |run| {
                let d_j = array::from_fn(|j| run[D + j * DIGEST_ELEMENTS + i].into());
                select::<AB, DELTA>(&s, d_j)
            })
        });

        // 1. The constraints
        KeyAir::rules(&mut columns(builder, KEY..MASK_SUM), pk);
        MaskSumAir::rules(&mut columns(builder, MASK_SUM..SUM), m);
        SumAir::rules(&mut columns(builder, SUM..RESPONSE), e);
        ResponseAir::rules(&mut columns(builder, RESPONSE..PADS), j, y_j);
        PadsAir::rules(&mut columns(builder, PADS..NUM_COLS), d);

        // 2. The values they share
        let main = builder.main();
        let row = main.current_slice();
        let key_columns = &row[KEY..MASK_SUM];
        let mask_sum_columns = &row[MASK_SUM..SUM];
        let sum_columns = &row[SUM..RESPONSE];
        let response_columns = &row[RESPONSE..PADS];
        let pads_columns = &row[PADS..NUM_COLS];

        // The key bits are the first columns of (K) and of (A).
        let key_sk = &key_columns[..KEY_BITS];
        let sum_sk = &sum_columns[..KEY_BITS];
        for (&key_bit, &sum_bit) in key_sk.iter().zip(sum_sk) {
            builder.assert_eq(sum_bit, key_bit);
        }

        // `r̃_Σ` of the row's run is one column in (A) and one of (M)'s
        // `RUNS_PER_EVALUATION` columns, which `u` picks.
        let r_sigma_sums = &mask_sum_columns[m_mask_sum::R_SIGMA..m_mask_sum::RANDOMNESS];
        let r_sigma_sums = array::from_fn(|k| r_sigma_sums[k].into());
        let r_sigma_sum = select::<AB, RUNS_PER_EVALUATION>(&u, r_sigma_sums);
        builder.assert_eq(sum_columns[a_sum::R_SIGMA], r_sigma_sum);

        // `ã_Σ` is bits in (A) and one column of (R).
        let a_sigma_bits = &sum_columns[a_sum::A_SIGMA..a_sum::QUOTIENT];
        let a_sigma_sum = pack_bits_le::<AB::Expr, _, _>(a_sigma_bits.iter().copied());
        builder.assert_eq(response_columns[r_response::A_SIGMA], a_sigma_sum);

        // The pad of the row's entry is one column of (R) and one of (P).
        builder.assert_eq(response_columns[r_response::PAD], pads_columns[p_pads::PAD]);
    }
}

fn public_values(statement: &Online) -> Vec<Val> {
    let mut values = statement.pk.0.to_vec();
    values.extend(statement.m.0);
    for run in &statement.runs {
        let d = in_response_order(&run.d, run.b_bar_prime);
        values.extend(a_sum::public_values(&run.e));
        values.extend(r_response::public_values(&run.y));
        values.extend(p_pads::public_values(&d));
    }
    values
}

impl ProofSystem<Online> for Plonky3 {
    type Proof = Proof;
    type ProveError = ProveError;
    type VerifyError = VerifyError;

    fn prove(&self, statement: &Online, witness: &OnlineWitness) -> Result<Proof, ProveError> {
        if !statement.holds_for(witness) {
            return Err(ProveError::WrongWitness);
        }
        let trace = OnlineAir::trace(statement, witness);
        prove(&self.config, &OnlineAir, trace, &public_values(statement))
            .map_err(ProveError::Prover)
    }

    fn verify(&self, statement: &Online, proof: &Proof) -> Result<(), VerifyError> {
        Plonky3::verified(|| verify(&self.config, &OnlineAir, proof, &public_values(statement)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::random_online;
    use p3_air::{ConstraintReport, DebugConstraintBuilder, check_all_constraints};
    use pool_prf::modular::reduce_q;
    use pool_prf::params::ZqAccum;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// The run the tests change: the last, so that a circuit that checks
    /// the first run only is caught.
    const LAST: usize = RUNS_PER_EVALUATION - 1;

    /// A random witness and the honest statement for it, from `seed`.
    fn random(seed: u64) -> (Online, OnlineWitness) {
        random_online(seed)
    }

    /// Runs the rules over `trace` for `statement`.
    fn report(trace: &RowMajorMatrix<Val>, statement: &Online) -> ConstraintReport {
        check_all_constraints(&OnlineAir, trace, &public_values(statement), None)
    }

    /// The honest rows of every run.
    fn honest_rows(statement: &Online, witness: &OnlineWitness) -> [RunRows; RUNS_PER_EVALUATION] {
        array::from_fn(|k| RunRows::honest(&witness.sk, &statement.runs[k], &witness.runs[k]))
    }

    /// Whether `rows`, repeated to `ROWS` rows, pass the rules of `air` for
    /// `public_values`.
    fn holds_alone<A>(air: &A, rows: &[Val], public_values: &[Val]) -> bool
    where
        A: BaseAir<Val> + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
    {
        let width = air.width();
        let table = RowMajorMatrix::new(rows.repeat(ROWS * width / rows.len()), width);
        check_all_constraints(air, &table, public_values, None).is_ok()
    }

    /// Whether each constraint holds on run `k`'s rows alone.
    fn each_holds_alone(
        key: &[Val],
        mask_sum: &[Val],
        rows: &RunRows,
        statement: &Online,
        k: usize,
    ) -> bool {
        let run = &statement.runs[k];
        let e = a_sum::public_values(&run.e);
        let y = r_response::public_values(&run.y);
        let d = p_pads::public_values(&in_response_order(&run.d, run.b_bar_prime));
        holds_alone(&KeyAir, key, &statement.pk.0)
            && holds_alone(&MaskSumAir, mask_sum, &statement.m.0)
            && holds_alone(&SumAir, &rows.sum, &e)
            && holds_alone(&ResponseAir, &rows.response, &y)
            && holds_alone(&PadsAir, &rows.pads, &d)
    }

    #[test]
    fn the_rules_hold() {
        let (statement, witness) = random(1);
        let trace = OnlineAir::trace(&statement, &witness);
        assert!(report(&trace, &statement).is_ok());
    }

    /// The public values of each run are checked on its rows: another `e`,
    /// `y` or `d` in any run refuses the honest table.
    #[test]
    fn every_run_is_checked() {
        let (statement, witness) = random(7);
        let (other, _) = random(8);
        let trace = OnlineAir::trace(&statement, &witness);
        // `e_i` enters the sum where `sk_i = 1` only.
        let i = witness
            .sk
            .as_bits()
            .iter()
            .position(|&bit| bit == 1)
            .expect("a set bit");
        for k in 0..RUNS_PER_EVALUATION {
            let mut e = statement.clone();
            e.runs[k].e[i] ^= 1;
            let mut y = statement.clone();
            y.runs[k].y[0] ^= 1;
            let mut d = statement.clone();
            d.runs[k].d[0] = other.runs[k].d[0];
            for wrong in [e, y, d] {
                assert!(!report(&trace, &wrong).is_ok(), "run {k}");
            }
        }
    }

    /// Each constraint holds on its own columns, so only the rule that ties the key bits refuses it.
    #[test]
    fn a_sum_with_another_key_is_refused() {
        let (mut statement, witness) = random(2);
        let other = SecretKey::random(&mut StdRng::seed_from_u64(3));
        let run_witness = &witness.runs[LAST];
        let run = &mut statement.runs[LAST];
        let a_sigma_sum = pool_eval::a_sigma_sum(&other, run_witness.r_sigma_sum, &run.e);
        run.y = pool_eval::respond(a_sigma_sum, &run_witness.pads, run.b_bar_prime);
        let sum = SumAir::row(&other, run_witness.r_sigma_sum, &run.e);
        let response = ResponseAir::entries(a_sigma_sum, &run_witness.pads, run.b_bar_prime);

        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sums(), witness.m_randomness);
        let mut runs = honest_rows(&statement, &witness);
        runs[LAST].sum = sum;
        runs[LAST].response = response;

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key,
            &mask_sum,
            &runs[LAST],
            &statement,
            LAST
        ));

        // Together they do not.
        let trace = OnlineAir::table(&key, &mask_sum, &runs);
        assert!(!report(&trace, &statement).is_ok());
    }

    /// Each constraint holds on its own columns, so only the rule that ties `r̃_Σ` refuses it.
    #[test]
    fn a_sum_with_another_r_sigma_sum_is_refused() {
        let (mut statement, witness) = random(4);
        let run_witness = &witness.runs[LAST];
        let run = &mut statement.runs[LAST];
        let other = reduce_q(ZqAccum::from(run_witness.r_sigma_sum) + 1);
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, other, &run.e);
        run.y = pool_eval::respond(a_sigma_sum, &run_witness.pads, run.b_bar_prime);
        let sum = SumAir::row(&witness.sk, other, &run.e);
        let response = ResponseAir::entries(a_sigma_sum, &run_witness.pads, run.b_bar_prime);

        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sums(), witness.m_randomness);
        let mut runs = honest_rows(&statement, &witness);
        runs[LAST].sum = sum;
        runs[LAST].response = response;

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key,
            &mask_sum,
            &runs[LAST],
            &statement,
            LAST
        ));

        // Together they do not.
        let trace = OnlineAir::table(&key, &mask_sum, &runs);
        assert!(!report(&trace, &statement).is_ok());
    }

    /// Each constraint holds on its own columns, so only the rule that ties `ã_Σ` refuses it.
    #[test]
    fn a_response_from_another_a_sigma_sum_is_refused() {
        let (mut statement, witness) = random(5);
        let run_witness = &witness.runs[LAST];
        let run = &mut statement.runs[LAST];
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, run_witness.r_sigma_sum, &run.e);
        let other = reduce_q(ZqAccum::from(a_sigma_sum) + 1);
        run.y = pool_eval::respond(other, &run_witness.pads, run.b_bar_prime);
        let response = ResponseAir::entries(other, &run_witness.pads, run.b_bar_prime);

        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sums(), witness.m_randomness);
        let mut runs = honest_rows(&statement, &witness);
        runs[LAST].response = response;

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key,
            &mask_sum,
            &runs[LAST],
            &statement,
            LAST
        ));

        // Together they do not.
        let trace = OnlineAir::table(&key, &mask_sum, &runs);
        assert!(!report(&trace, &statement).is_ok());
    }

    /// Each constraint holds on its own columns, so only the rule that ties the pads refuses it.
    #[test]
    fn a_response_with_other_pads_is_refused() {
        let (mut statement, witness) = random(6);
        let run_witness = &witness.runs[LAST];
        let run = &mut statement.runs[LAST];
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, run_witness.r_sigma_sum, &run.e);
        let mut other = run_witness.pads;
        other[0] ^= 1;
        run.y = pool_eval::respond(a_sigma_sum, &other, run.b_bar_prime);
        let response = ResponseAir::entries(a_sigma_sum, &other, run.b_bar_prime);

        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sums(), witness.m_randomness);
        let mut runs = honest_rows(&statement, &witness);
        runs[LAST].response = response;

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key,
            &mask_sum,
            &runs[LAST],
            &statement,
            LAST
        ));

        // Together they do not.
        let trace = OnlineAir::table(&key, &mask_sum, &runs);
        assert!(!report(&trace, &statement).is_ok());
    }
}
