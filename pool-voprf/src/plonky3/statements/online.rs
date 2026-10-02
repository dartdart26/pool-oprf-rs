//! The online statement on Plonky3. Its constraints are (K), (A), (R), (M)
//! and (P).
//!
//! # Layout
//!
//! One proof covers one evaluation: `RUNS_PER_EVALUATION` runs, one per
//! output element. The key and `m` are the same in every run, everything
//! else is per run. Row `Δ·k + j` belongs to run `k` and entry `j`, so the
//! table has `RUNS_PER_EVALUATION·Δ = ROWS` rows. The columns of each
//! constraint are side by side:
//!
//! | row      |     | (K)     | (M)     | (A)       | (R)       | (P)                   |     | `s_0` | … | `s_{Δ-1}` | `u_0` | … | `u_{RUNS_PER_EVALUATION-1}` |
//! |----------|-----|---------|---------|-----------|-----------|-----------------------|-----|-------|---|-----------|-------|---|-----------------------------|
//! | `0`      | c   | its row | its row | run 0's   | run 0's   | run 0, entry `0`      | p   | 1     | … | 0         | 1     | … | 0                           |
//! | `1`      | o   | same    | same    | same      | same      | run 0, entry `1`      | e   | 0     | … | 0         | 1     | … | 0                           |
//! | `2`      | m   | same    | same    | same      | same      | run 0, entry `2`      | r   | 0     | … | 0         | 1     | … | 0                           |
//! | …        | m   | …       | …       | …         | …         | …                     | i   | …     | … | …         | …     | … | …                           |
//! | `Δ-1`    | i → | same    | same    | same      | same      | run 0, entry `Δ-1`    | o → | 0     | … | 1         | 1     | … | 0                           |
//! | `Δ`      | t   | same    | same    | run 1's   | run 1's   | run 1, entry `0`      | d   | 1     | … | 0         | 0     | … | 0                           |
//! | `Δ+1`    | t   | same    | same    | same      | same      | run 1, entry `1`      | i   | 0     | … | 0         | 0     | … | 0                           |
//! | …        | e   | …       | …       | …         | …         | …                     | c   | …     | … | …         | …     | … | …                           |
//! | `2Δ-1`   | d   | same    | same    | same      | same      | run 1, entry `Δ-1`    |     | 0     | … | 1         | 0     | … | 0                           |
//! | …        |     | …       | …       | …         | …         | …                     |     | …     | … | …         | …     | … | …                           |
//! | `ROWS-1` |     | same    | same    | last's    | last's    | last run, entry `Δ-1` |     | 0     | … | 1         | 0     | … | 1                           |
//!
//! (K) and (M) hold everything in one row and repeat it. (A) and (R) hold
//! everything of a run in one row and repeat it on the `Δ` rows of the
//! run. (P) holds one entry per row: entry `j` of run `k` on row
//! `Δ·k + j`.
//!
//! `s_j` is 1 on the rows of entry `j` and `u_k` on the rows of run `k`, 0
//! on the others. They are not columns of the table: they are periodic,
//! both sides compute them, see [`selectors`].
//!
//! The public values are `pk` and `m`, then `e`, `y` and `d` of each run.
//!
//! # 1. The constraints
//!
//! Each constraint checks its own columns with its own rules, on every
//! row. (K) and (M) check against `pk` and `m`. (A), (R) and (P) check
//! against the public values of the row's run, which `u` picks out:
//!
//! ```text
//! value = u_0·value_0 + u_1·value_1 + …
//!         + u_{RUNS_PER_EVALUATION-1}·value_{RUNS_PER_EVALUATION-1}
//! ```
//!
//! On the rows of run `k`, `u_k` is 1 and the others are 0, so the right
//! side is `value_k`. For (P), `s` then picks the `d` of the row's entry
//! out of the run's `Δ`.
//!
//! Nothing ties the rows of a run to one another. Each row opens `pk`,
//! `m` and its `d` on its own, so every row holds what they commit to.
//!
//! # 2. The values they share
//!
//! Some constraints share a value. Each keeps it in its own columns, so a
//! rule makes the copies equal.

use crate::plonky3::commitments::DIGEST_ELEMENTS;
use crate::plonky3::commitments::key::KeyCommitment;
use crate::plonky3::commitments::mask_sum::MaskSumCommitment;
use crate::plonky3::commitments::pad::PadCommitment;
use crate::plonky3::constraints::{a_sum, k_key, m_mask_sum, p_pads, r_response};
use crate::plonky3::selectors::{select, selectors};
use crate::plonky3::{
    KeyAir, MaskSumAir, PadsAir, Plonky3, Proof, ProveError, ROWS, ResponseAir, SumAir, Val,
    VerifyError,
};
use crate::statements::online::{OnlineStatement, OnlineWitness, Run, RunWitness};
use crate::traits::{ProofSystem, Statement};
use core::array;
use core::ops::Range;
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SubAirBuilder, prove, verify};
use pool_prf::params::{DELTA, N, RUNS_PER_EVALUATION};
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

/// The rows of one run: one of (A) and (R) each, the `Δ` entries of (P).
struct RunRows {
    sum: Vec<Val>,
    response: Vec<Val>,
    pads: Vec<Val>,
}

impl RunRows {
    fn honest(sk: &SecretKey, run: &Run<PadCommitment>, witness: &RunWitness) -> Self {
        let a_sigma_sum = pool_eval::a_sigma_sum(sk, witness.r_sigma_sum, &run.e);
        Self {
            sum: SumAir::row(sk, witness.r_sigma_sum, &run.e),
            response: ResponseAir::row(a_sigma_sum, &witness.pads, run.b_bar_prime),
            pads: PadsAir::entries(&witness.pads, &witness.d_randomness, run.b_bar_prime),
        }
    }
}

struct OnlineAir;

impl OnlineAir {
    fn trace(statement: &Online, witness: &OnlineWitness) -> RowMajorMatrix<Val> {
        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sum(), witness.m_randomness);
        let runs =
            array::from_fn(|k| RunRows::honest(&witness.sk, &statement.runs[k], &witness.runs[k]));
        Self::table(&key, &mask_sum, &runs)
    }

    /// Row `Δ·k + j` is the rows of (K) and (M), then run `k`'s rows of (A)
    /// and (R), then its entry `j` of (P).
    fn table(
        key: &[Val],
        mask_sum: &[Val],
        runs: &[RunRows; RUNS_PER_EVALUATION],
    ) -> RowMajorMatrix<Val> {
        let mut values = Vec::with_capacity(ROWS * NUM_COLS);
        for run in runs {
            for entry in run.pads.chunks(p_pads::NUM_COLS) {
                values.extend_from_slice(key);
                values.extend_from_slice(mask_sum);
                values.extend_from_slice(&run.sum);
                values.extend_from_slice(&run.response);
                values.extend_from_slice(entry);
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
        let y: [AB::Expr; DELTA] =
            array::from_fn(|j| of_run::<AB>(&u, public, |run| run[Y + j].into()));
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
        ResponseAir::rules(&mut columns(builder, RESPONSE..PADS), y);
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
        let key_sk = &key_columns[..N];
        let sum_sk = &sum_columns[a_sum::SK..a_sum::R_SIGMA];
        for (&key_bit, &sum_bit) in key_sk.iter().zip(sum_sk) {
            builder.assert_eq(sum_bit, key_bit);
        }

        // `r̃_Σ` of the row's run is one column in (A) and one of (M)'s
        // `RUNS_PER_EVALUATION` columns, which `u` picks.
        let r_sigma_sums = &mask_sum_columns[m_mask_sum::R_SIGMA..m_mask_sum::RANDOMNESS];
        let r_sigma_sums = array::from_fn(|k| r_sigma_sums[k].into());
        let r_sigma_sum = select::<AB, RUNS_PER_EVALUATION>(&u, r_sigma_sums);
        builder.assert_eq(sum_columns[a_sum::R_SIGMA], r_sigma_sum);

        // `ã_Σ` is bits in (A) and the first column of (R).
        let a_sigma_bits = &sum_columns[a_sum::A_SIGMA..a_sum::QUOTIENT];
        let a_sigma_sum = pack_bits_le::<AB::Expr, _, _>(a_sigma_bits.iter().copied());
        builder.assert_eq(response_columns[0], a_sigma_sum);

        // (P) has one pad column: on the rows of entry `j` it holds `pad_j`.
        // (R) has Δ pad columns, `pad_0 .. pad_{Δ-1}`, the same on every row.
        // `s` picks `pad_j` out of (R)'s Δ, and it must equal (P)'s.
        let pad_of_p = pads_columns[p_pads::PAD];
        let pads_of_r = array::from_fn(|j| response_columns[r_response::pad_column(j)].into());
        let pad_of_r = select::<AB, DELTA>(&s, pads_of_r);
        builder.assert_eq(pad_of_p, pad_of_r);
    }
}

fn public_values(statement: &Online) -> Vec<Val> {
    let mut values = statement.pk.0.to_vec();
    values.extend(statement.m.0);
    for run in &statement.runs {
        values.extend(a_sum::public_values(&run.e));
        values.extend(r_response::public_values(&run.y));
        values.extend(p_pads::public_values(&run.d, run.b_bar_prime));
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
    use p3_air::{ConstraintReport, DebugConstraintBuilder, check_all_constraints};
    use pool_prf::modular::reduce_q;
    use pool_prf::params::{Q, Zdelta, ZqAccum};
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// The run the tests change: the last, so that a circuit that checks
    /// the first run only is caught.
    const LAST: usize = RUNS_PER_EVALUATION - 1;

    /// A random witness and the honest statement for it, from `seed`.
    fn random(seed: u64) -> (Online, OnlineWitness) {
        let mut rng = StdRng::seed_from_u64(seed);
        let witness = OnlineWitness {
            sk: SecretKey::random(&mut rng),
            m_randomness: rng.random(),
            runs: array::from_fn(|_| RunWitness {
                r_sigma_sum: rng.random_range(0..Q),
                pads: rng.random(),
                d_randomness: rng.random(),
            }),
        };
        let e = array::from_fn(|_| array::from_fn(|_| rng.random_range(0..Q)));
        let b_bar_prime = array::from_fn(|_| rng.random_range(0..DELTA as Zdelta));
        (
            OnlineStatement::for_witness(&witness, &e, &b_bar_prime),
            witness,
        )
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
        let d = p_pads::public_values(&run.d, run.b_bar_prime);
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
        let response = ResponseAir::row(a_sigma_sum, &run_witness.pads, run.b_bar_prime);

        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sum(), witness.m_randomness);
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
        let response = ResponseAir::row(a_sigma_sum, &run_witness.pads, run.b_bar_prime);

        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sum(), witness.m_randomness);
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
        let response = ResponseAir::row(other, &run_witness.pads, run.b_bar_prime);

        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sum(), witness.m_randomness);
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
        let response = ResponseAir::row(a_sigma_sum, &other, run.b_bar_prime);

        let key = KeyAir::row(&witness.sk);
        let mask_sum = MaskSumAir::row(&witness.r_sigma_sum(), witness.m_randomness);
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
