//! Constraint (T) on Plonky3:
//!
//! ```text
//! r̃^{v, k}_Σ = Σ_i (1 - 2·sk_i)·r^{v, k}_{b_i, i}   mod q
//! ```
//!
//! (T) takes `sk` and the masks as given - (K) and (S) pin them down.
//!
//! # Layout
//!
//! One row holds one OT block `i` with its mask of every run `k`.
//! The rows after block `n-1`, up to `N_TABLE_ROWS`, repeat the row of
//! block `n-1`. The bits are lowest first.
//!
//! | row              | `sk_i` (1) | masks (`RUNS_PER_EVALUATION`) | sums (`RUNS_PER_EVALUATION`) | `r̃^{v, k}_Σ` (`LOG_Q` per run) | quotient (`QUOTIENT_BITS` per run) |
//! |------------------|------------|-------------------------------|------------------------------|--------------------------------|------------------------------------|
//! | `0`              | `sk_0`     | `r^{v, k}_{b_0, 0}`           | `S^{v, k}_0`                 | bits                           | bits                               |
//! | `1`              | `sk_1`     | `r^{v, k}_{b_1, 1}`           | `S^{v, k}_1`                 | bits                           | bits                               |
//! | …                | …          | …                             | …                            | …                              | …                                  |
//! | `n-1`            | `sk_{n-1}` | `r^{v, k}_{b_{n-1}, n-1}`     | `S^{v, k}_{n-1}`             | bits                           | bits                               |
//! | `n`              | `sk_{n-1}` | `r^{v, k}_{b_{n-1}, n-1}`     | `S^{v, k}_{n-1}`             | bits                           | bits                               |
//! | …                | …          | …                             | …                            | …                              | …                                  |
//! | `N_TABLE_ROWS-1` | `sk_{n-1}` | `r^{v, k}_{b_{n-1}, n-1}`     | `S^{v, k}_{n-1}`             | bits                           | bits                               |
//!
//! `r̃^{v, k}_Σ` and `quotient^{v, k}` are the same on every row.
//!
//! # 1. The sum
//!
//! Row `i` adds its mask to the row above where `sk_i = 0` and subtracts it
//! where `sk_i = 1`, because `1 - 2·sk_i` is 1 if `sk_i = 0` and -1 if
//! `sk_i = 1`. Instead of subtracting the mask, it adds `q` minus the mask.
//! Mod `q`, that is the same as subtracting. Unlike subtracting, adding
//! never takes the sum below zero.
//!
//! ```text
//! S^{v, k}_i = S^{v, k}_{i-1} + r^{v, k}_{b_i, i}        where sk_i = 0
//! S^{v, k}_i = S^{v, k}_{i-1} + q - r^{v, k}_{b_i, i}    where sk_i = 1
//! ```
//!
//! Row 0 starts from 0 and row `n-1` holds the whole sum.
//!
//! # 2. The sum mod `q`
//!
//! The server computes `r̃^{v, k}_Σ = S^{v, k}_{n-1} mod q` and
//! `quotient^{v, k}` and puts both in the row as bits. The rule checks:
//!
//! ```text
//! S^{v, k}_{n-1} = r̃^{v, k}_Σ + q·quotient^{v, k}
//! ```
//!
//! `r̃^{v, k}_Σ` is `LOG_Q` bits, therefore below `q`.
//!
//! No rule here checks that a mask is in `ℤ_q`. Instead, (S) ties the masks to
//! the client's commitment and the client commits to masks in `ℤ_q`. Each row,
//! therefore, adds at most `q`, so the sum is at most `n·q` and the quotient at
//! most `n`. Both sides stay below the field's prime, therefore no huge
//! `quotient^{v, k}` can make a wrong `r̃^{v, k}_Σ` pass the checks.
//!
//! # 3. Which rows check what
//!
//! Plonky3 runs every rule on every row, and a rule sees only its own row and
//! the next one. To run a rule on some rows only, the rule is multiplied by a
//! periodic column: a column both sides know, 1 on those rows and 0 on the
//! others. Where it is 0, the rule is `0 = 0`. (T) has three periodic
//! columns:
//!
//! | row              | `first_block` | `has_next_block` | `last_block` |
//! |------------------|---------------|------------------|--------------|
//! | `0`              | 1             | 1                | 0            |
//! | `1`              | 0             | 1                | 0            |
//! | …                | …             | …                | …            |
//! | `n-2`            | 0             | 1                | 0            |
//! | `n-1`            | 0             | 0                | 1            |
//! | `n`              | 0             | 0                | 0            |
//! | …                | …             | …                | …            |
//! | `N_TABLE_ROWS-1` | 0             | 0                | 0            |
//!
//! On the rows where its periodic column is 1, each rule checks:
//!
//! ```text
//! first_block, row 0:     S^{v, k}_0     = r^{v, k}_{b_0, 0}                           where sk_0 = 0
//!                         S^{v, k}_0     = q - r^{v, k}_{b_0, 0}                       where sk_0 = 1
//! has_next_block, row i:  S^{v, k}_{i+1} = S^{v, k}_i + r^{v, k}_{b_{i+1}, i+1}        where sk_{i+1} = 0
//!                         S^{v, k}_{i+1} = S^{v, k}_i + q - r^{v, k}_{b_{i+1}, i+1}    where sk_{i+1} = 1
//! last_block, row n-1:    S^{v, k}_{n-1} = r̃^{v, k}_Σ + q·quotient^{v, k}
//! ```
//!
//! On every row, the rules check that each bit column is 0 or 1.

use crate::plonky3::constraints::common::bits;
use crate::plonky3::{N_BITS, N_TABLE_ROWS, Val};
use core::array;
use core::iter;
use core::ops::Range;
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::integers::QuotientMap;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::modular::{quotient_q, reduce_q};
use pool_prf::params::{LOG_Q, N, Q, RUNS_PER_EVALUATION, Zq, ZqAccum};
use pool_prf::prf::SecretKey;
use std::borrow::Cow;

pub(crate) const R_SIGMA_BITS: usize = LOG_Q as usize;
/// The quotient is at most `n`.
const QUOTIENT_BITS: usize = N_BITS;

/// Where each part of the row starts.
pub(crate) const SK_I: usize = 0;
pub(crate) const MASKS: usize = SK_I + 1;
const SUMS: usize = MASKS + RUNS_PER_EVALUATION;
pub(crate) const R_SIGMA: usize = SUMS + RUNS_PER_EVALUATION;
pub(crate) const QUOTIENT: usize = R_SIGMA + RUNS_PER_EVALUATION * R_SIGMA_BITS;
pub(crate) const NUM_COLS: usize = QUOTIENT + RUNS_PER_EVALUATION * QUOTIENT_BITS;

/// Both sides of the rule of step 2 are below this.
const SUM_BOUND: usize = (Q as usize) << QUOTIENT_BITS;
const _: () = assert!(SUM_BOUND < Val::ORDER_U32 as usize);

/// What block `i` adds to a sum: `r` where `sk_i = 0`, `q - r` where
/// `sk_i = 1`.
fn term(sk_i: u8, r: Zq) -> ZqAccum {
    ZqAccum::from(if sk_i == 0 { r } else { Q - r })
}

/// `first_block`, `has_next_block` and `last_block`.
pub(crate) const NUM_PERIODIC_COLUMNS: usize = 3;

pub fn periodic_columns() -> [Vec<Val>; NUM_PERIODIC_COLUMNS] {
    let column = |ones: Range<usize>| {
        (0..N_TABLE_ROWS)
            .map(|row| Val::from_bool(ones.contains(&row)))
            .collect()
    };
    [column(0..1), column(0..N - 1), column(N - 1..N)]
}

pub struct SumOfMasksAir;

impl SumOfMasksAir {
    pub fn rows(sk: &SecretKey, masks: &[[Zq; RUNS_PER_EVALUATION]; N]) -> Vec<Val> {
        let sk = sk.as_bits();
        let mut sums = Vec::with_capacity(N);
        let mut sum = [0; RUNS_PER_EVALUATION];
        for i in 0..N {
            sum = array::from_fn(|k| sum[k] + term(sk[i], masks[i][k]));
            sums.push(sum);
        }
        let mut rows = Vec::with_capacity(N_TABLE_ROWS * NUM_COLS);
        for row in 0..N_TABLE_ROWS {
            let i = row.min(N - 1);
            rows.push(Val::from_int(sk[i]));
            rows.extend(masks[i].map(Val::from_int));
            rows.extend(sums[i].map(Val::from_int));
            rows.extend(
                sum.iter()
                    .flat_map(|&s| bits(reduce_q(s).into(), R_SIGMA_BITS)),
            );
            rows.extend(sum.iter().flat_map(|&s| bits(quotient_q(s), QUOTIENT_BITS)));
        }
        rows
    }

    pub fn trace(sk: &SecretKey, masks: &[[Zq; RUNS_PER_EVALUATION]; N]) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(Self::rows(sk, masks), NUM_COLS)
    }

    pub fn rules<AB: AirBuilder<F = Val>>(
        builder: &mut AB,
        first_block: AB::Expr,
        has_next_block: AB::Expr,
        last_block: AB::Expr,
    ) {
        let main = builder.main();
        let (row, next) = (main.current_slice(), main.next_slice());
        let r_sigma_bits = &row[R_SIGMA..QUOTIENT];
        let quotient_bits = &row[QUOTIENT..NUM_COLS];
        for &bit in iter::once(&row[SK_I])
            .chain(r_sigma_bits)
            .chain(quotient_bits)
        {
            builder.assert_bool(bit);
        }

        let q: AB::Expr = Val::from_int(Q).into();
        // r + sk·(q - 2·r): r where sk = 0, q - r where sk = 1.
        let term = |row: &[AB::Var], k: usize| -> AB::Expr {
            let (sk, r) = (row[SK_I], row[MASKS + k]);
            r + sk * (q.clone() - r * Val::TWO)
        };
        let runs = r_sigma_bits
            .chunks(R_SIGMA_BITS)
            .zip(quotient_bits.chunks(QUOTIENT_BITS));
        for (k, (r_sigma_bits, quotient_bits)) in runs.enumerate() {
            let (sum, next_sum) = (row[SUMS + k], next[SUMS + k]);
            builder
                .when(first_block.clone())
                .assert_eq(sum, term(row, k));
            builder
                .when(has_next_block.clone())
                .assert_eq(next_sum, sum + term(next, k));

            // S^{v, k}_{n-1} = r̃^{v, k}_Σ + q·quotient^{v, k}
            let r_sigma = pack_bits_le::<AB::Expr, _, _>(r_sigma_bits.iter().copied());
            let quotient = pack_bits_le::<AB::Expr, _, _>(quotient_bits.iter().copied());
            builder
                .when(last_block.clone())
                .assert_eq(sum, r_sigma + quotient * q.clone());
        }
    }
}

impl BaseAir<Val> for SumOfMasksAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn num_periodic_columns(&self) -> usize {
        NUM_PERIODIC_COLUMNS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Owned(periodic_columns().into())
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for SumOfMasksAir {
    fn eval(&self, builder: &mut AB) {
        let [first_block, has_next_block, last_block]: [AB::PeriodicVar; NUM_PERIODIC_COLUMNS] =
            builder
                .periodic_values()
                .try_into()
                .expect("periodic columns");
        Self::rules(
            builder,
            first_block.into(),
            has_next_block.into(),
            last_block.into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::r_sigma_sums;
    use p3_air::check_all_constraints;
    use p3_matrix::Matrix;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    type Masks = [[Zq; RUNS_PER_EVALUATION]; N];

    fn random_masks(rng: &mut StdRng) -> Masks {
        array::from_fn(|_| array::from_fn(|_| rng.random_range(0..Q)))
    }

    fn cases() -> Vec<(SecretKey, Masks)> {
        let mut rng = StdRng::seed_from_u64(1);
        let keys = [
            SecretKey::from_bits([0; N]).expect("bits"),
            SecretKey::from_bits([1; N]).expect("bits"),
            SecretKey::random(&mut rng),
        ];
        let masks = [
            [[0; RUNS_PER_EVALUATION]; N],
            [[Q - 1; RUNS_PER_EVALUATION]; N],
            random_masks(&mut rng),
        ];
        let mut cases = Vec::new();
        for sk in &keys {
            for masks in &masks {
                cases.push((sk.clone(), *masks));
            }
        }
        cases
    }

    fn holds(trace: &RowMajorMatrix<Val>) -> bool {
        check_all_constraints(&SumOfMasksAir, trace, &[], None).is_ok()
    }

    /// `r̃^{v, k}_Σ` of each run `k` as the trace holds it, from its bits.
    fn r_sigma_sums_of(trace: &RowMajorMatrix<Val>) -> Vec<Zq> {
        let row = trace.row_slice(0).expect("a row");
        row[R_SIGMA..QUOTIENT]
            .chunks(R_SIGMA_BITS)
            .map(|bits| pack_bits_le::<Val, _, _>(bits.iter().copied()).as_canonical_u32() as Zq)
            .collect()
    }

    #[test]
    fn the_rules_hold_in_every_case() {
        for (sk, masks) in cases() {
            assert!(holds(&SumOfMasksAir::trace(&sk, &masks)));
        }
    }

    /// The trace holds the `r̃^{v, k}_Σ` the server computes.
    #[test]
    fn r_sigma_sums_are_the_servers() {
        for (sk, masks) in cases() {
            let trace = SumOfMasksAir::trace(&sk, &masks);
            assert_eq!(r_sigma_sums_of(&trace), r_sigma_sums(&sk, &masks));
        }
    }

    #[test]
    fn a_wrong_r_sigma_sum_is_refused() {
        let mut rng = StdRng::seed_from_u64(2);
        let (sk, masks) = (SecretKey::random(&mut rng), random_masks(&mut rng));
        let mut trace = SumOfMasksAir::trace(&sk, &masks);
        for row in trace.values.chunks_mut(NUM_COLS) {
            // flip a bit
            row[R_SIGMA] = Val::ONE - row[R_SIGMA];
        }
        assert!(!holds(&trace));
    }

    #[test]
    fn another_mask_is_refused() {
        let mut rng = StdRng::seed_from_u64(3);
        let (sk, masks) = (SecretKey::random(&mut rng), random_masks(&mut rng));
        for i in [0, 1, N - 1] {
            let mut trace = SumOfMasksAir::trace(&sk, &masks);
            trace.row_mut(i)[MASKS] += Val::ONE;
            assert!(!holds(&trace), "block {i} is not counted");
        }
    }
}
