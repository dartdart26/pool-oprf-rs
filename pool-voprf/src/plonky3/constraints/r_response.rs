//! Constraint (R) on Plonky3:
//!
//! ```text
//! y^{v, k}_j = ⌈(ã^{v, k}_Σ - j) mod q⌋ + r′^{v, k}_{(j - b̄′^{v, k}) mod Δ}   mod p,   j = 0 .. Δ-1
//! ```
//!
//! Let's define:
//!
//! ```text
//! t_j   = (ã^{v, k}_Σ - j) mod q
//! pad_j = r′^{v, k}_{(j - b̄′^{v, k}) mod Δ}
//! ```
//!
//! (R) checks the arithmetic only. It takes `ã^{v, k}_Σ` and `r′^{v, k}` as
//! given, without checking that they are in `ℤ_q` and `ℤ_p` - (A) and (P) pin
//! them down.
//!
//! # Layout
//!
//! One row holds one entry `j`. Entry `j` is on row `j`, and again every `Δ`
//! rows. The bits are lowest first.
//!
//! | row       | `ã^{v, k}_Σ` (1) | `t_j` (`LOG_Q`)   | wrapped (1) | pad (1)     | carry (1) |
//! |-----------|------------------|-------------------|-------------|-------------|-----------|
//! | `0`       | `ã^{v, k}_Σ`     | bits of `t_0`     | bit         | `pad_0`     | bit       |
//! | `1`       | `ã^{v, k}_Σ`     | bits of `t_1`     | bit         | `pad_1`     | bit       |
//! | …         | …                | …                 | …           | …           | …         |
//! | `Δ-1`     | `ã^{v, k}_Σ`     | bits of `t_{Δ-1}` | bit         | `pad_{Δ-1}` | bit       |
//! | `Δ`       | `ã^{v, k}_Σ`     | bits of `t_0`     | bit         | `pad_0`     | bit       |
//! | …         | …                | …                 | …           | …           | …         |
//! | `Δ·k + j` | `ã^{v, k}_Σ`     | bits of `t_j`     | bit         | `pad_j`     | bit       |
//!
//! `wrapped` is 1 if `ã^{v, k}_Σ - j` was below zero. `carry` is 1 if
//! `⌈t_j⌋ + pad_j` reached `p`.
//!
//! Each row gets its `j` and its `y^{v, k}_j` from the selectors
//! `s_0 .. s_{Δ-1}`, see [`selectors`]. On the rows of entry `j`, `s_j` is 1
//! and every other selector is 0. So multiplying each selector by its entry's
//! number, or by its entry's `y^{v, k}_j`, and adding up leaves only entry
//! `j`'s:
//!
//! ```text
//! j          = 0·s_0          + 1·s_1          + … + (Δ-1)·s_{Δ-1}
//! y^{v, k}_j = y^{v, k}_0·s_0 + y^{v, k}_1·s_1 + … + y^{v, k}_{Δ-1}·s_{Δ-1}
//! ```
//!
//! For example, on a row of entry 5 only `s_5` is 1, so `j = 5·1 = 5` and
//! `y^{v, k}_j = y^{v, k}_5·1 = y^{v, k}_5`.
//!
//! # 1. `t_j` mod `q`
//!
//! `t_j` is laid out as `LOG_Q` bits, and no number above `q - 1` fits in
//! `LOG_Q` bits. So once the rule checks that each column is a bit, `t_j`
//! is in `ℤ_q`. The rule then computes `t_j` twice and compares:
//!
//! ```text
//! Σ_l 2^l · t_{j,l}  =  ã^{v, k}_Σ - j + q·wrapped
//! ```
//!
//! The left side computes `t_j` from its `LOG_Q` bits, `t_{j,l}` being bit
//! `l`. The right side computes it from the `ã^{v, k}_Σ` column, with `q` added
//! back when `ã^{v, k}_Σ - j` went below zero.
//!
//! # 2. Rounding `t_j`, i.e. `⌈t_j⌋`
//!
//! `⌈t_j⌋` is the nearest integer to `t_j / Δ`, ties down. Since `Δ` is a
//! power of two, the division is a split of the bits of `t_j`: the quotient
//! is the high `LOG_P` bits and the remainder is the low `LOG_DELTA` bits.
//! The remainder decides the direction: above `Δ/2` rounds up, otherwise
//! down. So
//!
//! ```text
//! ⌈t_j⌋ = quotient + up
//! ```
//!
//! where `up` is 1 if the remainder is above `Δ/2`, else 0.
//!
//! To get `up` from the bits, call the remainder `m`, with bits `m_0` to
//! `m_{LOG_DELTA-1}`. In binary `Δ/2` is a one followed by `LOG_DELTA - 1`
//! zeros, i.e. `m_{LOG_DELTA-1} = 1` and every lower bit 0. So `m` is above
//! `Δ/2` exactly when `m_{LOG_DELTA-1}` is 1 and at least one lower bit is 1
//! as well.
//!
//! At least one lower bit being 1 is the opposite of all of them being 0,
//! and the product of the flipped lower bits is 1 exactly when all are 0:
//!
//! ```text
//! any_lower = 1 - (1 - m_0)·(1 - m_1)·…·(1 - m_{LOG_DELTA-2})
//! up        = m_{LOG_DELTA-1} · any_lower
//! ```
//!
//! # 3. `y^{v, k}_j` mod `p`
//!
//! `⌈t_j⌋` is at most `p` and `pad_j` is below `p`. So their sum is below
//! `2p` and taking it mod `p` subtracts `p` at most once. `carry` is a bit
//! that says whether:
//!
//! ```text
//! y^{v, k}_j = ⌈t_j⌋ + pad_j - p·carry
//! ```

use crate::plonky3::selectors::{index, select, selectors};
use crate::plonky3::{ROWS, Val};
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_field::integers::QuotientMap;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::modular::sub_q;
use pool_prf::params::{DELTA, LOG_DELTA, LOG_Q, P, Q, Zdelta, Zp, Zq};
use pool_prf::round::round;
use std::borrow::Cow;

const T_BITS: usize = LOG_Q as usize;

/// Where each part of the row starts.
pub(crate) const A_SIGMA: usize = 0;
const T: usize = A_SIGMA + 1;
const WRAPPED: usize = T + T_BITS;
pub(crate) const PAD: usize = WRAPPED + 1;
const CARRY: usize = PAD + 1;
pub(crate) const NUM_COLS: usize = CARRY + 1;
/// `y^{v, k}_0 .. y^{v, k}_{Δ-1}`.
const NUM_PUBLIC_VALUES: usize = DELTA;
/// `s_0 .. s_{Δ-1}`.
const NUM_PERIODIC_COLUMNS: usize = DELTA;

const _: () = assert!(ROWS.is_multiple_of(DELTA), "the entries must repeat whole");

/// `up` of step 2, from the bits `m` of the remainder. Lowest bit first in `m`.
fn up<AB: AirBuilder>(m: &[AB::Var]) -> AB::Expr {
    let (&top, lower) = m.split_last().expect("a bit");
    let any_lower = AB::Expr::ONE
        - lower
            .iter()
            .map(|&bit| AB::Expr::ONE - bit)
            .product::<AB::Expr>();
    top * any_lower
}

pub struct ResponseAir;

impl ResponseAir {
    /// The `Δ` entries for `ã^{v, k}_Σ`, the pads and `b̄′^{v, k}`, one row
    /// each: entry `j` on row `j`.
    pub fn entries(a_sigma_sum: Zq, pads: &[Zp; DELTA], b_bar_prime: Zdelta) -> Vec<Val> {
        let mut rows = Vec::with_capacity(DELTA * NUM_COLS);
        for j in 0..DELTA {
            let t = sub_q(a_sigma_sum, j as Zq);
            let wrapped = a_sigma_sum < j as Zq;
            let rounded = round(t);
            let pad = pool_eval::pad(pads, j, b_bar_prime);
            let carry = (rounded + Zq::from(pad)) >= P;
            rows.push(Val::from_int(a_sigma_sum));
            rows.extend((0..T_BITS).map(|k| Val::from_int((t >> k) & 1)));
            rows.push(Val::from_bool(wrapped));
            rows.push(Val::from_int(pad));
            rows.push(Val::from_bool(carry));
        }
        rows
    }

    /// The table - the entries, repeated to `ROWS` rows.
    pub fn trace(a_sigma_sum: Zq, pads: &[Zp; DELTA], b_bar_prime: Zdelta) -> RowMajorMatrix<Val> {
        let entries = Self::entries(a_sigma_sum, pads, b_bar_prime);
        RowMajorMatrix::new(entries.repeat(ROWS / DELTA), NUM_COLS)
    }

    /// The rules for (R) on the row, for its entry `j` and `y^{v, k}_j`.
    pub fn rules<AB: AirBuilder<F = Val>>(builder: &mut AB, j: AB::Expr, y_j: AB::Expr) {
        let main = builder.main();
        let row = main.current_slice();
        let a_sigma_sum: AB::Expr = row[A_SIGMA].into();
        let t_bits = &row[T..WRAPPED];
        let (wrapped, pad, carry) = (row[WRAPPED], row[PAD], row[CARRY]);
        for &bit in t_bits {
            builder.assert_bool(bit);
        }
        builder.assert_bool(wrapped);
        builder.assert_bool(carry);

        // 1. t_j = ã^{v, k}_Σ - j + q·wrapped
        let t = pack_bits_le::<AB::Expr, _, _>(t_bits.iter().copied());
        builder.assert_eq(t, a_sigma_sum - j + wrapped * Val::from_int(Q));

        // 2. ⌈t_j⌋ = quotient + up
        let (m, quotient) = t_bits.split_at(LOG_DELTA);
        let rounded = pack_bits_le::<AB::Expr, _, _>(quotient.iter().copied()) + up::<AB>(m);

        // 3. y^{v, k}_j = ⌈t_j⌋ + pad_j - carry·p
        builder.assert_eq(rounded + pad - carry * Val::from_int(P), y_j);
    }
}

impl BaseAir<Val> for ResponseAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

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
        Cow::Owned(selectors::<DELTA>(1).into())
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for ResponseAir {
    fn eval(&self, builder: &mut AB) {
        let y: [AB::PublicVar; DELTA] = builder.public_values().try_into().expect("y");
        let s: [AB::PeriodicVar; DELTA] = builder.periodic_values().try_into().expect("s_j");
        let j = index::<AB, DELTA>(&s);
        let y_j = select::<AB, DELTA>(&s, y.map(Into::into));
        Self::rules(builder, j, y_j);
    }
}

pub fn public_values(y: &[Zp; DELTA]) -> [Val; DELTA] {
    y.map(Val::from_int)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::{ConstraintReport, check_all_constraints};
    use pool_prf::params::{DELTA_ZQ, ZP_MAX, Zq};
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// A random `ã^{v, k}_Σ`, pads and `b̄′^{v, k}`, from `seed`.
    fn random(seed: u64) -> (Zq, [Zp; DELTA], Zdelta) {
        let mut rng = StdRng::seed_from_u64(seed);
        let a_sigma_sum = rng.random_range(0..Q);
        let pads = rng.random();
        let b_bar_prime = rng.random_range(0..DELTA as Zdelta);
        (a_sigma_sum, pads, b_bar_prime)
    }

    /// Runs the rules over `trace` for `y^{v, k}`.
    fn report(trace: &RowMajorMatrix<Val>, y: &[Zp; DELTA]) -> ConstraintReport {
        check_all_constraints(&ResponseAir, trace, &public_values(y), None)
    }

    /// An honest trace passes the rules wherever a bit of it flips.
    ///
    /// `wrapped` flips when `ã^{v, k}_Σ < j` (`ã^{v, k}_Σ` below `Δ`).
    /// `carry` flips when `⌈t_j⌋ + pad_j` reaches `p`.
    /// `up` flips at every remainder and one row has them all.
    #[test]
    fn the_rules_hold_at_every_wrap() {
        let mut rng = StdRng::seed_from_u64(1);
        let below_delta = 0..=DELTA_ZQ;
        let near_q = Q - DELTA_ZQ..Q;
        let random: Vec<Zq> = (0..8).map(|_| rng.random_range(0..Q)).collect();
        for a_sigma_sum in below_delta.chain(near_q).chain(random) {
            for pads in [[0; DELTA], [ZP_MAX; DELTA], rng.random()] {
                let y = pool_eval::respond(a_sigma_sum, &pads, 0);
                let trace = ResponseAir::trace(a_sigma_sum, &pads, 0);
                assert!(
                    report(&trace, &y).is_ok(),
                    "ã_Σ = {a_sigma_sum}, pads = {pads:?}"
                );
            }
        }
    }

    #[test]
    fn every_entry_is_checked() {
        let (a_sigma_sum, pads, b_bar_prime) = random(2);
        let y = pool_eval::respond(a_sigma_sum, &pads, b_bar_prime);
        let trace = ResponseAir::trace(a_sigma_sum, &pads, b_bar_prime);
        for j in 0..DELTA {
            let mut changed = y;
            changed[j] ^= 1;
            assert!(
                !report(&trace, &changed).is_ok(),
                "entry {j} is not checked"
            );
        }
    }

    /// With `ã^{v, k}_Σ = 3`, entry 0 has `t_0 = 3`, whose lowest two bits are
    /// 1, 1. Writing them as 3, 0 on the rows of entry 0 violates the rule that
    /// columns of `t_0` are bits, namely constraint 0.
    #[test]
    fn a_bit_that_is_not_a_bit_is_refused() {
        let pads = [0; DELTA];
        let y = pool_eval::respond(3, &pads, 0);
        let mut trace = ResponseAir::trace(3, &pads, 0);
        assert!(report(&trace, &y).is_ok());
        for row in trace.values.chunks_mut(NUM_COLS).step_by(DELTA) {
            assert_eq!(row[T..T + 2], [Val::ONE, Val::ONE]);
            row[T] = Val::from_int(3);
            row[T + 1] = Val::ZERO;
        }
        let failures = report(&trace, &y).failures;
        assert!(!failures.is_empty());
        assert!(
            failures.iter().all(|failure| failure.constraint == 0),
            "{failures:?}"
        );
    }
}
