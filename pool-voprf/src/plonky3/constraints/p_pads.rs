//! Constraint (P) on Plonky3: `r′_0 .. r′_{Δ-1}` open `d_0 .. d_{Δ-1}`.
//!
//! The pads are kept in the order of (R):
//!
//! ```text
//! pad_j = r′_{(j - b̄′) mod Δ}
//! ```
//!
//! Entry `j` opens `d_{(j - b̄′) mod Δ}`. `b̄′` is public, so the verifier
//! puts `d` in the same order.
//!
//! # Layout
//!
//! One entry per row. A row is `pad_j`, then the random value in
//! `RANDOMNESS_ELEMENTS` columns, then Poseidon2's columns, as in (M).
//! Entry `j` is on row `j`, and again every `Δ` rows.
//!
//! Next to them are `Δ` periodic columns, `s_0 .. s_{Δ-1}`. `s_j` is the
//! selector of entry `j`: 1 on its rows, 0 on the others, see
//! [`selectors`].
//!
//! | row      |     | `pad_j`     | random value   | Poseidon2      |     | `s_0` | `s_1` | … | `s_{Δ-1}` |
//! |----------|-----|-------------|----------------|----------------|-----|-------|-------|---|-----------|
//! | `0`      | c   | `pad_0`     | of `pad_0`     | of `pad_0`     | p   | 1     | 0     | … | 0         |
//! | `1`      | o   | `pad_1`     | of `pad_1`     | of `pad_1`     | e   | 0     | 1     | … | 0         |
//! | `2`      | m   | `pad_2`     | of `pad_2`     | of `pad_2`     | r   | 0     | 0     | … | 0         |
//! | …        | m   | …           | …              | …              | i   | …     | …     | … | …         |
//! | `Δ-1`    | i → | `pad_{Δ-1}` | of `pad_{Δ-1}` | of `pad_{Δ-1}` | o → | 0     | 0     | … | 1         |
//! | `Δ`      | t   | `pad_0`     | of `pad_0`     | of `pad_0`     | d   | 1     | 0     | … | 0         |
//! | `Δ+1`    | t   | `pad_1`     | of `pad_1`     | of `pad_1`     | i   | 0     | 1     | … | 0         |
//! | …        | e   | …           | …              | …              | c   | …     | …     | … | …         |
//! | `2Δ-1`   | d   | `pad_{Δ-1}` | of `pad_{Δ-1}` | of `pad_{Δ-1}` |     | 0     | 0     | … | 1         |
//! | …        |     | …           | …              | …              |     | …     | …     | … | …         |
//! | `ROWS-1` |     | `pad_{Δ-1}` | of `pad_{Δ-1}` | of `pad_{Δ-1}` |     | 0     | 0     | … | 1         |
//!
//! # 1. The hash
//!
//! Poseidon2 takes `WIDTH` slots:
//!
//! | slots                 | content                               |
//! |-----------------------|---------------------------------------|
//! | 1                     | the domain                            |
//! | 1                     | `pad_j`                               |
//! | `RANDOMNESS_ELEMENTS` | the random value, one column per slot |
//! | the rest              | zero                                  |
//!
//! The permutation ends in the `d` of the row's entry. The rules are the
//! same on every row, so the rule says which `d` with the selectors:
//!
//! ```text
//! hash = s_0·d_0 + s_1·d_1 + … + s_{Δ-1}·d_{Δ-1}
//! ```
//!
//! On the rows of entry `j`, `s_j` is 1 and the others are 0, so the right
//! side is `d_j`.
//!
//! No rule checks `pad_j` or the random value. The random value hides
//! `pad_j`, so a bad one only harms the server. `pad_j` is whatever `d`
//! commits to, and the client checks `d_{b′}` against its own pad.
//!
//! [`PadsAir::rules`] takes the `hash` from its caller. Alone, that is the
//! sum above over the public values. In the online statement, it is the
//! `d` of the row's entry of the row's run.

use crate::CommitmentRandomness;
use crate::plonky3::commitments::pad::{INPUT_ELEMENTS, PadCommitment, elements};
use crate::plonky3::commitments::{DIGEST_ELEMENTS, RANDOMNESS_ELEMENTS, concat, pack_randomness};
use crate::plonky3::selectors::{select, selectors};
use crate::plonky3::sponge::{
    PERMUTATION, PERMUTATION_COLS, eval_sponge, permutations, sponge_trace,
};
use crate::plonky3::{ROWS, Val};
use core::array;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::integers::QuotientMap;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::modular::sub_delta;
use pool_prf::params::{DELTA, Zdelta, Zp};
use std::borrow::Cow;

const PERMUTATIONS: usize = permutations(INPUT_ELEMENTS);

/// Where each part of the row starts.
pub(crate) const PAD: usize = 0;
const RANDOMNESS: usize = PAD + 1;
const SPONGE: usize = RANDOMNESS + RANDOMNESS_ELEMENTS;
pub(crate) const NUM_COLS: usize = SPONGE + PERMUTATIONS * PERMUTATION_COLS;
/// `d_0 .. d_{Δ-1}`.
pub(crate) const NUM_PUBLIC_VALUES: usize = DELTA * DIGEST_ELEMENTS;
/// `s_0 .. s_{Δ-1}`.
const NUM_PERIODIC_COLUMNS: usize = DELTA;

const _: () = assert!(ROWS.is_multiple_of(DELTA), "the entries must repeat whole");

/// `(j - b̄′) mod Δ`
fn pad_index(j: usize, b_bar_prime: Zdelta) -> usize {
    usize::from(sub_delta(j as Zdelta, b_bar_prime))
}

pub struct PadsAir;

impl PadsAir {
    /// The `Δ` entries, one row each: entry `j` on row `j`.
    pub fn entries(
        pads: &[Zp; DELTA],
        randomness: &[CommitmentRandomness; DELTA],
        b_bar_prime: Zdelta,
    ) -> Vec<Val> {
        let mut rows = Vec::new();
        for j in 0..DELTA {
            let pad_index = pad_index(j, b_bar_prime);
            let pad = pads[pad_index];
            let randomness = randomness[pad_index];
            rows.push(Val::from_int(pad));
            rows.extend(pack_randomness(randomness));
            let input = PadCommitment::input(elements(pad, randomness));
            rows.extend(sponge_trace(input));
        }
        rows
    }

    /// The table - the entries, repeated to `ROWS` rows.
    pub fn trace(
        pads: &[Zp; DELTA],
        randomness: &[CommitmentRandomness; DELTA],
        b_bar_prime: Zdelta,
    ) -> RowMajorMatrix<Val> {
        let entries = Self::entries(pads, randomness, b_bar_prime);
        RowMajorMatrix::new(entries.repeat(ROWS / DELTA), NUM_COLS)
    }

    /// The rules for (P) on the row: its pad and random value hash to
    /// `hash`.
    pub fn rules<AB: AirBuilder<F = Val>>(builder: &mut AB, hash: [AB::Expr; DIGEST_ELEMENTS]) {
        let main = builder.main();
        let row = main.current_slice();
        let pad: AB::Expr = row[PAD].into();
        let randomness: [AB::Expr; RANDOMNESS_ELEMENTS] =
            array::from_fn(|k| row[RANDOMNESS + k].into());
        let input = PadCommitment::input(concat([pad], randomness));
        eval_sponge(builder, SPONGE, input, hash);
    }
}

impl BaseAir<Val> for PadsAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// A row holds a whole entry, so no rule reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        PERMUTATION.max_constraint_degree()
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

impl<AB: AirBuilder<F = Val>> Air<AB> for PadsAir {
    // Checks that the commitment to `pad_j` in the table equals public value
    // `j`, which is `d_{(j - b̄′) mod Δ}`: the verifier puts `d` in the order
    // of (R), see `public_values`.
    fn eval(&self, builder: &mut AB) {
        let public_values = builder.public_values();
        let d: [[AB::PublicVar; DIGEST_ELEMENTS]; DELTA] = array::from_fn(|j| {
            let start = j * DIGEST_ELEMENTS;
            public_values[start..start + DIGEST_ELEMENTS]
                .try_into()
                .expect("d_j")
        });
        let s: [AB::PeriodicVar; DELTA] = builder.periodic_values().try_into().expect("s_j");

        // The `hash` of this row's entry:
        //
        //     hash = s_0·d_0 + s_1·d_1 + … + s_{Δ-1}·d_{Δ-1}
        //
        // A hash is `DIGEST_ELEMENTS` elements, so the sum is taken element by
        // element.
        let hash: [AB::Expr; DIGEST_ELEMENTS] = array::from_fn(|k| {
            let element_k = d.map(|d_j| d_j[k].into());
            select::<AB, DELTA>(&s, element_k)
        });
        Self::rules(builder, hash);
    }
}

/// `d` in the order of (R).
pub fn public_values(d: &[PadCommitment; DELTA], b_bar_prime: Zdelta) -> Vec<Val> {
    (0..DELTA)
        .flat_map(|j| d[pad_index(j, b_bar_prime)].0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::commitments::pad::commit;
    use p3_air::{ConstraintReport, check_all_constraints};
    use pool_prf::modular::reduce_delta;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    fn random(seed: u64) -> ([Zp; DELTA], [CommitmentRandomness; DELTA], Zdelta) {
        let mut rng = StdRng::seed_from_u64(seed);
        (
            rng.random(),
            rng.random(),
            rng.random_range(0..DELTA as Zdelta),
        )
    }

    fn commitments(
        pads: &[Zp; DELTA],
        randomness: &[CommitmentRandomness; DELTA],
    ) -> [PadCommitment; DELTA] {
        array::from_fn(|j| commit(pads[j], randomness[j]))
    }
    fn report(
        trace: &RowMajorMatrix<Val>,
        d: &[PadCommitment; DELTA],
        b_bar_prime: Zdelta,
    ) -> ConstraintReport {
        check_all_constraints(&PadsAir, trace, &public_values(d, b_bar_prime), None)
    }

    #[test]
    fn the_rules_hold() {
        let (pads, randomness, b_bar_prime) = random(2);
        let trace = PadsAir::trace(&pads, &randomness, b_bar_prime);
        let d = commitments(&pads, &randomness);
        assert!(report(&trace, &d, b_bar_prime).is_ok());
    }

    #[test]
    fn every_entry_is_checked() {
        let (pads, randomness, b_bar_prime) = random(3);
        let trace = PadsAir::trace(&pads, &randomness, b_bar_prime);
        for j in 0..DELTA {
            let mut d = commitments(&pads, &randomness);
            d[j] = commit(pads[j], randomness[j] ^ 1);
            assert!(
                !report(&trace, &d, b_bar_prime).is_ok(),
                "entry {j} is not checked"
            );
        }
    }

    #[test]
    fn another_b_bar_prime_is_refused() {
        let (pads, randomness, b_bar_prime) = random(4);
        let trace = PadsAir::trace(&pads, &randomness, b_bar_prime);
        let d = commitments(&pads, &randomness);
        let other = reduce_delta(b_bar_prime + 1);
        assert!(!report(&trace, &d, other).is_ok());
    }
}
