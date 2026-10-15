//! Constraint (P) on Plonky3:
//!
//! ```text
//! d_j = Commit(Domain::Pad, r′_j, randomness_j),   j = 0 .. Δ-1
//! ```
//!
//! # Layout
//!
//! One entry per row. A row is `pad_j`, then the random value in
//! `RANDOMNESS_ELEMENTS` columns, then Poseidon2's columns, as in (M).
//! Entry `j` is on row `j`, and again every `Δ` rows.
//!
//! | row       | `pad_j`     | random value   | Poseidon2      |
//! |-----------|-------------|----------------|----------------|
//! | `0`       | `pad_0`     | of `pad_0`     | of `pad_0`     |
//! | `1`       | `pad_1`     | of `pad_1`     | of `pad_1`     |
//! | …         | …           | …              | …              |
//! | `Δ-1`     | `pad_{Δ-1}` | of `pad_{Δ-1}` | of `pad_{Δ-1}` |
//! | `Δ`       | `pad_0`     | of `pad_0`     | of `pad_0`     |
//! | …         | …           | …              | …              |
//! | `Δ·k + j` | `pad_j`     | of `pad_j`     | of `pad_j`     |
//!
//! # 1. The hash
//!
//! Poseidon2 takes the domain, then `pad_j` and the random value in the
//! order of the row, one per slot, and zeros in the rest of its `WIDTH`
//! slots.
//!
//! The permutation ends in the `d` of the row's entry. The rules are the
//! same on every row, so the rule says which `d` with the selectors, see
//! [`selectors`]:
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

use crate::commitments::CommitmentRandomness;
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
use pool_prf::params::{DELTA, Zp};
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

pub struct PadsAir;

impl PadsAir {
    /// The `Δ` entries, one row each: entry `j` on row `j`.
    pub fn entries(pads: &[Zp; DELTA], randomness: &[CommitmentRandomness; DELTA]) -> Vec<Val> {
        let mut rows = Vec::new();
        for (&pad, &randomness) in pads.iter().zip(randomness) {
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
    ) -> RowMajorMatrix<Val> {
        let entries = Self::entries(pads, randomness);
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
    // Checks that the commitment to `pad_j` in the table equals public value `d_j`.
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

/// `d_0 .. d_{Δ-1}`.
pub fn public_values(d: &[PadCommitment; DELTA]) -> Vec<Val> {
    d.iter().flat_map(|d_j| d_j.0).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::commitments::pad::commit;
    use p3_air::{ConstraintReport, check_all_constraints};
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    fn random(seed: u64) -> ([Zp; DELTA], [CommitmentRandomness; DELTA]) {
        let mut rng = StdRng::seed_from_u64(seed);
        (rng.random(), rng.random())
    }

    fn commitments(
        pads: &[Zp; DELTA],
        randomness: &[CommitmentRandomness; DELTA],
    ) -> [PadCommitment; DELTA] {
        array::from_fn(|j| commit(pads[j], randomness[j]))
    }
    fn report(trace: &RowMajorMatrix<Val>, d: &[PadCommitment; DELTA]) -> ConstraintReport {
        check_all_constraints(&PadsAir, trace, &public_values(d), None)
    }

    #[test]
    fn the_rules_hold() {
        let (pads, randomness) = random(2);
        let trace = PadsAir::trace(&pads, &randomness);
        let d = commitments(&pads, &randomness);
        assert!(report(&trace, &d).is_ok());
    }

    #[test]
    fn every_entry_is_checked() {
        let (pads, randomness) = random(3);
        let trace = PadsAir::trace(&pads, &randomness);
        for j in 0..DELTA {
            let mut d = commitments(&pads, &randomness);
            d[j] = commit(pads[j], randomness[j] ^ 1);
            assert!(!report(&trace, &d).is_ok(), "entry {j} is not checked");
        }
    }
}
