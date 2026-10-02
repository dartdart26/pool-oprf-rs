//! Selectors: periodic columns that say which rows a value belongs to.
//!
//! A rule is the same on every row. When a table holds different values on
//! different rows, such as entry `j` of (P) on row `j`, the rule picks the
//! public value of the row with selectors: `s_j` is 1 on the rows of entry
//! `j` and 0 on the others, so `Σ_j s_j·d_j` is the `d_j` of the row.
//!
//! Selectors are not columns of the table: the prover does not commit to
//! them, both sides compute them.

use crate::plonky3::Val;
use core::array;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;

/// `K` selectors of period `K·width`: `s_k` is 1 on rows `k·width` to
/// `(k+1)·width - 1` and 0 on the others. So the rows cycle through the
/// `K` values, `width` rows each.
pub fn selectors<const K: usize>(width: usize) -> [Vec<Val>; K] {
    array::from_fn(|k| {
        (0..K * width)
            .map(|row| Val::from_bool(row / width == k))
            .collect()
    })
}

/// `Σ_k s_k·values[k]`: the one of `values` where `s_k` is 1.
pub fn select<AB: AirBuilder, const K: usize>(
    s: &[AB::PeriodicVar; K],
    values: [AB::Expr; K],
) -> AB::Expr {
    s.iter()
        .zip(values)
        .map(|(&s_k, value)| {
            let s_k: AB::Expr = s_k.into();
            s_k * value
        })
        .sum()
}
