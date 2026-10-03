//! Selectors: columns of 1s and 0s that let one rule check each row
//! against a different public value.
//!
//! A circuit has one set of rules for all rows. Say row `k` must be checked
//! against public value `v_k`. The rule uses `sel_0·v_0 + sel_1·v_1 + …`,
//! where `sel_k` is 1 on row `k` and 0 on the others such that the sum is `v_k`
//! there. [`selectors`] can also set `sel_k` to 1 on several rows which
//! are then all checked against `v_k`.
//!
//! The prover does not commit to selectors. Both sides compute them.

use crate::plonky3::Val;
use core::array;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_field::integers::QuotientMap;

/// `K` selectors that take turns being 1, for `width` rows each, and then
/// start over. The function returns one round, `K·width` rows, and Plonky3
/// repeats it down the table.
///
/// With `K = 2` and `width = 2`:
///
/// | row | `sel_0` | `sel_1` |
/// |-----|---------|---------|
/// | 0   | 1       | 0       |
/// | 1   | 1       | 0       |
/// | 2   | 0       | 1       |
/// | 3   | 0       | 1       |
/// | 4   | 1       | 0       |
/// | 5   | 1       | 0       |
/// | …   | …       | …       |
pub fn selectors<const K: usize>(width: usize) -> [Vec<Val>; K] {
    array::from_fn(|k| {
        (0..K * width)
            .map(|row| Val::from_bool(row / width == k))
            .collect()
    })
}

/// `Σ_k sel_k·values[k]`: the one of `values` where `sel_k` is 1.
pub fn select<AB: AirBuilder, const K: usize>(
    sel: &[AB::PeriodicVar; K],
    values: [AB::Expr; K],
) -> AB::Expr {
    sel.iter()
        .zip(values)
        .map(|(&sel_k, value)| {
            let sel_k: AB::Expr = sel_k.into();
            sel_k * value
        })
        .sum()
}

/// `Σ_k k·sel_k`: the `k` where `sel_k` is 1.
pub fn index<AB: AirBuilder<F = Val>, const K: usize>(sel: &[AB::PeriodicVar; K]) -> AB::Expr {
    select::<AB, K>(sel, array::from_fn(|k| Val::from_int(k).into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::DebugConstraintBuilder;
    use p3_field::integers::QuotientMap;

    /// With `K = 2` and `width = 2`: one round of `K·width = 4` rows.
    ///
    /// | row | `sel_0` | `sel_1` |
    /// |-----|---------|---------|
    /// | 0   | 1       | 0       |
    /// | 1   | 1       | 0       |
    /// | 2   | 0       | 1       |
    /// | 3   | 0       | 1       |
    #[test]
    fn selectors_are_correct() {
        let [sel_0, sel_1] = selectors::<2>(2);
        assert_eq!(sel_0, [Val::ONE, Val::ONE, Val::ZERO, Val::ZERO]);
        assert_eq!(sel_1, [Val::ZERO, Val::ZERO, Val::ONE, Val::ONE]);
    }

    #[test]
    fn select_picks_the_value_whose_selector_is_1() {
        type N = DebugConstraintBuilder<'static, Val>;
        let values = [Val::from_int(7u32), Val::from_int(9u32)];
        assert_eq!(select::<N, 2>(&[Val::ONE, Val::ZERO], values), values[0]);
        assert_eq!(select::<N, 2>(&[Val::ZERO, Val::ONE], values), values[1]);
    }
}
