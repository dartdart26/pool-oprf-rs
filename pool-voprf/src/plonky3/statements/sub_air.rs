//! Running the rules of a constraint inside the circuit of a statement.
//!
//! The rules of a constraint expect their own columns and their own public
//! values, each starting at 0. Plonky3's [`SubAirBuilder`] shows them their
//! columns only. [`SubPublicValues`] does the same for the public values.
//! The periodic values are not cut, every constraint is shown all of them.
//! Only (P) has any, so only (P) reads them.

use crate::plonky3::Val;
use core::ops::Range;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_uni_stark::SubAirBuilder;

/// A builder that shows the public values in `range` only.
pub struct SubPublicValues<'a, AB: AirBuilder> {
    inner: &'a mut AB,
    range: Range<usize>,
}

impl<AB: AirBuilder> AirBuilder for SubPublicValues<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = AB::MainWindow;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;

    fn main(&self) -> Self::MainWindow {
        self.inner.main()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x);
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.inner.public_values()[self.range.clone()]
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}

pub fn eval_sub_air<AB, A>(
    builder: &mut AB,
    air: &A,
    columns: Range<usize>,
    public_values: Range<usize>,
) where
    AB: AirBuilder<F = Val>,
    A: BaseAir<Val> + for<'a, 'b> Air<SubAirBuilder<'a, SubPublicValues<'b, AB>, A, AB::Var>>,
{
    let mut builder = SubPublicValues {
        inner: builder,
        range: public_values,
    };
    air.eval(&mut SubAirBuilder::new(&mut builder, columns));
}
