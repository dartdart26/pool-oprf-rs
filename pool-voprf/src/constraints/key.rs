//! Constraint (K) from `docs/voprf.md`: `sk` opens `pk`, and each `sk_i` is
//! either 0 or 1.
//!
//! `pk` is a [`Commitment`] to `sk`.

use crate::traits::{Commitment, Constraint};
use pool_prf::prf::SecretKey;

pub struct Key<'a, PK> {
    pub pk: &'a PK,
    pub sk: &'a SecretKey,
}

impl<PK: Commitment<Value = SecretKey>> Constraint for Key<'_, PK> {
    fn holds(&self) -> bool {
        PK::commit(self.sk) == *self.pk
    }
}
