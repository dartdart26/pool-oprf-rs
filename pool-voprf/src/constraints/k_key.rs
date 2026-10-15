//! Constraint (K) from `docs/voprf.md`.
//!
//! ```text
//! pk = Commit(Domain::Key, sk),   each sk_i in {0, 1}
//! ```
//!
//! `pk` is a [`Commitment`] to `sk`.

use crate::traits::{Commitment, Constraint};
use pool_prf::prf::SecretKey;

pub struct Key<'a, PK> {
    pub pk: &'a PK,
    pub sk: &'a SecretKey,
}

impl<PK: Commitment<Input = SecretKey>> Constraint for Key<'_, PK> {
    fn holds(&self) -> bool {
        PK::commit(self.sk) == *self.pk
    }
}
