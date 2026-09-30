//! The setup statement: what the server proves when it publishes `pk`.
//!
//! Its constraint is (K). `pk` is public, the key is the witness.

use crate::constraints::key::Key;
use crate::traits::{Commitment, Constraint, Statement};
use pool_prf::prf::SecretKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SetupStatement<PK> {
    pub pk: PK,
}

impl<PK: Commitment<Value = SecretKey>> SetupStatement<PK> {
    pub fn for_key(sk: &SecretKey) -> Self {
        Self { pk: PK::commit(sk) }
    }
}

impl<PK: Commitment<Value = SecretKey>> Statement for SetupStatement<PK> {
    type Witness = SecretKey;

    fn holds_for(&self, sk: &SecretKey) -> bool {
        Key { pk: &self.pk, sk }.holds()
    }
}
