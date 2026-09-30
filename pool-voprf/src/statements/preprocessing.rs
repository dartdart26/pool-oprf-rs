//! The preprocessing statement: what the server proves at the end of
//! preprocessing.
//!
//! Its constraints are (K), (S), (T) and (M).

use crate::constraints::key::Key;
use crate::traits::{Commitment, Constraint, Statement};
use pool_prf::prf::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreprocessingStatement<PK> {
    pub pk: PK,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PreprocessingWitness {
    pub sk: SecretKey,
}

impl<PK: Commitment<Value = SecretKey>> PreprocessingStatement<PK> {
    /// The statement an honest server makes.
    pub fn for_witness(witness: &PreprocessingWitness) -> Self {
        Self {
            pk: PK::commit(&witness.sk),
        }
    }
}

impl<PK: Commitment<Value = SecretKey>> Statement for PreprocessingStatement<PK> {
    type Witness = PreprocessingWitness;

    // TODO: (S), (T) and (M).
    fn holds_for(&self, witness: &PreprocessingWitness) -> bool {
        let key = Key {
            pk: &self.pk,
            sk: &witness.sk,
        };
        key.holds()
    }
}
