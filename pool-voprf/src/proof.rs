//! The interface between the protocol and a proof system.
//!
//! A proof is about a [`Statement`]: public values both parties hold plus a
//! witness only the prover holds.
//!
//! A [`ProofSystem`] is one circuit per statement.

use serde::Serialize;
use serde::de::DeserializeOwned;

pub trait Statement {
    type Witness;
}

/// A proof system for one kind of statement.
pub trait ProofSystem<S: Statement> {
    type Proof: Serialize + DeserializeOwned;
    type ProveError: std::error::Error;
    type VerifyError: std::error::Error;

    /// Prove `statement` from `witness`, in zero knowledge. Fails if the
    /// witness does not satisfy the statement.
    fn prove(&self, statement: &S, witness: &S::Witness) -> Result<Self::Proof, Self::ProveError>;

    /// Check `proof` against `statement`. `Ok(())` means it verified.
    fn verify(&self, statement: &S, proof: &Self::Proof) -> Result<(), Self::VerifyError>;
}
