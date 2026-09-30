use crate::traits::Statement;
use serde::Serialize;
use serde::de::DeserializeOwned;

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
