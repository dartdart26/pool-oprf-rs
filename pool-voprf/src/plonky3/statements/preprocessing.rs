//! The preprocessing statement on Plonky3. Its constraints are (K), (S), (T)
//! and (M).

use crate::plonky3::commitments::key::KeyCommitment;
use crate::plonky3::constraints::k_key::KeyAir;
use crate::plonky3::{Plonky3, Proof, ProveError, VerifyError};
use crate::statements::preprocessing::{PreprocessingStatement, PreprocessingWitness};
use crate::traits::{ProofSystem, Statement};
use p3_uni_stark::{prove, verify};

// TODO: (S), (T) and (M). Until then the circuit is (K) alone.
impl ProofSystem<PreprocessingStatement<KeyCommitment>> for Plonky3 {
    type Proof = Proof;
    type ProveError = ProveError;
    type VerifyError = VerifyError;

    fn prove(
        &self,
        statement: &PreprocessingStatement<KeyCommitment>,
        witness: &PreprocessingWitness,
    ) -> Result<Proof, ProveError> {
        if !statement.holds_for(witness) {
            return Err(ProveError::WrongWitness);
        }
        let trace = KeyAir::trace(&witness.sk);
        prove(&self.config, &KeyAir, trace, &statement.pk.0).map_err(ProveError::Prover)
    }

    fn verify(
        &self,
        statement: &PreprocessingStatement<KeyCommitment>,
        proof: &Proof,
    ) -> Result<(), VerifyError> {
        Plonky3::verified(|| verify(&self.config, &KeyAir, proof, &statement.pk.0))
    }
}
