//! The setup statement on Plonky3. Its constraint is (K).

use crate::plonky3::commitments::key::KeyCommitment;
use crate::plonky3::constraints::k_key::KeyAir;
use crate::plonky3::{Plonky3, Proof, ProveError, VerifyError};
use crate::statements::setup::SetupStatement;
use crate::traits::{ProofSystem, Statement};
use p3_uni_stark::{prove, verify};
use pool_prf::prf::SecretKey;

impl ProofSystem<SetupStatement<KeyCommitment>> for Plonky3 {
    type Proof = Proof;
    type ProveError = ProveError;
    type VerifyError = VerifyError;

    fn prove(
        &self,
        statement: &SetupStatement<KeyCommitment>,
        sk: &SecretKey,
    ) -> Result<Proof, ProveError> {
        if !statement.holds_for(sk) {
            return Err(ProveError::WrongWitness);
        }
        let trace = KeyAir::trace(sk);
        prove(&self.config, &KeyAir, trace, &statement.pk.0).map_err(ProveError::Prover)
    }

    fn verify(
        &self,
        statement: &SetupStatement<KeyCommitment>,
        proof: &Proof,
    ) -> Result<(), VerifyError> {
        Plonky3::verified(|| verify(&self.config, &KeyAir, proof, &statement.pk.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::Val;
    use p3_field::PrimeCharacteristicRing;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn every_element_of_pk_is_checked() {
        let system = Plonky3::from_rng(&mut StdRng::seed_from_u64(1));
        let sk = SecretKey::random(&mut StdRng::seed_from_u64(2));
        let statement = SetupStatement::for_key(&sk);
        let proof = system.prove(&statement, &sk).expect("proving");
        system.verify(&statement, &proof).expect("verifying");
        for i in 0..statement.pk.0.len() {
            let mut pk = statement.pk;
            pk.0[i] += Val::ONE;
            assert!(
                system.verify(&SetupStatement { pk }, &proof).is_err(),
                "element {i} of pk is not checked"
            );
        }
    }
}
