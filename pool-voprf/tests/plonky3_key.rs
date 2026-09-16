#![cfg(feature = "plonky3")]

use pool_prf::prf::SecretKey;
use pool_voprf::key::KeyStatement;
use pool_voprf::plonky3::{Plonky3, ProveError, VerifyError};
use pool_voprf::proof::ProofSystem;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

fn system() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(1))
}

#[test]
fn proves_and_verifies_the_committed_key() {
    let system = system();
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(2));
    let statement = KeyStatement::for_key(&sk);

    let started = Instant::now();
    let proof = system.prove(&statement, &sk).expect("proving");
    let proving = started.elapsed();
    let bytes = bincode::serialize(&proof).expect("serializing");

    let started = Instant::now();
    system.verify(&statement, &proof).expect("verifying");
    let verifying = started.elapsed();

    let (conjectured, proven) = system.security(&proof);
    eprintln!(
        "prove {proving:?}, verify {verifying:?}, proof {} bytes, security {conjectured:?} {proven:?}",
        bytes.len()
    );
}

#[test]
fn refuses_to_prove_with_a_key_that_does_not_open_pk() {
    let system = system();
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(3));
    let other = SecretKey::random(&mut StdRng::seed_from_u64(4));
    assert!(matches!(
        system.prove(&KeyStatement::for_key(&other), &sk),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn rejects_the_commitment_of_another_key() {
    let system = system();
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(5));
    let other = SecretKey::random(&mut StdRng::seed_from_u64(6));
    let proof = system
        .prove(&KeyStatement::for_key(&sk), &sk)
        .expect("proving");
    assert!(matches!(
        system.verify(&KeyStatement::for_key(&other), &proof),
        Err(VerifyError::Invalid(_))
    ));
}

#[test]
fn a_proof_survives_serialization() {
    let system = system();
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(7));
    let statement = KeyStatement::for_key(&sk);
    let proof = system.prove(&statement, &sk).expect("proving");
    let bytes = bincode::serialize(&proof).expect("serializing");
    let proof = bincode::deserialize(&bytes).expect("deserializing");
    system.verify(&statement, &proof).expect("verifying");
}

#[test]
fn rejects_a_tampered_proof() {
    let system = system();
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(8));
    let statement = KeyStatement::for_key(&sk);
    let proof = system.prove(&statement, &sk).expect("proving");
    let mut bytes = bincode::serialize(&proof).expect("serializing");
    // Somewhere in the opened values, after the commitments.
    let at = bytes.len() / 3;
    bytes[at] ^= 0x55;
    if let Ok(proof) = bincode::deserialize(&bytes) {
        assert!(system.verify(&statement, &proof).is_err());
    }
}

#[test]
fn a_verifier_needs_no_shared_randomness() {
    let prover = Plonky3::from_rng(&mut StdRng::seed_from_u64(9));
    let verifier = Plonky3::from_rng(&mut StdRng::seed_from_u64(10));
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(11));
    let statement = KeyStatement::for_key(&sk);
    let proof = prover.prove(&statement, &sk).expect("proving");
    verifier.verify(&statement, &proof).expect("verifying");
}

#[test]
fn every_byte_of_pk_is_checked() {
    let system = system();
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(12));
    let statement = KeyStatement::for_key(&sk);
    let proof = system.prove(&statement, &sk).expect("proving");
    for i in 0..statement.pk.0.len() {
        let mut pk = statement.pk;
        pk.0[i] ^= 1;
        assert!(
            system.verify(&KeyStatement { pk }, &proof).is_err(),
            "byte {i} of pk is not checked"
        );
    }
}
