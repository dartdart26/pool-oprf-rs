//! VOPRF over the public API: the server proves, the client verifies.

use pool_oprf::client::OprfClient;
use pool_oprf::preprocessing::{PreprocError, preproc_client_voprf, preproc_server, tau_for};
use pool_oprf::server::OprfServer;
use pool_oprf::testing::verified_key;
use pool_oprf::voprf::{MAX_VOPRF_BATCH_EVALUATIONS, VerifiedKey, VerifyError};
use pool_prf::prf::{SecretKey, evaluate};
use rand::{SeedableRng, rngs::StdRng};

/// The public tag.
const TAG: &[u8] = b"tag-1";

fn server(seed: u64) -> OprfServer {
    OprfServer::new(SecretKey::random(&mut StdRng::seed_from_u64(seed)))
}

#[test]
fn a_client_takes_the_pk_of_the_server() {
    let (pk, proof) = server(1).public_key().expect("proving");
    VerifiedKey::verify(pk, &proof).expect("verifying");
}

#[test]
fn a_client_refuses_a_pk_with_the_proof_of_another_key() {
    let (pk, _) = server(2).public_key().expect("proving");
    let (_, proof) = server(3).public_key().expect("proving");
    assert!(matches!(
        VerifiedKey::verify(pk, &proof),
        Err(VerifyError::Invalid(_))
    ));
}

#[tokio::test]
async fn a_maximum_voprf_batch_works() {
    let (server_conn, client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let server = server(4);
    let pk = verified_key(server.key());
    let inputs: Vec<String> = (0..MAX_VOPRF_BATCH_EVALUATIONS)
        .map(|i| format!("input-{i}"))
        .collect();

    let mut rng = StdRng::seed_from_u64(5);
    let (client, session) = tokio::join!(
        OprfClient::new_voprf(client_conn, &pk, inputs.len(), &mut rng),
        server.session(server_conn, inputs.len()),
    );
    let mut client = client.expect("client preprocessing");
    let mut session = session.expect("server preprocessing");

    let (outputs, served) = tokio::join!(client.evaluate_batch(TAG, &inputs), session.serve_next());
    assert!(served.unwrap(), "client closed early");
    for (x, output) in inputs.iter().zip(outputs.unwrap()) {
        assert_eq!(
            output,
            evaluate(server.key(), TAG, x.as_bytes()),
            "input {x}"
        );
    }
}

#[tokio::test]
async fn a_client_refuses_the_preprocessing_under_another_key() {
    let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let other_pk = verified_key(server(6).key());
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(7));

    let mut rng = StdRng::seed_from_u64(8);
    let (client, server) = tokio::join!(
        preproc_client_voprf(&mut client_conn, &other_pk, tau_for(1), &mut rng),
        preproc_server(&mut server_conn, &sk, tau_for(1)),
    );
    server.expect("server preprocessing");
    assert!(matches!(client, Err(PreprocError::Verify(_))));
}

#[tokio::test]
async fn a_client_refuses_a_voprf_for_less_than_one_evaluation() {
    let (_server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let pk = verified_key(server(9).key());
    let tau = tau_for(1) - 1;

    let mut rng = StdRng::seed_from_u64(10);
    let client = preproc_client_voprf(&mut client_conn, &pk, tau, &mut rng).await;
    assert!(matches!(
        client,
        Err(PreprocError::VoprfTauTooSmall { tau: got }) if got == tau
    ));
}
