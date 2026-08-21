//! Full-protocol test: PreProc (Figure 3) followed by Request, BlindEval and
//! Finalize (Figure 4) must reproduce the plaintext PRF.
//!
//! This runs over a real connection and uses only the crate's public API, so
//! it also checks that the public surface is enough to drive the protocol.

use pool_oprf::client::{ClientError, OprfClient};
use pool_oprf::online::{blind_eval, finalize, request};
use pool_oprf::preprocessing::{PreprocError, preproc_client, preproc_server, tau_for};
use pool_oprf::server::OprfServer;
use pool_prf::prf::{SecretKey, evaluate};
use rand::{SeedableRng, rngs::StdRng};

/// The public tag, where its value does not matter to the test.
const TAG: &[u8] = b"tag-1";

#[tokio::test]
async fn oprf_matches_plaintext_prf() {
    let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let mut client_rng = StdRng::seed_from_u64(1);
    let mut server_rng = StdRng::seed_from_u64(2);
    let sk = SecretKey::random(&mut server_rng);

    let evaluations = 3;
    let tau = tau_for(evaluations);

    let (mut client_state, mut server_state) = tokio::try_join!(
        preproc_client(&mut client_conn, tau, &mut client_rng),
        preproc_server(&mut server_conn, &sk, tau),
    )
    .unwrap();
    assert_eq!(client_state.uid(), server_state.uid());

    // "alice" twice, on different slots and so under different masks. A PRF
    // must give the same answer both times, which it only does if the blinding
    // is removed exactly.
    for x in [b"alice".as_slice(), b"bob".as_slice(), b"alice".as_slice()] {
        let (req, fin) = request(&mut client_state, TAG, x).unwrap();
        let resp = blind_eval(&mut server_state, &sk, &req).unwrap();
        let z = finalize(&fin, &resp).unwrap();
        assert_eq!(z, evaluate(&sk, TAG, x), "input {x:?}");
    }

    // Both sides consumed the same amount.
    assert_eq!(client_state.remaining_slots(), 0);
    assert_eq!(server_state.remaining_slots(), 0);

    // A fourth evaluation fails.
    assert!(request(&mut client_state, TAG, b"carol").is_err());
}

/// The server must not learn the input: the request carries no usable trace of
/// it. Weak as a privacy statement, but it does catch a Request that forgets
/// to blind - the plain hash rows must not appear on the wire.
#[tokio::test]
async fn request_does_not_leak_the_hash_rows() {
    use pool_prf::hash::hash_to_zq_matrix;

    let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let mut client_rng = StdRng::seed_from_u64(3);
    let mut server_rng = StdRng::seed_from_u64(4);
    let sk = SecretKey::random(&mut server_rng);
    let tau = tau_for(1);

    let (mut client_state, _server) = tokio::try_join!(
        preproc_client(&mut client_conn, tau, &mut client_rng),
        preproc_server(&mut server_conn, &sk, tau),
    )
    .unwrap();

    let x = b"secret input";
    let (blinded, _) = request(&mut client_state, TAG, x).unwrap();
    let plain = hash_to_zq_matrix(TAG, x);

    for (k, blinded_row) in blinded.rows.iter().enumerate() {
        assert_ne!(
            blinded_row.e.as_slice(),
            plain.row(k).as_slice(),
            "row {k} is unblinded"
        );
    }
    // The tag, by contrast, is public and travels as-is.
    assert_eq!(blinded.tag, TAG);
}

#[tokio::test]
async fn networked_oprf_matches_plaintext_prf() {
    let (server_conn, client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let mut client_rng = StdRng::seed_from_u64(5);
    let mut server_rng = StdRng::seed_from_u64(6);
    let sk = SecretKey::random(&mut server_rng);
    let server = OprfServer::new(sk.clone());

    let evaluations = 3;

    let (client, session) = tokio::join!(
        OprfClient::new(client_conn, evaluations, &mut client_rng),
        server.session(server_conn, evaluations),
    );
    let mut client = client.unwrap();
    let mut session = session.unwrap();

    assert_eq!(client.uid(), session.uid());
    assert_eq!(client.remaining_evaluations(), evaluations);
    assert_eq!(session.remaining_evaluations(), evaluations);

    let inputs: [&[u8]; 3] = [b"alice", b"bob", b"alice"];

    let client_side = async {
        let mut outputs = Vec::new();
        for x in inputs {
            outputs.push(client.evaluate(TAG, x).await.unwrap());
        }
        outputs
    };
    let server_side = async {
        for _ in 0..inputs.len() {
            assert!(session.serve_next().await.unwrap(), "client closed early");
        }
    };
    let (outputs, ()) = tokio::join!(client_side, server_side);

    // OPRF outputs match the plaintext PRF ones.
    for (x, out) in inputs.into_iter().zip(&outputs) {
        assert_eq!(*out, evaluate(&sk, TAG, x), "input {x:?}");
    }
    // Same input on different slots must still give the same output.
    assert_eq!(outputs[0], outputs[2]);

    assert_eq!(client.remaining_evaluations(), 0);
    assert_eq!(session.remaining_evaluations(), 0);
}

#[tokio::test]
async fn networked_client_stops_when_preprocessing_runs_out() {
    let (server_conn, client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let mut client_rng = StdRng::seed_from_u64(7);
    let mut server_rng = StdRng::seed_from_u64(8);
    let sk = SecretKey::random(&mut server_rng);
    let server = OprfServer::new(sk.clone());
    let (client, session) = tokio::join!(
        OprfClient::new(client_conn, 1, &mut client_rng),
        server.session(server_conn, 1),
    );
    let mut client = client.unwrap();
    let mut session = session.unwrap();

    let client_side = async {
        let first = client.evaluate(TAG, b"alice").await.unwrap();
        // Second must fail locally, without a round trip.
        let second = client.evaluate(TAG, b"bob").await;
        (first, second)
    };
    let server_side = async { session.serve_next().await.unwrap() };
    let ((first, second), served) = tokio::join!(client_side, server_side);

    assert!(served);
    assert_eq!(first, evaluate(&sk, TAG, b"alice"));
    assert!(matches!(second, Err(ClientError::Request(_))), "{second:?}");
    assert_eq!(client.remaining_evaluations(), 0);
    assert_eq!(session.remaining_evaluations(), 0);
}

#[tokio::test]
async fn a_renewed_session_keeps_serving() {
    let (server_conn, client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let mut client_rng = StdRng::seed_from_u64(60);
    let mut server_rng = StdRng::seed_from_u64(61);
    let sk = SecretKey::random(&mut server_rng);
    let server = OprfServer::new(sk.clone());
    let (client, session) = tokio::join!(
        OprfClient::new(client_conn, 1, &mut client_rng),
        server.session(server_conn, 1),
    );
    let mut client = client.unwrap();
    let mut session = session.unwrap();
    let old_uid = *client.uid();

    // Spend the session.
    let (first, served) = tokio::join!(client.evaluate(TAG, b"alice"), session.serve_next());
    assert_eq!(first.unwrap(), evaluate(&sk, TAG, b"alice"));
    assert!(served.unwrap());
    assert_eq!(client.remaining_evaluations(), 0);

    // Renew.
    let (client_uid, session_uid) =
        tokio::join!(client.renew(1, &mut client_rng), session.renew(1),);
    let new_uid = client_uid.unwrap();
    assert_eq!(new_uid, session_uid.unwrap(), "both sides agree on the uid");
    assert_ne!(new_uid, old_uid, "renewal starts a new session");
    assert_eq!(client.remaining_evaluations(), 1);
    assert_eq!(session.uid(), &new_uid, "the spent session is replaced");
    assert_eq!(session.remaining_evaluations(), 1);

    // The evaluation channel from before the renewal still works.
    let (second, served) = tokio::join!(client.evaluate(TAG, b"bob"), session.serve_next());
    assert_eq!(second.unwrap(), evaluate(&sk, TAG, b"bob"));
    assert!(served.unwrap());
}

#[tokio::test]
async fn preprocessing_rejects_a_tau_mismatch() {
    let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let mut client_rng = StdRng::seed_from_u64(50);
    let mut server_rng = StdRng::seed_from_u64(51);
    let sk = SecretKey::random(&mut server_rng);

    let (client, server) = tokio::join!(
        preproc_client(&mut client_conn, tau_for(2), &mut client_rng),
        preproc_server(&mut server_conn, &sk, tau_for(3)),
    );

    match client {
        Err(PreprocError::TauMismatch { ours, theirs }) => {
            assert_eq!((ours, theirs), (tau_for(2), tau_for(3)));
        }
        _ => panic!("the client must reject a tau mismatch"),
    }
    match server {
        Err(PreprocError::TauMismatch { ours, theirs }) => {
            assert_eq!((ours, theirs), (tau_for(3), tau_for(2)));
        }
        _ => panic!("the server must reject a tau mismatch"),
    }
}

#[tokio::test]
async fn preprocessing_rejects_a_zero_tau() {
    let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let mut rng = StdRng::seed_from_u64(52);
    let sk = SecretKey::random(&mut rng);

    let client_state = preproc_client(&mut client_conn, 0, &mut rng).await;
    assert!(matches!(client_state, Err(PreprocError::ZeroTau)));

    let server_state = preproc_server(&mut server_conn, &sk, 0).await;
    assert!(matches!(server_state, Err(PreprocError::ZeroTau)));
}

#[tokio::test]
async fn networked_batch_matches_plaintext_prf() {
    let (server_conn, client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let mut client_rng = StdRng::seed_from_u64(30);
    let mut server_rng = StdRng::seed_from_u64(31);
    let sk = SecretKey::random(&mut server_rng);

    let inputs: [&[u8]; 5] = [b"alice", b"bob", b"carol", b"dave", b"alice"];
    let server = OprfServer::new(sk.clone());
    let (client, session) = tokio::join!(
        OprfClient::new(client_conn, inputs.len(), &mut client_rng),
        server.session(server_conn, inputs.len()),
    );
    let mut client = client.unwrap();
    let mut session = session.unwrap();

    let (outputs, served) = tokio::join!(client.evaluate_batch(TAG, &inputs), session.serve_next());
    let outputs = outputs.unwrap();
    assert!(served.unwrap(), "client closed early");

    assert_eq!(outputs.len(), inputs.len());
    for (x, out) in inputs.iter().zip(&outputs) {
        assert_eq!(*out, evaluate(&sk, TAG, x), "input {x:?}");
    }
    assert_eq!(outputs[0], outputs[4]);
    assert_eq!(client.remaining_evaluations(), 0);
    assert_eq!(session.remaining_evaluations(), 0);
}

#[tokio::test]
async fn two_connections_share_one_key() {
    let (server_conn_a, client_conn_a) = cryprot_net::testing::local_conn().await.unwrap();
    let (server_conn_b, client_conn_b) = cryprot_net::testing::local_conn().await.unwrap();
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(20));
    let server = OprfServer::new(sk.clone());
    let evaluations = 2;

    let mut rng_ca = StdRng::seed_from_u64(21);
    let mut rng_cb = StdRng::seed_from_u64(23);

    let (client_a, session_a) = tokio::join!(
        OprfClient::new(client_conn_a, evaluations, &mut rng_ca),
        server.session(server_conn_a, evaluations),
    );
    let (client_b, session_b) = tokio::join!(
        OprfClient::new(client_conn_b, evaluations, &mut rng_cb),
        server.session(server_conn_b, evaluations),
    );
    let (mut client_a, mut session_a) = (client_a.unwrap(), session_a.unwrap());
    let (mut client_b, mut session_b) = (client_b.unwrap(), session_b.unwrap());

    assert_ne!(session_a.uid(), session_b.uid());

    let ((out_a, out_b), (), ()) = tokio::join!(
        async {
            let a = client_a.evaluate(TAG, b"shared").await.unwrap();
            let b = client_b.evaluate(TAG, b"shared").await.unwrap();
            (a, b)
        },
        async { session_a.serve_next().await.map(|_| ()).unwrap() },
        async { session_b.serve_next().await.map(|_| ()).unwrap() },
    );

    let expected = evaluate(&sk, TAG, b"shared");
    assert_eq!(out_a, expected);
    assert_eq!(out_b, expected);

    // One evaluation each consumed, from its own session.
    assert_eq!(session_a.remaining_evaluations(), 1);
    assert_eq!(session_b.remaining_evaluations(), 1);
}
