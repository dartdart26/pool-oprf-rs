//! Full PSI runs over a real connection, using only the crate's public API.

use pool_prf::prf::SecretKey;
use pool_psi::client::PsiClient;
use pool_psi::error::PsiError;
use pool_psi::server::{PsiServer, PsiSession};
use rand::{SeedableRng, rngs::StdRng};

const TAG: &[u8] = b"tag-1";

/// Both halves of a run, from a fresh local connection.
async fn setup(set_size: usize, seed: u64) -> (PsiClient, PsiSession, SecretKey) {
    let (server_conn, client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let (mut client_rng, mut server_rng) = (
        StdRng::seed_from_u64(seed),
        StdRng::seed_from_u64(seed + 1000),
    );
    let sk = SecretKey::random(&mut server_rng);
    let server = PsiServer::new(sk.clone());

    let (client, session) = tokio::try_join!(
        PsiClient::new(client_conn, set_size, &mut client_rng),
        server.session(server_conn),
    )
    .unwrap();

    (client, session, sk)
}

#[tokio::test]
async fn client_learns_the_intersection() {
    let client_set: [&[u8]; 4] = [b"alice", b"bob", b"carol", b"dave"];
    let server_set: [&[u8]; 3] = [b"bob", b"dave", b"erin"];

    let (client, mut session, sk) = setup(client_set.len(), 1).await;
    assert_eq!(session.set_size(), client_set.len());
    assert_eq!(client.uid(), session.uid());

    let (indices, ()) = tokio::try_join!(
        client.intersect(&client_set),
        session.serve(&sk, TAG, &server_set),
    )
    .unwrap();

    // bob is index 1, dave is index 3.
    assert_eq!(indices, vec![1, 3]);

    assert_eq!(session.remaining_evaluations(), 0);
}

#[tokio::test]
async fn disjoint_sets_intersect_to_nothing() {
    let client_set: [&[u8]; 2] = [b"alice", b"carol"];
    let server_set: [&[u8]; 2] = [b"bob", b"dave"];

    let (client, mut session, sk) = setup(client_set.len(), 2).await;
    let (indices, ()) = tokio::try_join!(
        client.intersect(&client_set),
        session.serve(&sk, TAG, &server_set),
    )
    .unwrap();

    assert!(indices.is_empty());
}

async fn connect(server: &PsiServer, set_size: usize, seed: u64) -> (PsiClient, PsiSession) {
    let (server_conn, client_conn) = cryprot_net::testing::local_conn().await.unwrap();
    let mut crng = StdRng::seed_from_u64(seed);

    tokio::try_join!(
        PsiClient::new(client_conn, set_size, &mut crng),
        server.session(server_conn),
    )
    .unwrap()
}

#[tokio::test]
async fn two_clients_share_one_key() {
    let server_set: [&[u8]; 3] = [b"bob", b"dave", b"erin"];
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(7));
    let server = PsiServer::new(sk);
    let masked = server.mask(TAG, server_set);

    // Deliberately different sizes: `tau` follows the set size each client
    // announced, so the two sessions hold different numbers of slots and each
    // has to be charged against its own.
    let big: [&[u8]; 5] = [b"alice", b"bob", b"carol", b"dave", b"frank"];
    let small: [&[u8]; 2] = [b"erin", b"mallory"];

    let (client_a, mut session_a) = connect(&server, big.len(), 30).await;
    let (client_b, mut session_b) = connect(&server, small.len(), 40).await;

    assert_ne!(session_a.uid(), session_b.uid());
    assert_eq!(session_a.set_size(), big.len());
    assert_eq!(session_b.set_size(), small.len());

    let (found_a, (), found_b, ()) = tokio::try_join!(
        client_a.intersect(&big),
        session_a.serve_masked(TAG, &masked),
        client_b.intersect(&small),
        session_b.serve_masked(TAG, &masked),
    )
    .unwrap();

    assert_eq!(found_a, vec![1, 3]);
    assert_eq!(found_b, vec![0]);
    assert_eq!(session_a.remaining_evaluations(), 0);
    assert_eq!(session_b.remaining_evaluations(), 0);
}

#[tokio::test]
async fn a_finished_session_leaves_the_others_alone() {
    let server_set: [&[u8]; 2] = [b"bob", b"erin"];
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(8));
    let server = PsiServer::new(sk);
    let masked = server.mask(TAG, server_set);

    let first: [&[u8]; 3] = [b"alice", b"bob", b"carol"];
    let second: [&[u8]; 2] = [b"erin", b"dave"];

    let (client_a, mut session_a) = connect(&server, first.len(), 50).await;
    let (client_b, mut session_b) = connect(&server, second.len(), 60).await;

    let (found_a, ()) = tokio::try_join!(
        client_a.intersect(&first),
        session_a.serve_masked(TAG, &masked),
    )
    .unwrap();
    assert_eq!(found_a, vec![1]);

    assert_eq!(session_a.remaining_evaluations(), 0, "A spent its own");
    assert_eq!(
        session_b.remaining_evaluations(),
        second.len(),
        "B must still hold everything it preprocessed for"
    );

    // And B can still run, on slots a completed run did not touch.
    let (found_b, ()) = tokio::try_join!(
        client_b.intersect(&second),
        session_b.serve_masked(TAG, &masked),
    )
    .unwrap();
    assert_eq!(found_b, vec![0]);
    assert_eq!(session_b.remaining_evaluations(), 0);
}

#[tokio::test]
async fn a_set_of_the_wrong_size_is_rejected() {
    let (client, _session, _sk) = setup(3, 5).await;

    let too_many: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
    let err = client.intersect(&too_many).await.unwrap_err();
    assert!(
        matches!(
            err,
            PsiError::SetSizeMismatch {
                expected: 3,
                got: 4
            }
        ),
        "{err}"
    );
}
