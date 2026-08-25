//! Server side of the OPRF.
//!
//! [`OprfServer`] is long-lived: one key, any number of clients. Each
//! connection becomes an [`OprfSession`] holding the preprocessing it did.
//!
//! The server does not keep a table of those sessions - each is owned by the
//! task driving its connection and dies with it. So nothing has to evict
//! them, and a request can only ever spend the slots of the connection it
//! arrived on.

use crate::channel::{ChannelError, ServerChannel};
use crate::online::{BlindEvalError, blind_eval};
use crate::preprocessing::{
    PreprocError, ServerState, Uid, evaluations_for, preproc_server, tau_for,
};
use cryprot_net::Connection;
use pool_prf::prf::SecretKey;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("preprocessing failed")]
    Preproc(#[from] PreprocError),
    #[error("transport failed")]
    Channel(#[from] ChannelError),
    #[error("evaluating the request failed")]
    BlindEval(#[from] BlindEvalError),
}

#[derive(Clone)]
pub struct OprfServer {
    sk: Arc<SecretKey>,
}

impl OprfServer {
    pub fn new(sk: SecretKey) -> Self {
        Self { sk: Arc::new(sk) }
    }

    /// Run PreProc (Figure 3) with one client and open its online channel.
    ///
    /// Preprocesses for `evaluations` full OPRF evaluations. The peer must
    /// call [`crate::client::OprfClient::new`] with the same number.
    pub async fn session(
        &self,
        mut conn: Connection,
        evaluations: usize,
    ) -> Result<OprfSession, ServerError> {
        let state = preproc_server(&mut conn, &self.sk, tau_for(evaluations)).await?;
        let channel = ServerChannel::new(&mut conn).await?;
        Ok(OprfSession {
            conn,
            channel,
            sk: Arc::clone(&self.sk),
            state,
        })
    }

    pub fn key(&self) -> &SecretKey {
        &self.sk
    }
}

/// One client connection, with the preprocessing it did.
///
/// The slots live exactly as long as this does, so nothing has to evict them
/// and a request can only ever spend its own session's.
pub struct OprfSession {
    conn: Connection,
    channel: ServerChannel,
    sk: Arc<SecretKey>,
    state: ServerState,
}

impl OprfSession {
    /// Preprocess again on the same connection, replacing this session.
    ///
    /// Returns the new `uid`. The peer must call [`OprfClient::renew`] at the
    /// same point with the same number of evaluations. The online channel is
    /// untouched, so requests continue over it afterwards. A failed renewal
    /// leaves the old session in place, still serving.
    ///
    /// [`OprfClient::renew`]: crate::client::OprfClient::renew
    pub async fn renew(&mut self, evaluations: usize) -> Result<Uid, ServerError> {
        self.state = preproc_server(&mut self.conn, &self.sk, tau_for(evaluations)).await?;
        Ok(*self.state.uid())
    }

    /// Answer one request. Returns `false` once the client closes the stream.
    pub async fn serve_next(&mut self) -> Result<bool, ServerError> {
        let Some(req) = self.channel.next_request().await? else {
            return Ok(false);
        };
        if req.uid != *self.state.uid() {
            return Err(BlindEvalError::UnknownSession { uid: req.uid }.into());
        }
        let resp = blind_eval(&mut self.state, &self.sk, &req)?;
        self.channel.respond(resp).await?;
        Ok(true)
    }

    /// Answer requests until the client disconnects.
    pub async fn serve(&mut self) -> Result<(), ServerError> {
        while self.serve_next().await? {}
        Ok(())
    }

    pub fn remaining_evaluations(&self) -> usize {
        evaluations_for(self.state.remaining_slots())
    }

    pub fn uid(&self) -> &Uid {
        self.state.uid()
    }

    pub fn key(&self) -> &SecretKey {
        &self.sk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ClientChannel;
    use crate::online::{RequestMessage, RowRequest};
    use crate::preprocessing::preproc_client;
    use pool_prf::params::{H_ROWS, LAMBDA_BYTES, N};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const TAG: &[u8] = b"tag-1";

    /// `rows` all-zero rows. Every rejection here is decided before a row is
    /// read, so the values never matter.
    fn zero_rows(uid: Uid, rows: usize) -> RequestMessage {
        RequestMessage {
            uid,
            tag: TAG.to_vec(),
            rows: vec![
                RowRequest {
                    e: [0; N],
                    b_bar_prime: 0,
                };
                rows
            ],
        }
    }

    /// `request` already checks the client's own count, so testing the
    /// server's needs a client that skips it: this one puts a two-evaluation
    /// request on the wire against a one-evaluation session.
    ///
    /// Serving it would spend a slot twice.
    #[tokio::test]
    async fn rejects_a_request_beyond_its_remaining_slots() {
        let (server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let mut client_rng = StdRng::seed_from_u64(40);
        let mut server_rng = StdRng::seed_from_u64(41);
        let server = OprfServer::new(SecretKey::random(&mut server_rng));
        // The client half by hand, in `OprfServer::session`'s order. One
        // evaluation on both sides, counted in slots here and evaluations there.
        let (client, session) = tokio::join!(
            async {
                let state = preproc_client(&mut client_conn, tau_for(1), &mut client_rng)
                    .await
                    .unwrap();
                let channel = ClientChannel::new(&mut client_conn).await.unwrap();
                (state, channel)
            },
            server.session(server_conn, 1),
        );
        let (client_state, mut channel) = client;
        let mut session = session.unwrap();

        let req = zero_rows(*client_state.uid(), 2 * H_ROWS);

        // No answer ever comes, so `exchange` never resolves; `select!` drops it.
        tokio::select! {
            served = session.serve_next() => {
                let err = served.unwrap_err();
                assert!(
                    matches!(
                        err,
                        ServerError::BlindEval(BlindEvalError::Exhausted { .. })
                    ),
                    "{err}"
                );
            }
            _ = channel.exchange(req) => panic!("the server must not answer an over-budget request"),
        }

        // Refused without charging the session.
        assert_eq!(session.remaining_evaluations(), 1);
    }

    #[tokio::test]
    async fn rejects_a_request_for_another_session() {
        let (server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let mut client_rng = StdRng::seed_from_u64(42);
        let mut server_rng = StdRng::seed_from_u64(43);
        let server = OprfServer::new(SecretKey::random(&mut server_rng));
        let (mut channel, session) = tokio::join!(
            async {
                let _state = preproc_client(&mut client_conn, tau_for(1), &mut client_rng)
                    .await
                    .unwrap();
                ClientChannel::new(&mut client_conn).await.unwrap()
            },
            server.session(server_conn, 1),
        );
        let mut session = session.unwrap();

        let req = zero_rows([0xff; LAMBDA_BYTES], H_ROWS);
        assert_ne!(&req.uid, session.uid());

        tokio::select! {
            served = session.serve_next() => {
                let err = served.unwrap_err();
                assert!(
                    matches!(
                        err,
                        ServerError::BlindEval(BlindEvalError::UnknownSession { .. })
                    ),
                    "{err}"
                );
            }
            _ = channel.exchange(req) => panic!("the server must not answer for another session"),
        }

        assert_eq!(session.remaining_evaluations(), 1);
    }
}
