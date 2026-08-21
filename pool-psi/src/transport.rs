//! Wire transport for the PSI messages that sit around the OPRF.
//!
//! PSI adds two messages to the OPRF exchange: the client's set size up front,
//! so both sides size preprocessing identically, and the server's
//! [`MaskedServerSet`] afterwards.

use crate::error::PsiError;
use crate::protocol::MaskedServerSet;
use cryprot_net::{Connection, ReceiveStream, SendStream};
use futures::{SinkExt, StreamExt};

/// The client's end: announces its set size, receives the masked set.
pub struct ClientChannel {
    tx: SendStream<u64>,
    rx: ReceiveStream<MaskedServerSet>,
}

impl ClientChannel {
    /// Open the channel on a sub-connection of `conn`.
    pub async fn new(conn: &mut Connection) -> Result<Self, PsiError> {
        let (tx, rx) = conn.sub_connection().request_response_stream().await?;
        Ok(Self { tx, rx })
    }

    /// Announce how many elements this client will evaluate.
    ///
    /// Sent before preprocessing, since both sides derive `tau` from it. They
    /// refuse to run if they disagree - each states its own `tau` and gets
    /// `PreprocError::TauMismatch` before any OT starts. This message is what
    /// lets them agree in the first place: only the client knows its set size,
    /// so without it the server has nothing to size from.
    pub async fn send_client_set_size(&mut self, set_size: u64) -> Result<(), PsiError> {
        self.tx.send(set_size).await?;
        Ok(())
    }

    pub async fn recv_set(&mut self) -> Result<MaskedServerSet, PsiError> {
        self.rx
            .next()
            .await
            .ok_or(PsiError::UnexpectedClose)?
            .map_err(Into::into)
    }
}

/// The server's end: receives the client's set size, sends the masked set.
pub struct ServerChannel {
    tx: SendStream<MaskedServerSet>,
    rx: ReceiveStream<u64>,
}

impl ServerChannel {
    /// Open the channel on a sub-connection of `conn`.
    pub async fn new(conn: &mut Connection) -> Result<Self, PsiError> {
        let (tx, rx) = conn.sub_connection().request_response_stream().await?;
        Ok(Self { tx, rx })
    }

    /// How many elements the client says it will evaluate.
    pub async fn recv_client_set_size(&mut self) -> Result<u64, PsiError> {
        self.rx
            .next()
            .await
            .ok_or(PsiError::UnexpectedClose)?
            .map_err(Into::into)
    }

    pub async fn send_set(&mut self, set: MaskedServerSet) -> Result<(), PsiError> {
        self.tx.send(set).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{MAX_SERVER_SET, MaskedElement};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    #[tokio::test]
    async fn a_maximum_server_set_can_be_sent() {
        let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let mut rng = StdRng::seed_from_u64(1);
        let set = MaskedServerSet {
            tag: b"tag-1".to_vec(),
            elements: (0..MAX_SERVER_SET)
                .map(|_| rng.random::<MaskedElement>())
                .collect(),
        };

        let (client, server) = tokio::join!(
            ClientChannel::new(&mut client_conn),
            ServerChannel::new(&mut server_conn),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        let (got, sent) = tokio::join!(client.recv_set(), server.send_set(set));
        sent.expect("a maximum-size set did not fit");
        let got = got.expect("a maximum-size set did not fit");
        assert_eq!(got.elements.len(), MAX_SERVER_SET);
    }
}
