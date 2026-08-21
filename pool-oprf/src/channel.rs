//! Channels to sends and receive messages to a peer.
//!
//! A channel has a pair of streams, a rx and tx one.
//!
//! [`ClientChannel`] sends a request and waits for the response.
//! [`ServerChannel`] waits for a request and sends a response.

use crate::online::{RequestMessage, ResponseMessage};
use cryprot_net::{Connection, ConnectionError, ReceiveStream, SendStream};
use futures::{SinkExt, StreamExt};

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("establishing the stream failed")]
    Connection(#[from] ConnectionError),
    #[error("sending or receiving a message failed")]
    Io(#[from] std::io::Error),
    #[error("peer closed the stream unexpectedly")]
    UnexpectedClose,
}

pub struct ClientChannel {
    tx: SendStream<RequestMessage>,
    rx: ReceiveStream<ResponseMessage>,
}

impl ClientChannel {
    pub async fn new(conn: &mut Connection) -> Result<Self, ChannelError> {
        let (tx, rx) = conn.request_response_stream().await?;
        Ok(Self { tx, rx })
    }

    /// Send a request and wait for its response.
    pub async fn exchange(&mut self, req: RequestMessage) -> Result<ResponseMessage, ChannelError> {
        self.tx.send(req).await?;
        let resp = self
            .rx
            .next()
            .await
            .ok_or(ChannelError::UnexpectedClose)??;
        Ok(resp)
    }
}

pub struct ServerChannel {
    tx: SendStream<ResponseMessage>,
    rx: ReceiveStream<RequestMessage>,
}

impl ServerChannel {
    pub async fn new(conn: &mut Connection) -> Result<Self, ChannelError> {
        let (tx, rx) = conn.request_response_stream().await?;
        Ok(Self { tx, rx })
    }

    /// Wait for the next request, or `None` once the client is done.
    pub async fn next_request(&mut self) -> Result<Option<RequestMessage>, ChannelError> {
        match self.rx.next().await {
            Some(req) => Ok(Some(req?)),
            None => Ok(None),
        }
    }

    pub async fn respond(&mut self, resp: ResponseMessage) -> Result<(), ChannelError> {
        self.tx.send(resp).await?;
        Ok(())
    }
}
