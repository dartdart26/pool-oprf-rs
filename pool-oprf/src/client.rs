//! Networked OPRF client with preprocessing plus the online phase over a
//! [`Connection`].
//!
//! A caller that owns its own transport can use [`crate::online`]'s `request`
//! and `finalize` directly, with no async runtime; this type is the
//! convenience layer over a cryprot-net connection.

use crate::channel::{ChannelError, ClientChannel};
use crate::online::{
    FinalizeError, RequestError, finalize, finalize_batch, request, request_batch,
};
use crate::preprocessing::{
    ClientState, PreprocError, Uid, evaluations_for, preproc_client, tau_for,
};
use cryprot_net::Connection;
use pool_prf::prf::PrfOutput;
use rand::{CryptoRng, Rng};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("preprocessing failed")]
    Preproc(#[from] PreprocError),
    #[error("transport failed")]
    Channel(#[from] ChannelError),
    #[error("building the request failed")]
    Request(#[from] RequestError),
    #[error("finalizing the response failed")]
    Finalize(#[from] FinalizeError),
}

pub struct OprfClient {
    conn: Connection,
    channel: ClientChannel,
    state: ClientState,
}

impl OprfClient {
    /// Run PreProc (Figure 3) and open the online channel.
    ///
    /// Preprocesses for `evaluations` full OPRF evaluations. The peer must
    /// call [`crate::server::OprfServer::session`] with the same number.
    pub async fn new(
        mut conn: Connection,
        evaluations: usize,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Self, ClientError> {
        let state = preproc_client(&mut conn, tau_for(evaluations), rng).await?;
        let channel = ClientChannel::new(&mut conn).await?;
        Ok(Self {
            conn,
            channel,
            state,
        })
    }

    /// Preprocess again on the same connection, replacing this session.
    ///
    /// Returns the new `uid`. The peer must call [`OprfSession::renew`] at the
    /// same point with the same number of evaluations. The online
    /// channel is untouched, so requests continue over it afterwards.
    ///
    /// [`OprfSession::renew`]: crate::server::OprfSession::renew
    pub async fn renew(
        &mut self,
        evaluations: usize,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Uid, ClientError> {
        self.state = preproc_client(&mut self.conn, tau_for(evaluations), rng).await?;
        Ok(*self.state.uid())
    }

    /// Evaluate the OPRF on public tag `tag` and private input `x`, consuming
    /// one of the session's evaluations.
    ///
    /// The server sees `tag`, but learns neither `x` nor the output.
    pub async fn evaluate(&mut self, tag: &[u8], x: &[u8]) -> Result<PrfOutput, ClientError> {
        let (req, fin) = request(&mut self.state, tag, x)?;
        let resp = self.channel.exchange(req).await?;
        Ok(finalize(&fin, &resp)?)
    }

    /// Evaluate several inputs under one tag in a single round trip,
    /// consuming one of the session's evaluations per input.
    ///
    /// Outputs come back in the order of `inputs`. At most
    /// [`MAX_BATCH_EVALUATIONS`] per call.
    ///
    /// [`MAX_BATCH_EVALUATIONS`]: crate::online::MAX_BATCH_EVALUATIONS
    pub async fn evaluate_batch<T: AsRef<[u8]>>(
        &mut self,
        tag: &[u8],
        inputs: &[T],
    ) -> Result<Vec<PrfOutput>, ClientError> {
        let (req, fin) = request_batch(&mut self.state, tag, inputs)?;
        let resp = self.channel.exchange(req).await?;
        Ok(finalize_batch(&fin, &resp)?)
    }

    pub fn remaining_evaluations(&self) -> usize {
        evaluations_for(self.state.remaining_slots())
    }

    pub fn uid(&self) -> &Uid {
        self.state.uid()
    }
}
