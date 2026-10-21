//! Networked OPRF client with preprocessing plus the online phase over a
//! [`Connection`].
//!
//! A caller that owns its own transport can use [`crate::online`]'s `request`
//! and `finalize` directly, with no async runtime; this type is the
//! convenience layer over a cryprot-net connection.

use crate::channel::{ChannelError, ClientChannel};
use crate::online::{
    FinalizeError, MAX_BATCH_EVALUATIONS, RequestError, finalize, finalize_batch, request,
    request_batch,
};
use crate::preprocessing::{
    ClientState, PreprocError, Uid, evaluations_for, preproc_client, preproc_client_voprf, tau_for,
};
use crate::voprf::{MAX_VOPRF_BATCH_EVALUATIONS, VerifiedKey};
use cryprot_net::Connection;
use pool_prf::prf::PrfOutput;
use rand::CryptoRng;
use std::sync::{Arc, Mutex, MutexGuard};

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
    state: Arc<Mutex<ClientState>>,
}

fn lock(state: &Mutex<ClientState>) -> MutexGuard<'_, ClientState> {
    state
        .lock()
        .expect("a panic while evaluating poisoned the session")
}

impl OprfClient {
    /// Run PreProc (Figure 3) and open the online channel.
    ///
    /// Preprocesses for `evaluations` full OPRF evaluations. The peer must
    /// call [`crate::server::OprfServer::session`] with the same number.
    pub async fn new(
        mut conn: Connection,
        evaluations: usize,
        rng: &mut impl CryptoRng,
    ) -> Result<Self, ClientError> {
        let state = preproc_client(&mut conn, tau_for(evaluations), rng).await?;
        let channel = ClientChannel::new(&mut conn).await?;
        Ok(Self {
            conn,
            channel,
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// A VOPRF: the server proves its messages and the lient verifies the proofs against `pk`.
    pub async fn new_voprf(
        mut conn: Connection,
        pk: &VerifiedKey,
        evaluations: usize,
        rng: &mut impl CryptoRng,
    ) -> Result<Self, ClientError> {
        let state = preproc_client_voprf(&mut conn, pk, tau_for(evaluations), rng).await?;
        let channel = ClientChannel::new(&mut conn).await?;
        Ok(Self {
            conn,
            channel,
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Preprocess again on the same connection, replacing this session.
    ///
    /// Returns the new `uid`. The peer must call [`OprfSession::renew`] at the
    /// same point with the same number of evaluations. The online
    /// channel is untouched, so requests continue over it afterwards. A
    /// VOPRF stays a VOPRF.
    ///
    /// [`OprfSession::renew`]: crate::server::OprfSession::renew
    pub async fn renew(
        &mut self,
        evaluations: usize,
        rng: &mut impl CryptoRng,
    ) -> Result<Uid, ClientError> {
        let tau = tau_for(evaluations);
        let pk = lock(&self.state).voprf().map(|voprf| *voprf.pk());
        let state = match &pk {
            Some(pk) => preproc_client_voprf(&mut self.conn, pk, tau, rng).await?,
            None => preproc_client(&mut self.conn, tau, rng).await?,
        };
        let uid = *state.uid();
        self.state = Arc::new(Mutex::new(state));
        Ok(uid)
    }

    /// Evaluate the OPRF on public tag `tag` and private input `x`, consuming
    /// one of the session's evaluations.
    ///
    /// The server sees `tag`, but learns neither `x` nor the output.
    pub async fn evaluate(&mut self, tag: &[u8], x: &[u8]) -> Result<PrfOutput, ClientError> {
        let state = Arc::clone(&self.state);
        let (tag, x) = (tag.to_vec(), x.to_vec());
        let (req, fin) = tokio::task::spawn_blocking(move || request(&mut lock(&state), &tag, &x))
            .await
            .expect("requesting panicked")?;
        let resp = self.channel.exchange(req).await?;
        let output = tokio::task::spawn_blocking(move || finalize(&fin, &resp))
            .await
            .expect("finalizing panicked");
        Ok(output?)
    }

    /// Evaluate several inputs under one tag in a single round trip,
    /// consuming one of the session's evaluations per input.
    ///
    /// Outputs come back in the order of `inputs`. At most
    /// [`MAX_BATCH_EVALUATIONS`] per call, or [`MAX_VOPRF_BATCH_EVALUATIONS`]
    /// for a VOPRF.
    pub async fn evaluate_batch<T: AsRef<[u8]>>(
        &mut self,
        tag: &[u8],
        inputs: &[T],
    ) -> Result<Vec<PrfOutput>, ClientError> {
        let state = Arc::clone(&self.state);
        let tag = tag.to_vec();
        let inputs: Vec<Vec<u8>> = inputs.iter().map(|x| x.as_ref().to_vec()).collect();
        let (req, fin) =
            tokio::task::spawn_blocking(move || request_batch(&mut lock(&state), &tag, &inputs))
                .await
                .expect("requesting panicked")?;
        let resp = self.channel.exchange(req).await?;
        let outputs = tokio::task::spawn_blocking(move || finalize_batch(&fin, &resp))
            .await
            .expect("finalizing panicked");
        Ok(outputs?)
    }

    pub fn remaining_evaluations(&self) -> usize {
        evaluations_for(lock(&self.state).remaining_runs())
    }

    /// Most evaluations one [`Self::evaluate_batch`] call may carry:
    /// [`MAX_BATCH_EVALUATIONS`], or [`MAX_VOPRF_BATCH_EVALUATIONS`] for a
    /// VOPRF.
    pub fn max_batch_evaluations(&self) -> usize {
        match lock(&self.state).voprf() {
            Some(_) => MAX_VOPRF_BATCH_EVALUATIONS,
            None => MAX_BATCH_EVALUATIONS,
        }
    }

    pub fn uid(&self) -> Uid {
        *lock(&self.state).uid()
    }
}
