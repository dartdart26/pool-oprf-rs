//! PSI server: the party that holds the key and doesn't learn the intersection.
//!
//! The server's own set never goes through an OT. It holds `sk`, so it masks
//! its set with the plaintext PRF and sends the result. Only the client's set
//! needs the oblivious path.
//!
//! Masking is client-independent, so a server with many clients should
//! [`mask_server_set`] once per tag and hand the result to every connection
//! via [`PsiSession::serve_masked`].

use crate::error::PsiError;
use crate::protocol::{
    MAX_CLIENT_SET, MAX_SERVER_SET, MaskedElement, MaskedServerSet, chunks_for, mask_server_set,
};
use crate::transport::ServerChannel;
use cryprot_net::Connection;
use pool_oprf::preprocessing::Uid;
use pool_oprf::server::{OprfServer, OprfSession};
use pool_prf::prf::SecretKey;

#[derive(Clone)]
pub struct PsiServer {
    oprf: OprfServer,
}

impl PsiServer {
    pub fn new(sk: SecretKey) -> Self {
        Self {
            oprf: OprfServer::new(sk),
        }
    }

    /// Take the client's set size, then preprocess for exactly that much.
    pub async fn session(&self, mut conn: Connection) -> Result<PsiSession, PsiError> {
        // Opened before the OPRF's streams, matching the client.
        let mut channel = ServerChannel::new(&mut conn).await?;
        let announced = channel.recv_client_set_size().await?;

        let set_size = usize::try_from(announced)
            .map_err(|_| PsiError::Malformed("client set size does not fit in a usize"))?;
        if set_size == 0 {
            return Err(PsiError::Malformed("client announced an empty set"));
        }
        if set_size > MAX_CLIENT_SET {
            return Err(PsiError::ClientSetTooLarge {
                len: set_size,
                max: MAX_CLIENT_SET,
            });
        }

        let oprf = self.oprf.session(conn, set_size).await?;
        Ok(PsiSession {
            channel,
            oprf,
            set_size,
        })
    }

    /// Mask `set` under `tag`, ready to hand to every [`PsiSession`] this
    /// server opens. Convenience over [`mask_server_set`] with the server's
    /// own key.
    pub fn mask<T: AsRef<[u8]>>(
        &self,
        tag: &[u8],
        set: impl IntoIterator<Item = T>,
    ) -> Vec<MaskedElement> {
        mask_server_set(self.oprf.key(), tag, set)
    }

    /// The key this server masks and evaluates under.
    pub fn key(&self) -> &SecretKey {
        self.oprf.key()
    }
}

/// One client connection, preprocessed for the set size it announced.
pub struct PsiSession {
    channel: ServerChannel,
    oprf: OprfSession,
    set_size: usize,
}

impl PsiSession {
    /// Mask `set` under `tag` and run the online phase.
    ///
    /// Convenience for a server that has one client, or one whose set changes
    /// per client; anything else should [`PsiServer::mask`] once per tag and
    /// reuse the result across sessions.
    pub async fn serve<T: AsRef<[u8]>>(&mut self, tag: &[u8], set: &[T]) -> Result<(), PsiError> {
        let masked = mask_server_set(self.oprf.key(), tag, set);
        self.serve_masked(tag, &masked).await
    }

    /// Send an already-masked set, then answer the client's evaluations.
    ///
    /// `tag` must be the tag `masked` was built under: the client evaluates
    /// its own set under whatever tag arrives here, and a mismatch produces an
    /// empty intersection rather than an error.
    ///
    /// Returns once the client has spent its slots - the session was sized to
    /// exactly this run, so it is finished afterwards and can be dropped.
    pub async fn serve_masked(
        &mut self,
        tag: &[u8],
        masked: &[MaskedElement],
    ) -> Result<(), PsiError> {
        if masked.len() > MAX_SERVER_SET {
            return Err(PsiError::ServerSetTooLarge {
                len: masked.len(),
                max: MAX_SERVER_SET,
            });
        }

        self.channel
            .send_set(MaskedServerSet {
                tag: tag.to_vec(),
                elements: masked.to_vec(),
            })
            .await?;

        // The round count is derived from the set size, not signalled, so a
        // client that stops early is a protocol violation rather than an end
        // of stream.
        for _ in 0..chunks_for(self.set_size) {
            if !self.oprf.serve_next().await? {
                return Err(PsiError::UnexpectedClose);
            }
        }

        Ok(())
    }

    pub fn key(&self) -> &SecretKey {
        self.oprf.key()
    }

    /// How many elements this session was preprocessed for.
    pub fn set_size(&self) -> usize {
        self.set_size
    }

    /// Full evaluations left of what this session preprocessed for.
    pub fn remaining_evaluations(&self) -> usize {
        self.oprf.remaining_evaluations()
    }

    /// The OPRF session's `uid`, shared with the client.
    pub fn uid(&self) -> &Uid {
        self.oprf.uid()
    }
}
