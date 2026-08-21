//! PSI client: the party that learns the intersection.
//!
//! Two phases. [`PsiClient::new`] announces how many
//! elements this run will cover and does the preprocessing - the expensive
//! part that Pool supports and it happens before the inputs are
//! known. [`PsiClient::intersect`] then spends that material on the actual
//! set.

use crate::error::PsiError;
use crate::protocol::{MAX_CLIENT_SET, MAX_SERVER_SET, intersect};
use crate::transport::ClientChannel;
use cryprot_net::Connection;
use pool_oprf::client::OprfClient;
use pool_oprf::online::MAX_BATCH_EVALUATIONS;
use pool_oprf::preprocessing::Uid;
use pool_prf::prf::PrfOutput;
use rand::{CryptoRng, Rng};

/// A PSI client that has completed preprocessing for a set of a fixed size.
pub struct PsiClient {
    channel: ClientChannel,
    oprf: OprfClient,
    set_size: usize,
}

impl PsiClient {
    /// Announce a set size, then preprocess for it.
    pub async fn new(
        mut conn: Connection,
        set_size: usize,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Self, PsiError> {
        if set_size == 0 {
            return Err(PsiError::EmptyClientSet);
        }
        if set_size > MAX_CLIENT_SET {
            return Err(PsiError::ClientSetTooLarge {
                len: set_size,
                max: MAX_CLIENT_SET,
            });
        }

        let mut channel = ClientChannel::new(&mut conn).await?;
        channel.send_client_set_size(set_size as u64).await?;

        let oprf = OprfClient::new(conn, set_size, rng).await?;
        Ok(Self {
            channel,
            oprf,
            set_size,
        })
    }

    /// Run the online phase and return which of `set`'s entries the server also
    /// holds, as indices into `set`.
    ///
    /// `set` must have the length announced to [`PsiClient::new`], since
    /// preprocessing was sized to it. Duplicates are not collapsed: each one is
    /// evaluated and reported like any other element.
    ///
    /// Takes `self`: this spends the session's material exactly, and the server
    /// sends its masked set once, so there is nothing left for a second call.
    /// Another run means another [`PsiClient::new`].
    pub async fn intersect<T: AsRef<[u8]>>(mut self, set: &[T]) -> Result<Vec<usize>, PsiError> {
        if set.len() != self.set_size {
            return Err(PsiError::SetSizeMismatch {
                expected: self.set_size,
                got: set.len(),
            });
        }

        let masked = self.channel.recv_set().await?;
        if masked.elements.len() > MAX_SERVER_SET {
            return Err(PsiError::ServerSetTooLarge {
                len: masked.elements.len(),
                max: MAX_SERVER_SET,
            });
        }

        // One round trip per chunk. The server derives the same count from the
        // size it was told, so neither side has to signal when we are done.
        let mut outputs: Vec<PrfOutput> = Vec::with_capacity(set.len());
        for chunk in set.chunks(MAX_BATCH_EVALUATIONS) {
            outputs.extend(self.oprf.evaluate_batch(&masked.tag, chunk).await?);
        }

        Ok(intersect(&outputs, &masked.elements))
    }

    /// How many elements this session was preprocessed for.
    pub fn set_size(&self) -> usize {
        self.set_size
    }

    /// The OPRF session's `uid`, shared with the server.
    pub fn uid(&self) -> &Uid {
        self.oprf.uid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[tokio::test]
    async fn impossible_set_sizes_are_rejected() {
        let (_server_conn, client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let mut rng = StdRng::seed_from_u64(6);

        let empty = PsiClient::new(client_conn, 0, &mut rng).await;
        assert!(
            matches!(empty, Err(PsiError::EmptyClientSet)),
            "a zero-element set cannot be preprocessed for"
        );

        let (_server_conn, client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let huge = PsiClient::new(client_conn, MAX_CLIENT_SET + 1, &mut rng).await;
        assert!(
            matches!(huge, Err(PsiError::ClientSetTooLarge { .. })),
            "an oversized set must be refused"
        );
    }
}
