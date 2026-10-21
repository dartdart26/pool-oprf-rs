//! VOPRF: the server proves its messages and the client verifies the
//! proofs, see `docs/voprf.md`.

use crate::online::{RowRequest, RowResponse};
use crate::preprocessing::{PreprocError, RsEntry, expand, r_prime_from_block};
use cryprot_core::Block;
use cryprot_net::{Connection, ConnectionError, ReceiveStream, SendStream};
use futures::{SinkExt, StreamExt};
use pool_prf::params::{DELTA, N, RUNS_PER_EVALUATION, Zdelta, Zq};
use pool_prf::prf::SecretKey;
use pool_voprf::commitments::CommitmentRandomness;
use pool_voprf::hash_domains::Domain;
use pool_voprf::plonky3::Plonky3;
use pool_voprf::plonky3::commitments::key::KeyCommitment;
use pool_voprf::plonky3::commitments::mask_sum::MaskSumCommitment;
use pool_voprf::plonky3::commitments::masks::{self, MasksCommitment};
use pool_voprf::plonky3::commitments::pad::{self, PadCommitment};
use pool_voprf::statements::online::{self, OnlineWitness, RunStatement, RunWitness};
use pool_voprf::statements::preprocessing::{
    self, EvaluationStatement, EvaluationWitness, PreprocessingWitness,
};
use pool_voprf::statements::setup::SetupStatement;
use pool_voprf::traits::ProofSystem;
use serde::{Deserialize, Serialize};
use std::array;
use zeroize::Zeroize;

pub use pool_voprf::plonky3::{Proof, ProveError, VerifyError};

/// Most evaluations one VOPRF request may carry. The response carries
/// `π_online` of significant size for each evaluation, hence the limit.
/// TODO: Investigate how we can overcome that.
pub const MAX_VOPRF_BATCH_EVALUATIONS: usize = 8;

/// `pk`: the server's commitment to its key.
pub type PublicKey = KeyCommitment;

/// A `pk` whose `π_setup` verified.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifiedKey(PublicKey);

impl VerifiedKey {
    /// Verify `π_setup` of `pk`.
    pub fn verify(pk: PublicKey, proof: &Proof) -> Result<Self, VerifyError> {
        Plonky3::new().verify(&SetupStatement { pk }, proof)?;
        Ok(Self(pk))
    }
}

/// `pk` and `π_setup` of `sk`.
pub(crate) fn setup(sk: &SecretKey) -> Result<(PublicKey, Proof), ProveError> {
    let statement = SetupStatement::for_key(sk);
    let proof = Plonky3::new().prove(&statement, sk)?;
    Ok((statement.pk, proof))
}

type PreprocessingStatement =
    preprocessing::PreprocessingStatement<KeyCommitment, MasksCommitment, MaskSumCommitment>;

pub(crate) type OnlineStatement =
    online::OnlineStatement<KeyCommitment, MaskSumCommitment, PadCommitment>;

/// `c^v`: the `n` pairs `c^v_{0, i}`, `c^v_{1, i}`, one per `i`, of one
/// evaluation `v`.
type MasksCommitments = [[MasksCommitment; 2]; N];

type MasksMessage = Vec<[MasksCommitment; 2]>;

/// `d^{v, k}_0 .. d^{v, k}_{Δ-1}` of one run `k`.
type PadsCommitments = [PadCommitment; DELTA];

/// [`PadsCommitments`] of each run `k` of one evaluation `v`.
type PadsMessage = Vec<PadsCommitments>;

#[derive(Serialize, Deserialize)]
struct PreprocessingProof {
    // `m^v` of each evaluation `v`
    m: Vec<MaskSumCommitment>,
    // π_preproc
    proof: Proof,
}

/// An OT block as the random value of a commitment.
fn randomness(ot_block: &Block) -> CommitmentRandomness {
    CommitmentRandomness::from_le_bytes(*ot_block.as_bytes())
}

/// The first run of evaluation `v`.
fn first_run(v: usize) -> u64 {
    (v * RUNS_PER_EVALUATION) as u64
}

/// The pad of a 1-out-of-Δ OT block, with the OT block as the
/// random value.
fn pad_commitment(ot_block: &Block) -> PadCommitment {
    pad::commit(r_prime_from_block(ot_block), randomness(ot_block))
}

/// `randomness^v`, from the 1-out-of-Δ OT blocks of run 0 of evaluation `v`.
fn mask_sum_randomness(ot_blocks: &[Block; DELTA]) -> CommitmentRandomness {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(Domain::MaskSumRandomness as u32).to_le_bytes());
    for ot_block in ot_blocks {
        hasher.update(ot_block.as_bytes());
    }
    let hash = hasher.finalize();
    CommitmentRandomness::from_le_bytes(
        *hash
            .as_bytes()
            .first_chunk()
            .expect("a hash is wider than a random value"),
    )
}

/// What a VOPRF client keeps from the preprocessing.
#[derive(Debug)]
pub(crate) struct ClientVoprf {
    pk: VerifiedKey,
    /// `m^v` of each evaluation `v`.
    m: Vec<MaskSumCommitment>,
    /// `d^{v, k}_0 .. d^{v, k}_{Δ-1}` of each run.
    d: Vec<PadsCommitments>,
}

impl ClientVoprf {
    pub(crate) fn pk(&self) -> &VerifiedKey {
        &self.pk
    }

    /// The online statement of the evaluation on runs `first_run ..` with
    /// request `rows`. `y` is zero until the response comes.
    pub(crate) fn online_statement(&self, first_run: u64, rows: &[RowRequest]) -> OnlineStatement {
        let first_run = first_run as usize;
        OnlineStatement {
            pk: self.pk.0,
            m: self.m[first_run / RUNS_PER_EVALUATION],
            runs: array::from_fn(|k| RunStatement {
                d: self.d[first_run + k],
                e: rows[k].e,
                b_bar_prime: rows[k].b_bar_prime,
                y: [0; DELTA],
            }),
        }
    }
}

/// Verify `π_online` of one evaluation.
pub(crate) fn verify_online(
    statement: &OnlineStatement,
    rows: &[RowResponse],
    proof: &Proof,
) -> Result<(), VerifyError> {
    let mut statement = statement.clone();
    for (run, row) in statement.runs.iter_mut().zip(rows) {
        run.y = row.y;
    }
    Plonky3::new().verify(&statement, proof)
}

/// What a VOPRF server keeps from the preprocessing.
pub(crate) struct ServerVoprf {
    /// The 1-out-of-Δ OT blocks of each run: the pads and the random values
    /// of `d`.
    delta_ot_blocks: Vec<[Block; DELTA]>,
}

impl ServerVoprf {
    /// `π_online`.
    pub(crate) fn prove_online(
        &self,
        sk: &SecretKey,
        first_run: u64,
        rows: &[RowRequest],
        r_sigma_sums: &[Zq; RUNS_PER_EVALUATION],
    ) -> Result<Proof, ProveError> {
        let first_run = first_run as usize;
        let witness = OnlineWitness {
            sk: sk.clone(),
            // `randomness^v`, from run 0 of this evaluation.
            m_randomness: mask_sum_randomness(&self.delta_ot_blocks[first_run]),
            runs: array::from_fn(|k| {
                let ot_blocks = &self.delta_ot_blocks[first_run + k];
                RunWitness {
                    r_sigma_sum: r_sigma_sums[k],
                    pads: array::from_fn(|j| r_prime_from_block(&ot_blocks[j])),
                    d_randomness: array::from_fn(|j| randomness(&ot_blocks[j])),
                }
            }),
        };
        let e = array::from_fn(|k| rows[k].e);
        let b_bar_prime = array::from_fn(|k| rows[k].b_bar_prime);
        let statement = OnlineStatement::honest(&witness, &e, &b_bar_prime);
        Plonky3::new().prove(&statement, &witness)
    }
}

impl Zeroize for ServerVoprf {
    fn zeroize(&mut self) {
        for ot_blocks in &mut self.delta_ot_blocks {
            for ot_block in ot_blocks {
                ot_block.as_mut_bytes().zeroize();
            }
        }
    }
}

/// The client's side of a VOPRF preprocessing.
pub(crate) struct ClientPreprocessing<'a> {
    pk: &'a VerifiedKey,
    masks_tx: SendStream<MasksMessage>,
    pads_rx: ReceiveStream<PadsMessage>,
    proof_rx: ReceiveStream<PreprocessingProof>,
    /// `c^v` of each evaluation `v`.
    c: Vec<MasksCommitments>,
    /// `d^{v, k}_0 .. d^{v, k}_{Δ-1}` of each run.
    d: Vec<PadsCommitments>,
}

impl<'a> ClientPreprocessing<'a> {
    pub(crate) async fn open(
        conn: &mut Connection,
        pk: &'a VerifiedKey,
    ) -> Result<Self, ConnectionError> {
        let (masks_tx, pads_rx) = conn.request_response_stream().await?;
        let (_, proof_rx) = conn.stream().await?;
        Ok(Self {
            pk,
            masks_tx,
            pads_rx,
            proof_rx,
            c: Vec::new(),
            d: Vec::new(),
        })
    }

    pub(crate) async fn send_masks_commitments(
        &mut self,
        ot_blocks: &[[Block; 2]],
        evaluations: usize,
    ) -> Result<(), PreprocError> {
        let ot_blocks = ot_blocks.to_vec();
        let c: Vec<MasksCommitments> = tokio::task::spawn_blocking(move || {
            (0..evaluations)
                .map(|v| {
                    array::from_fn(|i| {
                        ot_blocks[i].map(|ot_block| {
                            masks::commit(&expand(&ot_block, first_run(v)), randomness(&ot_block))
                        })
                    })
                })
                .collect()
        })
        .await
        .expect("committing panicked");
        for c in c {
            self.masks_tx.send(c.to_vec()).await?;
            self.c.push(c);
        }
        Ok(())
    }

    /// Receive `d^{v, k}` of each run `k` of each evaluation `v` and check
    /// that `d^{v, k}_{b′^{v, k}}` commits to the client's pad and OT block.
    ///
    /// `ot_blocks` and `choices` are the client's 1-out-of-Δ OT blocks and
    /// choices `b′` of each run.
    pub(crate) async fn receive_pads_commitments(
        &mut self,
        ot_blocks: &[Block],
        choices: &[Zdelta],
        evaluations: usize,
    ) -> Result<(), PreprocError> {
        for v in 0..evaluations {
            let message = self
                .pads_rx
                .next()
                .await
                .ok_or(PreprocError::UnexpectedClose)??;
            if message.len() != RUNS_PER_EVALUATION {
                return Err(PreprocError::Malformed("d has wrong length"));
            }
            for (k, d) in message.into_iter().enumerate() {
                let run = v * RUNS_PER_EVALUATION + k;
                if d[usize::from(choices[run])] != pad_commitment(&ot_blocks[run]) {
                    return Err(PreprocError::PadsMismatch);
                }
                self.d.push(d);
            }
        }
        Ok(())
    }

    /// Receive `m^v` of each evaluation `v` and `π_preproc`, and verify
    /// `π_preproc`.
    pub(crate) async fn finish(mut self, b_bar: [u8; N]) -> Result<ClientVoprf, PreprocError> {
        let message = self
            .proof_rx
            .next()
            .await
            .ok_or(PreprocError::UnexpectedClose)??;
        if message.m.len() != self.c.len() {
            return Err(PreprocError::Malformed("m has wrong length"));
        }
        let statement = PreprocessingStatement {
            pk: self.pk.0,
            b_bar,
            evaluations: self
                .c
                .into_iter()
                .zip(&message.m)
                .map(|(c, &m)| EvaluationStatement { c, m })
                .collect(),
        };
        let proof = message.proof;
        tokio::task::spawn_blocking(move || Plonky3::new().verify(&statement, &proof))
            .await
            .expect("verifying panicked")?;
        Ok(ClientVoprf {
            pk: *self.pk,
            m: message.m,
            d: self.d,
        })
    }
}

/// The server's side of a VOPRF preprocessing.
pub(crate) struct ServerPreprocessing {
    masks_rx: ReceiveStream<MasksMessage>,
    pads_tx: SendStream<PadsMessage>,
    proof_tx: SendStream<PreprocessingProof>,
    /// `c^v` of each evaluation `v`.
    c: Vec<MasksCommitments>,
    /// The 1-out-of-Δ OT blocks of each run, once `d` is sent.
    delta_ot_blocks: Vec<[Block; DELTA]>,
}

impl ServerPreprocessing {
    pub(crate) async fn open(conn: &mut Connection) -> Result<Self, ConnectionError> {
        let (pads_tx, masks_rx) = conn.request_response_stream().await?;
        let (proof_tx, _) = conn.stream().await?;
        Ok(Self {
            masks_rx,
            pads_tx,
            proof_tx,
            c: Vec::new(),
            delta_ot_blocks: Vec::new(),
        })
    }

    /// Receive `c^v` of each evaluation `v` and check that each
    /// `c^v_{b_i, i}` commits to the server's masks and OT block.
    pub(crate) async fn receive_masks_commitments(
        &mut self,
        r_s: &[RsEntry],
        evaluations: usize,
    ) -> Result<(), PreprocError> {
        let mut c = Vec::with_capacity(evaluations);
        for _ in 0..evaluations {
            let message = self
                .masks_rx
                .next()
                .await
                .ok_or(PreprocError::UnexpectedClose)??;
            let c_v: MasksCommitments = message
                .try_into()
                .map_err(|_| PreprocError::Malformed("c has wrong length"))?;
            c.push(c_v);
        }
        let r_s = r_s.to_vec();
        let (c, matches) = tokio::task::spawn_blocking(move || {
            let matches = c.iter().enumerate().all(|(v, c_v)| {
                r_s.iter().zip(c_v).all(|(entry, c_i)| {
                    c_i[usize::from(entry.b)]
                        == masks::commit(
                            &expand(&entry.ot_block, first_run(v)),
                            randomness(&entry.ot_block),
                        )
                })
            });
            (c, matches)
        })
        .await
        .expect("checking panicked");
        if !matches {
            return Err(PreprocError::MasksMismatch);
        }
        self.c = c;
        Ok(())
    }

    /// Commit to the pads of each run `k` of each evaluation `v`, with their
    /// 1-out-of-Δ OT blocks as the random values, and send `d^{v, k}`.
    pub(crate) async fn send_pads_commitments(
        &mut self,
        delta_ot_blocks: Vec<[Block; DELTA]>,
        evaluations: usize,
    ) -> Result<(), PreprocError> {
        let (delta_ot_blocks, d) = tokio::task::spawn_blocking(move || {
            let d: Vec<PadsMessage> = (0..evaluations)
                .map(|v| {
                    delta_ot_blocks[v * RUNS_PER_EVALUATION..(v + 1) * RUNS_PER_EVALUATION]
                        .iter()
                        .map(|ot_blocks| array::from_fn(|j| pad_commitment(&ot_blocks[j])))
                        .collect()
                })
                .collect();
            (delta_ot_blocks, d)
        })
        .await
        .expect("committing panicked");
        self.delta_ot_blocks = delta_ot_blocks;
        for d in d {
            self.pads_tx.send(d).await?;
        }
        Ok(())
    }

    /// Prove the preprocessing and send `m^v` of each evaluation `v` and
    /// `π_preproc`.
    pub(crate) async fn prove(
        mut self,
        sk: &SecretKey,
        r_s: &[RsEntry],
        b_bar: [u8; N],
    ) -> Result<ServerVoprf, PreprocError> {
        let sk = sk.clone();
        let r_s = r_s.to_vec();
        let c = self.c;
        let delta_ot_blocks = self.delta_ot_blocks;
        let (delta_ot_blocks, m, proof) = tokio::task::spawn_blocking(move || {
            let evaluations = (0..c.len())
                .map(|v| {
                    // Run 0 of evaluation `v` is run `v · RUNS_PER_EVALUATION`.
                    let m_randomness =
                        mask_sum_randomness(&delta_ot_blocks[v * RUNS_PER_EVALUATION]);
                    evaluation_witness(&sk, &r_s, v, m_randomness)
                })
                .collect();
            let witness = PreprocessingWitness {
                ot_blocks: array::from_fn(|i| randomness(&r_s[i].ot_block)),
                evaluations,
                sk,
            };
            let statement = PreprocessingStatement::honest(&witness, b_bar, c);
            let proof = Plonky3::new().prove(&statement, &witness);
            let m: Vec<_> = statement
                .evaluations
                .into_iter()
                .map(|evaluation| evaluation.m)
                .collect();
            (delta_ot_blocks, m, proof)
        })
        .await
        .expect("proving panicked");
        let proof = proof?;
        self.proof_tx.send(PreprocessingProof { m, proof }).await?;
        Ok(ServerVoprf { delta_ot_blocks })
    }
}

/// The server's masks of evaluation `v` and `r̃^{v, k}_Σ` of each run `k`.
fn evaluation_witness(
    sk: &SecretKey,
    r_s: &[RsEntry],
    v: usize,
    m_randomness: CommitmentRandomness,
) -> EvaluationWitness {
    let masks: [[Zq; RUNS_PER_EVALUATION]; N] =
        array::from_fn(|i| expand(&r_s[i].ot_block, first_run(v)));
    let r_sigma_sums =
        array::from_fn(|k| pool_eval::r_sigma_sum(sk, &array::from_fn(|i| masks[i][k])));
    EvaluationWitness {
        masks,
        r_sigma_sums,
        m_randomness,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::verified_key;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn ot_block(label: u64) -> Block {
        let mut bytes = [0u8; Block::BYTES];
        bytes[..8].copy_from_slice(&label.to_le_bytes());
        Block::new(bytes)
    }

    /// The binary OT blocks: the client's pair of each `i`.
    fn binary_ot_blocks() -> Vec<[Block; 2]> {
        (0..N as u64)
            .map(|i| [ot_block(2 * i), ot_block(2 * i + 1)])
            .collect()
    }

    /// The server's choice `b_i` of each `i` and its OT block.
    fn server_entries(pairs: &[[Block; 2]]) -> Vec<RsEntry> {
        pairs
            .iter()
            .enumerate()
            .map(|(i, pair)| {
                let b = u8::from(i % 3 == 0);
                RsEntry {
                    b,
                    ot_block: pair[usize::from(b)],
                }
            })
            .collect()
    }

    /// The 1-out-of-Δ OT blocks of each run of one evaluation.
    fn delta_ot_blocks() -> Vec<[Block; DELTA]> {
        (0..RUNS_PER_EVALUATION)
            .map(|run| array::from_fn(|j| ot_block((run * DELTA + j) as u64)))
            .collect()
    }

    /// The client's choice `b′` of each run and the OT block it holds.
    fn client_delta_ot(delta_ot_blocks: &[[Block; DELTA]]) -> (Vec<Block>, Vec<Zdelta>) {
        let choices: Vec<Zdelta> = (0..RUNS_PER_EVALUATION)
            .map(|run| (run % DELTA) as Zdelta)
            .collect();
        let blocks = delta_ot_blocks
            .iter()
            .zip(&choices)
            .map(|(ot_blocks, &b_prime)| ot_blocks[usize::from(b_prime)])
            .collect();
        (blocks, choices)
    }

    #[tokio::test]
    async fn the_server_refuses_commitments_to_other_masks() {
        let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let sk = SecretKey::random(&mut StdRng::seed_from_u64(1));
        let pk = verified_key(&sk);
        let pairs = binary_ot_blocks();
        let r_s = server_entries(&pairs);
        // The client commits to another OT block than the server's.
        let mut other = pairs.clone();
        other[0][usize::from(r_s[0].b)] = ot_block(u64::MAX);

        let (client, server) = tokio::join!(
            async {
                let mut client = ClientPreprocessing::open(&mut client_conn, &pk).await?;
                client.send_masks_commitments(&other, 1).await
            },
            async {
                let mut server = ServerPreprocessing::open(&mut server_conn).await?;
                server.receive_masks_commitments(&r_s, 1).await
            },
        );
        client.expect("sending");
        assert!(matches!(server, Err(PreprocError::MasksMismatch)));
    }

    #[tokio::test]
    async fn the_client_refuses_a_commitment_to_another_pad() {
        let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let sk = SecretKey::random(&mut StdRng::seed_from_u64(2));
        let pk = verified_key(&sk);
        let delta_ot_blocks = delta_ot_blocks();
        let (client_blocks, choices) = client_delta_ot(&delta_ot_blocks);
        // The server commits to another pad at the client's choice in the
        // last run.
        let mut other = delta_ot_blocks.clone();
        other[RUNS_PER_EVALUATION - 1][usize::from(choices[RUNS_PER_EVALUATION - 1])] =
            ot_block(u64::MAX);

        let (client, server) = tokio::join!(
            async {
                let mut client = ClientPreprocessing::open(&mut client_conn, &pk).await?;
                client
                    .receive_pads_commitments(&client_blocks, &choices, 1)
                    .await
            },
            async {
                let mut server = ServerPreprocessing::open(&mut server_conn).await?;
                server.send_pads_commitments(other, 1).await
            },
        );
        server.expect("sending");
        assert!(matches!(client, Err(PreprocError::PadsMismatch)));
    }

    #[tokio::test]
    async fn the_client_refuses_the_preprocessing_proof_of_another_b_bar() {
        let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let sk = SecretKey::random(&mut StdRng::seed_from_u64(3));
        let pk = verified_key(&sk);
        let pairs = binary_ot_blocks();
        let r_s = server_entries(&pairs);
        let b_bar: [u8; N] = array::from_fn(|i| r_s[i].b ^ sk.as_bits()[i]);
        let delta_ot_blocks = delta_ot_blocks();
        let (client_blocks, choices) = client_delta_ot(&delta_ot_blocks);
        // The client checks the proof against a b̄ with another last bit.
        let mut other_b_bar = b_bar;
        other_b_bar[N - 1] ^= 1;

        let (client, server) = tokio::join!(
            async {
                let mut client = ClientPreprocessing::open(&mut client_conn, &pk).await?;
                client.send_masks_commitments(&pairs, 1).await?;
                client
                    .receive_pads_commitments(&client_blocks, &choices, 1)
                    .await?;
                client.finish(other_b_bar).await
            },
            async {
                let mut server = ServerPreprocessing::open(&mut server_conn).await?;
                server.receive_masks_commitments(&r_s, 1).await?;
                server.send_pads_commitments(delta_ot_blocks, 1).await?;
                server.prove(&sk, &r_s, b_bar).await
            },
        );
        server.expect("proving");
        assert!(matches!(client, Err(PreprocError::Verify(_))));
    }
}
