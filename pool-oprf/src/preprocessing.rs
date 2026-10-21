//! OT-based preprocessing for the Pool OPRF (Figure 3 of the paper).
//!
//! One preprocessing serves τ *runs* of the base protocol.
//! A run yields one ℤ_p element and is spent once. A full PRF evaluation
//! spends `H_ROWS` consecutive runs, so a session covers τ / `H_ROWS`
//! full evaluations.
//!
//! The paper says each binary-rOT message is a vector of τ ℤ_q elements,
//! i.e. randomness from the OT. Our OTs output a 128-bit [`Block`] per
//! message, so we take that randomness and expand it via BLAKE3: entry j of
//! the vector is `expand(ot_block, j)`, computed on demand instead of
//! stored.

use crate::delta_ot::{delta_ot_receive, delta_ot_send};
use crate::voprf::{
    ClientPreprocessing, ClientVoprf, ServerPreprocessing, ServerVoprf, VerifiedKey,
};
use cryprot_core::Block;
use cryprot_net::Connection;
use cryprot_ot::extension::BASE_OT_COUNT;
#[cfg(not(feature = "silent-ot"))]
use cryprot_ot::extension::{MaliciousOtExtensionReceiver, MaliciousOtExtensionSender};
#[cfg(feature = "silent-ot")]
use cryprot_ot::{
    MaliciousMarker,
    silent_ot::{SilentOtReceiver, SilentOtSender},
};
use cryprot_ot::{RandChoiceRotReceiver, RotSender};

/// The rOT type this build preprocesses with.
#[cfg(not(feature = "silent-ot"))]
pub(crate) type OtSender = MaliciousOtExtensionSender;
#[cfg(not(feature = "silent-ot"))]
pub(crate) type OtReceiver = MaliciousOtExtensionReceiver;
#[cfg(feature = "silent-ot")]
pub(crate) type OtSender = SilentOtSender<MaliciousMarker>;
#[cfg(feature = "silent-ot")]
pub(crate) type OtReceiver = SilentOtReceiver<MaliciousMarker>;

pub(crate) fn ot_sender(conn: Connection) -> OtSender {
    OtSender::new(conn)
}

pub(crate) fn ot_receiver(conn: Connection) -> OtReceiver {
    OtReceiver::new(conn)
}
use futures::{SinkExt, StreamExt};
use pool_prf::modular::{reduce_p, reduce_q};
use pool_prf::params::{DELTA, H_ROWS, LAMBDA_BYTES, N, Zdelta, Zp, Zq};
use pool_prf::prf::SecretKey;
use rand::{CryptoRng, RngExt};
use std::array;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session identifier, `uid` in Figure 3.
pub type Uid = [u8; LAMBDA_BYTES];

/// Sample a fresh `uid`.
pub fn random_uid(rng: &mut impl CryptoRng) -> Uid {
    let mut uid = Uid::default();
    rng.fill(&mut uid[..]);
    uid
}

/// The τ that `evaluations` full OPRF evaluations need.
///
/// Panics rather than wrapping.
pub const fn tau_for(evaluations: usize) -> usize {
    evaluations
        .checked_mul(H_ROWS)
        .expect("evaluations * H_ROWS overflows usize")
}

/// Full evaluations that `runs` can pay for. A remainder is unusable, since
/// an evaluation needs all `H_ROWS` of its rows.
pub const fn evaluations_for(runs: usize) -> usize {
    runs / H_ROWS
}

/// Domain separator for expanding OT blocks into the `r` masks.
const R_DOMAIN_SEPARATOR: &str = "pool-oprf v1 zq mask from ot seed";

/// Bytes of XOF output each mask is cut from.
const MASK_BYTES: usize = size_of::<Zq>();

/// The protocol wants τ masks per binary OT message, but our OT hands us
/// a single 128-bit `Block`, so we expand it to produce multiple masks via
/// BLAKE3.
///
/// `first_run` is the run the masks start at, from 0 to τ - 1.
///
/// `H_ROWS` at once rather than one at a time: an evaluation spends `H_ROWS`
/// consecutive runs, and a single hash setup covers all of them.
pub(crate) fn expand(ot_block: &Block, first_run: u64) -> [Zq; H_ROWS] {
    let mut hasher = blake3::Hasher::new_derive_key(R_DOMAIN_SEPARATOR);
    hasher.update(ot_block.as_bytes());
    let mut xof = hasher.finalize_xof();
    xof.set_position(first_run * MASK_BYTES as u64);

    let mut buf = [0u8; H_ROWS * MASK_BYTES];
    xof.fill(&mut buf);

    let (raws, _) = buf.as_chunks::<MASK_BYTES>();
    let mut out = [0 as Zq; H_ROWS];
    for (mask, raw) in out.iter_mut().zip(raws) {
        *mask = reduce_q(Zq::from_le_bytes(*raw));
    }
    out
}

/// Bytes of a block taken for one ℤ_p element.
const P_BYTES: usize = size_of::<Zp>();

/// The Block is a BLAKE3 output (see `delta_ot::derive_ot_block`), so its
/// leading bytes are uniform, and reducing them mod p leaves them uniform in
/// ℤ_p as p is a power of two.
pub(crate) fn r_prime_from_block(block: &Block) -> Zp {
    let raw = block
        .as_bytes()
        .first_chunk::<P_BYTES>()
        .expect("Block is wider than Zp");
    reduce_p(Zp::from_le_bytes(*raw))
}

#[derive(Clone, Copy)]
pub(crate) struct RcEntry {
    pub(crate) b_prime: Zdelta,
    pub(crate) r_prime: Zp,
}

/// Both fields are preprocessing secrets, so neither is printed.
impl std::fmt::Debug for RcEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RcEntry(****)")
    }
}

impl Zeroize for RcEntry {
    fn zeroize(&mut self) {
        self.b_prime.zeroize();
        self.r_prime.zeroize();
    }
}

/// The run budget: how many preprocessing runs exist, and how many are
/// spent.
#[derive(Debug)]
pub(crate) struct Runs {
    tau: usize,
    /// Next unspent run, 0 to τ - 1.
    ctr: usize,
}

impl Runs {
    fn new(tau: usize) -> Self {
        Self { tau, ctr: 0 }
    }

    fn remaining(&self) -> usize {
        self.tau - self.ctr
    }

    /// Take `count` runs, returning the first, or `None` if that many are not left.
    fn take(&mut self, count: usize) -> Option<u64> {
        if self.remaining() < count {
            return None;
        }
        let first = self.ctr;
        self.ctr += count;
        Some(first as u64)
    }
}

/// Client-side preprocessing state in Figure 3.
pub struct ClientState {
    /// `S_C` stored as OT blocks.
    /// `ot_blocks[i][0]` expands to the mask vector `(r^0_{0,i}, ..., r^{τ-1}_{0,i})`,
    /// `ot_blocks[i][1]` expands to the mask vector `(r^0_{1,i}, ..., r^{τ-1}_{1,i})`.
    ot_blocks: [[Block; 2]; N],

    /// `b̄_i = b_i ⊕ sk_i`, the masked key bits. One byte per bit,
    /// values 0 or 1.
    bhat: [u8; N],

    /// Length τ.
    r_c: Vec<RcEntry>,

    uid: Uid,

    runs: Runs,

    voprf: Option<ClientVoprf>,
}

/// One entry of `R_S`.
#[derive(Clone, Copy)]
pub(crate) struct RsEntry {
    /// `b_i`, 0 or 1.
    pub(crate) b: u8,
    /// Expands to `(r^0_{b_i,i}, ..., r^{τ-1}_{b_i,i})`.
    pub(crate) ot_block: Block,
}

impl std::fmt::Debug for RsEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsEntry(****)")
    }
}

impl Zeroize for RsEntry {
    fn zeroize(&mut self) {
        self.b.zeroize();
        self.ot_block.as_mut_bytes().zeroize();
    }
}

/// Server-side preprocessing state in Figure 3.
pub struct ServerState {
    r_s: [RsEntry; N],

    /// Length τ.
    s_s: Vec<[Zp; DELTA]>,

    uid: Uid,

    runs: Runs,

    voprf: Option<ServerVoprf>,
}

fn into_array<T: Copy, const N: usize>(v: Vec<T>, what: &str) -> [T; N] {
    v[..].try_into().expect(what)
}

impl ClientState {
    pub(crate) fn new(
        ot_blocks: Vec<[Block; 2]>,
        bhat: Vec<u8>,
        r_c: Vec<RcEntry>,
        uid: Uid,
        voprf: Option<ClientVoprf>,
    ) -> Self {
        let ot_blocks: [[Block; 2]; N] = into_array(ot_blocks, "N binary rOT block pairs");
        let bhat: [u8; N] = into_array(bhat, "N masked key bits");
        let runs = Runs::new(r_c.len());
        Self {
            ot_blocks,
            bhat,
            r_c,
            uid,
            runs,
            voprf,
        }
    }

    pub fn uid(&self) -> &Uid {
        &self.uid
    }

    pub fn remaining_runs(&self) -> usize {
        self.runs.remaining()
    }

    /// `r^j_{b̄_i,i}` onward, the client's blinding masks for coordinate `i`.
    pub(crate) fn r_bhat(&self, i: usize, first_run: u64) -> [Zq; H_ROWS] {
        expand(&self.ot_blocks[i][self.bhat[i] as usize], first_run)
    }

    /// `r^j_{1-b̄_i,i}` onward, the side not used for blinding.
    pub(crate) fn r_not_bhat(&self, i: usize, first_run: u64) -> [Zq; H_ROWS] {
        expand(&self.ot_blocks[i][1 - self.bhat[i] as usize], first_run)
    }

    pub(crate) fn r_c(&self, j: u64) -> RcEntry {
        self.r_c[j as usize]
    }

    pub(crate) fn voprf(&self) -> Option<&ClientVoprf> {
        self.voprf.as_ref()
    }

    /// Reserve `count` consecutive runs, returning the first, or `None` if
    /// that many are not left.
    pub(crate) fn next_runs(&mut self, count: usize) -> Option<u64> {
        self.runs.take(count)
    }
}

impl std::fmt::Debug for ClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientState")
            .field("uid", &self.uid)
            .field("runs", &self.runs)
            .finish_non_exhaustive()
    }
}

impl Zeroize for ClientState {
    fn zeroize(&mut self) {
        for pair in &mut self.ot_blocks {
            for ot_block in pair {
                ot_block.as_mut_bytes().zeroize();
            }
        }
        self.bhat.zeroize();
        self.r_c.zeroize();
    }
}

impl Drop for ClientState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClientState {}

impl ServerState {
    pub(crate) fn new(
        r_s: Vec<RsEntry>,
        s_s: Vec<[Zp; DELTA]>,
        uid: Uid,
        voprf: Option<ServerVoprf>,
    ) -> Self {
        let r_s: [RsEntry; N] = into_array(r_s, "N binary rOT entries");
        let runs = Runs::new(s_s.len());
        Self {
            r_s,
            s_s,
            uid,
            runs,
            voprf,
        }
    }

    pub fn uid(&self) -> &Uid {
        &self.uid
    }

    pub fn remaining_runs(&self) -> usize {
        self.runs.remaining()
    }

    /// `r^j_{b_i,i}` onward, the masks the server knows for binary OT `i`.
    pub(crate) fn r(&self, i: usize, first_run: u64) -> [Zq; H_ROWS] {
        expand(&self.r_s[i].ot_block, first_run)
    }

    pub(crate) fn s_s(&self, j: u64) -> &[Zp; DELTA] {
        &self.s_s[j as usize]
    }

    pub(crate) fn voprf(&self) -> Option<&ServerVoprf> {
        self.voprf.as_ref()
    }

    /// Reserve `count` consecutive runs, returning the first, or `None` if
    /// that many are not left.
    pub(crate) fn next_runs(&mut self, count: usize) -> Option<u64> {
        self.runs.take(count)
    }
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("uid", &self.uid)
            .field("runs", &self.runs)
            .finish_non_exhaustive()
    }
}

impl Zeroize for ServerState {
    fn zeroize(&mut self) {
        for entry in &mut self.r_s {
            entry.zeroize();
        }
        self.s_s.zeroize();
        if let Some(voprf) = &mut self.voprf {
            voprf.zeroize();
        }
    }
}

impl Drop for ServerState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ServerState {}

/// Errors during the preprocessing protocol.
#[derive(Debug, thiserror::Error)]
pub enum PreprocError {
    #[cfg(not(feature = "silent-ot"))]
    #[error("OT extension failed")]
    Ot(#[from] cryprot_ot::extension::Error),
    #[cfg(feature = "silent-ot")]
    #[error("silent OT failed")]
    Ot(#[from] cryprot_ot::silent_ot::Error),
    #[error("connection to peer failed")]
    Connection(#[from] cryprot_net::ConnectionError),
    #[error("sending or receiving a message failed")]
    Io(#[from] std::io::Error),
    #[error("peer closed the stream unexpectedly")]
    UnexpectedClose,
    #[error("peer sent a malformed message: {0}")]
    Malformed(&'static str),
    #[error("tau must be at least 1")]
    ZeroTau,
    #[error("a VOPRF needs tau of at least one evaluation, {H_ROWS}, got {tau}")]
    VoprfTauTooSmall { tau: usize },
    #[error("peer is preprocessing for tau = {theirs}, this side asked for {ours}")]
    TauMismatch { ours: usize, theirs: usize },
    #[error("the client's commitments to its masks do not match the server's masks")]
    MasksMismatch,
    #[error("the server's commitment to the client's pad does not match the client's pad")]
    PadsMismatch,
    #[error("proving the preprocessing failed")]
    Prove(#[from] crate::voprf::ProveError),
    #[error("the preprocessing proof does not verify")]
    Verify(#[from] crate::voprf::VerifyError),
}

/// The opening message: `uid`, τ as a little-endian `u64` and whether the
/// client asks for a VOPRF, 0 or 1.
const HELLO_BYTES: usize = LAMBDA_BYTES + 8 + 1;

const MAX_CONTROL_FRAME_BYTES: usize = N + 9;
const _: () = assert!(
    HELLO_BYTES <= N,
    "incorrect max control frame size calculation"
);

const _: () = assert!(
    size_of::<usize>() <= size_of::<u64>(),
    "tau is sent as a u64"
);

fn encode_tau(tau: usize) -> [u8; 8] {
    (tau as u64).to_le_bytes()
}

fn decode_tau(bytes: &[u8]) -> Result<usize, PreprocError> {
    let raw: [u8; 8] = bytes
        .try_into()
        .map_err(|_| PreprocError::Malformed("tau has wrong length"))?;
    usize::try_from(u64::from_le_bytes(raw))
        .map_err(|_| PreprocError::Malformed("tau does not fit in a usize"))
}

// The N binary rOTs, rounded up to CryProt's alignment; the extra
// OTs are discarded.
const BINARY_OT_COUNT: usize = N.next_multiple_of(BASE_OT_COUNT);

/// Run the client side of PreProc (Figure 3).
///
/// The client samples the `uid` (line 1), is the sender in the n
/// binary rOTs (line 2), the receiver in the τ 1-out-of-Δ rOTs
/// (line 3), and receives the masked key bits b̄ (line 4).
///
/// Both sides must pass the same `tau` - a disagreement is rejected before any
/// OT runs.
pub async fn preproc_client(
    conn: &mut Connection,
    tau: usize,
    rng: &mut impl CryptoRng,
) -> Result<ClientState, PreprocError> {
    preproc_client_with(conn, None, tau, rng).await
}

/// A VOPRF client.
pub async fn preproc_client_voprf(
    conn: &mut Connection,
    pk: &VerifiedKey,
    tau: usize,
    rng: &mut impl CryptoRng,
) -> Result<ClientState, PreprocError> {
    preproc_client_with(conn, Some(pk), tau, rng).await
}

async fn preproc_client_with(
    conn: &mut Connection,
    pk: Option<&VerifiedKey>,
    tau: usize,
    rng: &mut impl CryptoRng,
) -> Result<ClientState, PreprocError> {
    if tau == 0 {
        return Err(PreprocError::ZeroTau);
    }
    if pk.is_some() && evaluations_for(tau) == 0 {
        return Err(PreprocError::VoprfTauTooSmall { tau });
    }

    let binary_ot_conn = conn.sub_connection();
    let delta_ot_conn = conn.sub_connection();
    let (mut msg_send, mut msg_recv) = conn.stream::<Vec<u8>>().await?;
    msg_recv
        .get_mut()
        .decoder_mut()
        .set_max_frame_length(MAX_CONTROL_FRAME_BYTES);

    // Line (1): sample uid and share it with the server, along with tau.
    //
    // tau is not in the paper's message (it is assumed agreed). Both sides
    // state theirs and refuse to continue if the two differ.
    let uid = random_uid(rng);
    let mut hello = uid.to_vec();
    hello.extend_from_slice(&encode_tau(tau));
    hello.push(u8::from(pk.is_some()));
    msg_send.send(hello).await?;

    // The server echoes its own tau, so a mismatch fails.
    let echoed = msg_recv
        .next()
        .await
        .ok_or(PreprocError::UnexpectedClose)??;
    let theirs = decode_tau(&echoed)?;
    if theirs != tau {
        return Err(PreprocError::TauMismatch { ours: tau, theirs });
    }

    let mut voprf = match pk {
        Some(pk) => Some(ClientPreprocessing::open(conn, pk).await?),
        None => None,
    };

    // Line (2): N binary rOTs with the client as sender. Keep the OT block
    // pairs.
    let mut sender = ot_sender(binary_ot_conn);
    let mut ot_blocks = sender.send(BINARY_OT_COUNT).await?;
    ot_blocks.truncate(N);

    if let Some(voprf) = &mut voprf {
        voprf
            .send_masks_commitments(&ot_blocks, evaluations_for(tau))
            .await?;
    }

    // Line (3): tau 1-out-of-Δ rOTs with the client as receiver.
    let mut receiver = ot_receiver(delta_ot_conn);
    let receiver_out = delta_ot_receive(&mut receiver, tau).await?;
    let r_c = receiver_out
        .blocks
        .iter()
        .zip(&receiver_out.choices)
        .map(|(block, &b_prime)| RcEntry {
            b_prime,
            r_prime: r_prime_from_block(block),
        })
        .collect();

    if let Some(voprf) = &mut voprf {
        voprf
            .receive_pads_commitments(
                &receiver_out.blocks,
                &receiver_out.choices,
                evaluations_for(tau),
            )
            .await?;
    }

    // Line (4): receive the masked key bits b̄_i = b_i ⊕ sk_i.
    let bhat = msg_recv
        .next()
        .await
        .ok_or(PreprocError::UnexpectedClose)??;
    if bhat.len() != N {
        return Err(PreprocError::Malformed("b_hat has wrong length"));
    }
    if !bhat.iter().all(|&b| b <= 1) {
        return Err(PreprocError::Malformed("b_hat entries must be bits"));
    }

    let voprf = match voprf {
        Some(voprf) => {
            let b_bar = bhat[..].try_into().expect("length checked above");
            Some(voprf.finish(b_bar).await?)
        }
        None => None,
    };

    Ok(ClientState::new(ot_blocks, bhat, r_c, uid, voprf))
}

/// Run the server side of PreProc (Figure 3).
///
/// The server receives the `uid` (line 1), is the receiver in the n
/// binary rOTs (line 2), the sender in the τ 1-out-of-Δ rOTs
/// (line 3), and sends the masked key bits b̄ (line 4).
///
/// Both sides must pass the same `tau` - a disagreement is rejected before any
/// OT runs.
pub async fn preproc_server(
    conn: &mut Connection,
    sk: &SecretKey,
    tau: usize,
) -> Result<ServerState, PreprocError> {
    if tau == 0 {
        return Err(PreprocError::ZeroTau);
    }

    let binary_ot_conn = conn.sub_connection();
    let delta_ot_conn = conn.sub_connection();
    let (mut msg_send, mut msg_recv) = conn.stream::<Vec<u8>>().await?;
    msg_recv
        .get_mut()
        .decoder_mut()
        .set_max_frame_length(MAX_CONTROL_FRAME_BYTES);

    // Line (1): receive uid, and the tau the client is preprocessing for.
    let hello = msg_recv
        .next()
        .await
        .ok_or(PreprocError::UnexpectedClose)??;
    if hello.len() != HELLO_BYTES {
        return Err(PreprocError::Malformed("hello has wrong length"));
    }
    let uid: Uid = hello[..LAMBDA_BYTES]
        .try_into()
        .expect("length checked above");
    let theirs = decode_tau(&hello[LAMBDA_BYTES..HELLO_BYTES - 1])?;
    let wants_voprf = match hello[HELLO_BYTES - 1] {
        0 => false,
        1 => true,
        _ => return Err(PreprocError::Malformed("the VOPRF flag must be 0 or 1")),
    };

    // Echoed before the check so the client fails with the same error rather
    // than with a dropped connection.
    msg_send.send(encode_tau(tau).to_vec()).await?;
    if theirs != tau {
        return Err(PreprocError::TauMismatch { ours: tau, theirs });
    }
    if wants_voprf && evaluations_for(tau) == 0 {
        return Err(PreprocError::VoprfTauTooSmall { tau });
    }

    let mut voprf = if wants_voprf {
        Some(ServerPreprocessing::open(conn).await?)
    } else {
        None
    };

    // Line (2): N binary rOTs with the server as receiver.
    let mut receiver = ot_receiver(binary_ot_conn);
    let (ot_blocks, choices) = receiver.rand_choice_receive(BINARY_OT_COUNT).await?;
    let r_s: Vec<RsEntry> = choices
        .iter()
        .zip(ot_blocks)
        .take(N)
        .map(|(c, ot_block)| RsEntry {
            b: c.unwrap_u8(),
            ot_block,
        })
        .collect();

    if let Some(voprf) = &mut voprf {
        voprf
            .receive_masks_commitments(&r_s, evaluations_for(tau))
            .await?;
    }

    // Line (3): tau 1-out-of-Δ rOTs with the server as sender.
    let mut sender = ot_sender(delta_ot_conn);
    let sender_out = delta_ot_send(&mut sender, tau).await?;
    let s_s = sender_out
        .blocks
        .iter()
        .map(|blocks| std::array::from_fn(|k| r_prime_from_block(&blocks[k])))
        .collect();

    if let Some(voprf) = &mut voprf {
        voprf
            .send_pads_commitments(sender_out.blocks, evaluations_for(tau))
            .await?;
    }

    // Line (4): send the masked key bits b̄_i = b_i ⊕ sk_i.
    let bhat: [u8; N] = array::from_fn(|i| r_s[i].b ^ sk.as_bits()[i]);
    msg_send.send(bhat.to_vec()).await?;

    let voprf = match voprf {
        Some(voprf) => Some(voprf.prove(sk, &r_s, bhat).await?),
        None => None,
    };

    Ok(ServerState::new(r_s, s_s, uid, voprf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pool_prf::params::Q;

    #[test]
    fn expand_deterministic_and_in_range() {
        let ot_block = Block::new([7u8; Block::BYTES]);
        for j in 0..1000 {
            let r = expand(&ot_block, j)[0];
            assert_eq!(r, expand(&ot_block, j)[0]);
            assert!(r < Q);
        }
    }

    #[test]
    fn expand_differs_across_runs_and_ot_blocks() {
        let ot_block_a = Block::new([1u8; Block::BYTES]);
        let ot_block_b = Block::new([2u8; Block::BYTES]);

        assert_ne!(
            expand(&ot_block_a, 0),
            expand(&ot_block_a, 1),
            "a later run gives different masks"
        );
        assert_ne!(
            expand(&ot_block_a, 0),
            expand(&ot_block_b, 0),
            "a different OT block gives different masks"
        );
    }

    #[test]
    fn runs_exhaust_after_tau() {
        let tau = 4;
        let mut runs = Runs::new(tau);
        assert_eq!(runs.remaining(), tau);

        for taken in 0..tau {
            assert_eq!(runs.take(1), Some(taken as u64), "runs come out in order");
            assert_eq!(runs.remaining(), tau - 1 - taken);
        }

        assert_eq!(runs.take(1), None);
        assert_eq!(runs.take(1), None);
        assert_eq!(runs.remaining(), 0);
    }

    #[test]
    fn a_request_that_does_not_fit_spends_nothing() {
        let mut runs = Runs::new(4);

        assert_eq!(runs.take(3), Some(0));
        assert_eq!(runs.take(3), None, "only one run left");
        assert_eq!(runs.remaining(), 1, "the refusal spent nothing");
    }

    /// The client's own check stops it before the hello. This one skips it
    /// and sends a VOPRF hello for less than one evaluation.
    #[tokio::test]
    async fn the_server_refuses_a_voprf_for_less_than_one_evaluation() {
        let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let sk = SecretKey::random(&mut rand::rng());
        let tau = H_ROWS - 1;

        // The client's streams, in the order of `preproc_client`.
        let _binary_ot_conn = client_conn.sub_connection();
        let _delta_ot_conn = client_conn.sub_connection();
        let (mut msg_send, _msg_recv) = client_conn.stream::<Vec<u8>>().await.unwrap();
        let mut hello = [0u8; LAMBDA_BYTES].to_vec();
        hello.extend_from_slice(&encode_tau(tau));
        hello.push(1);
        msg_send.send(hello).await.unwrap();

        let server = preproc_server(&mut server_conn, &sk, tau).await;
        assert!(
            matches!(server, Err(PreprocError::VoprfTauTooSmall { tau: got }) if got == tau),
            "{server:?}"
        );
    }
}
