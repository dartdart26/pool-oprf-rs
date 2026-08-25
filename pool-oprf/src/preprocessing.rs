//! OT-based preprocessing for the Pool OPRF (Figure 3 of the paper).
//!
//! One preprocessing run produces `tau` *slots*, one per base protocol run.
//! A slot yields one Zp element and is spent once. A full PRF evaluation
//! spends `H_ROWS` consecutive slots, so a session covers `tau / H_ROWS`
//! full evaluations.
//!
//! The paper says each binary-rOT message is a vector of tau Zq elements,
//! i.e. randomness from the OT. Our OTs output a 128-bit [`Block`] per
//! message, so we take that randomness and expand it via BLAKE3: entry j of
//! the vector is `derive_r(block, j)`, computed on demand instead of
//! stored.

use crate::delta_ot::{delta_ot_receive, delta_ot_send};
use cryprot_core::Block;
use cryprot_net::Connection;
use cryprot_ot::extension::BASE_OT_COUNT;
#[cfg(not(feature = "silent-ot"))]
use cryprot_ot::extension::{SemiHonestOtExtensionReceiver, SemiHonestOtExtensionSender};
use cryprot_ot::{RandChoiceRotReceiver, RotSender};
#[cfg(feature = "silent-ot")]
use cryprot_ot::{
    SemiHonestMarker,
    silent_ot::{SilentOtReceiver, SilentOtSender},
};

/// The rOT type this build preprocesses with.
#[cfg(not(feature = "silent-ot"))]
pub(crate) type OtSender = SemiHonestOtExtensionSender;
#[cfg(not(feature = "silent-ot"))]
pub(crate) type OtReceiver = SemiHonestOtExtensionReceiver;
#[cfg(feature = "silent-ot")]
pub(crate) type OtSender = SilentOtSender<SemiHonestMarker>;
#[cfg(feature = "silent-ot")]
pub(crate) type OtReceiver = SilentOtReceiver<SemiHonestMarker>;

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
use rand::{CryptoRng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session identifier, `uid` in Figure 3.
pub type Uid = [u8; LAMBDA_BYTES];

/// Sample a fresh `uid`.
pub fn random_uid(rng: &mut (impl Rng + CryptoRng)) -> Uid {
    let mut uid = Uid::default();
    rng.fill(&mut uid);
    uid
}

/// The `tau` that `evaluations` full OPRF evaluations need.
///
/// Panics rather than wrapping.
pub const fn tau_for(evaluations: usize) -> usize {
    evaluations
        .checked_mul(H_ROWS)
        .expect("evaluations * H_ROWS overflows usize")
}

/// Full evaluations that `slots` can pay for. A remainder is unusable, since
/// an evaluation needs all `H_ROWS` of its rows.
pub const fn evaluations_for(slots: usize) -> usize {
    slots / H_ROWS
}

/// Domain separator for deriving the `r` masks from OT seed Blocks.
const R_DOMAIN_SEPARATOR: &str = "pool-oprf v1 zq mask from ot seed";

/// Bytes of XOF output each mask is cut from.
const MASK_BYTES: usize = size_of::<Zq>();

/// The protocol wants `tau` masks per binary OT message, but our OT hands us
/// a single 128-bit `Block`, so we expand it to produce multiple masks via
/// BLAKE3.
///
/// `first_slot` is the slot the masks start at, from 0 to `tau` - 1.
///
/// `H_ROWS` at once rather than one at a time: an evaluation spends `H_ROWS`
/// consecutive slots, and a single hash setup covers all of them.
pub(crate) fn derive_r(seed: &Block, first_slot: u64) -> [Zq; H_ROWS] {
    let mut hasher = blake3::Hasher::new_derive_key(R_DOMAIN_SEPARATOR);
    hasher.update(seed.as_bytes());
    let mut xof = hasher.finalize_xof();
    xof.set_position(first_slot * MASK_BYTES as u64);

    let mut buf = [0u8; H_ROWS * MASK_BYTES];
    xof.fill(&mut buf);

    let (raws, _) = buf.as_chunks::<MASK_BYTES>();
    let mut out = [0 as Zq; H_ROWS];
    for (mask, raw) in out.iter_mut().zip(raws) {
        *mask = reduce_q(Zq::from_le_bytes(*raw));
    }
    out
}

/// Bytes of a block taken for one Zp element.
const P_BYTES: usize = size_of::<Zp>();

/// The Block is a BLAKE3 output (see `delta_ot::derive_ot_block`), so its
/// leading bytes are uniform, and reducing them mod p leaves them uniform in
/// Zp as p is a power of two.
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

/// The slot budget: how many preprocessing slots exist, and how many are
/// spent.
#[derive(Debug)]
pub(crate) struct Slots {
    tau: usize,
    /// Next unspent slot, 0 to `tau` - 1.
    ctr: usize,
}

impl Slots {
    fn new(tau: usize) -> Self {
        Self { tau, ctr: 0 }
    }

    fn remaining(&self) -> usize {
        self.tau - self.ctr
    }

    /// Take `count` slots, returning the first, or `None` if that many are not left.
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
    /// `S_C` stored as seeds.
    /// `r_seeds[i][0]` expands to the mask vector `(r^0_{0,i}, ..., r^tau-1_{0,i})`,
    /// `r_seeds[i][1]` expands to the mask vector `(r^0_{1,i}, ..., r^tau-1_{1,i})`.
    r_seeds: [[Block; 2]; N],

    /// `b_hat_i = b_i ^ sk_i`, the masked key bits. One byte per bit,
    /// values 0 or 1.
    bhat: [u8; N],

    /// Length `tau`.
    r_c: Vec<RcEntry>,

    uid: Uid,

    slots: Slots,
}

/// One entry of `R_S`.
#[derive(Clone, Copy)]
pub(crate) struct RsEntry {
    /// `b_i`, 0 or 1.
    pub(crate) b: u8,
    /// Expands to `(r^0_{b_i,i}, ..., r^{tau-1}_{b_i,i})`.
    pub(crate) r_seed: Block,
}

impl std::fmt::Debug for RsEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsEntry(****)")
    }
}

impl Zeroize for RsEntry {
    fn zeroize(&mut self) {
        self.b.zeroize();
        self.r_seed.as_mut_bytes().zeroize();
    }
}

/// Server-side preprocessing state in Figure 3.
pub struct ServerState {
    r_s: [RsEntry; N],

    /// Length `tau`.
    s_s: Vec<[Zp; DELTA]>,

    uid: Uid,

    slots: Slots,
}

impl ClientState {
    pub(crate) fn new(
        r_seeds: Vec<[Block; 2]>,
        bhat: Vec<u8>,
        r_c: Vec<RcEntry>,
        uid: Uid,
    ) -> Self {
        let r_seeds: [[Block; 2]; N] = r_seeds.try_into().expect("N binary rOT seed pairs");
        let bhat: [u8; N] = bhat.try_into().expect("N masked key bits");
        let slots = Slots::new(r_c.len());
        Self {
            r_seeds,
            bhat,
            r_c,
            uid,
            slots,
        }
    }

    pub fn uid(&self) -> &Uid {
        &self.uid
    }

    pub fn remaining_slots(&self) -> usize {
        self.slots.remaining()
    }

    /// `r^j_{b_hat_i,i}` onward, the client's blinding masks for coordinate `i`.
    pub(crate) fn r_bhat(&self, i: usize, first_slot: u64) -> [Zq; H_ROWS] {
        derive_r(&self.r_seeds[i][self.bhat[i] as usize], first_slot)
    }

    /// `r^j_{1-b_hat_i,i}` onward, the side not used for blinding.
    pub(crate) fn r_not_bhat(&self, i: usize, first_slot: u64) -> [Zq; H_ROWS] {
        derive_r(&self.r_seeds[i][1 - self.bhat[i] as usize], first_slot)
    }

    pub(crate) fn r_c(&self, j: u64) -> RcEntry {
        self.r_c[j as usize]
    }

    /// Reserve `count` consecutive slots, returning the first, or `None` if
    /// that many are not left.
    pub(crate) fn next_slots(&mut self, count: usize) -> Option<u64> {
        self.slots.take(count)
    }
}

impl std::fmt::Debug for ClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientState")
            .field("uid", &self.uid)
            .field("slots", &self.slots)
            .finish_non_exhaustive()
    }
}

impl Zeroize for ClientState {
    fn zeroize(&mut self) {
        for pair in &mut self.r_seeds {
            for seed in pair {
                seed.as_mut_bytes().zeroize();
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
    pub(crate) fn new(r_s: Vec<RsEntry>, s_s: Vec<[Zp; DELTA]>, uid: Uid) -> Self {
        let r_s: [RsEntry; N] = r_s.try_into().expect("N binary rOT entries");
        let slots = Slots::new(s_s.len());
        Self {
            r_s,
            s_s,
            uid,
            slots,
        }
    }

    pub fn uid(&self) -> &Uid {
        &self.uid
    }

    pub fn remaining_slots(&self) -> usize {
        self.slots.remaining()
    }

    /// `r^j_{b_i,i}` onward, the masks the server knows for binary OT `i`.
    pub(crate) fn r(&self, i: usize, first_slot: u64) -> [Zq; H_ROWS] {
        derive_r(&self.r_s[i].r_seed, first_slot)
    }

    pub(crate) fn s_s(&self, j: u64) -> &[Zp; DELTA] {
        &self.s_s[j as usize]
    }

    /// Reserve `count` consecutive slots, returning the first, or `None` if
    /// that many are not left.
    pub(crate) fn next_slots(&mut self, count: usize) -> Option<u64> {
        self.slots.take(count)
    }
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("uid", &self.uid)
            .field("slots", &self.slots)
            .finish_non_exhaustive()
    }
}

impl Zeroize for ServerState {
    fn zeroize(&mut self) {
        for entry in &mut self.r_s {
            entry.zeroize();
        }
        self.s_s.zeroize();
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
    #[error("peer is preprocessing for tau = {theirs}, this side asked for {ours}")]
    TauMismatch { ours: usize, theirs: usize },
}

/// The opening message: `uid` followed by `tau` as a little-endian `u64`.
const HELLO_BYTES: usize = LAMBDA_BYTES + 8;

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
/// The client samples the `uid` (line 1), is the sender in the N
/// binary rOTs (line 2), the receiver in the tau (DELTA-choose-1) rOTs
/// (line 3), and receives the masked key bits b_hat (line 4).
///
/// Both sides must pass the same `tau` - a disagreement is rejected before any
/// OT runs.
pub async fn preproc_client(
    conn: &mut Connection,
    tau: usize,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<ClientState, PreprocError> {
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

    // Line (1): sample uid and share it with the server, along with tau.
    //
    // tau is not in the paper's message (it is assumed agreed). Both sides
    // state theirs and refuse to continue if the two differ.
    let uid = random_uid(rng);
    let mut hello = uid.to_vec();
    hello.extend_from_slice(&encode_tau(tau));
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

    // Line (2): N binary rOTs with the client as sender. Keep the seed
    // pairs.
    let mut sender = ot_sender(binary_ot_conn);
    let mut r_seeds = sender.send(BINARY_OT_COUNT).await?;
    r_seeds.truncate(N);

    // Line (3): tau (DELTA-choose-1) rOTs with the client as receiver.
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

    // Line (4): receive the masked key bits b_hat_i = b_i ^ sk_i.
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

    Ok(ClientState::new(r_seeds, bhat, r_c, uid))
}

/// Run the server side of PreProc (Figure 3).
///
/// The server receives the `uid` (line 1), is the receiver in the N
/// binary rOTs (line 2), the sender in the tau (DELTA-choose-1) rOTs
/// (line 3), and sends the masked key bits b_hat (line 4).
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
    let theirs = decode_tau(&hello[LAMBDA_BYTES..])?;

    // Echoed before the check so the client fails with the same error rather
    // than with a dropped connection.
    msg_send.send(encode_tau(tau).to_vec()).await?;
    if theirs != tau {
        return Err(PreprocError::TauMismatch { ours: tau, theirs });
    }

    // Line (2): N binary rOTs with the server as receiver.
    let mut receiver = ot_receiver(binary_ot_conn);
    let (r_seeds, choices) = receiver.rand_choice_receive(BINARY_OT_COUNT).await?;
    let r_s: Vec<RsEntry> = choices
        .iter()
        .zip(r_seeds)
        .take(N)
        .map(|(c, r_seed)| RsEntry {
            b: c.unwrap_u8(),
            r_seed,
        })
        .collect();

    // Line (3): tau (DELTA-choose-1) rOTs with the server as sender.
    let mut sender = ot_sender(delta_ot_conn);
    let sender_out = delta_ot_send(&mut sender, tau).await?;
    let s_s = sender_out
        .blocks
        .iter()
        .map(|blocks| std::array::from_fn(|k| r_prime_from_block(&blocks[k])))
        .collect();

    // Line (4): send the masked key bits b_hat_i = b_i ^ sk_i.
    let bhat: Vec<u8> = r_s
        .iter()
        .zip(sk.as_bits())
        .map(|(entry, &sk_i)| entry.b ^ sk_i)
        .collect();
    msg_send.send(bhat).await?;

    Ok(ServerState::new(r_s, s_s, uid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pool_prf::params::Q;

    #[test]
    fn derive_r_deterministic_and_in_range() {
        let seed = Block::new([7u8; Block::BYTES]);
        for j in 0..1000 {
            let r = derive_r(&seed, j)[0];
            assert_eq!(r, derive_r(&seed, j)[0]);
            assert!(r < Q);
        }
    }

    #[test]
    fn derive_r_differs_across_slots_and_seeds() {
        let seed_a = Block::new([1u8; Block::BYTES]);
        let seed_b = Block::new([2u8; Block::BYTES]);

        assert_ne!(
            derive_r(&seed_a, 0),
            derive_r(&seed_a, 1),
            "a later slot gives different masks"
        );
        assert_ne!(
            derive_r(&seed_a, 0),
            derive_r(&seed_b, 0),
            "a different seed gives different masks"
        );
    }

    #[test]
    fn slots_exhaust_after_tau() {
        let tau = 4;
        let mut slots = Slots::new(tau);
        assert_eq!(slots.remaining(), tau);

        for taken in 0..tau {
            assert_eq!(slots.take(1), Some(taken as u64), "slots come out in order");
            assert_eq!(slots.remaining(), tau - 1 - taken);
        }

        assert_eq!(slots.take(1), None);
        assert_eq!(slots.take(1), None);
        assert_eq!(slots.remaining(), 0);
    }

    #[test]
    fn a_request_that_does_not_fit_spends_nothing() {
        let mut slots = Slots::new(4);

        assert_eq!(slots.take(3), Some(0));
        assert_eq!(slots.take(3), None, "only one slot left");
        assert_eq!(slots.remaining(), 1, "the refusal spent nothing");
    }
}
