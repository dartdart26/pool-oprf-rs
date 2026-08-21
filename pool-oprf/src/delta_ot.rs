//! Builds (DELTA-choose-1) random OT from binary (2-choose-1) random OTs.
//!
//! Since DELTA is a power of 2, a 1-of-DELTA choice is LOG_DELTA binary
//! choices, so LOG_DELTA binary rOTs make one DELTA-choose-1 rOT. Both
//! parties then derive output Blocks by hashing combinations of the binary OT
//! outputs.
//!
//! As an example, say DELTA is 16 and LOG_DELTA is 4, so one DELTA-choose-1
//! rOT costs 4 binary rOTs. Out of those the sender holds a pair
//! (b_i^0, b_i^1) for each i in 0..4 and derives all 16 outputs from them.
//! Bit i of the choice picks which block of pair i to use, least significant
//! bit first, so for c = 3 = 0b0011 the bits are 1, 1, 0, 0 and
//!
//! ```text
//! d3 = hash(b_0^1, b_1^1, b_2^0, b_3^0, 3)
//! ```
//!
//! Every output hashes one block from every pair.
//!
//! A receiver whose binary choices came out [1, 1, 0, 0] holds exactly
//! b_0^1, b_1^1, b_2^0, b_3^0, i.e. one block per pair. It folds those
//! bits into c = 3 and hashes the same inputs, so it gets the same d3 and
//! unable to get any other.

use blake3::Hasher;
use cryprot_core::Block;
use cryprot_ot::RandChoiceRotReceiver;
use cryprot_ot::RotSender;
use cryprot_ot::extension::BASE_OT_COUNT;
use pool_prf::params::{DELTA, LOG_DELTA, Zdelta};
use subtle::Choice;

pub(crate) struct DeltaOtSenderOutput {
    pub(crate) blocks: Vec<[Block; DELTA]>,
}

pub(crate) struct DeltaOtReceiverOutput {
    pub(crate) blocks: Vec<Block>,
    pub(crate) choices: Vec<Zdelta>,
}

// Required by CryProt to be a multiple of BASE_OT_COUNT.
#[inline]
fn required_binary_ot_count(delta_ot_count: usize) -> usize {
    assert!(delta_ot_count > 0, "delta_ot_count must be nonzero");
    (LOG_DELTA * delta_ot_count).next_multiple_of(BASE_OT_COUNT)
}

#[inline]
fn bit(value: Zdelta, i: usize) -> u8 {
    u8::from((value >> i) & 1 != 0)
}

fn choice_from_bits(bits: &[Choice; LOG_DELTA]) -> Zdelta {
    bits.iter().enumerate().fold(0 as Zdelta, |index, (i, c)| {
        index | ((c.unwrap_u8() as Zdelta) << i)
    })
}

// Derive one output Block for a (DELTA-choose-1) rOT by hashing
// LOG_DELTA Blocks together with `choice`.
fn derive_ot_block(blocks: &[Block; LOG_DELTA], choice: Zdelta) -> Block {
    assert!(
        (choice as usize) < DELTA,
        "choice {choice} out of range 0..{DELTA}"
    );
    let mut hasher = Hasher::new();
    for block in blocks {
        hasher.update(block.as_bytes());
    }
    hasher.update(&choice.to_le_bytes());
    let hash = hasher.finalize();
    Block::new(
        *hash
            .as_bytes()
            .first_chunk::<{ Block::BYTES }>()
            .expect("enough bytes from hasher"),
    )
}

// Select one Block from each pair based on the bits of `choice`,
// then derive the output Block.
fn select_and_derive_ot_block(pairs: &[[Block; 2]; LOG_DELTA], choice: Zdelta) -> Block {
    let selected: [Block; LOG_DELTA] = std::array::from_fn(|i| pairs[i][bit(choice, i) as usize]);
    derive_ot_block(&selected, choice)
}

/// Run the sender side of (DELTA-choose-1) random OT.
pub(crate) async fn delta_ot_send<S: RotSender>(
    sender: &mut S,
    delta_ot_count: usize,
) -> Result<DeltaOtSenderOutput, S::Error> {
    let binary_ot_count = required_binary_ot_count(delta_ot_count);
    let pairs = sender.send(binary_ot_count).await?;
    let (chunks, _padding) = pairs.as_chunks::<LOG_DELTA>();
    let blocks = chunks
        .iter()
        .take(delta_ot_count)
        .map(|ot_pairs| {
            std::array::from_fn(|choice| select_and_derive_ot_block(ot_pairs, choice as Zdelta))
        })
        .collect();

    Ok(DeltaOtSenderOutput { blocks })
}

/// Run the receiver side of (DELTA-choose-1) rOT.
pub(crate) async fn delta_ot_receive<R: RandChoiceRotReceiver>(
    receiver: &mut R,
    delta_ot_count: usize,
) -> Result<DeltaOtReceiverOutput, R::Error> {
    let binary_ot_count = required_binary_ot_count(delta_ot_count);
    let (ot_blocks, binary_choices) = receiver.rand_choice_receive(binary_ot_count).await?;
    let (choice_chunks, _padding) = binary_choices.as_chunks::<LOG_DELTA>();
    let choices: Vec<Zdelta> = choice_chunks
        .iter()
        .take(delta_ot_count)
        .map(choice_from_bits)
        .collect();
    let (block_chunks, _padding) = ot_blocks.as_chunks::<LOG_DELTA>();
    let blocks = block_chunks
        .iter()
        .zip(&choices)
        .map(|(selected, &choice)| derive_ot_block(selected, choice))
        .collect();

    Ok(DeltaOtReceiverOutput { blocks, choices })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preprocessing::{ot_receiver, ot_sender};

    // The binary rOT pairs a sender holds for one DELTA-OT.
    fn binary_ot_pairs() -> [[Block; 2]; LOG_DELTA] {
        std::array::from_fn(|i| {
            [
                Block::new([(i * 2) as u8; Block::BYTES]),
                Block::new([(i * 2 + 1) as u8; Block::BYTES]),
            ]
        })
    }

    #[test]
    fn choice_bits_round_trip() {
        for choice in 0..DELTA as Zdelta {
            let bits: [Choice; LOG_DELTA] = std::array::from_fn(|i| Choice::from(bit(choice, i)));
            assert_eq!(choice_from_bits(&bits), choice);
        }
    }

    #[test]
    fn choice_is_in_the_hash() {
        let pairs = binary_ot_pairs();
        let blocks: [Block; LOG_DELTA] = std::array::from_fn(|i| pairs[i][0]);
        let baseline = derive_ot_block(&blocks, 0);

        for choice in 1..DELTA as Zdelta {
            assert_ne!(
                baseline,
                derive_ot_block(&blocks, choice),
                "choices 0 and {choice} derive the same block"
            );
        }
    }

    // Both sides reject a zero count before they touch the connection.
    #[tokio::test]
    #[should_panic(expected = "delta_ot_count must be nonzero")]
    async fn send_rejects_zero_count() {
        let (sender_conn, _receiver_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let mut sender = ot_sender(sender_conn);
        let _ = delta_ot_send(&mut sender, 0).await;
    }

    #[tokio::test]
    #[should_panic(expected = "delta_ot_count must be nonzero")]
    async fn receive_rejects_zero_count() {
        let (_sender_conn, receiver_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let mut receiver = ot_receiver(receiver_conn);
        let _ = delta_ot_receive(&mut receiver, 0).await;
    }

    #[tokio::test]
    async fn sender_and_receiver_agree() {
        const COUNT: usize = 3;

        let (sender_conn, receiver_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let mut sender = ot_sender(sender_conn);
        let mut receiver = ot_receiver(receiver_conn);

        let (sent, received) = tokio::join!(
            delta_ot_send(&mut sender, COUNT),
            delta_ot_receive(&mut receiver, COUNT),
        );
        let sent = sent.unwrap();
        let received = received.unwrap();

        assert_eq!(sent.blocks.len(), COUNT);
        assert_eq!(received.blocks.len(), COUNT);
        assert_eq!(received.choices.len(), COUNT);

        for j in 0..COUNT {
            let choice = received.choices[j] as usize;
            assert!(choice < DELTA, "choice {choice} is outside 0..{DELTA}");
            assert_eq!(
                sent.blocks[j][choice], received.blocks[j],
                "DELTA-OT {j}: the receiver's block is not the sender's candidate at its choice"
            );
        }
    }

    #[test]
    fn different_choices_produce_different_blocks() {
        let pairs = binary_ot_pairs();

        let blocks: Vec<Block> = (0..DELTA as Zdelta)
            .map(|choice| select_and_derive_ot_block(&pairs, choice))
            .collect();

        for i in 0..DELTA {
            for j in (i + 1)..DELTA {
                assert_ne!(blocks[i], blocks[j], "blocks {i} and {j} should differ");
            }
        }
    }
}
