//! Private set intersection from the Pool OPRF.

use pool_oprf::online::MAX_BATCH_EVALUATIONS;
use pool_prf::params::OUTPUT_ELEMENTS;
use pool_prf::prf::{PrfOutput, SecretKey, evaluate};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub type MaskedElement = [u8; OUTPUT_ELEMENTS];

pub const MAX_CLIENT_SET: usize = 1 << 16;
pub const MAX_SERVER_SET: usize = 1 << 20;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaskedServerSet {
    /// The public tag every element was evaluated under. The server chooses
    /// it.
    pub tag: Vec<u8>,
    /// `F_sk(tag, y)` for each `y`, sorted and deduplicated.
    pub elements: Vec<MaskedElement>,
}

/// Round trips the online phase will take for a set of `set_size`, one per batch.
pub fn chunks_for(set_size: usize) -> usize {
    set_size.div_ceil(MAX_BATCH_EVALUATIONS)
}

/// Mask the server's set: `F_sk(tag, y)` for each `y`.
///
/// Sorted and deduplicated. Sorting the masked results leaks less.
pub fn mask_server_set<T: AsRef<[u8]>>(
    sk: &SecretKey,
    tag: &[u8],
    set: impl IntoIterator<Item = T>,
) -> Vec<MaskedElement> {
    let mut masked: Vec<MaskedElement> = set
        .into_iter()
        .map(|y| *evaluate(sk, tag, y.as_ref()).elements())
        .collect();
    masked.sort_unstable();
    masked.dedup();
    masked
}

/// Indices into `outputs` whose element is in the server's set.
///
/// `outputs` are the client's OPRF results in the order of its own set, so
/// the indices returned index that set too.
pub fn intersect(outputs: &[PrfOutput], server: &[MaskedElement]) -> Vec<usize> {
    let haystack: HashSet<&MaskedElement> = server.iter().collect();
    outputs
        .iter()
        .enumerate()
        .filter(|(_, out)| haystack.contains(out.elements()))
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: &[u8] = b"tag-1";

    fn key() -> SecretKey {
        SecretKey::random(&mut rand::rng())
    }

    #[test]
    fn intersect_finds_exactly_the_common_elements() {
        let sk = key();
        let client: [&[u8]; 4] = [b"alice", b"bob", b"carol", b"dave"];
        let server: [&[u8]; 3] = [b"bob", b"dave", b"erin"];

        let masked = mask_server_set(&sk, TAG, server);
        let outputs: Vec<PrfOutput> = client.iter().map(|x| evaluate(&sk, TAG, x)).collect();

        // bob is index 1, dave is index 3.
        assert_eq!(intersect(&outputs, &masked), vec![1, 3]);
    }

    #[test]
    fn disjoint_sets_intersect_to_nothing() {
        let sk = key();
        let client: [&[u8]; 2] = [b"alice", b"carol"];
        let server: [&[u8]; 2] = [b"bob", b"dave"];

        let masked = mask_server_set(&sk, TAG, server);
        let outputs: Vec<PrfOutput> = client.iter().map(|x| evaluate(&sk, TAG, x)).collect();

        assert!(intersect(&outputs, &masked).is_empty());
    }

    #[test]
    fn a_different_tag_matches_nothing() {
        let sk = key();
        let set: [&[u8]; 3] = [b"alice", b"bob", b"carol"];

        let masked = mask_server_set(&sk, b"tag-1", set);
        let outputs: Vec<PrfOutput> = set.iter().map(|x| evaluate(&sk, b"tag-2", x)).collect();

        assert!(intersect(&outputs, &masked).is_empty());
    }

    #[test]
    fn a_different_key_matches_nothing() {
        let set: [&[u8]; 3] = [b"alice", b"bob", b"carol"];
        let masked = mask_server_set(&key(), TAG, set);

        let other = key();
        let outputs: Vec<PrfOutput> = set.iter().map(|x| evaluate(&other, TAG, x)).collect();

        assert!(intersect(&outputs, &masked).is_empty());
    }

    #[test]
    fn masking_sorts_and_deduplicates() {
        let sk = key();
        let with_repeats: [&[u8]; 5] = [b"bob", b"alice", b"bob", b"carol", b"alice"];

        let masked = mask_server_set(&sk, TAG, with_repeats);

        assert_eq!(masked.len(), 3, "repeats must collapse");
        assert!(
            masked.is_sorted_by(|a, b| a < b),
            "must be sorted and deduplicated"
        );
    }

    #[test]
    fn client_duplicates_are_reported_separately() {
        let sk = key();
        let client: [&[u8]; 3] = [b"bob", b"alice", b"bob"];
        let server: [&[u8]; 1] = [b"bob"];

        let masked = mask_server_set(&sk, TAG, server);
        let outputs: Vec<PrfOutput> = client.iter().map(|x| evaluate(&sk, TAG, x)).collect();

        assert_eq!(intersect(&outputs, &masked), vec![0, 2]);
    }

    #[test]
    fn sizing_matches_the_oprf_batching() {
        assert_eq!(chunks_for(1), 1);
        assert_eq!(chunks_for(MAX_BATCH_EVALUATIONS), 1);
        assert_eq!(chunks_for(MAX_BATCH_EVALUATIONS + 1), 2);
        assert_eq!(chunks_for(2 * MAX_BATCH_EVALUATIONS), 2);
    }
}
