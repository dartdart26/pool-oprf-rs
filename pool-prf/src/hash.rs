use crate::modular::reduce_q;
use crate::params::{H_ROWS, N, Zq};

/// A vector of `N` elements in Zq (one row of the hash matrix).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZqVector(pub(crate) [Zq; N]);

impl ZqVector {
    pub fn as_slice(&self) -> &[Zq] {
        &self.0
    }
}

/// A matrix of `H_ROWS` x `N` elements in Zq, produced by hashing an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZqMatrix(pub(crate) [ZqVector; H_ROWS]);

impl ZqMatrix {
    pub fn row(&self, idx: usize) -> &ZqVector {
        &self.0[idx]
    }
}

/// Domain separator for the random oracle.
const RO_DOMAIN_SEPARATOR: &str = "pool-oprf v1 random oracle to zq matrix";

/// Hash a tag and an input to a matrix in Zq^{H_ROWS x N} using BLAKE3 in XOF
/// mode. This is `RO(t, x)` from Figure 4.
///
/// `tag` is the public input of the partial OPRF - the server sees it, unlike
/// `input`.
///
/// The tag's length goes in first so the hash can tell where the tag ends.
/// Without it, tag "ab" + input "c" and tag "a" + input "bc" are the same
/// bytes, so they would hash the same - and a value made under one tag would
/// then be valid under another.
///
/// Each element is 12 bits (values in 0..4095). We extract 2 bytes per element
/// from the XOF output and mask to 12 bits.
pub fn hash_to_zq_matrix(tag: &[u8], input: &[u8]) -> ZqMatrix {
    let mut hasher = blake3::Hasher::new_derive_key(RO_DOMAIN_SEPARATOR);
    hasher.update(&(tag.len() as u64).to_le_bytes());
    hasher.update(tag);
    hasher.update(input);
    let mut xof = hasher.finalize_xof();

    const TOTAL_ELEMENTS: usize = H_ROWS * N;
    let mut buf = vec![0u8; TOTAL_ELEMENTS * 2];
    xof.fill(&mut buf);

    let rows = std::array::from_fn(|row| {
        let mut vec = [0 as Zq; N];
        let offset = row * N * 2;
        for i in 0..N {
            let lo = Zq::from(buf[offset + 2 * i]);
            let hi = Zq::from(buf[offset + 2 * i + 1]);
            vec[i] = reduce_q(lo | (hi << 8));
        }
        ZqVector(vec)
    });

    ZqMatrix(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        assert_eq!(
            hash_to_zq_matrix(b"tag", b"test input"),
            hash_to_zq_matrix(b"tag", b"test input"),
        );
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(
            hash_to_zq_matrix(b"tag", b"input A"),
            hash_to_zq_matrix(b"tag", b"input B"),
        );
    }

    #[test]
    fn different_tags_differ() {
        assert_ne!(
            hash_to_zq_matrix(b"tag A", b"input"),
            hash_to_zq_matrix(b"tag B", b"input"),
        );
        assert_ne!(
            hash_to_zq_matrix(b"", b"input"),
            hash_to_zq_matrix(b"tag", b"input"),
        );
    }

    /// The length prefix must make the (tag, input) split unambiguous: these
    /// two pairs concatenate to the same bytes but must hash differently.
    #[test]
    fn tag_boundary_is_unambiguous() {
        assert_ne!(
            hash_to_zq_matrix(b"ab", b"c"),
            hash_to_zq_matrix(b"a", b"bc"),
        );
    }

    #[test]
    fn values_in_range() {
        let m = hash_to_zq_matrix(b"tag", b"range check");
        for row in 0..H_ROWS {
            for &elem in &m.0[row].0 {
                assert!(elem < crate::params::Q, "element {elem} >= Q");
            }
        }
    }

    #[test]
    fn rows_are_independent() {
        let m = hash_to_zq_matrix(b"tag", b"independence check");
        // All rows should be distinct (overwhelmingly likely)
        for i in 0..H_ROWS {
            for j in (i + 1)..H_ROWS {
                assert_ne!(m.0[i], m.0[j], "rows {i} and {j} are identical");
            }
        }
    }
}
