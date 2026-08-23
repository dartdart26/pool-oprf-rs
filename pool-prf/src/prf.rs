use crate::hash::{ZqMatrix, ZqVector, hash_to_zq_matrix};
use crate::modular::reduce_q;
use crate::params::{N, OUTPUT_ELEMENTS, Zp, Zq, ZqAccum};
use crate::round::round_zq_to_zp;
use rand::{CryptoRng, Rng};
use serde::Deserialize;
use serde::Serialize;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret key for the LWR-based PRF: a binary vector of length N.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) [u8; N]);

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let bits: [u8; N] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            de::Error::custom(format!("expected {} bytes, got {}", N, bytes.len()))
        })?;
        SecretKey::from_bits(bits).ok_or_else(|| de::Error::custom("key bytes must be 0 or 1"))
    }
}

impl SecretKey {
    /// Sample a fresh key.
    pub fn random(rng: &mut (impl Rng + CryptoRng)) -> Self {
        let mut key = [0u8; N];
        rng.fill(&mut key[..]);
        for k in &mut key {
            *k &= 1;
        }
        SecretKey(key)
    }

    pub fn from_bits(bits: [u8; N]) -> Option<Self> {
        bits.iter().all(|&b| b <= 1).then_some(SecretKey(bits))
    }

    pub fn as_bits(&self) -> &[u8; N] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(****)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrfOutput([Zp; OUTPUT_ELEMENTS]);

impl PrfOutput {
    pub fn elements(&self) -> &[Zp; OUTPUT_ELEMENTS] {
        &self.0
    }
}

impl From<[Zp; OUTPUT_ELEMENTS]> for PrfOutput {
    fn from(elements: [Zp; OUTPUT_ELEMENTS]) -> Self {
        Self(elements)
    }
}

/// Evaluate the PRF on the given tag and input - `Eval(sk, t, x)` of Figure 4.
///
/// `tag` is the OPRF's public input.
/// RO(t, x) produces a matrix of H_ROWS rows, each a vector in Zq^N.
/// For each row, we compute the inner product with sk and round to Zp,
/// giving one output element per row.
pub fn evaluate(sk: &SecretKey, tag: &[u8], input: &[u8]) -> PrfOutput {
    let m = hash_to_zq_matrix(tag, input);
    evaluate_with_matrix(sk, &m)
}

/// Evaluate the PRF given a precomputed hash matrix.
pub fn evaluate_with_matrix(sk: &SecretKey, m: &ZqMatrix) -> PrfOutput {
    let mut output = [0 as Zp; OUTPUT_ELEMENTS];
    for (row, out) in output.iter_mut().enumerate() {
        *out = evaluate_single_row(sk, m.row(row));
    }
    PrfOutput(output)
}

/// Evaluate via a single inner product + round, outputting one Zp element.
pub fn evaluate_single_row(sk: &SecretKey, v: &ZqVector) -> Zp {
    let inner = inner_product(v, sk);
    round_zq_to_zp(inner)
}

/// Compute the inner product of a Zq vector with a binary secret key.
///
/// Since sk is binary, this is just the sum of v[i] where sk[i] = 1,
/// reduced mod Q.
pub(crate) fn inner_product(v: &ZqVector, sk: &SecretKey) -> Zq {
    // Since sk is binary, the inner product is just the sum of v[i] where sk[i] = 1.
    let sum: ZqAccum =
        v.0.iter()
            .zip(&sk.0)
            .map(|(&vi, &si)| vi as ZqAccum * si as ZqAccum)
            .sum();
    reduce_q(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::H_ROWS;

    #[test]
    fn prf_deterministic() {
        let sk = SecretKey::random(&mut rand::rng());
        let out1 = evaluate(&sk, b"tag", b"hello world");
        let out2 = evaluate(&sk, b"tag", b"hello world");
        assert_eq!(out1, out2);
    }

    #[test]
    fn output_has_one_element_per_row() {
        let sk = SecretKey::random(&mut rand::rng());
        let out = evaluate(&sk, b"tag", b"test");
        assert_eq!(out.elements().len(), H_ROWS);
    }

    #[test]
    fn different_keys_different_outputs() {
        let sk1 = SecretKey::random(&mut rand::rng());
        let sk2 = SecretKey::random(&mut rand::rng());
        let out1 = evaluate(&sk1, b"tag", b"test");
        let out2 = evaluate(&sk2, b"tag", b"test");
        assert_ne!(out1, out2);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let sk = SecretKey::random(&mut rand::rng());
        let out1 = evaluate(&sk, b"tag", b"input A");
        let out2 = evaluate(&sk, b"tag", b"input B");
        assert_ne!(out1, out2);
    }

    #[test]
    fn different_tags_different_outputs() {
        let sk = SecretKey::random(&mut rand::rng());
        let out1 = evaluate(&sk, b"2026-07", b"input");
        let out2 = evaluate(&sk, b"2026-08", b"input");
        assert_ne!(out1, out2);
    }

    #[test]
    fn zero_key_gives_zero() {
        let sk = SecretKey([0u8; N]);
        let out = evaluate(&sk, b"tag", b"anything");
        assert_eq!(out.elements(), &[0 as Zp; OUTPUT_ELEMENTS]);
    }

    #[test]
    fn debug_redacts_key() {
        let sk = SecretKey::random(&mut rand::rng());
        let debug = format!("{:?}", sk);
        assert_eq!(debug, "SecretKey(****)");
    }

    #[test]
    fn row_by_row_equals_full_evaluation() {
        let sk = SecretKey::random(&mut rand::rng());
        let matrix = hash_to_zq_matrix(b"tag", b"consistency");
        let full = evaluate_with_matrix(&sk, &matrix);
        for row in 0..H_ROWS {
            assert_eq!(
                full.elements()[row],
                evaluate_single_row(&sk, matrix.row(row))
            );
        }
    }
}
