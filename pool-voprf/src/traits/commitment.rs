//! A generic commitment trait.

pub trait Commitment: PartialEq {
    /// What it commits to.
    type Value;

    fn commit(value: &Self::Value) -> Self;
}
