//! A generic commitment trait.

pub trait Commitment: PartialEq {
    /// What it commits to.
    type Input;

    fn commit(input: &Self::Input) -> Self;
}
