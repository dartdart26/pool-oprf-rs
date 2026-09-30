pub trait Statement {
    type Witness;

    /// Whether `witness` satisfies the statement.
    fn holds_for(&self, witness: &Self::Witness) -> bool;
}
