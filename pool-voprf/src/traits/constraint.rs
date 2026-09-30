pub trait Constraint {
    /// Whether the values satisfy the constraint.
    fn holds(&self) -> bool;
}
