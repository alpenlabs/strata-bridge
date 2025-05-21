pub trait Semigroup {
    fn merge(self, other: Self) -> Self;
}
