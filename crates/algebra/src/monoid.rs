use crate::semigroup::Semigroup;

pub trait Monoid: Semigroup {
    fn empty() -> Self;
}

pub fn concat<T: Monoid>(xs: impl IntoIterator<Item = T>) -> T {
    xs.into_iter().fold(T::empty(), <T as Semigroup>::merge)
}

pub fn fold_map<T: Monoid, U, Iter: IntoIterator<Item = U>, F: FnMut(U) -> T>(f: F, xs: Iter) -> T {
    concat(xs.into_iter().map(f))
}
