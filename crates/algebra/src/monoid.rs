use crate::semigroup::Semigroup;

/// A [`Monoid`] is an algebraic structure with [`Semigroup`] properties as well as equipped with
/// a single identity element. The key property of the [`Monoid::empty`] value is as follows:
///
/// a: T
/// T: Monoid
/// T::empty().merge(a) == a.merge(T::empty()) == a
///
/// Intuitively this means that giving [`Monoid::empty`] as an argument to [`Semigroup::merge`] MUST
/// return the merge's other argument.
pub trait Monoid: Semigroup {
    fn empty() -> Self;
}

/// The free catamorphism (fold) over a Monoidal iterator. If the iterator has no elements, it
/// returns [`Monoid::empty`], otherwise it folds the iterator using [`Semigroup::merge`].
pub fn concat<T: Monoid>(xs: impl IntoIterator<Item = T>) -> T {
    xs.into_iter().fold(T::empty(), <T as Semigroup>::merge)
}

/// The universal catamorphism over all iterators. If given the iterant type has a morphism into a
/// Monoidal structure this function will use that Monoidal structure to fold.
pub fn fold_map<T: Monoid, U, Iter: IntoIterator<Item = U>, F: FnMut(U) -> T>(f: F, xs: Iter) -> T {
    concat(xs.into_iter().map(f))
}
