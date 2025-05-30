//! Monoid module.

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
    /// The empty value.
    fn empty() -> Self;
}

/// The free catamorphism (fold) over a Monoidal iterator. If the iterator has no elements, it
/// returns [`Monoid::empty`], otherwise it folds the iterator using [`Semigroup::merge`].
pub fn concat<T: Monoid>(xs: impl IntoIterator<Item = T>) -> T {
    xs.into_iter().fold(T::empty(), <T as Semigroup>::merge)
}

/// The universal catamorphism over all iterators. Provided the iterant type has a morphism into a
/// Monoidal structure this function will use that Monoidal structure to fold.
pub fn fold_map<T: Monoid, U, Iter: IntoIterator<Item = U>, F: FnMut(U) -> T>(f: F, xs: Iter) -> T {
    concat(xs.into_iter().map(f))
}

impl<T> Monoid for Vec<T> {
    fn empty() -> Self {
        Vec::new()
    }
}

/// Laws for the [`Monoid`] trait.
pub mod laws {
    use std::fmt::Debug;

    use proptest::prelude::TestCaseError;

    use super::Monoid;

    /// Checks if the empty value is a left identity.
    #[coverage(off)]
    pub fn merge_left_identity<T: Debug + Monoid + Clone + Eq>(a: T) -> Result<(), TestCaseError> {
        let lhs = T::empty().merge(a.clone());
        if lhs != a {
            let type_name = std::any::type_name::<T>();
            return Err(TestCaseError::fail(format!(
                "{type_name:?}::empty is not a left identity on {type_name:?}::merge: {a:?}"
            )));
        }
        Ok(())
    }

    /// Checks if the empty value is a right identity.
    #[coverage(off)]
    pub fn merge_right_identity<T: Debug + Monoid + Clone + Eq>(a: T) -> Result<(), TestCaseError> {
        let rhs = a.clone().merge(T::empty());
        if a != rhs {
            let type_name = std::any::type_name::<T>();
            return Err(TestCaseError::fail(format!(
                "{type_name:?}::empty is not a left identity on {type_name:?}::merge: {a:?}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prelude::any, prop_assert_eq, proptest};

    proptest! {
        #[test]
        fn vec_monoid_laws(
            a in proptest::collection::vec(any::<u32>(), 1..20)
        ) {
            super::laws::merge_left_identity(a.clone())?;
            super::laws::merge_right_identity(a)?;
        }

        #[test]
        fn concat_is_fold_map_identity(
            a in proptest::collection::vec(proptest::collection::vec(any::<u32>(), 1..5), 1..10)
        ) {
            prop_assert_eq!(super::concat(a.clone()), super::fold_map(|x|x, a))
        }
    }
}
