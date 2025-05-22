/// A [`Semigroup`] is an algebraic structure that is closed under a binary associative operation.
/// To define a lawful semigroup impl you must define the [`Semigroup::merge`] operation. The
/// requirement is as follows:
///
/// a: T
/// b: T
/// c: T
/// a.merge(b).merge(c) == a.merge(b.merge(c))
pub trait Semigroup {
    /// The canonical semigroup operation. This operation is associative and linear in both
    /// arguments.
    fn merge(self, other: Self) -> Self;
}

/// A folding operation over an iterator that uses the `T`'s [`Semigroup::merge`] function as the
/// folding function.
pub fn sconcat<T: Semigroup>(xs: impl IntoIterator<Item = T>) -> Option<T> {
    xs.into_iter().fold(None, |opt, x| {
        Some(match opt {
            Some(acc) => acc.merge(x),
            None => x,
        })
    })
}

impl Semigroup for () {
    fn merge(self, _: Self) -> Self {}
}

impl<T> Semigroup for Vec<T> {
    fn merge(mut self, other: Self) -> Self {
        self.extend(other);
        self
    }
}

impl<T: Semigroup> Semigroup for Option<T> {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (None, None) => None,
            (None, b @ Some(_)) => b,
            (a @ Some(_), None) => a,
            (Some(a), Some(b)) => Some(a.merge(b)),
        }
    }
}

impl<T, E> Semigroup for Result<T, E> {
    fn merge(self, other: Self) -> Self {
        if self.is_ok() {
            self
        } else {
            other
        }
    }
}

pub mod laws {
    use std::fmt::Debug;

    use proptest::prelude::TestCaseError;

    use super::Semigroup;

    pub fn merge_associative_clone_eq<T: Debug + Semigroup + Clone + Eq>(
        a: T,
        b: T,
        c: T,
    ) -> Result<(), TestCaseError> {
        let lhs = a.clone().merge(b.clone()).merge(c.clone());
        let rhs = a.clone().merge(b.clone().merge(c.clone()));
        if lhs != rhs {
            return Err(TestCaseError::fail(format!(
                "{:?}::merge is not associative: {a:?}, {b:?}, {c:?}",
                std::any::type_name::<T>()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prelude::any, proptest};

    proptest! {
        #[test]
        fn vec_semigroup_laws(
            a in proptest::collection::vec(any::<u32>(), 1..20),
            b in proptest::collection::vec(any::<u32>(), 1..20),
            c in proptest::collection::vec(any::<u32>(), 1..20),
        ) {
            super::laws::merge_associative_clone_eq(a, b, c)?;
        }

        #[test]
        fn result_semigroup_laws(
            a in proptest::result::maybe_ok(any::<u32>(), any::<String>()),
            b in proptest::result::maybe_ok(any::<u32>(), any::<String>()),
            c in proptest::result::maybe_ok(any::<u32>(), any::<String>()),
        ) {
            super::laws::merge_associative_clone_eq(a, b, c)?;
        }
    }
}
