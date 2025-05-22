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
    let mut res: Option<T> = None;
    for x in xs {
        res = Some(match res {
            Some(acc) => acc.merge(x),
            None => x,
        })
    }
    res
}
