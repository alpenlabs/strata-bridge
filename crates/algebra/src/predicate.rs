//! This module provides function definitions for all of the canonical predicate combinators.
use std::borrow::Borrow;

/// Predicate that always returns true.
pub const fn always<A>(_: &A) -> bool {
    true
}

/// Predicate that always returns false.
pub const fn never<A>(_: &A) -> bool {
    false
}

/// Predicate combinator for the ! operation.
#[inline(always)]
pub fn not<A>(f: impl Fn(&A) -> bool) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| !f(a)
}

/// Predicate combinator for the && operation.
#[inline(always)]
pub fn and<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| f(a) && g(a)
}

/// Predicate combinator for the || operation.
#[inline(always)]
pub fn or<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&A) -> bool {
    move |a| f(a) || g(a)
}

/// Predicate combinator for the xor operation.
#[inline(always)]
pub fn xor<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&A) -> bool {
    move |a| f(a) ^ g(a)
}

/// Predicate combinator for the nand operation.
#[inline(always)]
pub fn nand<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| !(f(a) & g(a))
}

/// Predicate combinator for the nor operation.
#[inline(always)]
pub fn nor<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| !(f(a) | g(a))
}

/// Contravariant functor map over predicates.
#[inline(always)]
pub fn contramap<A, B>(
    f: impl Fn(&A) -> B,
    p: impl Fn(&B) -> bool,
) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| p(&f(a))
}

/// Curried version of the [`PartialEq::eq`] function that can be used to construct a predicate.
#[inline(always)]
pub fn eq<A: Eq + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b == a.borrow()
}

/// Curried version of the [`PartialEq::ne`] function that can be used to construct a predicate.
#[inline(always)]
pub fn ne<A: Eq + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b != a.borrow()
}

/// Curried version of the [`PartialOrd::gt`] function that can be used to construct a predicate.
#[inline(always)]
pub fn gt<A: Ord + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b > a.borrow()
}

/// Curried version of the [`PartialOrd::ge`] function that can be used to construct a predicate.
#[inline(always)]
pub fn ge<A: Ord + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b >= a.borrow()
}

/// Curried version of the [`PartialOrd::lt`] function that can be used to construct a predicate.
#[inline(always)]
pub fn lt<A: Ord + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b < a.borrow()
}

/// Curried version of the [`PartialOrd::le`] function that can be used to construct a predicate.
#[inline(always)]
pub fn le<A: Ord + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b <= a.borrow()
}

/// Eliminates values that don't pass the predicate.
#[inline(always)]
pub fn guard<A>(pred: impl Fn(&A) -> bool) -> impl Fn(A) -> Option<A> {
    move |a| pred(&a).then_some(a)
}

/// Eliminates values that don't pass the state-changing predicate.
#[inline(always)]
pub fn guard_mut<'pred, A>(
    mut pred: impl FnMut(&A) -> bool + 'pred,
) -> impl FnMut(A) -> Option<A> + 'pred {
    move |a| pred(&a).then_some(a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_pred_eq() {
        let a = 2i32;
        let b = 2i32;

        let pred = super::eq(&a);

        assert_eq!(pred(&b), i32::eq(&a, &b));
    }

    #[test]
    fn test_pred_neq() {
        let a = 2i32;
        let b = 2i32;

        let pred = super::ne(&a);

        assert_eq!(pred(&b), i32::ne(&a, &b));
    }

    #[test]
    fn test_pred_gt() {
        let a = 2i32;
        let b = 2i32;

        let pred = super::gt(&a);

        assert_eq!(pred(&b), i32::gt(&a, &b));
    }

    #[test]
    fn test_pred_gte() {
        let a = 2i32;
        let b = 2i32;

        let pred = super::ge(&a);

        assert_eq!(pred(&b), i32::ge(&a, &b));
    }

    #[test]
    fn test_pred_lt() {
        let a = 2i32;
        let b = 2i32;

        let pred = super::lt(&a);

        assert_eq!(pred(&b), i32::lt(&a, &b));
    }

    #[test]
    fn test_pred_lte() {
        let a = 2i32;
        let b = 2i32;

        let pred = super::le(&a);

        assert_eq!(pred(&b), i32::le(&a, &b));
    }
}
