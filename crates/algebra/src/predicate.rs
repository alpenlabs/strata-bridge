//! This module provides function definitions for all of the canonical predicate combinators.
use std::borrow::Borrow;

/// Predicate combinator for the ! operation.
pub fn not<A>(f: impl Fn(&A) -> bool) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| !f(a)
}

/// Predicate combinator for the && operation.
pub fn and<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| f(a) && g(a)
}

/// Predicate combinator for the || operation.
pub fn or<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&A) -> bool {
    move |a| f(a) || g(a)
}

/// Predicate combinator for the xor operation.
pub fn xor<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&A) -> bool {
    move |a| f(a) ^ g(a)
}

/// Predicate combinator for the nand operation.
pub fn nand<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| !(f(a) & g(a))
}

/// Predicate combinator for the nor operation.
pub fn nor<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| !(f(a) | g(a))
}

/// Contravariant functor map over predicates.
pub fn contramap<A, B>(
    f: impl Fn(&A) -> B,
    p: impl Fn(&B) -> bool,
) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| p(&f(a))
}

/// Curried version of the Eq::eq function that can be used to construct a predicate.
pub fn eq<A: Eq + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b == a.borrow()
}

/// Curried version of the negated Eq::eq function that can be used to construct a predicate.
pub fn ne<A: Eq + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b != a.borrow()
}

/// Curried version of the Ord::gt function that can be used to construct a predicate.
pub fn gt<A: Ord + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b > a.borrow()
}

/// Curried version of the Ord::ge function that can be used to construct a predicate.
pub fn ge<A: Ord + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b >= a.borrow()
}

/// Curried version of the Ord::lt function that can be used to construct a predicate.
pub fn lt<A: Ord + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b < a.borrow()
}

/// Curried version of the Ord::le function that can be used to construct a predicate.
pub fn le<A: Ord + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| b <= a.borrow()
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
