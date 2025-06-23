//! This module provides function definitions for all of the canonical predicate combinators.
use crate::boolean;

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
    move |a| boolean::nand(f(a), g(a))
}

/// Predicate combinator for the nor operation.
pub fn nor<A>(f: impl Fn(&A) -> bool, g: impl Fn(&A) -> bool) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| boolean::nor(f(a), g(a))
}

/// Contravariant functor map over predicates.
pub fn contramap<A, B>(
    f: impl Fn(&A) -> B,
    p: impl Fn(&B) -> bool,
) -> impl for<'a> Fn(&'a A) -> bool {
    move |a| p(&f(a))
}
