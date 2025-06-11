//! This module provides all of the functions you'd expect from a category in all of their linear
//! variants.

/// Performs left-to-right composition for closures that only implement [`FnOnce`].
pub fn comp_once<A, B, C>(f: impl FnOnce(A) -> B, g: impl FnOnce(B) -> C) -> impl FnOnce(A) -> C {
    |a| g(f(a))
}

/// Performs left-to-right composition for closures that only implement [`FnMut`].
pub fn comp_mut<A, B, C>(
    mut f: impl FnMut(A) -> B,
    mut g: impl FnMut(B) -> C,
) -> impl FnMut(A) -> C {
    move |a| g(f(a))
}

/// Performs left-to-right composition for any closures.
pub fn comp<A, B, C>(f: impl Fn(A) -> B, g: impl Fn(B) -> C) -> impl Fn(A) -> C {
    move |a| g(f(a))
}

/// The identity morphism.
pub const fn iden<A>(a: A) -> A {
    a
}
