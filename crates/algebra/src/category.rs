//! This module provides all of the functions you'd expect from a category in all of their linear
//! variants.

/// Performs left-to-right composition for closures that only implement [`FnOnce`].
#[inline(always)]
pub fn comp_once<A, B, C>(f: impl FnOnce(A) -> B, g: impl FnOnce(B) -> C) -> impl FnOnce(A) -> C {
    |a| g(f(a))
}

/// Performs left-to-right composition for closures that only implement [`FnMut`].
#[inline(always)]
pub fn comp_mut<'f, A, B, C>(
    mut f: impl FnMut(A) -> B + 'f,
    mut g: impl FnMut(B) -> C + 'f,
) -> impl FnMut(A) -> C + 'f {
    move |a| g(f(a))
}

/// Performs left-to-right composition for functions where there is a lifetime dependency in the
/// first argument, and the second closure operates over the output reference of the first argument.
#[inline(always)]
pub fn comp_as_ref_mut<'f, A, B: ?Sized, C>(
    mut f: impl FnMut(&A) -> &B + 'f,
    mut g: impl FnMut(&B) -> C + 'f,
) -> impl for<'a> FnMut(&'a A) -> C + 'f {
    move |a| g(f(a))
}

/// Performs left-to-right composition for any functions operating over owned values.
#[inline(always)]
pub fn comp<'f, A, B, C>(f: impl Fn(A) -> B + 'f, g: impl Fn(B) -> C + 'f) -> impl Fn(A) -> C + 'f {
    move |a| g(f(a))
}

/// Performs left-to-right composition for functions where there is a lifetime dependency in the
/// first argument, and the second closure operates over the output reference of the first argument.
#[inline(always)]
pub fn comp_as_ref<'f, A, B: ?Sized, C>(
    f: impl Fn(&A) -> &B + 'f,
    g: impl Fn(&B) -> C + 'f,
) -> impl for<'a> Fn(&'a A) -> C + 'f {
    move |a| g(f(a))
}

/// Performs left-to-right composition for closures that have lifetime dependencies in both
/// arguments.
#[inline(always)]
pub fn comp_as_refs<'f, A: ?Sized, B: ?Sized + 'static, C: ?Sized>(
    f: impl Fn(&A) -> &B + 'f,
    g: impl Fn(&B) -> &C + 'f,
) -> impl for<'a> Fn(&'a A) -> &'a C + 'f {
    move |a| g(f(a))
}

/// The identity morphism.
pub const fn iden<A>(a: A) -> A {
    a
}

/// Lifts an `FnOnce` that takes a borrowed argument into one that consumes that argument. This is
/// useful because there is no way to build a function of type `f : A -> &A`
#[inline(always)]
pub fn moved_once<A, B>(f: impl FnOnce(&A) -> B) -> impl FnOnce(A) -> B {
    move |a| f(&a)
}

/// Lifts an `FnMut` that takes a borrowed argument into one that consumes that argument. This is
/// useful because there is no way to build a function of type `f : A -> &A`
#[inline(always)]
pub fn moved_mut<'f, A, B>(mut f: impl FnMut(&A) -> B + 'f) -> impl FnMut(A) -> B + 'f {
    move |a| f(&a)
}

/// Lifts an `Fn` that takes a borrowed argument into one that consumes that argument. This is
/// useful because there is no way to build a function of type `f : A -> &A`
#[inline(always)]
pub fn moved<'f, A, B>(f: impl Fn(&A) -> B + 'f) -> impl Fn(A) -> B + 'f {
    move |a| f(&a)
}

/// Lifts an `Fn` that takes an owned argument into one that just borrows it, cloning the value
/// internally before consuming it with the argument. This is the conceptual opposite of [`moved`].
pub fn borrowed<'f, A: Clone + 'f, B>(f: impl Fn(A) -> B + 'f) -> impl Fn(&'f A) -> B + 'f {
    comp(A::clone, f)
}

/// Takes two functions, one that borrows the argument and one that consumes the same type of
/// argument and pairs the results.
#[inline(always)]
pub fn fork<'f, A, B, C>(
    borrow: impl Fn(&A) -> B + 'f,
    consume: impl Fn(A) -> C + 'f,
) -> impl Fn(A) -> (B, C) + 'f {
    move |a| (borrow(&a), consume(a))
}

/// Categorical dual of [`fork`]. This joins two independent functions into a single bus operation.
/// This is most useful in KV iterator pipelines.
#[inline(always)]
pub fn bus<A, B, C, D>(f: impl Fn(A) -> C, g: impl Fn(B) -> D) -> impl Fn((A, B)) -> (C, D) {
    move |(a, b)| (f(a), g(b))
}

/// Reverses the component order of a 2-tuple.
pub fn swap<A, B>((a, b): (A, B)) -> (B, A) {
    (b, a)
}

/// Transforms a function into one that pairs the argument with the return value.
#[inline]
pub fn annotate<'f, A: 'f, B: 'f>(f: impl Fn(&A) -> B + 'f) -> impl Fn(A) -> (A, B) + 'f {
    comp(fork(f, iden), swap)
}

/// Transforms a function into one that pairs the return value with the argument.
#[inline]
pub fn index<'f, A: 'f, B: 'f>(f: impl Fn(&B) -> A + 'f) -> impl Fn(B) -> (A, B) + 'f {
    fork(f, iden)
}

#[cfg(test)]
mod category_tests {
    /// This is a compile time test that asserts that we can ergonomically and sensibly compose all
    /// of the fundamentally possible composition patterns without violating compilation or
    /// ownership issues.
    #[allow(dead_code, reason = "This is a compile time test that takes arguments")]
    fn test_comp_combinators<A, B: 'static, C>(
        converter_ab: impl Fn(A) -> B,
        converter_bc: impl Fn(B) -> C,
        analyzer_ab: impl Fn(&A) -> B,
        analyzer_bc: impl Fn(&B) -> C,
        projector_ab: impl Fn(&A) -> &B,
        projector_bc: impl Fn(&B) -> &C,
        new_a: impl Fn() -> A,
    ) {
        // Definitions:
        // - converter: takes an opaque type and converts it to another opaque type
        // - analyzer: takes a reference of any lifetime to an opaque type and produces an opaque
        //   type
        // - projector: takes a reference of any lifetime and produces a reference of the same
        //   lifetime

        // compose a converter with another converter
        let cc = super::comp(&converter_ab, &converter_bc);
        let a0 = new_a();
        let _c0 = cc(a0);
        let a0 = new_a(); // ensure composed function is reusable
        let _c0 = cc(a0);

        // compose a converter with an analyzer.
        let ca = super::comp(&converter_ab, super::moved(&analyzer_bc));
        let a1 = new_a();
        let _c1 = ca(a1);
        let a1 = new_a(); // ensure composed function is reusable
        let _c1 = ca(a1);

        // compose a converter with a projector.
        // This is intentionally missing since we cannot produce references to temporary values. As
        // such this composition pattern is fundamentally impossible and if you find
        // yourself needing it, it demands that you rethink your approach.

        // compose an analyzer with a converter.
        let ac = super::comp(&analyzer_ab, &converter_bc);
        let a2 = new_a();
        let _c2 = ac(&a2);
        let a2 = new_a(); // ensure composed function is reusable
        let _c2 = ac(&a2);

        // compose an analyzer with another analyzer.
        let aa = super::comp(&analyzer_ab, super::moved(&analyzer_bc));
        let a3 = new_a();
        let _c3 = aa(&a3);
        let a3 = new_a(); // ensure composed function is reusable
        let _c3 = aa(&a3);

        // compose an aanalyzer with a projector.
        // This is intentionally missing since we cannot produce references to temporary values. As
        // such this composition pattern is fundamentally impossible and if you find
        // yourself needing it, it demands that you rethink your approach.

        // compose a projector with an analyzer.
        let pa = super::comp_as_ref(&projector_ab, &analyzer_bc);
        let a4 = new_a();
        let _c4 = pa(&a4);
        let a4 = new_a(); // ensure composed function is reusable
        let _c4 = pa(&a4);

        // compose a projector with another projector.
        let pp = super::comp_as_refs(&projector_ab, &projector_bc);
        let a5 = new_a();
        let _c5 = pp(&a5);
        let a5 = new_a(); // ensure composed function is reusable
        let _c5 = pp(&a5);
    }
}
