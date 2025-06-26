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

/// Performs left-to-right composition for any functions operating over owned values.
pub fn comp<'composed, A, B, C>(
    f: impl Fn(A) -> B + 'composed,
    g: impl Fn(B) -> C + 'composed,
) -> impl for<'a> Fn(A) -> C + 'composed {
    move |a| g(f(a))
}

/// Performs left-to-right composition for functions where there is a lifetime dependency in the
/// first argument, and the second closure operates over the output reference of the first argument.
pub fn comp_as_ref<A, B: ?Sized, C>(
    f: impl Fn(&A) -> &B,
    g: impl Fn(&B) -> C,
) -> impl for<'a> Fn(&'a A) -> C {
    move |a| g(f(a))
}

/// Performs left-to-right composition for closures that have lifetime dependencies in both
/// arguments.
pub fn comp_as_refs<A: ?Sized, B: ?Sized + 'static, C: ?Sized>(
    f: impl Fn(&A) -> &B,
    g: impl Fn(&B) -> &C,
) -> impl for<'a> Fn(&'a A) -> &'a C {
    move |a| g(f(a))
}

/// The identity morphism.
pub const fn iden<A>(a: A) -> A {
    a
}

/// Lifts an `FnOnce` that takes a borrowed argument into one that consumes that argument. This is
/// useful because there is no way to build a function of type `f : A -> &A`
pub fn moved_once<A, B>(f: impl FnOnce(&A) -> B) -> impl FnOnce(A) -> B {
    move |a| f(&a)
}

/// Lifts an `FnMut` that takes a borrowed argument into one that consumes that argument. This is
/// useful because there is no way to build a function of type `f : A -> &A`
pub fn moved_mut<A, B>(mut f: impl FnMut(&A) -> B) -> impl FnMut(A) -> B {
    move |a| f(&a)
}

/// Lifts an `Fn` that takes a borrowed argument into one that consumes that argument. This is
/// useful because there is no way to build a function of type `f : A -> &A`
pub fn moved<A, B>(f: impl Fn(&A) -> B) -> impl Fn(A) -> B {
    move |a| f(&a)
}

#[cfg(test)]
mod category_tests {
    /// This is a compile time test that asserts that we can ergonomically and sensibly compose all
    /// of the fundamentally possible composition patterns without violating compilation or
    /// ownership issues.
    #[allow(dead_code)]
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
