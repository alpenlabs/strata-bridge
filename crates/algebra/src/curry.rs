//! Curried versions of common functions

use std::borrow::Borrow;

/// Curried version of the Eq::eq function.
pub fn eq<A: Eq + ?Sized, R: Borrow<A>>(a: R) -> impl for<'a> Fn(&'a A) -> bool {
    move |b| a.borrow() == b
}

mod tests {
    #[test]
    fn test_curried_eq() {
        let a = 2i32;
        let b = 2i32;

        let pred = super::eq(&a);

        assert_eq!(pred(&b), i32::eq(&a, &b));
    }
}
