//! Algebraic Abstractions that relies heavily on the Functional Programming paradigm.

#![cfg_attr(feature = "proptest", feature(coverage_attribute))]

pub mod bijection;
pub mod category;
pub mod monoid;
pub mod predicate;
pub mod semigroup;

cfg_if::cfg_if! {
    if #[cfg(feature = "async")] {
        pub mod req;
        pub mod retry;
        pub mod state_machine;
    }
}
