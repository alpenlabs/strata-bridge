//! A space-efficient array implementation for storing types representable as two boolean values.
//!
//! This module provides a [`DoubleBoolArray`] that packs pairs of boolean values into individual
//! bits, allowing efficient storage of enum-like states with four possible variants. Each `u64`
//! chunk stores 32 entries, making it particularly useful for memory-constrained scenarios or
//! when working with large collections of state values. This also allows for efficient iteration
//! over the array for scanning for a slot in a particular state.
//!
//! # Examples
//! ```
//! use std::convert::Infallible;
//!
//! use secret_service_server::bool_arr::DoubleBoolArray;
//!
//! #[derive(Debug, PartialEq)]
//! enum State {
//!     A,
//!     B,
//!     C,
//!     D,
//! }
//!
//! impl From<State> for (bool, bool) {
//!     fn from(s: State) -> Self {
//!         match s {
//!             State::A => (false, false),
//!             State::B => (true, false),
//!             State::C => (false, true),
//!             State::D => (true, true),
//!         }
//!     }
//! }
//!
//! impl TryFrom<(bool, bool)> for State {
//!     type Error = Infallible;
//!     fn try_from((b1, b2): (bool, bool)) -> Result<Self, Self::Error> {
//!         Ok(match (b1, b2) {
//!             (false, false) => State::A,
//!             (true, false) => State::B,
//!             (false, true) => State::C,
//!             (true, true) => State::D,
//!         })
//!     }
//! }
//!
//! let mut arr = DoubleBoolArray::<2, State>::default();
//! arr.set(0, State::B);
//! arr.set(31, State::C);
//! assert_eq!(arr.get(0), State::B);
//! ```

use std::{
    fmt::{self, Debug},
    marker::PhantomData,
};

/// Compact storage for types representable as two boolean values (four possible states).
///
/// Each entry is stored as two bits, with the following mapping:
/// - Bit 0: First boolean value (LSB)
/// - Bit 1: Second boolean value
///
/// The generic type `T` must implement bidirectional conversion to/from `(bool, bool)`.
/// IMPORTANT: When T is `(false, false)`, it represents an empty state.
///
/// # Type Parameters
/// - `N`: Number of `u64` chunks used for storage (capacity = N × 32)
/// - `T`: Stored type that can be converted to/from `(bool, bool)` pairs
///
/// # Implementation Details
/// - Stores values in N `u64` integers (8N bytes total)
/// - Provides O(1) access time for get/set operations
/// - Implements space-efficient storage with 2 bits per entry
pub struct DoubleBoolArray<const N: usize, T>([u64; N], PhantomData<T>)
where
    T: Into<(bool, bool)> + TryFrom<(bool, bool)> + Debug,
    <T as TryFrom<(bool, bool)>>::Error: Debug;

impl<const N: usize, T> fmt::Debug for DoubleBoolArray<N, T>
where
    T: Into<(bool, bool)> + TryFrom<(bool, bool)> + fmt::Debug,
    <T as TryFrom<(bool, bool)>>::Error: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct DebugValues<'a, const N: usize, T>(&'a DoubleBoolArray<N, T>)
        where
            T: Into<(bool, bool)> + TryFrom<(bool, bool)> + Debug,
            <T as TryFrom<(bool, bool)>>::Error: Debug;

        impl<'a, const N: usize, T> fmt::Debug for DebugValues<'a, N, T>
        where
            T: Into<(bool, bool)> + TryFrom<(bool, bool)> + fmt::Debug,
            <T as TryFrom<(bool, bool)>>::Error: fmt::Debug,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut list = f.debug_list();
                for i in 0..DoubleBoolArray::<N, T>::capacity() {
                    list.entry(&self.0.get(i));
                }
                list.finish()
            }
        }

        f.debug_struct("DoubleBoolArray")
            .field("values", &DebugValues(self))
            .finish()
    }
}

impl<const N: usize, T> Default for DoubleBoolArray<N, T>
where
    T: Into<(bool, bool)> + TryFrom<(bool, bool)> + Debug,
    <T as TryFrom<(bool, bool)>>::Error: Debug,
{
    fn default() -> Self {
        Self([0; N], PhantomData)
    }
}

impl<const N: usize, T> DoubleBoolArray<N, T>
where
    T: Into<(bool, bool)> + TryFrom<(bool, bool)> + Debug,
    <T as TryFrom<(bool, bool)>>::Error: Debug,
{
    /// Returns the capacity of the array in terms of the number of (bool, bool) slots it can hold.
    pub const fn capacity() -> usize {
        N * (std::mem::size_of::<u64>() * 8 / 2)
    }

    /// Find the index of the first slot with the specified value.
    pub fn find_first_slot_with(&self, target: T) -> Option<usize> {
        let (target_0, target_1) = target.into();
        let target = (target_0 as u64) | ((target_1 as u64) << 1);
        for (chunk_idx, &chunk) in self.0.iter().enumerate() {
            for slot in 0..32 {
                let mask = 0b11 << (slot * 2);
                if (chunk & mask) == target {
                    return Some(chunk_idx * 32 + slot);
                }
            }
        }
        None
    }

    /// Get the two boolean values at specified index
    /// Panics if index >= N * 32
    pub fn get(&self, index: usize) -> T {
        assert!(index < N * 32, "Index out of bounds");
        let chunk_idx = index / 32;
        let slot = index % 32;
        let chunk = self.0[chunk_idx];

        let bits = (chunk >> (slot * 2)) & 0b11;
        T::try_from(((bits & 0b01) != 0, (bits & 0b10) != 0))
            .expect("T::try_from(T::Into) should always succeed")
    }

    /// Set the two boolean values at specified index
    /// Panics if index >= N * 32
    pub fn set(&mut self, index: usize, value: T) {
        assert!(index < N * 32, "Index out of bounds");
        let chunk_idx = index / 32;
        let slot = index % 32;
        let chunk = &mut self.0[chunk_idx];

        let mask = !(0b11 << (slot * 2));
        let values: (bool, bool) = value.into();
        let new_bits = (values.0 as u64) | ((values.1 as u64) << 1);

        *chunk = (*chunk & mask) | (new_bits << (slot * 2));
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone)]
    enum TestState {
        A,
        B,
        C,
        D,
    }

    impl From<TestState> for (bool, bool) {
        fn from(val: TestState) -> Self {
            match val {
                TestState::A => (false, false),
                TestState::B => (true, false),
                TestState::C => (false, true),
                TestState::D => (true, true),
            }
        }
    }

    impl TryFrom<(bool, bool)> for TestState {
        type Error = Infallible;
        fn try_from(value: (bool, bool)) -> Result<Self, Self::Error> {
            Ok(match value {
                (false, false) => TestState::A,
                (true, false) => TestState::B,
                (false, true) => TestState::C,
                (true, true) => TestState::D,
            })
        }
    }

    #[test]
    fn capacity_calculation() {
        assert_eq!(DoubleBoolArray::<1, TestState>::capacity(), 32);
        assert_eq!(DoubleBoolArray::<3, TestState>::capacity(), 96);
    }

    #[test]
    fn default_initialization() {
        let arr = DoubleBoolArray::<2, TestState>::default();
        assert_eq!(arr.find_first_slot_with(TestState::A), Some(0));
    }

    #[test]
    fn basic_set_get() {
        let mut arr = DoubleBoolArray::<2, TestState>::default();

        arr.set(0, TestState::B);
        assert_eq!(arr.get(0), TestState::B);

        arr.set(31, TestState::C);
        assert_eq!(arr.get(31), TestState::C);

        arr.set(63, TestState::D);
        assert_eq!(arr.get(63), TestState::D);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn get_out_of_bounds() {
        let arr = DoubleBoolArray::<1, TestState>::default();
        arr.get(32);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn set_out_of_bounds() {
        let mut arr = DoubleBoolArray::<1, TestState>::default();
        arr.set(32, TestState::A);
    }

    #[test]
    fn find_empty_slots() {
        let mut arr = DoubleBoolArray::<2, TestState>::default();

        arr.set(5, TestState::B);
        assert_eq!(arr.find_first_slot_with(TestState::A), Some(0));

        arr.set(0, TestState::C);
        assert_eq!(arr.find_first_slot_with(TestState::A), Some(1));

        for i in 0..64 {
            arr.set(i, TestState::D);
        }
        assert_eq!(arr.find_first_slot_with(TestState::A), None);
    }

    #[test]
    fn slot_independence() {
        let mut arr = DoubleBoolArray::<1, TestState>::default();

        arr.set(0, TestState::B);
        arr.set(1, TestState::C);
        arr.set(2, TestState::D);

        assert_eq!(arr.get(0), TestState::B);
        assert_eq!(arr.get(1), TestState::C);
        assert_eq!(arr.get(2), TestState::D);
    }

    #[test]
    fn all_state_combinations() {
        let mut arr = DoubleBoolArray::<1, TestState>::default();
        let states = [TestState::A, TestState::B, TestState::C, TestState::D];

        for (i, state) in states.iter().enumerate() {
            arr.set(i, state.clone());
            assert_eq!(arr.get(i), *state);
        }
    }
}
