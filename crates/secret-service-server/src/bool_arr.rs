use std::marker::PhantomData;

// Kind of like a bitmap for storing bools as bits, but instead we're storing
// (bool, bool) instead of just a bool, allowing us to check up to 4 different
// states. Each 64 bit word can store 32 of these slots.
pub struct DoubleBoolArray<const N: usize, T>([u64; N], PhantomData<T>)
where
    T: Into<(bool, bool)> + TryFrom<(bool, bool)>,
    <T as TryFrom<(bool, bool)>>::Error: std::fmt::Debug;

impl<const N: usize, T> Default for DoubleBoolArray<N, T>
where
    T: Into<(bool, bool)> + TryFrom<(bool, bool)>,
    <T as TryFrom<(bool, bool)>>::Error: std::fmt::Debug,
{
    fn default() -> Self {
        Self([0; N], PhantomData)
    }
}

impl<const N: usize, T> DoubleBoolArray<N, T>
where
    T: Into<(bool, bool)> + TryFrom<(bool, bool)>,
    <T as TryFrom<(bool, bool)>>::Error: std::fmt::Debug,
{
    pub const fn capacity() -> usize {
        N * (std::mem::size_of::<u64>() * 8 / 2)
    }

    pub fn find_next_empty_slot(&self) -> Option<usize> {
        for (chunk_idx, &chunk) in self.0.iter().enumerate() {
            for slot in 0..32 {
                let mask = 0b11 << (slot * 2);
                if (chunk & mask) == 0 {
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
