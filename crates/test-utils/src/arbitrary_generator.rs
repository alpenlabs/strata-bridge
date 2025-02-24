use arbitrary::{Arbitrary, Unstructured};
use rand_core::{OsRng, TryCryptoRng};

/// The default buffer size for the `ArbitraryGenerator`.
const ARB_GEN_LEN: usize = 1024;

/// A generator for producing arbitrary data based on a persistent buffer.
#[derive(Debug)]
pub struct ArbitraryGenerator {
    /// Persistent buffer
    buf: Vec<u8>,
}

impl Default for ArbitraryGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ArbitraryGenerator {
    /// Creates a new `ArbitraryGenerator` with a default buffer size.
    ///
    /// # Returns
    ///
    /// A new instance of `ArbitraryGenerator`.
    pub fn new() -> Self {
        Self::new_with_size(ARB_GEN_LEN)
    }

    /// Creates a new `ArbitraryGenerator` with a specified buffer size.
    ///
    /// # Arguments
    ///
    /// * `s` - The size of the buffer to be used.
    ///
    /// # Returns
    ///
    /// A new instance of `ArbitraryGenerator` with the specified buffer size.
    pub fn new_with_size(s: usize) -> Self {
        Self { buf: vec![0u8; s] }
    }

    /// Generates an arbitrary instance of type `T` using the default RNG, [`OsRng`].
    ///
    /// # Returns
    ///
    /// An arbitrary instance of type `T`.
    pub fn generate<'a, T>(&'a mut self) -> T
    where
        T: Arbitrary<'a> + Clone,
    {
        self.generate_with_rng::<T, OsRng>(&mut OsRng)
    }

    /// Generates an arbitrary instance of type `T`.
    ///
    /// # Arguments
    ///
    /// * `rng` - An RNG to be used for generating the arbitrary instance. Provided RNG must
    ///   implement the [`TryCryptoRng`] trait.
    ///
    /// # Returns
    ///
    /// An arbitrary instance of type `T`.
    pub fn generate_with_rng<'a, T, R>(&'a mut self, rng: &mut R) -> T
    where
        T: Arbitrary<'a> + Clone,
        R: TryCryptoRng,
    {
        rng.try_fill_bytes(&mut self.buf)
            .expect("must be able to generate random bytes");
        let mut u = Unstructured::new(&self.buf);
        T::arbitrary(&mut u).expect("Failed to generate arbitrary instance")
    }
}
