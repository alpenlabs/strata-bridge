//! Module to generate arbitrary values for testing.

use ::bitcoin::{hashes::Hash, OutPoint, Txid};
use arbitrary::{Arbitrary, Unstructured};
use proptest::prelude::*;
use rand_core::{OsRng, TryCryptoRng};

/// The default buffer size for the `ArbitraryGenerator`.
const ARB_GEN_LEN: usize = 1024;
/// Maximum number of times to retry arbitrary generation before panicking.
const ARB_GEN_MAX_ATTEMPTS: usize = 128;

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
    pub fn generate<T>(&mut self) -> T
    where
        T: for<'a> Arbitrary<'a> + Clone,
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
    pub fn generate_with_rng<T, R>(&mut self, rng: &mut R) -> T
    where
        T: for<'a> Arbitrary<'a> + Clone,
        R: TryCryptoRng,
    {
        let mut last_err = None;

        for _attempt in 0..ARB_GEN_MAX_ATTEMPTS {
            rng.try_fill_bytes(&mut self.buf)
                .expect("must be able to generate random bytes");
            let mut u = Unstructured::new(&self.buf);
            match T::arbitrary(&mut u) {
                Ok(value) => return value,
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }

        panic!(
            "Failed to generate arbitrary instance after {ARB_GEN_MAX_ATTEMPTS} attempts: {:?}",
            last_err
        );
    }
}

/// Generates an arbitrary Txid.
pub fn arb_txid() -> impl Strategy<Value = Txid> {
    any::<[u8; 32]>().prop_map(|bytes| Txid::from_slice(&bytes).unwrap())
}

/// Generates an arbitrary [`OutPoint`].
pub fn arb_outpoint() -> impl Strategy<Value = OutPoint> {
    (arb_txid(), any::<u32>()).prop_map(|(txid, vout)| OutPoint { txid, vout })
}

/// Generates an arbitrary non-empty `Vec<OutPoint>` (1–10 entries).
pub fn arb_outpoints() -> impl Strategy<Value = Vec<OutPoint>> {
    proptest::collection::vec(arb_outpoint(), 1..=10)
}
