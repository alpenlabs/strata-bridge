//! This module contains a functor-like data structure
//! that facilitates presigning via Musig2.

use std::{array, future::Future};

use algebra::semigroup::Semigroup;
use futures::future::join_all;
use serde::{Deserialize, Serialize};

use crate::transactions::{
    contest::ContestTx,
    prelude::{
        BridgeProofTimeoutTx, ContestedPayoutTx, CounterproofAckTx, CounterproofTx, SlashTx,
        UncontestedPayoutTx,
    },
};

/// Functor-like data structure for associating generic data
/// with each presigned transaction input of the game graph.
///
/// # Note
///
/// Transactions that are not presigned are not included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameFunctor<A> {
    /// Data for each input of the bridge proof timeout transaction.
    pub bridge_proof_timeout: [A; BridgeProofTimeoutTx::N_INPUTS],

    /// Data for each input of the contested payout transaction.
    pub contested_payout: [A; ContestedPayoutTx::N_INPUTS],

    /// Data for each input of the slash transaction.
    pub slash: [A; SlashTx::N_INPUTS],

    /// Data for each input of the uncontested payout transaction.
    pub uncontested_payout: [A; UncontestedPayoutTx::N_INPUTS],

    /// Data for each watchtower.
    pub watchtowers: Vec<WatchtowerFunctor<A>>,
}

/// Functor-like data structure for associating generic data
/// with each presigned transaction input of the transactions
/// of a given watchtower.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerFunctor<A> {
    /// For the contesting watchtower, data for the single contest transaction input.
    pub contest: [A; ContestTx::N_INPUTS],
    /// For the counterproving watchtower, data for the single counterproof transaction input.
    pub counterproof: [A; CounterproofTx::N_INPUTS],
    /// For the counterproving watchtower, data for each input of the counterproof ACK transaction.
    pub counterproof_ack: [A; CounterproofAckTx::N_INPUTS],
}

impl<A> GameFunctor<A> {
    /// Packs the data into a vector.
    pub fn pack(self) -> Vec<A> {
        let total_len = BridgeProofTimeoutTx::N_INPUTS
            + ContestedPayoutTx::N_INPUTS
            + SlashTx::N_INPUTS
            + UncontestedPayoutTx::N_INPUTS
            + (ContestTx::N_INPUTS + CounterproofTx::N_INPUTS + CounterproofAckTx::N_INPUTS)
                * self.watchtowers.len();

        let mut packed = Vec::with_capacity(total_len);
        packed.extend(self.bridge_proof_timeout);
        packed.extend(self.contested_payout);
        packed.extend(self.slash);
        packed.extend(self.uncontested_payout);

        for watchtower in self.watchtowers {
            packed.extend(watchtower.contest);
            packed.extend(watchtower.counterproof);
            packed.extend(watchtower.counterproof_ack);
        }

        debug_assert_eq!(packed.len(), total_len);
        packed
    }

    /// Unpacks the data from a vector.
    ///
    /// The `n_watchtowers` parameter specifies how many watchtowers to expect.
    pub fn unpack(graph_vec: Vec<A>, n_watchtowers: usize) -> Option<GameFunctor<A>> {
        let mut cursor = graph_vec.into_iter();
        let cursor = cursor.by_ref();

        let bridge_proof_timeout = take_array(cursor)?;
        let contested_payout = take_array(cursor)?;
        let slash = take_array(cursor)?;
        let uncontested_payout = take_array(cursor)?;

        let watchtowers = (0..n_watchtowers)
            .map(|_| {
                let contest = take_array(cursor)?;
                let counterproof = take_array(cursor)?;
                let counterproof_ack = take_array(cursor)?;
                Some(WatchtowerFunctor {
                    contest,
                    counterproof,
                    counterproof_ack,
                })
            })
            .collect::<Option<Vec<WatchtowerFunctor<A>>>>()?;

        Some(GameFunctor {
            bridge_proof_timeout,
            contested_payout,
            slash,
            uncontested_payout,
            watchtowers,
        })
    }

    /// Returns references to the data.
    pub fn as_ref(&self) -> GameFunctor<&A> {
        GameFunctor {
            bridge_proof_timeout: self.bridge_proof_timeout.each_ref(),
            contested_payout: self.contested_payout.each_ref(),
            slash: self.slash.each_ref(),
            uncontested_payout: self.uncontested_payout.each_ref(),
            watchtowers: self
                .watchtowers
                .iter()
                .map(|watchtower| WatchtowerFunctor {
                    contest: watchtower.contest.each_ref(),
                    counterproof: watchtower.counterproof.each_ref(),
                    counterproof_ack: watchtower.counterproof_ack.each_ref(),
                })
                .collect(),
        }
    }

    /// Maps the data to a new type.
    pub fn map<B>(self, mut f: impl FnMut(A) -> B) -> GameFunctor<B> {
        GameFunctor {
            bridge_proof_timeout: self.bridge_proof_timeout.map(&mut f),
            contested_payout: self.contested_payout.map(&mut f),
            slash: self.slash.map(&mut f),
            uncontested_payout: self.uncontested_payout.map(&mut f),
            watchtowers: self
                .watchtowers
                .into_iter()
                .map(|watchtower| WatchtowerFunctor {
                    contest: watchtower.contest.map(&mut f),
                    counterproof: watchtower.counterproof.map(&mut f),
                    counterproof_ack: watchtower.counterproof_ack.map(&mut f),
                })
                .collect(),
        }
    }

    /// Zips the data of two functors.
    pub fn zip<B>(self, other: GameFunctor<B>) -> GameFunctor<(A, B)> {
        GameFunctor {
            bridge_proof_timeout: zip_arrays(self.bridge_proof_timeout, other.bridge_proof_timeout),
            contested_payout: zip_arrays(self.contested_payout, other.contested_payout),
            slash: zip_arrays(self.slash, other.slash),
            uncontested_payout: zip_arrays(self.uncontested_payout, other.uncontested_payout),
            watchtowers: self
                .watchtowers
                .into_iter()
                .zip(other.watchtowers.into_iter())
                .map(|(w1, w2)| WatchtowerFunctor {
                    contest: zip_arrays(w1.contest, w2.contest),
                    counterproof: zip_arrays(w1.counterproof, w2.counterproof),
                    counterproof_ack: zip_arrays(w1.counterproof_ack, w2.counterproof_ack),
                })
                .collect(),
        }
    }

    /// Zips 3 functors into a functor of a 3-tuple.
    pub fn zip3<B, C>(
        a: GameFunctor<A>,
        b: GameFunctor<B>,
        c: GameFunctor<C>,
    ) -> GameFunctor<(A, B, C)> {
        GameFunctor::zip_with_3(|a, b, c| (a, b, c), a, b, c)
    }

    /// Zips 4 functors into a functor of a 4-tuple.
    pub fn zip4<B, C, D>(
        a: GameFunctor<A>,
        b: GameFunctor<B>,
        c: GameFunctor<C>,
        d: GameFunctor<D>,
    ) -> GameFunctor<(A, B, C, D)> {
        GameFunctor::zip_with_4(|a, b, c, d| (a, b, c, d), a, b, c, d)
    }

    /// Zips 5 functors into a functor of a 5-tuple.
    pub fn zip5<B, C, D, E>(
        a: GameFunctor<A>,
        b: GameFunctor<B>,
        c: GameFunctor<C>,
        d: GameFunctor<D>,
        e: GameFunctor<E>,
    ) -> GameFunctor<(A, B, C, D, E)> {
        GameFunctor::zip_with_5(|a, b, c, d, e| (a, b, c, d, e), a, b, c, d, e)
    }

    /// Zips a functor of functions with a functor of data,
    /// resulting in an functor of mapped data.
    pub fn zip_apply<O>(f: GameFunctor<impl Fn(A) -> O>, a: GameFunctor<A>) -> GameFunctor<O> {
        GameFunctor {
            bridge_proof_timeout: zip_apply_arrays(f.bridge_proof_timeout, a.bridge_proof_timeout),
            contested_payout: zip_apply_arrays(f.contested_payout, a.contested_payout),
            slash: zip_apply_arrays(f.slash, a.slash),
            uncontested_payout: zip_apply_arrays(f.uncontested_payout, a.uncontested_payout),
            watchtowers: f
                .watchtowers
                .into_iter()
                .zip(a.watchtowers.into_iter())
                .map(|(w1, w2)| WatchtowerFunctor {
                    contest: zip_apply_arrays(w1.contest, w2.contest),
                    counterproof: zip_apply_arrays(w1.counterproof, w2.counterproof),
                    counterproof_ack: zip_apply_arrays(w1.counterproof_ack, w2.counterproof_ack),
                })
                .collect(),
        }
    }

    /// Zips the data of two functors and applies a function to the result.
    pub fn zip_with<B, O>(
        f: impl Fn(A, B) -> O,
        a: GameFunctor<A>,
        b: GameFunctor<B>,
    ) -> GameFunctor<O> {
        a.zip(b).map(|(a, b)| f(a, b))
    }

    /// Zips the data of three functors and applies a function to the result.
    pub fn zip_with_3<B, C, O>(
        f: impl Fn(A, B, C) -> O,
        a: GameFunctor<A>,
        b: GameFunctor<B>,
        c: GameFunctor<C>,
    ) -> GameFunctor<O> {
        a.zip(b).zip(c).map(|((a, b), c)| f(a, b, c))
    }

    /// Zips the data of four functors and applies a function to the result.
    pub fn zip_with_4<B, C, D, O>(
        f: impl Fn(A, B, C, D) -> O,
        a: GameFunctor<A>,
        b: GameFunctor<B>,
        c: GameFunctor<C>,
        d: GameFunctor<D>,
    ) -> GameFunctor<O> {
        a.zip(b).zip(c.zip(d)).map(|((a, b), (c, d))| f(a, b, c, d))
    }

    /// Zips the data of five functors and applies a function to the result.
    pub fn zip_with_5<B, C, D, E, O>(
        f: impl Fn(A, B, C, D, E) -> O,
        a: GameFunctor<A>,
        b: GameFunctor<B>,
        c: GameFunctor<C>,
        d: GameFunctor<D>,
        e: GameFunctor<E>,
    ) -> GameFunctor<O> {
        a.zip(b)
            .zip(c)
            .zip(d)
            .zip(e)
            .map(|((((a, b), c), d), e)| f(a, b, c, d, e))
    }

    /// Converts a functor of options into an option of a functor,
    /// returning `None` if any functor component is `None`.
    pub fn sequence_option(graph: GameFunctor<Option<A>>) -> Option<GameFunctor<A>> {
        Some(GameFunctor {
            bridge_proof_timeout: sequence_option_array(graph.bridge_proof_timeout)?,
            contested_payout: sequence_option_array(graph.contested_payout)?,
            slash: sequence_option_array(graph.slash)?,
            uncontested_payout: sequence_option_array(graph.uncontested_payout)?,
            watchtowers: graph
                .watchtowers
                .into_iter()
                .map(|watchtower| {
                    Some(WatchtowerFunctor {
                        contest: sequence_option_array(watchtower.contest)?,
                        counterproof: sequence_option_array(watchtower.counterproof)?,
                        counterproof_ack: sequence_option_array(watchtower.counterproof_ack)?,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
        })
    }

    /// Converts a functor of results into the result of a functor,
    /// returning `Err` if any functor component is `Err`.
    ///
    /// The returned `Err` is the first one that was encountered.
    pub fn sequence_result<E>(graph: GameFunctor<Result<A, E>>) -> Result<GameFunctor<A>, E> {
        Ok(GameFunctor {
            bridge_proof_timeout: sequence_result_array(graph.bridge_proof_timeout)?,
            contested_payout: sequence_result_array(graph.contested_payout)?,
            slash: sequence_result_array(graph.slash)?,
            uncontested_payout: sequence_result_array(graph.uncontested_payout)?,
            watchtowers: graph
                .watchtowers
                .into_iter()
                .map(|watchtower| {
                    Ok(WatchtowerFunctor {
                        contest: sequence_result_array(watchtower.contest)?,
                        counterproof: sequence_result_array(watchtower.counterproof)?,
                        counterproof_ack: sequence_result_array(watchtower.counterproof_ack)?,
                    })
                })
                .collect::<Result<Vec<_>, E>>()?,
        })
    }

    /// Converts a vector of functors into a functor of vectors.
    ///
    /// The number of watchtowers in the resulting functor is the minimum
    /// of the numbers of watchtowers from the input functors.
    /// Excess watchtowers are truncated.
    pub fn sequence_functor(graphs: Vec<GameFunctor<A>>) -> GameFunctor<Vec<A>> {
        let n_watchtowers = graphs
            .iter()
            .map(|graph| graph.watchtowers.len())
            .min()
            .unwrap_or(0);

        let mut bridge_proof_timeout_iter = Vec::with_capacity(graphs.len());
        let mut contested_payout_iter = Vec::with_capacity(graphs.len());
        let mut slash_iter = Vec::with_capacity(graphs.len());
        let mut uncontested_payout_iter = Vec::with_capacity(graphs.len());
        let mut watchtowers_iter = Vec::with_capacity(graphs.len());

        for graph in graphs {
            bridge_proof_timeout_iter.push(graph.bridge_proof_timeout.into_iter());
            contested_payout_iter.push(graph.contested_payout.into_iter());
            slash_iter.push(graph.slash.into_iter());
            uncontested_payout_iter.push(graph.uncontested_payout.into_iter());
            watchtowers_iter.push(graph.watchtowers.into_iter().take(n_watchtowers));
        }

        GameFunctor {
            bridge_proof_timeout: array::from_fn(|_| {
                bridge_proof_timeout_iter
                    .iter_mut()
                    .map(|it| it.next().unwrap())
                    .collect()
            }),
            contested_payout: array::from_fn(|_| {
                contested_payout_iter
                    .iter_mut()
                    .map(|it| it.next().unwrap())
                    .collect()
            }),
            slash: array::from_fn(|_| slash_iter.iter_mut().map(|it| it.next().unwrap()).collect()),
            uncontested_payout: array::from_fn(|_| {
                uncontested_payout_iter
                    .iter_mut()
                    .map(|it| it.next().unwrap())
                    .collect()
            }),
            watchtowers: (0..n_watchtowers)
                .map(|_| {
                    WatchtowerFunctor::sequence_functor(
                        watchtowers_iter
                            .iter_mut()
                            .map(|it| it.next().unwrap())
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

impl<A> WatchtowerFunctor<A> {
    /// Converts a vector of watchtower functors into a watchtower functor of vectors.
    pub fn sequence_functor(watchtowers: Vec<WatchtowerFunctor<A>>) -> WatchtowerFunctor<Vec<A>> {
        let mut contest_iter = Vec::with_capacity(watchtowers.len());
        let mut counterproof_iter = Vec::with_capacity(watchtowers.len());
        let mut counterproof_ack_iter = Vec::with_capacity(watchtowers.len());

        for watchtower in watchtowers {
            contest_iter.push(watchtower.contest.into_iter());
            counterproof_iter.push(watchtower.counterproof.into_iter());
            counterproof_ack_iter.push(watchtower.counterproof_ack.into_iter());
        }

        WatchtowerFunctor {
            contest: array::from_fn(|_| {
                contest_iter
                    .iter_mut()
                    .map(|it| it.next().unwrap())
                    .collect()
            }),
            counterproof: array::from_fn(|_| {
                counterproof_iter
                    .iter_mut()
                    .map(|it| it.next().unwrap())
                    .collect()
            }),
            counterproof_ack: array::from_fn(|_| {
                counterproof_ack_iter
                    .iter_mut()
                    .map(|it| it.next().unwrap())
                    .collect()
            }),
        }
    }
}

impl<A, B> GameFunctor<(A, B)> {
    /// Converts a functor of pairs into two functors of the respective components.
    pub fn unzip(self) -> (GameFunctor<A>, GameFunctor<B>) {
        let (bridge_proof_timeout_a, bridge_proof_timeout_b) =
            unzip_array(self.bridge_proof_timeout);
        let (contested_payout_a, contested_payout_b) = unzip_array(self.contested_payout);
        let (slash_a, slash_b) = unzip_array(self.slash);
        let (uncontested_payout_a, uncontested_payout_b) = unzip_array(self.uncontested_payout);

        let (watchtowers_a, watchtowers_b): (Vec<_>, Vec<_>) = self
            .watchtowers
            .into_iter()
            .map(|watchtower| {
                let (contest_a, contest_b) = unzip_array(watchtower.contest);
                let (counterproof_a, counterproof_b) = unzip_array(watchtower.counterproof);
                let (counterproof_ack_a, counterproof_ack_b) =
                    unzip_array(watchtower.counterproof_ack);
                (
                    WatchtowerFunctor {
                        contest: contest_a,
                        counterproof: counterproof_a,
                        counterproof_ack: counterproof_ack_a,
                    },
                    WatchtowerFunctor {
                        contest: contest_b,
                        counterproof: counterproof_b,
                        counterproof_ack: counterproof_ack_b,
                    },
                )
            })
            .unzip();

        (
            GameFunctor {
                bridge_proof_timeout: bridge_proof_timeout_a,
                contested_payout: contested_payout_a,
                slash: slash_a,
                uncontested_payout: uncontested_payout_a,
                watchtowers: watchtowers_a,
            },
            GameFunctor {
                bridge_proof_timeout: bridge_proof_timeout_b,
                contested_payout: contested_payout_b,
                slash: slash_b,
                uncontested_payout: uncontested_payout_b,
                watchtowers: watchtowers_b,
            },
        )
    }
}

impl<A: Clone> GameFunctor<&A> {
    /// Maps a functor of references to a functor of owned values by cloning its contents.
    pub fn cloned(self) -> GameFunctor<A> {
        self.map(A::clone)
    }
}

impl<F> GameFunctor<F>
where
    F: Future,
    F::Output: std::fmt::Debug,
{
    /// Converts a functor of futures into a functor of outputs,
    /// by joining and awaiting the futures.
    pub async fn join_all(self) -> GameFunctor<F::Output> {
        let n_watchtowers = self.watchtowers.len();
        GameFunctor::unpack(join_all(self.pack()).await, n_watchtowers).unwrap()
    }
}

impl<T: Semigroup> Semigroup for GameFunctor<T> {
    /// [`MusigFunctor`] preserves the [`Semigroup`] structure of its leaves.
    fn merge(self, other: Self) -> Self {
        GameFunctor::<T>::zip_with(T::merge, self, other)
    }
}

// Helper functions

/// Creates an array of `N` elements from an iterator.
fn take_array<T, const N: usize>(iter: &mut impl Iterator<Item = T>) -> Option<[T; N]> {
    // NOTE: (@uncomputable) The nightly feature `array_try_from_fn` would remove the allocation.
    iter.take(N).collect::<Vec<T>>().try_into().ok()
}

/// Zips the contents of two arrays of the same length.
fn zip_arrays<A, B, const N: usize>(a: [A; N], b: [B; N]) -> [(A, B); N] {
    let mut a_iter = a.into_iter();
    let mut b_iter = b.into_iter();
    // NOTE: (@uncomputable) Unwraps never fail because the array size is known at compile time.
    //                       We have to use iterators because `A` and `B` don't implement `Copy`.
    array::from_fn(|_| (a_iter.next().unwrap(), b_iter.next().unwrap()))
}

/// Zips an array of functions with an array of data,
/// resulting in an array of mapped data.
fn zip_apply_arrays<A, B, F: Fn(A) -> B, const N: usize>(f: [F; N], a: [A; N]) -> [B; N] {
    let mut f_iter = f.into_iter();
    let mut a_iter = a.into_iter();
    array::from_fn(|_| (f_iter.next().unwrap())(a_iter.next().unwrap()))
}

/// Converts an array of options into an option of an array,
/// returning `None` if any array element is `None`.
fn sequence_option_array<T, const N: usize>(arr: [Option<T>; N]) -> Option<[T; N]> {
    // NOTE: (@uncomputable) The nightly feature `array::try_map` would remove the allocation.
    match arr.into_iter().collect::<Option<Vec<T>>>()?.try_into() {
        Ok(array) => Some(array),
        Err(_) => unreachable!("array size is known at compile time"),
    }
}

/// Converts an array of results into a result of an array,
/// returning `Err` if any array element is `Err`.
///
/// The returned `Err` is the first one that was encountered.
fn sequence_result_array<T, E, const N: usize>(arr: [Result<T, E>; N]) -> Result<[T; N], E> {
    // NOTE: (@uncomputable) The nightly feature `array::try_map` would remove the allocation.
    // NOTE: (@uncomputable) We cannot use `expect` because `T` doesn't implement `Debug`.
    match arr.into_iter().collect::<Result<Vec<T>, E>>()?.try_into() {
        Ok(array) => Ok(array),
        Err(_) => unreachable!("array size is known at compile time"),
    }
}

/// Unzips the contents of an array of pairs.
fn unzip_array<A, B, const N: usize>(arr: [(A, B); N]) -> ([A; N], [B; N]) {
    let (vec_a, vec_b): (Vec<A>, Vec<B>) = arr.into_iter().unzip();
    let arr_a: [A; N] = match vec_a.try_into() {
        Ok(x) => x,
        Err(_) => unreachable!("correct length guaranteed by type bounds"),
    };
    let arr_b: [B; N] = match vec_b.try_into() {
        Ok(x) => x,
        Err(_) => unreachable!("correct length guaranteed by type bounds"),
    };
    (arr_a, arr_b)
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;

    const N_WATCHTOWERS: usize = 10;
    const PACKED_LEN: usize = UncontestedPayoutTx::N_INPUTS
        + BridgeProofTimeoutTx::N_INPUTS
        + ContestedPayoutTx::N_INPUTS
        + SlashTx::N_INPUTS
        + (ContestTx::N_INPUTS + CounterproofTx::N_INPUTS + CounterproofAckTx::N_INPUTS)
            * N_WATCHTOWERS;

    #[test]
    fn unpack_too_short() {
        let too_short: Vec<i32> = (0..PACKED_LEN - 1).map(|i| i as i32).collect();
        assert!(GameFunctor::<i32>::unpack(too_short, N_WATCHTOWERS).is_none());
    }

    #[test]
    fn unpack_pack_roundtrip() {
        let packed: Vec<i32> = (0..PACKED_LEN).map(|i| i as i32).collect();
        let functor = GameFunctor::unpack(packed.clone(), N_WATCHTOWERS).expect("enough data");
        assert_eq!(packed, functor.pack());
    }

    fn get_functor(start: usize) -> GameFunctor<i32> {
        let packed: Vec<i32> = (start..start + PACKED_LEN).map(|i| i as i32).collect();
        GameFunctor::unpack(packed, N_WATCHTOWERS).expect("enough data")
    }

    static A: LazyLock<GameFunctor<i32>> = LazyLock::new(|| get_functor(0));
    static B: LazyLock<GameFunctor<i32>> = LazyLock::new(|| get_functor(PACKED_LEN));
    static C: LazyLock<GameFunctor<i32>> = LazyLock::new(|| get_functor(PACKED_LEN * 2));
    static D: LazyLock<GameFunctor<i32>> = LazyLock::new(|| get_functor(PACKED_LEN * 3));
    static E: LazyLock<GameFunctor<i32>> = LazyLock::new(|| get_functor(PACKED_LEN * 4));

    #[test]
    fn as_ref_cloned_roundtrip() {
        let as_ref = A.as_ref();
        let cloned = as_ref.cloned();
        assert_eq!(*A, cloned);
    }

    #[test]
    fn map_back_roundtrip() {
        assert_eq!(*A, A.as_ref().map(|x| -x).map(|x| -x));
    }

    #[test]
    fn zip_unzip_roundtrip() {
        let (a_prime, b_prime) = A.clone().zip(B.clone()).unzip();
        assert_eq!(*A, a_prime);
        assert_eq!(*B, b_prime);
    }

    #[test]
    fn zip3_unzip_roundtrip() {
        let (ab_prime, c_prime) = GameFunctor::zip3(A.clone(), B.clone(), C.clone())
            .map(|(a, b, c)| ((a, b), c))
            .unzip();
        let (a_prime, b_prime) = ab_prime.unzip();
        assert_eq!(*A, a_prime);
        assert_eq!(*B, b_prime);
        assert_eq!(*C, c_prime);
    }

    #[test]
    fn zip4_unzip_roundtrip() {
        let (ab_prime, cd_prime) = GameFunctor::zip4(A.clone(), B.clone(), C.clone(), D.clone())
            .map(|(a, b, c, d)| ((a, b), (c, d)))
            .unzip();
        let (a_prime, b_prime) = ab_prime.unzip();
        let (c_prime, d_prime) = cd_prime.unzip();
        assert_eq!(*A, a_prime);
        assert_eq!(*B, b_prime);
        assert_eq!(*C, c_prime);
        assert_eq!(*D, d_prime);
    }

    #[test]
    fn zip5_unzip_roundtrip() {
        let (abcd_prime, e_prime) =
            GameFunctor::zip5(A.clone(), B.clone(), C.clone(), D.clone(), E.clone())
                .map(|(a, b, c, d, e)| (((a, b), (c, d)), e))
                .unzip();
        let (ab_prime, cd_prime) = abcd_prime.unzip();
        let (a_prime, b_prime) = ab_prime.unzip();
        let (c_prime, d_prime) = cd_prime.unzip();
        assert_eq!(*A, a_prime);
        assert_eq!(*B, b_prime);
        assert_eq!(*C, c_prime);
        assert_eq!(*D, d_prime);
        assert_eq!(*E, e_prime);
    }

    #[test]
    fn zip_apply_roundtrip() {
        let f = GameFunctor::unpack(
            (0..PACKED_LEN)
                .map(|i| {
                    if i % 2 == 0 {
                        (|x| x * 2) as fn(i32) -> i32
                    } else {
                        (|x| x * -2) as fn(i32) -> i32
                    }
                })
                .collect(),
            N_WATCHTOWERS,
        )
        .expect("enough data");
        let inverse_f = GameFunctor::unpack(
            (0..PACKED_LEN)
                .map(|i| {
                    if i % 2 == 0 {
                        (|x| x / 2) as fn(i32) -> i32
                    } else {
                        (|x| x / -2) as fn(i32) -> i32
                    }
                })
                .collect(),
            N_WATCHTOWERS,
        )
        .expect("enough data");

        let a_applied = GameFunctor::zip_apply(f, A.clone());
        let a_prime = GameFunctor::zip_apply(inverse_f, a_applied);
        assert_eq!(*A, a_prime);
    }

    #[test]
    fn zip_with_roundtrip() {
        let (a_prime, b_prime) = GameFunctor::zip_with(|a, b| (a, b), A.clone(), B.clone()).unzip();
        assert_eq!(*A, a_prime);
        assert_eq!(*B, b_prime);
    }

    #[test]
    fn zip_with_3_roundtrip() {
        let (ab_prime, c_prime) =
            GameFunctor::zip_with_3(|a, b, c| ((a, b), c), A.clone(), B.clone(), C.clone()).unzip();
        let (a_prime, b_prime) = ab_prime.unzip();
        assert_eq!(*A, a_prime);
        assert_eq!(*B, b_prime);
        assert_eq!(*C, c_prime);
    }

    #[test]
    fn zip_with_4_roundtrip() {
        let (ab_prime, cd_prime) = GameFunctor::zip_with_4(
            |a, b, c, d| ((a, b), (c, d)),
            A.clone(),
            B.clone(),
            C.clone(),
            D.clone(),
        )
        .unzip();
        let (a_prime, b_prime) = ab_prime.unzip();
        let (c_prime, d_prime) = cd_prime.unzip();
        assert_eq!(*A, a_prime);
        assert_eq!(*B, b_prime);
        assert_eq!(*C, c_prime);
        assert_eq!(*D, d_prime);
    }

    #[test]
    fn zip_with_5_roundtrip() {
        let (abcd_prime, e_prime) = GameFunctor::zip_with_5(
            |a, b, c, d, e| (((a, b), (c, d)), e),
            A.clone(),
            B.clone(),
            C.clone(),
            D.clone(),
            E.clone(),
        )
        .unzip();
        let (ab_prime, cd_prime) = abcd_prime.unzip();
        let (a_prime, b_prime) = ab_prime.unzip();
        let (c_prime, d_prime) = cd_prime.unzip();
        assert_eq!(*A, a_prime);
        assert_eq!(*B, b_prime);
        assert_eq!(*C, c_prime);
        assert_eq!(*D, d_prime);
        assert_eq!(*E, e_prime);
    }

    #[test]
    fn sequence_option_none() {
        let mut has_none = vec![Some(0); PACKED_LEN - 1];
        has_none.push(None);
        let has_none = GameFunctor::unpack(has_none, N_WATCHTOWERS).expect("enough data");
        assert!(GameFunctor::sequence_option(has_none).is_none());
    }

    #[test]
    fn sequence_option_some() {
        let mut all_some = vec![Some(0); PACKED_LEN];
        all_some.push(None);
        let all_some = GameFunctor::unpack(all_some, N_WATCHTOWERS).expect("enough data");
        assert!(GameFunctor::sequence_option(all_some).is_some());
    }

    #[test]
    fn sequence_result_err() {
        let mut has_err = vec![Ok(0); PACKED_LEN - 2];
        has_err.push(Err(0));
        has_err.push(Err(1));
        let has_err = GameFunctor::unpack(has_err, N_WATCHTOWERS).expect("enough data");
        assert_eq!(GameFunctor::sequence_result(has_err), Err(0));
    }

    #[test]
    fn sequence_result_ok() {
        let mut all_ok = vec![Result::<u32, u32>::Ok(0); PACKED_LEN];
        all_ok.push(Ok(0));
        let all_ok = GameFunctor::unpack(all_ok, N_WATCHTOWERS).expect("enough data");
        assert!(GameFunctor::sequence_result(all_ok).is_ok());
    }

    #[test]
    fn sequence_functor() {
        let abc_prime = GameFunctor::sequence_functor(vec![A.clone(), B.clone(), C.clone()]);
        let abc_packed: Vec<Vec<i32>> = A
            .clone()
            .pack()
            .into_iter()
            .zip(B.clone().pack())
            .zip(C.clone().pack())
            .map(|((a, b), c)| vec![a, b, c])
            .collect();
        let abc = GameFunctor::unpack(abc_packed, N_WATCHTOWERS).expect("enough data");
        assert_eq!(abc_prime, abc);
    }

    #[test]
    fn semigroup_merge_elementwise() {
        // Vec<T> is a Semigroup that concatenates elements
        let a: GameFunctor<Vec<i32>> = A.as_ref().map(|&x| vec![x]);
        let b: GameFunctor<Vec<i32>> = B.as_ref().map(|&x| vec![x]);
        let merged = a.clone().merge(b.clone());

        let expected: GameFunctor<Vec<i32>> =
            GameFunctor::zip_with(|a_vec, b_vec| [a_vec, b_vec].concat(), a, b);

        assert_eq!(merged, expected);
    }

    #[test]
    fn semigroup_merge_associative() {
        // Test associativity: (A merge B) merge C == A merge (B merge C)
        let a: GameFunctor<Vec<i32>> = A.as_ref().map(|&x| vec![x]);
        let b: GameFunctor<Vec<i32>> = B.as_ref().map(|&x| vec![x]);
        let c: GameFunctor<Vec<i32>> = C.as_ref().map(|&x| vec![x]);

        let lhs = a.clone().merge(b.clone()).merge(c.clone());
        let rhs = a.clone().merge(b.clone().merge(c.clone()));

        assert_eq!(lhs, rhs);
    }

    #[tokio::test]
    async fn join_all_resolves_futures() {
        use std::future::ready;

        // Create a MusigFunctor of ready futures
        let functor_of_futures: GameFunctor<_> = A.as_ref().map(|&x| ready(x * 2));

        let result = functor_of_futures.join_all().await;

        // Each element should be doubled
        let expected = A.as_ref().map(|&x| x * 2);
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn join_all_preserves_structure() {
        use std::future::ready;

        // Create futures that return different values based on position
        let functor_of_futures: GameFunctor<_> = A.as_ref().map(|&x| ready(x));

        let result = functor_of_futures.join_all().await;

        // Result should match the original values
        assert_eq!(result, *A);
    }
}
