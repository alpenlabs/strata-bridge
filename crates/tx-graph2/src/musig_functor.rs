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
/// The claim, bridge proof, counterproof NACK, admin burn and unstaking burn
/// transactions are not included, because they are not presigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MusigFunctor<T> {
    /// Data for each input of the uncontested payout transaction.
    pub uncontested_payout: [T; UncontestedPayoutTx::N_INPUTS],

    /// For each contesting watchtower, data for the single contest transaction input.
    pub contest: Vec<T>,

    /// Data for each input of the bridge proof timeout transaction.
    pub bridge_proof_timeout: [T; BridgeProofTimeoutTx::N_INPUTS],

    /// For each watchtower, data for the single counterproof transaction input.
    pub counterproofs: Vec<T>,

    /// For each watchtower, data for each input of the counterproof ACK transaction.
    pub counterproof_acks: Vec<[T; CounterproofAckTx::N_INPUTS]>,

    /// Data for each input of the contested payout transaction.
    pub contested_payout: [T; ContestedPayoutTx::N_INPUTS],

    /// Data for each input of the slash transaction.
    pub slash: [T; SlashTx::N_INPUTS],
}

impl<T> MusigFunctor<T> {
    /// Packs the data into a vector.
    pub fn pack(self) -> Vec<T> {
        debug_assert_eq!(self.contest.len(), self.counterproofs.len());
        debug_assert_eq!(self.contest.len(), self.counterproof_acks.len());

        let total_len = UncontestedPayoutTx::N_INPUTS
            + ContestTx::N_INPUTS * self.contest.len()
            + BridgeProofTimeoutTx::N_INPUTS
            + CounterproofTx::N_INPUTS * self.contest.len()
            + CounterproofAckTx::N_INPUTS * self.contest.len()
            + ContestedPayoutTx::N_INPUTS
            + SlashTx::N_INPUTS;

        // TODO: (@uncomputable): ensure that this is the correct canonical ordering for stuff in
        // the graph as it is sent over the wire in the p2p message.
        let mut packed = Vec::with_capacity(total_len);
        packed.extend(self.uncontested_payout);
        packed.extend(self.contest);
        packed.extend(self.bridge_proof_timeout);
        packed.extend(self.counterproofs);
        for x in self.counterproof_acks {
            packed.extend(x);
        }
        packed.extend(self.contested_payout);
        packed.extend(self.slash);
        debug_assert_eq!(packed.len(), total_len);

        packed
    }

    /// Unpacks the data from a vector.
    ///
    /// The `n_watchtowers` parameter specifies how many watchtowers to expect.
    pub fn unpack(graph_vec: Vec<T>, n_watchtowers: usize) -> Option<MusigFunctor<T>> {
        let mut cursor = graph_vec.into_iter();
        let cursor = cursor.by_ref();

        let uncontested_payout = take_array(cursor)?;

        let mut contest = Vec::with_capacity(n_watchtowers);
        for _ in 0..n_watchtowers {
            contest.push(cursor.next()?);
        }

        let bridge_proof_timeout = take_array(cursor)?;

        let mut counterproofs = Vec::with_capacity(n_watchtowers);
        for _ in 0..n_watchtowers {
            counterproofs.push(cursor.next()?);
        }

        let mut counterproof_acks = Vec::with_capacity(n_watchtowers);
        for _ in 0..n_watchtowers {
            counterproof_acks.push(take_array(cursor)?);
        }

        let contested_payout = take_array(cursor)?;
        let slash = take_array(cursor)?;

        Some(MusigFunctor {
            uncontested_payout,
            contest,
            bridge_proof_timeout,
            counterproofs,
            counterproof_acks,
            contested_payout,
            slash,
        })
    }

    /// Returns references to the data.
    pub fn as_ref(&self) -> MusigFunctor<&T> {
        MusigFunctor {
            uncontested_payout: self.uncontested_payout.each_ref(),
            contest: self.contest.iter().collect(),
            bridge_proof_timeout: self.bridge_proof_timeout.each_ref(),
            counterproofs: self.counterproofs.iter().collect(),
            counterproof_acks: self
                .counterproof_acks
                .iter()
                .map(|a| a.each_ref())
                .collect(),
            contested_payout: self.contested_payout.each_ref(),
            slash: self.slash.each_ref(),
        }
    }

    /// Maps the data to a new type.
    pub fn map<U>(self, mut f: impl FnMut(T) -> U) -> MusigFunctor<U> {
        MusigFunctor {
            uncontested_payout: self.uncontested_payout.map(&mut f),
            contest: self.contest.into_iter().map(&mut f).collect(),
            bridge_proof_timeout: self.bridge_proof_timeout.map(&mut f),
            counterproofs: self.counterproofs.into_iter().map(&mut f).collect(),
            counterproof_acks: self
                .counterproof_acks
                .into_iter()
                .map(|a| a.map(&mut f))
                .collect(),
            contested_payout: self.contested_payout.map(&mut f),
            slash: self.slash.map(&mut f),
        }
    }

    /// Zips the data of two functors.
    pub fn zip<U>(self, other: MusigFunctor<U>) -> MusigFunctor<(T, U)> {
        MusigFunctor {
            uncontested_payout: zip_arrays(self.uncontested_payout, other.uncontested_payout),
            contest: self.contest.into_iter().zip(other.contest).collect(),
            bridge_proof_timeout: zip_arrays(self.bridge_proof_timeout, other.bridge_proof_timeout),
            counterproofs: self
                .counterproofs
                .into_iter()
                .zip(other.counterproofs)
                .collect(),
            counterproof_acks: self
                .counterproof_acks
                .into_iter()
                .zip(other.counterproof_acks)
                .map(|(a, b)| zip_arrays(a, b))
                .collect(),
            contested_payout: zip_arrays(self.contested_payout, other.contested_payout),
            slash: zip_arrays(self.slash, other.slash),
        }
    }

    /// Zips 3 functors into a functor of a 3-tuple.
    pub fn zip3<A, B, C>(
        a: MusigFunctor<A>,
        b: MusigFunctor<B>,
        c: MusigFunctor<C>,
    ) -> MusigFunctor<(A, B, C)> {
        MusigFunctor::<(A, B, C)>::zip_with_3(|a, b, c| (a, b, c), a, b, c)
    }

    /// Zips 4 functors into a functor of a 4-tuple.
    pub fn zip4<A, B, C, D>(
        a: MusigFunctor<A>,
        b: MusigFunctor<B>,
        c: MusigFunctor<C>,
        d: MusigFunctor<D>,
    ) -> MusigFunctor<(A, B, C, D)> {
        MusigFunctor::<(A, B, C, D)>::zip_with_4(|a, b, c, d| (a, b, c, d), a, b, c, d)
    }

    /// Zips 5 functors into a functor of a 5-tuple.
    pub fn zip5<A, B, C, D, E>(
        a: MusigFunctor<A>,
        b: MusigFunctor<B>,
        c: MusigFunctor<C>,
        d: MusigFunctor<D>,
        e: MusigFunctor<E>,
    ) -> MusigFunctor<(A, B, C, D, E)> {
        MusigFunctor::<(A, B, C, D, E)>::zip_with_5(|a, b, c, d, e| (a, b, c, d, e), a, b, c, d, e)
    }

    /// Zips a functor of functions with a functor of data,
    /// resulting in an functor of mapped data.
    pub fn zip_apply<A, O>(
        f: MusigFunctor<impl Fn(A) -> O>,
        a: MusigFunctor<A>,
    ) -> MusigFunctor<O> {
        MusigFunctor {
            uncontested_payout: zip_apply_arrays(f.uncontested_payout, a.uncontested_payout),
            contest: f
                .contest
                .into_iter()
                .zip(a.contest)
                .map(|(fp, ap)| fp(ap))
                .collect(),
            bridge_proof_timeout: zip_apply_arrays(f.bridge_proof_timeout, a.bridge_proof_timeout),
            counterproofs: f
                .counterproofs
                .into_iter()
                .zip(a.counterproofs)
                .map(|(fp, ap)| fp(ap))
                .collect(),
            counterproof_acks: f
                .counterproof_acks
                .into_iter()
                .zip(a.counterproof_acks)
                .map(|(fp, ap)| zip_apply_arrays(fp, ap))
                .collect(),
            contested_payout: zip_apply_arrays(f.contested_payout, a.contested_payout),
            slash: zip_apply_arrays(f.slash, a.slash),
        }
    }

    /// Zips the data of two functors and applies a function to the result.
    pub fn zip_with<A, B, O>(
        f: impl Fn(A, B) -> O,
        a: MusigFunctor<A>,
        b: MusigFunctor<B>,
    ) -> MusigFunctor<O> {
        a.zip(b).map(|(a, b)| f(a, b))
    }

    /// Zips the data of three functors and applies a function to the result.
    pub fn zip_with_3<A, B, C, O>(
        f: impl Fn(A, B, C) -> O,
        a: MusigFunctor<A>,
        b: MusigFunctor<B>,
        c: MusigFunctor<C>,
    ) -> MusigFunctor<O> {
        a.zip(b).zip(c).map(|((a, b), c)| f(a, b, c))
    }

    /// Zips the data of four functors and applies a function to the result.
    pub fn zip_with_4<A, B, C, D, O>(
        f: impl Fn(A, B, C, D) -> O,
        a: MusigFunctor<A>,
        b: MusigFunctor<B>,
        c: MusigFunctor<C>,
        d: MusigFunctor<D>,
    ) -> MusigFunctor<O> {
        a.zip(b).zip(c.zip(d)).map(|((a, b), (c, d))| f(a, b, c, d))
    }

    /// Zips the data of five functors and applies a function to the result.
    pub fn zip_with_5<A, B, C, D, E, O>(
        f: impl Fn(A, B, C, D, E) -> O,
        a: MusigFunctor<A>,
        b: MusigFunctor<B>,
        c: MusigFunctor<C>,
        d: MusigFunctor<D>,
        e: MusigFunctor<E>,
    ) -> MusigFunctor<O> {
        a.zip(b)
            .zip(c)
            .zip(d)
            .zip(e)
            .map(|((((a, b), c), d), e)| f(a, b, c, d, e))
    }

    /// Converts a functor of options into an option of a functor,
    /// returning `None` if any functor component is `None`.
    pub fn sequence_option(graph: MusigFunctor<Option<T>>) -> Option<MusigFunctor<T>> {
        Some(MusigFunctor {
            uncontested_payout: sequence_option_array(graph.uncontested_payout)?,
            contest: graph.contest.into_iter().collect::<Option<Vec<_>>>()?,
            bridge_proof_timeout: sequence_option_array(graph.bridge_proof_timeout)?,
            counterproofs: graph
                .counterproofs
                .into_iter()
                .collect::<Option<Vec<_>>>()?,
            counterproof_acks: graph
                .counterproof_acks
                .into_iter()
                .map(sequence_option_array)
                .collect::<Option<Vec<_>>>()?,
            contested_payout: sequence_option_array(graph.contested_payout)?,
            slash: sequence_option_array(graph.slash)?,
        })
    }

    /// Converts a functor of results into the result of a functor,
    /// returning `Err` if any functor component is `Err`.
    ///
    /// The returned `Err` is the first one that was encountered.
    pub fn sequence_result<E>(graph: MusigFunctor<Result<T, E>>) -> Result<MusigFunctor<T>, E> {
        Ok(MusigFunctor {
            uncontested_payout: sequence_result_array(graph.uncontested_payout)?,
            contest: graph.contest.into_iter().collect::<Result<Vec<_>, E>>()?,
            bridge_proof_timeout: sequence_result_array(graph.bridge_proof_timeout)?,
            counterproofs: graph
                .counterproofs
                .into_iter()
                .collect::<Result<Vec<_>, E>>()?,
            counterproof_acks: graph
                .counterproof_acks
                .into_iter()
                .map(sequence_result_array)
                .collect::<Result<Vec<_>, E>>()?,
            contested_payout: sequence_result_array(graph.contested_payout)?,
            slash: sequence_result_array(graph.slash)?,
        })
    }

    /// Converts a vector of functors into a functor of vectors.
    ///
    /// The order of functors is inverted in the resulting vectors.
    ///
    /// The number of watchtowers in the resulting functor is the minimum
    /// of the numbers of watchtowers from the input functors.
    /// Excess watchtowers are truncated.
    pub fn sequence_musig_functor(graphs: Vec<MusigFunctor<T>>) -> MusigFunctor<Vec<T>> {
        for graph in &graphs {
            debug_assert_eq!(graph.contest.len(), graph.counterproofs.len());
            debug_assert_eq!(graph.contest.len(), graph.counterproof_acks.len());
        }

        let n_watchtowers = graphs.iter().map(|g| g.contest.len()).min().unwrap_or(0);

        // NOTE: (@uncomputable) We cannot use `Vec::with_capacity(graphs.len())`
        //                       because `T` doesn't implement `Default`.
        let init = MusigFunctor {
            uncontested_payout: array::from_fn(|_| Vec::new()),
            contest: (0..n_watchtowers).map(|_| Vec::new()).collect(),
            bridge_proof_timeout: array::from_fn(|_| Vec::new()),
            counterproofs: (0..n_watchtowers).map(|_| Vec::new()).collect(),
            counterproof_acks: (0..n_watchtowers)
                .map(|_| array::from_fn(|_| Vec::new()))
                .collect(),
            contested_payout: array::from_fn(|_| Vec::new()),
            slash: array::from_fn(|_| Vec::new()),
        };

        graphs
            .into_iter()
            // Lift each element into a vector, because `Vec` implements `Semigroup`.
            // The resulting functor also implements `Semigroup`.
            .map(|g| g.map(|a| vec![a]))
            // Because `MusigFunctor::merge` calls `MusigFunctor::zip_with`,
            // this operation silently truncates each vector to the minimum shared length.
            // Since the vector lengths are always equal to the number of watchtowers,
            // this effectively reduces the number of watchtowers to the minimum shared length.
            .fold(init, MusigFunctor::<_>::merge)
    }
}

impl<T: Clone, U: Clone> MusigFunctor<(T, U)> {
    /// Converts a functor of pairs into two functors of the respective components.
    pub fn unzip(self) -> (MusigFunctor<T>, MusigFunctor<U>) {
        let game_t = MusigFunctor {
            uncontested_payout: self.uncontested_payout.clone().map(|(t, _)| t),
            contest: self.contest.iter().cloned().map(|(t, _)| t).collect(),
            bridge_proof_timeout: self.bridge_proof_timeout.clone().map(|(t, _)| t),
            counterproofs: self.counterproofs.iter().cloned().map(|(t, _)| t).collect(),
            counterproof_acks: self
                .counterproof_acks
                .iter()
                .cloned()
                .map(|a| a.map(|(t, _)| t))
                .collect(),
            contested_payout: self.contested_payout.clone().map(|(t, _)| t),
            slash: self.slash.clone().map(|(t, _)| t),
        };
        let game_u = MusigFunctor {
            uncontested_payout: self.uncontested_payout.map(|(_, u)| u),
            contest: self.contest.into_iter().map(|(_, u)| u).collect(),
            bridge_proof_timeout: self.bridge_proof_timeout.map(|(_, u)| u),
            counterproofs: self.counterproofs.into_iter().map(|(_, u)| u).collect(),
            counterproof_acks: self
                .counterproof_acks
                .into_iter()
                .map(|a| a.map(|(_, u)| u))
                .collect(),
            contested_payout: self.contested_payout.map(|(_, u)| u),
            slash: self.slash.map(|(_, u)| u),
        };

        (game_t, game_u)
    }
}

impl<T: Clone> MusigFunctor<&T> {
    /// Maps a [`MusigFunctor<&T>`] to a [`MusigFunctor<T>`] by cloning its contents.
    pub fn cloned(self) -> MusigFunctor<T> {
        self.map(T::clone)
    }
}

impl<F> MusigFunctor<F>
where
    F: Future,
    F::Output: std::fmt::Debug,
{
    /// Converts a functor of futures into a functor of outputs,
    /// by joining and awaiting the futures.
    ///
    /// The `n_watchtowers` parameter is needed for unpacking the results.
    pub async fn join_all(self, n_watchtowers: usize) -> MusigFunctor<F::Output> {
        MusigFunctor::unpack(join_all(self.pack()).await, n_watchtowers).unwrap()
    }
}

impl<T: Semigroup> Semigroup for MusigFunctor<T> {
    /// [`MusigFunctor`] preserves the [`Semigroup`] structure of its leaves.
    fn merge(self, other: Self) -> Self {
        MusigFunctor::<T>::zip_with(T::merge, self, other)
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
