//! Functor like data structure for holding an arbitrary data structure that is matched with each of
//! the inputs of the peg-out graph.

use std::{array, future::Future};

use algebra::semigroup::Semigroup;
use futures::future::join_all;
use serde::{Deserialize, Serialize};

use crate::transactions::{
    assert_chain::{deserialize_assert_vector, serialize_assert_vector},
    payout::NUM_PAYOUT_INPUTS,
    prelude::{NUM_PAYOUT_OPTIMISTIC_INPUTS, NUM_POST_ASSERT_INPUTS},
    slash_stake::NUM_SLASH_STAKE_INPUTS,
};

/// Functor like data structure for holding an arbitrary data structure that is matched with each of
/// the inputs of the peg-out graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PogMusigF<T> {
    /// Data associated with the challenge transaction input.
    pub challenge: T,

    /// Data associated with the pre-assert transaction input.
    pub pre_assert: T,

    /// Data associated with the post-assert transaction inputs.
    #[serde(serialize_with = "serialize_assert_vector")]
    #[serde(deserialize_with = "deserialize_assert_vector")]
    pub post_assert: [T; NUM_POST_ASSERT_INPUTS],

    /// Data associated with the payout optimistic transaction inputs.
    pub payout_optimistic: [T; NUM_PAYOUT_OPTIMISTIC_INPUTS],

    /// Data associated with the payout transaction inputs.
    pub payout: [T; NUM_PAYOUT_INPUTS],

    /// Data associated with the disprove transaction input.
    pub disprove: T,

    /// Data for each of the slash stake transaction input pairs.
    pub slash_stake: Vec<[T; NUM_SLASH_STAKE_INPUTS]>,
}

impl<T> PogMusigF<T> {
    /// Packs the data into a vector.
    pub fn pack(self) -> Vec<T> {
        // TODO(proofofkeags): ensure that this is the correct canonical ordering for stuff in the
        // graph as it is sent over the wire in the p2p message.
        let mut packed = Vec::new();
        packed.push(self.challenge);
        packed.push(self.pre_assert);
        packed.extend(self.post_assert);
        packed.extend(self.payout_optimistic);
        packed.extend(self.payout);
        packed.push(self.disprove);
        for pair in self.slash_stake.into_iter() {
            packed.extend(pair);
        }
        packed
    }

    /// Unpacks the data from a vector.
    pub fn unpack(graph_vec: Vec<T>) -> Option<PogMusigF<T>> {
        let mut cursor = graph_vec.into_iter();
        let cursor = cursor.by_ref();

        let challenge = cursor.next()?;

        let pre_assert = cursor.next()?;

        let Ok(post_assert): Result<[T; NUM_POST_ASSERT_INPUTS], _> = cursor
            .take(NUM_POST_ASSERT_INPUTS)
            .collect::<Vec<T>>()
            .try_into()
        else {
            return None;
        };

        let Ok(payout_optimistic): Result<[T; NUM_PAYOUT_OPTIMISTIC_INPUTS], _> = cursor
            .take(NUM_PAYOUT_OPTIMISTIC_INPUTS)
            .collect::<Vec<T>>()
            .try_into()
        else {
            return None;
        };

        let Ok(payout): Result<[T; NUM_PAYOUT_INPUTS], _> = cursor
            .take(NUM_PAYOUT_INPUTS)
            .collect::<Vec<T>>()
            .try_into()
        else {
            return None;
        };

        let disprove = cursor.next()?;

        let mut slash_stake = Vec::new();
        loop {
            let Some(a) = cursor.next() else {
                break;
            };
            let b = cursor.next()?;

            slash_stake.push([a, b]);
        }

        Some(PogMusigF {
            challenge,
            pre_assert,
            post_assert,
            payout_optimistic,
            payout,
            disprove,
            slash_stake,
        })
    }

    /// Returns a reference to the data.
    pub fn as_ref(&self) -> PogMusigF<&T> {
        PogMusigF {
            challenge: &self.challenge,
            pre_assert: &self.pre_assert,
            post_assert: self.post_assert.each_ref(),
            payout_optimistic: self.payout_optimistic.each_ref(),
            payout: self.payout.each_ref(),
            disprove: &self.disprove,
            slash_stake: self
                .slash_stake
                .iter()
                .map(|x| x.each_ref())
                .collect::<Vec<[&T; NUM_SLASH_STAKE_INPUTS]>>(),
        }
    }

    /// Maps the data to a new type.
    pub fn map<U>(self, mut f: impl FnMut(T) -> U) -> PogMusigF<U> {
        PogMusigF {
            challenge: f(self.challenge),
            pre_assert: f(self.pre_assert),
            post_assert: self.post_assert.map(&mut f),
            payout_optimistic: self.payout_optimistic.map(&mut f),
            payout: self.payout.map(&mut f),
            disprove: f(self.disprove),
            slash_stake: self
                .slash_stake
                .into_iter()
                .map(|[a, b]| [f(a), f(b)])
                .collect::<Vec<[U; NUM_SLASH_STAKE_INPUTS]>>(),
        }
    }

    /// Zips the data with another data structure.
    pub fn zip<U>(self, other: PogMusigF<U>) -> PogMusigF<(T, U)> {
        PogMusigF {
            challenge: (self.challenge, other.challenge),
            pre_assert: (self.pre_assert, other.pre_assert),
            post_assert: self
                .post_assert
                .into_iter()
                .zip(other.post_assert)
                // TODO(proofofokeags): figure out how to do without intermediate Vec
                .collect::<Vec<(T, U)>>()
                .try_into()
                .ok()
                .unwrap(),
            payout_optimistic: self
                .payout_optimistic
                .into_iter()
                .zip(other.payout_optimistic)
                // TODO(proofofokeags): figure out how to do without intermediate Vec
                .collect::<Vec<(T, U)>>()
                .try_into()
                .ok()
                .unwrap(),
            payout: self
                .payout
                .into_iter()
                .zip(other.payout)
                // TODO(proofofokeags): figure out how to do without intermediate Vec
                .collect::<Vec<(T, U)>>()
                .try_into()
                .ok()
                .unwrap(),
            disprove: (self.disprove, other.disprove),
            slash_stake: self
                .slash_stake
                .into_iter()
                .zip(other.slash_stake)
                .map(|(a, b)| {
                    a.into_iter()
                        .zip(b)
                        // TODO(proofofokeags): figure out how to do without intermediate Vec
                        .collect::<Vec<(T, U)>>()
                        .try_into()
                        .ok()
                        .unwrap()
                })
                .collect(),
        }
    }

    /// Applies a function to the data while zipping it with another data structure.
    pub fn zip_apply<A, B>(f: PogMusigF<impl Fn(A) -> B>, a: PogMusigF<A>) -> PogMusigF<B> {
        PogMusigF {
            challenge: (f.challenge)(a.challenge),
            pre_assert: (f.pre_assert)(a.pre_assert),
            post_assert: f
                .post_assert
                .into_iter()
                .zip(a.post_assert)
                .map(|(f, a)| f(a))
                .collect::<Vec<B>>()
                .try_into()
                .ok()
                .unwrap(),
            payout_optimistic: f
                .payout_optimistic
                .into_iter()
                .zip(a.payout_optimistic)
                .map(|(f, a)| f(a))
                .collect::<Vec<B>>()
                .try_into()
                .ok()
                .unwrap(),
            payout: f
                .payout
                .into_iter()
                .zip(a.payout)
                .map(|(f, a)| f(a))
                .collect::<Vec<B>>()
                .try_into()
                .ok()
                .unwrap(),
            disprove: (f.disprove)(a.disprove),
            slash_stake: f
                .slash_stake
                .into_iter()
                .zip(a.slash_stake)
                .map(|([f0, f1], [a0, a1])| [f0(a0), f1(a1)])
                .collect::<Vec<[B; NUM_SLASH_STAKE_INPUTS]>>(),
        }
    }

    /// Applies a function to the data while zipping it with other two data structures.
    pub fn zip_with<A, B, C>(
        f: impl Fn(A, B) -> C,
        a: PogMusigF<A>,
        b: PogMusigF<B>,
    ) -> PogMusigF<C> {
        a.zip(b).map(|(a, b)| f(a, b))
    }

    /// Applies a function to the data while zipping it with other three data structures.
    pub fn zip_with_3<A, B, C, O>(
        f: impl Fn(A, B, C) -> O,
        a: PogMusigF<A>,
        b: PogMusigF<B>,
        c: PogMusigF<C>,
    ) -> PogMusigF<O> {
        a.zip(b).zip(c).map(|((a, b), c)| f(a, b, c))
    }

    /// Applies a function to the data while zipping it with other four data structures.
    pub fn zip_with_4<A, B, C, D, O>(
        f: impl Fn(A, B, C, D) -> O,
        a: PogMusigF<A>,
        b: PogMusigF<B>,
        c: PogMusigF<C>,
        d: PogMusigF<D>,
    ) -> PogMusigF<O> {
        a.zip(b).zip(c.zip(d)).map(|((a, b), (c, d))| f(a, b, c, d))
    }

    /// Applies a function to the data while zipping five different [`PogMusigF`]s.
    pub fn zip_with_5<A, B, C, D, E, O>(
        f: impl Fn(A, B, C, D, E) -> O,
        a: PogMusigF<A>,
        b: PogMusigF<B>,
        c: PogMusigF<C>,
        d: PogMusigF<D>,
        e: PogMusigF<E>,
    ) -> PogMusigF<O> {
        a.zip(b)
            .zip(c)
            .zip(d)
            .zip(e)
            .map(|((((a, b), c), d), e)| f(a, b, c, d, e))
    }

    /// Attempts to project a PogMusigF with optional components into one with non-optional
    /// components, returning None if any component is None.
    pub fn sequence_option(mut graph: PogMusigF<Option<T>>) -> Option<PogMusigF<T>> {
        Some(PogMusigF {
            challenge: graph.challenge?,
            pre_assert: graph.pre_assert?,
            post_assert: graph
                .post_assert
                .into_iter()
                .collect::<Option<Vec<T>>>()?
                .try_into()
                .ok()?,
            payout_optimistic: [
                graph.payout_optimistic[0].take()?,
                graph.payout_optimistic[1].take()?,
                graph.payout_optimistic[2].take()?,
                graph.payout_optimistic[3].take()?,
                graph.payout_optimistic[4].take()?,
            ],
            payout: [
                graph.payout[0].take()?,
                graph.payout[1].take()?,
                graph.payout[2].take()?,
                graph.payout[3].take()?,
            ],
            disprove: graph.disprove?,
            slash_stake: graph
                .slash_stake
                .into_iter()
                .map(|[a, b]| a.and_then(|a| b.map(|b| [a, b])))
                .collect::<Option<Vec<[T; 2]>>>()?,
        })
    }

    /// Transposes the result of a [`PogMusigF`].
    pub fn sequence_result<E>(graph: PogMusigF<Result<T, E>>) -> Result<PogMusigF<T>, E> {
        Ok(PogMusigF {
            challenge: graph.challenge?,
            pre_assert: graph.pre_assert?,
            post_assert: graph
                .post_assert
                .into_iter()
                .collect::<Result<Vec<T>, E>>()?
                .try_into()
                .ok()
                .unwrap(),
            payout_optimistic: graph
                .payout_optimistic
                .into_iter()
                .collect::<Result<Vec<T>, E>>()?
                .try_into()
                .ok()
                .unwrap(),
            payout: graph
                .payout
                .into_iter()
                .collect::<Result<Vec<T>, E>>()?
                .try_into()
                .ok()
                .unwrap(),
            disprove: graph.disprove?,
            slash_stake: graph
                .slash_stake
                .into_iter()
                .map(|[ra, rb]| Ok::<[T; NUM_SLASH_STAKE_INPUTS], E>([ra?, rb?]))
                .collect::<Result<Vec<[T; NUM_SLASH_STAKE_INPUTS]>, E>>()?,
        })
    }

    /// Transposes a [`Vec`] of [`PogMusigF`]s into the inverse functor order. Order is preserved
    /// component wise.
    pub fn sequence_pog_musig_f(graphs: Vec<PogMusigF<T>>) -> PogMusigF<Vec<T>> {
        // We sample the initial size so we can have an appropriately sized zip length.
        let mut num_left = graphs.first().map(|g| g.slash_stake.len()).unwrap_or(0);

        // NOTE(proofofkeags): We initialize the accumulator with empty vectors in all targets with
        // an initial stake slash length of the first graph. The stake slash size is guaranteed to
        // be the minimum of the lengths in the vector so sampling any one of them is as good as any
        // other as it will trim things down to the shortest length that appears in all of the
        // graphs in the vector.
        //
        // This isn't ideal, ideally we'd want to be able to lift a runtime value into the length of
        // the stake chain vector but it would require messing with type level programming that I'm
        // not yet sure is worth it. To truly make this a Monoid, we would have to generalize this
        // structure from having a Vec of slash_stake to having an impl IntoIterator of them. This
        // would allow us to use [`std::iter::repeat(Vec::new())`] as the monoidal unit value since
        // it will never trim on zip.
        let init = PogMusigF {
            challenge: Vec::new(),
            pre_assert: Vec::new(),
            post_assert: array::from_fn(|_| Vec::new()),
            payout_optimistic: array::from_fn(|_| Vec::new()),
            payout: array::from_fn(|_| Vec::new()),
            disprove: Vec::new(),
            slash_stake: std::iter::from_fn(move || {
                if num_left == 0 {
                    None
                } else {
                    num_left -= 1;
                    Some([Vec::new(), Vec::new()])
                }
            })
            .collect(),
        };

        // Now we just fold it vector wise.
        graphs
            .into_iter()
            .map(|g| g.map(|a| vec![a]))
            .fold(init, PogMusigF::<_>::merge)
    }
}

impl<T: Clone, U: Clone> PogMusigF<(T, U)> {
    /// Unzips the data into two data structures.
    pub fn unzip(self) -> (PogMusigF<T>, PogMusigF<U>) {
        let pog_t = PogMusigF {
            challenge: self.challenge.0,
            pre_assert: self.pre_assert.0,
            post_assert: self.post_assert.clone().map(|x| x.0),
            payout_optimistic: self.payout_optimistic.clone().map(|x| x.0),
            payout: self.payout.clone().map(|x| x.0),
            disprove: self.disprove.0,
            slash_stake: self
                .slash_stake
                .iter()
                .map(|[(t0, _), (t1, _)]| [t0.clone(), t1.clone()])
                .collect(),
        };
        let pog_u = PogMusigF {
            challenge: self.challenge.1,
            pre_assert: self.pre_assert.1,
            post_assert: self.post_assert.map(|x| x.1),
            payout_optimistic: self.payout_optimistic.map(|x| x.1),
            payout: self.payout.map(|x| x.1),
            disprove: self.disprove.1,
            slash_stake: self
                .slash_stake
                .into_iter()
                .map(|[(_, u0), (_, u1)]| [u0, u1])
                .collect(),
        };
        (pog_t, pog_u)
    }
}

impl<T: Clone> PogMusigF<&T> {
    /// Clones the component references.
    pub fn cloned(self) -> PogMusigF<T> {
        self.map(T::clone)
    }
}

impl<F> PogMusigF<F>
where
    F: Future,
    F::Output: std::fmt::Debug,
{
    /// Joins all the futures in the data structure.
    pub async fn join_all(self) -> PogMusigF<F::Output> {
        PogMusigF::unpack(join_all(self.pack()).await).unwrap()
    }
}

impl<A: Semigroup> Semigroup for PogMusigF<A> {
    fn merge(self, other: Self) -> Self {
        PogMusigF::<A>::zip_with(A::merge, self, other)
    }
}
