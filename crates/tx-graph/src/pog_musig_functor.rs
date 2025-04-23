use std::future::Future;

use futures::future::join_all;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::constants::NUM_ASSERT_DATA_TX;

use crate::transactions::assert_chain::{deserialize_assert_vector, serialize_assert_vector};

/// Functor like data structure for holding an arbitrary data structure that is matched with each of
/// the inputs of the peg-out graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PogMusigF<T> {
    /// Data associated with the challenge transaction input.
    pub challenge: T,

    /// Data associated with the pre-assert transaction input.
    pub pre_assert: T,

    /// Data associated with the post-assert transaction inputs.
    #[serde(serialize_with = "serialize_assert_vector")]
    #[serde(deserialize_with = "deserialize_assert_vector")]
    pub post_assert: [T; NUM_ASSERT_DATA_TX],

    /// Data associated with the payout optimistic transaction inputs.
    pub payout_optimistic: [T; 5],

    /// Data associated with the payout transaction inputs.
    pub payout: [T; 4],

    /// Data associated with the disprove transaction input.
    pub disprove: T,

    /// Data for each of the slash stake transaction input pairs.
    pub slash_stake: Vec<[T; 2]>,
}

impl<T> PogMusigF<T> {
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

    pub fn unpack(graph_vec: Vec<T>) -> Option<PogMusigF<T>> {
        let mut cursor = graph_vec.into_iter();

        let challenge = cursor.next()?;

        let pre_assert = cursor.next()?;

        let Ok(post_assert): Result<[T; NUM_ASSERT_DATA_TX], _> = cursor
            .by_ref()
            .take(NUM_ASSERT_DATA_TX)
            .collect::<Vec<T>>()
            .try_into()
        else {
            return None;
        };

        let Ok(payout_optimistic): Result<[T; 5], _> =
            cursor.by_ref().take(5).collect::<Vec<T>>().try_into()
        else {
            return None;
        };

        let Ok(payout): Result<[T; 4], _> = cursor.by_ref().take(5).collect::<Vec<T>>().try_into()
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
                .collect::<Vec<[&T; 2]>>(),
        }
    }

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
                .collect::<Vec<[U; 2]>>(),
        }
    }

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
                .collect::<Vec<[B; 2]>>(),
        }
    }

    pub fn zip_with<A, B, C>(
        f: impl Fn(A, B) -> C,
        a: PogMusigF<A>,
        b: PogMusigF<B>,
    ) -> PogMusigF<C> {
        a.zip(b).map(|(a, b)| f(a, b))
    }

    pub fn zip_with_3<A, B, C, O>(
        f: impl Fn(A, B, C) -> O,
        a: PogMusigF<A>,
        b: PogMusigF<B>,
        c: PogMusigF<C>,
    ) -> PogMusigF<O> {
        a.zip(b).zip(c).map(|((a, b), c)| f(a, b, c))
    }

    pub fn zip_with_4<A, B, C, D, O>(
        f: impl Fn(A, B, C, D) -> O,
        a: PogMusigF<A>,
        b: PogMusigF<B>,
        c: PogMusigF<C>,
        d: PogMusigF<D>,
    ) -> PogMusigF<O> {
        a.zip(b).zip(c.zip(d)).map(|((a, b), (c, d))| f(a, b, c, d))
    }

    pub fn transpose_result<E>(graph: PogMusigF<Result<T, E>>) -> Result<PogMusigF<T>, E> {
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
                .map(|[ra, rb]| Ok::<[T; 2], E>([ra?, rb?]))
                .collect::<Result<Vec<[T; 2]>, E>>()?,
        })
    }
}

impl<T: Clone, U: Clone> PogMusigF<(T, U)> {
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

impl<F> PogMusigF<F>
where
    F: Future,
    F::Output: std::fmt::Debug,
{
    pub async fn join_all(self) -> PogMusigF<F::Output> {
        PogMusigF::unpack(join_all(self.pack()).await).unwrap()
    }
}
