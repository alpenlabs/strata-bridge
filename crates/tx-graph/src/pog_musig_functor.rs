use std::future::Future;

use futures::future::join_all;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::constants::NUM_ASSERT_DATA_TX;

use crate::transactions::{
    assert_chain::{deserialize_assert_vector, serialize_assert_vector},
    post_assert,
};

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
        packed.extend(self.post_assert.into_iter());
        packed.extend(self.payout_optimistic.into_iter());
        packed.extend(self.payout.into_iter());
        packed.push(self.disprove);
        for pair in self.slash_stake.into_iter() {
            packed.extend(pair);
        }
        packed
    }

    pub fn unpack(graph_vec: Vec<T>) -> Option<PogMusigF<T>> {
        let mut cursor = graph_vec.into_iter();

        let Some(challenge) = cursor.next() else {
            return None;
        };

        let Some(pre_assert) = cursor.next() else {
            return None;
        };

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

        let Some(disprove) = cursor.next() else {
            return None;
        };

        let mut slash_stake = Vec::new();
        loop {
            let Some(a) = cursor.next() else {
                break;
            };
            let Some(b) = cursor.next() else {
                return None;
            };

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
            post_assert: self.post_assert.map(|x| f(x)),
            payout_optimistic: self.payout_optimistic.map(|x| f(x)),
            payout: self.payout.map(|x| f(x)),
            disprove: f(self.disprove),
            slash_stake: self
                .slash_stake
                .into_iter()
                .map(|[a, b]| [f(a), f(b)])
                .collect::<Vec<[U; 2]>>(),
        }
    }

    pub fn zip<U: std::fmt::Debug>(self, other: PogMusigF<U>) -> PogMusigF<(T, U)> {
        PogMusigF {
            challenge: (self.challenge, other.challenge),
            pre_assert: (self.pre_assert, other.pre_assert),
            post_assert: self
                .post_assert
                .into_iter()
                .zip(other.post_assert.into_iter())
                // TODO(proofofokeags): figure out how to do without intermediate Vec
                .collect::<Vec<(T, U)>>()
                .try_into()
                .ok()
                .unwrap(),
            payout_optimistic: self
                .payout_optimistic
                .into_iter()
                .zip(other.payout_optimistic.into_iter())
                // TODO(proofofokeags): figure out how to do without intermediate Vec
                .collect::<Vec<(T, U)>>()
                .try_into()
                .ok()
                .unwrap(),
            payout: self
                .payout
                .into_iter()
                .zip(other.payout.into_iter())
                // TODO(proofofokeags): figure out how to do without intermediate Vec
                .collect::<Vec<(T, U)>>()
                .try_into()
                .ok()
                .unwrap(),
            disprove: (self.disprove, other.disprove),
            slash_stake: self
                .slash_stake
                .into_iter()
                .zip(other.slash_stake.into_iter())
                .map(|(a, b)| {
                    a.into_iter()
                        .zip(b.into_iter())
                        // TODO(proofofokeags): figure out how to do without intermediate Vec
                        .collect::<Vec<(T, U)>>()
                        .try_into()
                        .ok()
                        .unwrap()
                })
                .collect(),
        }
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
