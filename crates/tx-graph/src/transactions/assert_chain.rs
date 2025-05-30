//! Constructs the assert chain.

use core::fmt;
use std::{marker::PhantomData, mem::MaybeUninit};

use bitcoin::{Amount, Txid};
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use strata_bridge_connectors::prelude::*;
use strata_bridge_primitives::constants::*;
use tracing::trace;

use super::prelude::*;

/// Data needed to construct an [`AssertChain`].
#[derive(Debug, Clone)]
pub struct AssertChainData {
    /// The data for the pre-assert transaction.
    pub pre_assert_data: PreAssertData,

    /// The txid of the deposit UTXO that can be withdrawn via this withdrawal fulfillment.
    pub deposit_txid: Txid,
}

/// A chain of transactions that asserts the operator's claim.
#[derive(Debug, Clone)]
pub struct AssertChain {
    /// The pre-assert transaction, the first transaction in the chain.
    pub pre_assert: PreAssertTx,

    /// The set of assert data transactions that contain bitcommitments to the intermediate values
    /// in the proof.
    pub assert_data: AssertDataTxBatch,

    /// The post-assert transaction, the last transaction in the chain.
    pub post_assert: PostAssertTx,
}

impl AssertChain {
    /// Constructs a new instance of the assert chain.
    ///
    /// This method constructs the pre-assert, assert data, and post-assert transactions in order.
    pub fn new(
        data: AssertChainData,
        connector_c0: ConnectorC0,
        connector_a2: ConnectorNOfN,
        connector_a3: ConnectorA3,
        connector_cpfp: ConnectorCpfp,
        connector_a_hash_factory: ConnectorAHashFactory<
            NUM_HASH_CONNECTORS_BATCH_1,
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1,
            NUM_HASH_CONNECTORS_BATCH_2,
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2,
        >,
        connector_a256_factory: ConnectorA256Factory<
            NUM_FIELD_CONNECTORS_BATCH_1,
            NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1,
            NUM_FIELD_CONNECTORS_BATCH_2,
            NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2,
        >,
    ) -> Self {
        let pre_assert = PreAssertTx::new(
            data.pre_assert_data,
            connector_c0,
            connector_cpfp,
            connector_a256_factory,
            connector_a_hash_factory,
        );
        let pre_assert_txid = pre_assert.compute_txid();
        trace!(event = "created pre-assert tx", %pre_assert_txid);

        let assert_data_input = AssertDataTxInput {
            pre_assert_txid,
            pre_assert_txouts: pre_assert.tx_outs(),
        };

        trace!(event = "constructed assert data input", ?assert_data_input);
        let assert_data = AssertDataTxBatch::new(assert_data_input, connector_a2, connector_cpfp);

        let assert_data_txids = assert_data.compute_txids().to_vec();
        trace!(event = "created assert_data tx batch", ?assert_data_txids);

        let input_amount = assert_data
            .psbts()
            .iter()
            .fold(Amount::from_sat(0), |acc, psbt| {
                acc + psbt.unsigned_tx.output[0].value
            });

        let post_assert_data = PostAssertTxData {
            assert_data_txids,
            pre_assert_txid,
            input_amount,
            deposit_txid: data.deposit_txid,
        };

        let post_assert =
            PostAssertTx::new(post_assert_data, connector_a2, connector_a3, connector_cpfp);

        trace!(event = "created post_assert tx", post_assert_txid = ?post_assert.compute_txid());

        Self {
            pre_assert,
            assert_data,
            post_assert,
        }
    }
}

/// This is needed because the blanket implementation of serde's deserializers doesn't go past fixed
/// length arrays of larger than 32.
pub fn serialize_assert_vector<T: Serialize, S: Serializer>(
    data: &[T; NUM_ASSERT_DATA_TX],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_tuple(NUM_ASSERT_DATA_TX)?;
    for e in data {
        seq.serialize_element(e)?;
    }
    seq.end()
}

/// This is needed because the blanket implementation of serde's deserializers doesn't go past fixed
/// length arrays of larger than 32.
pub fn deserialize_assert_vector<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<[T; NUM_ASSERT_DATA_TX], D::Error> {
    // The api design of serde completely lacks any sort of taste so we're forced to specify all of
    // this bullshit.
    struct AssertVisitor<const N: usize, T> {
        marker: PhantomData<T>,
    }

    impl<'de, const N: usize, T> Visitor<'de> for AssertVisitor<N, T>
    where
        T: Deserialize<'de>,
    {
        type Value = [T; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a sequence")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = [const { MaybeUninit::<T>::uninit() }; N];
            let mut num_successfully_deserialized = 0;

            let cleanup = |mut vs: [MaybeUninit<T>; N], n: usize| {
                for written in &mut vs[..n] {
                    unsafe {
                        written.assume_init_drop();
                    }
                }
            };

            while let Some(res) = seq.next_element().transpose() {
                match res {
                    Ok(value) => {
                        if num_successfully_deserialized >= NUM_ASSERT_DATA_TX {
                            cleanup(values, num_successfully_deserialized);
                            return Err(serde::de::Error::invalid_length(
                                num_successfully_deserialized + 1,
                                &self,
                            ));
                        }

                        values[num_successfully_deserialized].write(value);
                        num_successfully_deserialized += 1;
                    }
                    Err(e) => {
                        cleanup(values, num_successfully_deserialized);
                        return Err(e);
                    }
                }
            }

            if num_successfully_deserialized < NUM_ASSERT_DATA_TX {
                cleanup(values, num_successfully_deserialized);
                Err(serde::de::Error::invalid_length(
                    num_successfully_deserialized,
                    &self,
                ))
            } else {
                Ok(unsafe { MaybeUninit::array_assume_init(values) })
            }
        }
    }

    let visitor = AssertVisitor::<NUM_ASSERT_DATA_TX, T> {
        marker: PhantomData,
    };
    deserializer.deserialize_seq(visitor)
}
