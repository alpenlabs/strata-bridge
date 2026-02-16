//! Implementation of the [`BridgeDb`] trait for FdbClient.

use std::fmt::Debug;

use bitcoin::Txid;
use foundationdb::FdbBindingError;
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_sm::{deposit::machine::DepositSM, graph::machine::GraphSM};
use terrors::OneOf;

use crate::{
    fdb::{
        client::FdbClient,
        row_spec::signatures::{SignatureKey, SignatureRowSpec},
    },
    traits::BridgeDb,
};

/// Distinction between key and value failures.
#[derive(Debug)]
pub enum FailureTarget {
    /// Key-related failure.
    Key,
    /// Value-related failure.
    Value,
}

/// Standard error type for FoundationDB layer errors
#[derive(Debug)]
pub enum LayerError {
    /// Something failed to decode. This cannot be programmatically
    /// introspected and should be logged.
    FailedToDeserialize(FailureTarget, Box<dyn Debug>),

    /// Something failed to encode. This cannot be programmatically
    /// introspected and should be logged.
    FailedToSerialize(FailureTarget, Box<dyn Debug>),
}

impl LayerError {
    /// Creates a new `LayerError` for a failed key unpacking.
    pub fn failed_to_unpack_key(error: impl Debug + 'static) -> Self {
        LayerError::FailedToDeserialize(FailureTarget::Key, Box::new(error))
    }

    /// Creates a new `LayerError` for a failed key serialization.
    pub fn failed_to_pack_key(error: impl Debug + 'static) -> Self {
        LayerError::FailedToSerialize(FailureTarget::Key, Box::new(error))
    }

    /// Creates a new `LayerError` for a failed value deserialization.
    pub fn failed_to_deserialize_value(error: impl Debug + 'static) -> Self {
        LayerError::FailedToDeserialize(FailureTarget::Value, Box::new(error))
    }

    /// Creates a new `LayerError` for a failed value serialization.
    pub fn failed_to_serialize_value(error: impl Debug + 'static) -> Self {
        LayerError::FailedToSerialize(FailureTarget::Value, Box::new(error))
    }
}

impl BridgeDb for FdbClient {
    type Error = OneOf<(FdbBindingError, LayerError)>;

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> Result<Option<Signature>, Self::Error> {
        self.basic_get::<SignatureRowSpec>(SignatureKey {
            operator_idx,
            txid,
            input_index,
        })
        .await
    }

    async fn set_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> Result<(), Self::Error> {
        self.basic_set::<SignatureRowSpec>(
            SignatureKey {
                operator_idx,
                txid,
                input_index,
            },
            signature,
        )
        .await
    }

    async fn get_deposit_state(
        &self,
        _deposit_idx: DepositIdx,
    ) -> Result<Option<DepositSM>, Self::Error> {
        todo!()
    }

    async fn set_deposit_state(
        &self,
        _deposit_idx: DepositIdx,
        _state: DepositSM,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn get_all_deposit_states(&self) -> Result<Vec<(DepositIdx, DepositSM)>, Self::Error> {
        todo!()
    }

    async fn delete_deposit_state(&self, _deposit_idx: DepositIdx) -> Result<(), Self::Error> {
        todo!()
    }

    async fn get_graph_state(
        &self,
        _deposit_idx: DepositIdx,
        _operator_idx: OperatorIdx,
    ) -> Result<Option<GraphSM>, Self::Error> {
        todo!()
    }

    async fn set_graph_state(
        &self,
        _deposit_idx: DepositIdx,
        _operator_idx: OperatorIdx,
        _state: GraphSM,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn get_all_graph_states(&self) -> Result<Vec<(GraphIdx, GraphSM)>, Self::Error> {
        todo!()
    }

    async fn delete_graph_state(
        &self,
        _deposit_idx: DepositIdx,
        _operator_idx: OperatorIdx,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn get_funds(&self, _txid: Txid) -> Result<Option<Vec<bitcoin::OutPoint>>, Self::Error> {
        todo!()
    }

    async fn set_funds(
        &self,
        _txid: Txid,
        _outpoints: Vec<bitcoin::OutPoint>,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn delete_funds(&self, _txid: Txid) -> Result<(), Self::Error> {
        todo!()
    }

    async fn delete_deposit(&self, _deposit_idx: DepositIdx) -> Result<(), Self::Error> {
        todo!()
    }

    async fn delete_operator(&self, _operator_idx: OperatorIdx) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use bitcoin::hashes::Hash;
    use proptest::prelude::*;
    use secp256k1::{
        Keypair, Message, Secp256k1,
        rand::{random, thread_rng},
    };

    use super::*;
    use crate::fdb::{cfg::Config, client::MustDrop};

    static TEST_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    static FDB_CLIENT: OnceLock<(FdbClient, MustDrop)> = OnceLock::new();

    fn get_runtime() -> &'static tokio::runtime::Runtime {
        TEST_RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    /// Runs a future to completion, handling the case where we're already inside a runtime.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // We're inside a runtime, use block_in_place to avoid nested runtime error
            tokio::task::block_in_place(|| handle.block_on(f))
        } else {
            // We're not in a runtime, use our static runtime
            get_runtime().block_on(f)
        }
    }

    fn get_client() -> &'static FdbClient {
        &FDB_CLIENT
            .get_or_init(|| {
                block_on(async {
                    // Use a random root directory name for test isolation
                    let random_suffix: u64 = random();
                    let fdb_config = Config {
                        root_directory: format!("test-{random_suffix}"),
                        ..Default::default()
                    };
                    FdbClient::setup(fdb_config).await.unwrap()
                })
            })
            .0
    }

    /// Generates an arbitrary valid Schnorr signature.
    fn arb_signature() -> impl Strategy<Value = Signature> {
        any::<[u8; 32]>().prop_map(|msg_bytes| {
            let secp = Secp256k1::new();
            let (secret_key, _) = secp.generate_keypair(&mut thread_rng());
            let keypair = Keypair::from_secret_key(&secp, &secret_key);
            keypair.sign_schnorr(Message::from_digest(msg_bytes))
        })
    }

    /// Generates an arbitrary Txid.
    fn arb_txid() -> impl Strategy<Value = Txid> {
        any::<[u8; 32]>().prop_map(|bytes| Txid::from_slice(&bytes).unwrap())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property: any signature stored in the database can be retrieved with the same key.
        #[test]
        fn signature_roundtrip(
            operator_idx in any::<OperatorIdx>(),
            txid in arb_txid(),
            input_index in any::<u32>(),
            signature in arb_signature(),
        ) {
            block_on(async {
                let client = get_client();

                client
                    .set_signature(operator_idx, txid, input_index, signature)
                    .await
                    .unwrap();

                let retrieved_signature = client
                    .get_signature(operator_idx, txid, input_index)
                    .await
                    .unwrap();

                prop_assert_eq!(Some(signature), retrieved_signature);

                Ok(())
            })?;
        }
    }
}
