//! Implementation of the [`BridgeDb`] trait for FdbClient.

use std::fmt::Debug;

use bitcoin::Txid;
use foundationdb::{FdbBindingError, RetryableTransaction};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::types::OperatorIdx;
use terrors::OneOf;

use crate::{
    fdb::{
        FdbClient,
        row_spec::{PackableKey, SerializableValue, signatures::SignatureKey},
    },
    traits::BridgeDb,
};

#[derive(Debug)]
/// Distinction between key and value failures.
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
        let key = SignatureKey {
            operator_idx,
            txid,
            input_index,
        };

        let key = key
            .pack(&self.dirs)
            .map_err(LayerError::failed_to_pack_key)
            .map_err(OneOf::new)?;

        let trx = |trx: RetryableTransaction, _maybe_committed| {
            let key = key.clone();
            async move { Ok(trx.get(key.as_ref(), true).await?) }
        };
        let Some(sig_bytes) = self.db.run(trx).await.map_err(OneOf::new)? else {
            return Ok(None);
        };
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(LayerError::failed_to_deserialize_value)
            .map_err(OneOf::new)?;
        Ok(Some(sig))
    }

    async fn set_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> Result<(), Self::Error> {
        let key = SignatureKey {
            operator_idx,
            txid,
            input_index,
        };

        let key = &key
            .pack(&self.dirs)
            .map_err(LayerError::failed_to_pack_key)
            .map_err(OneOf::new)?;
        let value = &<Signature as SerializableValue>::serialize(&signature)
            .map_err(LayerError::failed_to_serialize_value)
            .map_err(OneOf::new)?;

        let trx = |trx: RetryableTransaction, _maybe_committed| async move {
            trx.set(key.as_ref(), value.as_ref());
            Ok(())
        };
        self.db.run(trx).await.map_err(OneOf::new)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use secp256k1::{
        Keypair, Message, Secp256k1,
        rand::{random, thread_rng},
    };
    use strata_p2p_types::P2POperatorPubKey;

    use super::*;
    use crate::fdb::Config;

    #[tokio::test]
    async fn test_signature_e2e() {
        let pubkey_bytes: [u8; 32] = random();
        let fdb_config = Config::default();
        let p2p_pubkey = P2POperatorPubKey::from(Vec::from(pubkey_bytes));
        let (client, _guard) = FdbClient::setup(fdb_config, p2p_pubkey).await.unwrap();

        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut thread_rng());
        let keypair = Keypair::from_secret_key(&secp, &secret_key);

        for operator_idx in 0..10 {
            for i in 0..10 {
                let mut txid_b = [0u8; 32];
                txid_b[0] = i as u8;
                let txid = Txid::from_slice(&txid_b).unwrap();
                let input_index = i;
                let signature = keypair.sign_schnorr(Message::from_digest(txid_b));
                client
                    .set_signature(operator_idx, txid, input_index, signature)
                    .await
                    .unwrap();
                let retrieved_signature = client
                    .get_signature(operator_idx, txid, input_index)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(signature, retrieved_signature);
            }
        }

        client.clear().await.unwrap().unwrap();
        drop(_guard);
    }
}
