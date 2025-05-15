use bitcoin::{
    block::Header,
    blockdata::block::Block,
    consensus::encode::{deserialize_hex, serialize_hex},
    hashes::Hash,
    merkle_tree::PartialMerkleTree,
    Transaction, Txid, Wtxid,
};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use strata_l1tx::{envelope::parser::parse_envelope_payloads, filter::types::TxFilterConfig};
use strata_primitives::params::RollupParams;
use strata_state::batch::{Checkpoint, SignedCheckpoint};

#[derive(Debug, Clone)]
pub struct InclusionProof(pub PartialMerkleTree);

/// Implement `Serialize` for `PartialMerkleTree` using hex encoding.
impl Serialize for InclusionProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&serialize_hex(&self.0))
    }
}

/// Implement `Deserialize` for `PartialMerkleTree` using hex decoding.
impl<'de> Deserialize<'de> for InclusionProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(InclusionProof(
            deserialize_hex(&String::deserialize(deserializer)?).map_err(D::Error::custom)?,
        ))
    }
}

pub trait WtxidToTxid {
    fn to_txid(&self) -> Txid;
}

impl WtxidToTxid for Wtxid {
    fn to_txid(&self) -> Txid {
        Txid::from_byte_array(self.to_byte_array())
    }
}

pub trait WithInclusionProof {
    fn with_inclusion_proof(&self, block: &Block) -> TransactionWithInclusionProof;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionWithInclusionProof {
    // Transaction and PMT for transaction (and coinbase) inclusion proof
    pub tx: (Transaction, InclusionProof),

    // Coinbase transaction and PMT for witness inclusion proof
    pub witness: Option<(Transaction, InclusionProof)>,
}

impl WithInclusionProof for Transaction {
    fn with_inclusion_proof(&self, block: &Block) -> TransactionWithInclusionProof {
        let (txids, wtxids): (Vec<_>, Vec<_>) = block
            .txdata
            .iter()
            .map(|tx| {
                (
                    tx.compute_txid(),
                    if tx.is_coinbase() {
                        Txid::all_zeros()
                    } else {
                        tx.compute_wtxid().to_txid()
                    },
                )
            })
            .unzip();

        let txid = self.compute_txid();
        let wtxid = self.compute_wtxid().to_txid();

        let (incl_txids, witness) = if txid == wtxid || self.is_coinbase() {
            // Non-Segwit
            (vec![txid], None)
        } else {
            // Segwit
            let coinbase_tx = block.txdata[0].clone();
            let coinbase_txid = coinbase_tx.compute_txid();
            (
                vec![coinbase_txid, txid],
                Some((
                    coinbase_tx,
                    InclusionProof(PartialMerkleTree::from_txids(
                        &wtxids,
                        &wtxids.iter().map(|&id| id == wtxid).collect::<Vec<_>>(),
                    )),
                )),
            )
        };

        TransactionWithInclusionProof {
            tx: (
                self.clone(),
                InclusionProof(PartialMerkleTree::from_txids(
                    &txids,
                    &txids
                        .iter()
                        .map(|id| incl_txids.contains(id))
                        .collect::<Vec<_>>(),
                )),
            ),
            witness,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeProofInput {
    /// headers after last verified l1 block
    pub headers: Vec<Header>,

    /// Deposit Txid
    pub deposit_txid: [u8; 32],

    /// Block height of checkpoint tx, and it's inclusion proof
    pub checkpoint: (u32, TransactionWithInclusionProof),

    /// Block height of withdrawal_fulfillment tx, and it's inclusion proof
    pub withdrawal_fulfillment: (u32, TransactionWithInclusionProof),
}

pub fn checkpoint_last_verified_l1_height(
    tx: &Transaction,
    rollup_params: &RollupParams,
) -> Option<u64> {
    let filter_config =
        TxFilterConfig::derive_from(rollup_params).expect("rollup params must be valid");
    if let Some(script) = tx.input[0].witness.taproot_leaf_script() {
        let script = script.script.to_bytes();
        if let Ok(inscription) = parse_envelope_payloads(&script.into(), &filter_config) {
            if inscription.is_empty() {
                return None;
            }
            if let Ok(signed_checkpoint) =
                borsh::from_slice::<SignedCheckpoint>(inscription[0].data())
            {
                let checkpoint: Checkpoint = signed_checkpoint.into();
                return Some(checkpoint.batch_info().epoch());
            }
        }
    }
    None
}
