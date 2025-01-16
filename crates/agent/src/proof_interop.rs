use bitcoin::{
    block::Header,
    blockdata::block::Block,
    consensus::encode::{deserialize_hex, serialize_hex},
    hashes::Hash,
    merkle_tree::PartialMerkleTree,
    Transaction, Txid, Wtxid,
};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use strata_bridge_btcio::traits::Reader;
use strata_l1tx::envelope::parser::parse_envelope_data;
use strata_state::{
    batch::{BatchCheckpoint, SignedBatchCheckpoint},
    l1::{
        get_difficulty_adjustment_height, BtcParams, HeaderVerificationState, L1BlockId,
        TimestampStore,
    },
};
use tracing::trace;

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

    /// superblock period start ts
    pub superblock_period_start_ts: u32,
}

/// Gets the [`HeaderVerificationState`] for the particular block
pub async fn get_verification_state(
    client: &impl Reader,
    height: u64,
    params: &BtcParams,
) -> anyhow::Result<HeaderVerificationState> {
    // Get the difficulty adjustment block just before `block_height`
    let h1 = get_difficulty_adjustment_height(0, height as u32, params);
    let b1 = client.get_block_at(h1).await?;

    // Consider the block before `block_height` to be the last verified block
    let vh = height - 1; // verified_height
    let vb = client.get_block_at(vh as u32).await?; // verified_block

    const N: usize = 11;
    let mut timestamps: [u32; N] = [0u32; N];

    // Fetch the previous timestamps of block from `vh`
    // This fetches timestamps of `vh-10`,`vh-9`, ... `vh-1`, `vh`
    for i in 0..N {
        if vh >= i as u64 {
            let height_to_fetch = vh - i as u64;
            let h = client.get_block_at(height_to_fetch as u32).await?;
            timestamps[N - 1 - i] = h.header.time;
        } else {
            // No more blocks to fetch; the rest remain zero
            timestamps[N - 1 - i] = 0;
        }
    }

    // Calculate the 'head' index for the ring buffer based on the current block height.
    // The 'head' represents the position in the buffer where the next timestamp will be inserted.
    let head = height as usize % N;
    let last_11_blocks_timestamps = TimestampStore::new_with_head(timestamps, head);

    let l1_blkid: L1BlockId = vb.header.block_hash().into();

    let header_vs = HeaderVerificationState {
        last_verified_block_num: vh as u32,
        last_verified_block_hash: l1_blkid,
        next_block_target: vb.header.target().to_compact_lossy().to_consensus(),
        interval_start_timestamp: b1.header.time,
        total_accumulated_pow: 0u128,
        last_11_blocks_timestamps,
    };
    trace!(%height, ?header_vs, "HeaderVerificationState");

    Ok(header_vs)
}

pub fn checkpoint_last_verified_l1_height(tx: &Transaction) -> Option<u32> {
    if let Some(script) = tx.input[0].witness.tapscript() {
        let script = script.to_bytes();
        if let Ok(inscription) = parse_envelope_data(&script.into(), "alpenstrata") {
            if let Ok(signed_batch_checkpoint) =
                borsh::from_slice::<SignedBatchCheckpoint>(inscription.data())
            {
                let batch_checkpoint: BatchCheckpoint = signed_batch_checkpoint.into();
                return Some(batch_checkpoint.batch_info().l1_range.1 as u32);
            }
        }
    }
    None
}
