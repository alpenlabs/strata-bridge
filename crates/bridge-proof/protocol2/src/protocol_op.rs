use anyhow::{anyhow, Result};
use bitcoin::Transaction;
use strata_primitives::block_credential::CredRule;
use strata_state::batch::{BatchCheckpoint, SignedBatchCheckpoint};
use strata_tx_parser::inscription::parse_inscription_data;

// TODO: maybe read this from params or somewhere.
pub const ROLLUP_NAME: &str = "alpenstrata";

pub fn extract_checkpoint(tx: &Transaction, cred_rule: &CredRule) -> Result<BatchCheckpoint> {
    for inp in &tx.input {
        if let Some(scr) = inp.witness.tapscript() {
            if let Ok(data) = parse_inscription_data(&scr.into(), ROLLUP_NAME) {
                if let Ok(checkpoint) =
                    borsh::from_slice::<SignedBatchCheckpoint>(data.batch_data())
                {
                    if let CredRule::SchnorrKey(seq_pubkey) = cred_rule {
                        assert!(
                            checkpoint.verify_sig(seq_pubkey),
                            "invalid signature for checkpoint"
                        );
                    }
                    return Ok(checkpoint.into());
                }
            }
        }
    }

    Err(anyhow!("No valid SignedBatchCheckpoint found"))
}
