//! Signing of a CPFP child.

use bitcoin::{
    FeeRate, Psbt, ScriptBuf, TapSighashType, Transaction, TxOut, Witness,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash},
};
use btc_tracker::cpfp::CpfpStrategy;
use strata_bridge_primitives::cpfp::{ChildSigner, ChildWitness};

use super::{
    errors::{CpfpError, SignerError},
    ladder::CpfpContext,
};

/// Signs every input of the unsigned child `psbt` and extracts the transaction.
///
/// - A spend signed by the protocol key is one anchor input, signed by the signer of its witness
///   kind, plus wallet funding inputs.
/// - An owned spend has only operator-controlled inputs: the output of the parent and wallet
///   funding inputs.
///
/// The wallet signer goes first for the wallet inputs. An input it holds no key for goes through
/// `wallet_input_signer`. A sighash commits to no other witness, so the order does not matter.
pub(super) async fn sign_child(
    ctx: &CpfpContext,
    strategy: &CpfpStrategy,
    mut psbt: Psbt,
) -> Result<Transaction, CpfpError> {
    let spend = &strategy.spend;
    let prevouts = prevouts_of(&psbt).map_err(CpfpError::MalformedChild)?;
    let anchor_idx = (spend.signer() == ChildSigner::Protocol)
        .then(|| {
            psbt.unsigned_tx
                .input
                .iter()
                .position(|input| input.previous_output == spend.outpoint())
                .ok_or_else(|| {
                    CpfpError::MalformedChild("the child does not spend the anchor".to_string())
                })
        })
        .transpose()?;

    if let Some(anchor_idx) = anchor_idx {
        let witness = match spend.witness() {
            // Key-path: sign the tweaked output key, witness is the bare signature.
            ChildWitness::KeyPath => {
                let sighash = key_path_sighash(&psbt.unsigned_tx, anchor_idx, &prevouts)
                    .map_err(CpfpError::MalformedChild)?;
                let sig = (ctx.anchor_input_signer)(Message::from(sighash))
                    .await
                    .map_err(CpfpError::AnchorSigner)?;
                let mut witness = Witness::new();
                witness.push(sig.as_ref());
                witness
            }
            // Script-path: the sighash commits to the leaf, the signature is untweaked,
            // and the witness carries the leaf script and control block after it.
            ChildWitness::ScriptPath {
                leaf_script,
                control_block,
            } => {
                let sighash =
                    script_path_sighash(&psbt.unsigned_tx, anchor_idx, &prevouts, leaf_script)
                        .map_err(CpfpError::MalformedChild)?;
                let sig = (ctx.multi_anchor_signer)(Message::from(sighash))
                    .await
                    .map_err(CpfpError::AnchorSigner)?;
                let mut witness = Witness::new();
                witness.push(sig.as_ref());
                witness.push(leaf_script.to_bytes());
                witness.push(control_block.serialize());
                witness
            }
        };
        psbt.inputs[anchor_idx].final_script_witness = Some(witness);
    }

    let wallet_input_idxs: Vec<usize> = (0..psbt.inputs.len())
        .filter(|i| Some(*i) != anchor_idx)
        .collect();
    let signer_witnesses = ctx
        .wallet
        .sign_owned_inputs(&psbt.unsigned_tx, &wallet_input_idxs, &prevouts)
        .await
        .map_err(CpfpError::WalletSigner)?;
    if signer_witnesses.len() != wallet_input_idxs.len() {
        return Err(CpfpError::WalletSigner(SignerError(format!(
            "the wallet answered for {} of {} inputs",
            signer_witnesses.len(),
            wallet_input_idxs.len()
        ))));
    }
    for (idx, signer_witness) in wallet_input_idxs.into_iter().zip(signer_witnesses) {
        let witness = match signer_witness {
            Some(witness) => witness,
            None => {
                let sighash = key_path_sighash(&psbt.unsigned_tx, idx, &prevouts)
                    .map_err(CpfpError::MalformedChild)?;
                let sig = (ctx.wallet_input_signer)(Message::from(sighash))
                    .await
                    .map_err(CpfpError::WalletSigner)?;
                let mut witness = Witness::new();
                witness.push(sig.as_ref());
                witness
            }
        };
        psbt.inputs[idx].final_script_witness = Some(witness);
    }

    // `max_fee_rate` is the only limit on what a child pays. A child holds the fee of the whole
    // package in its own few vbytes, so a per-transaction limit refuses a package under the cap.
    psbt.extract_tx_with_fee_rate_limit(FeeRate::MAX)
        .map_err(|e| CpfpError::MalformedChild(format!("{e:?}")))
}

/// The output that each input of `psbt` spends, in input order.
///
/// A missing `witness_utxo` is an error and not a panic: `psbt` crosses the [`CpfpWallet`]
/// boundary, so a malformed one is a failed bump that the next trigger retries, not a bug in this
/// crate.
fn prevouts_of(psbt: &Psbt) -> Result<Vec<TxOut>, String> {
    psbt.inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| format!("PSBT input {i}: witness_utxo not populated"))
        })
        .collect()
}

/// Computes the BIP-341 **script-path** sighash for one input of a child.
///
/// Differs from [`key_path_sighash`] in that the message commits to the specific leaf being
/// satisfied (via its [`TapLeafHash`]), so a signature made for one leaf cannot be replayed
/// against another. Used for multi-anchor outputs, whose leaves are
/// `<watchtower_pubkey> OP_CHECKSIG`.
fn script_path_sighash(
    tx: &Transaction,
    input_idx: usize,
    prevouts: &[TxOut],
    leaf_script: &ScriptBuf,
) -> Result<bitcoin::TapSighash, String> {
    let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);
    SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            input_idx,
            &Prevouts::All(prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| format!("script-path sighash compute (input {input_idx}): {e:?}"))
}

/// Computes the BIP-341 key-path Taproot sighash for one input of a child.
///
/// Uses [`TapSighashType::Default`] (sighash byte omitted from the witness; signature is the
/// bare 64-byte Schnorr signature).
fn key_path_sighash(
    tx: &Transaction,
    input_idx: usize,
    prevouts: &[TxOut],
) -> Result<bitcoin::TapSighash, String> {
    SighashCache::new(tx)
        .taproot_key_spend_signature_hash(
            input_idx,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| format!("sighash compute (input {input_idx}): {e:?}"))
}
