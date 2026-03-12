use anyhow::{Context, Result};
use bitcoin::{
    hashes::Hash,
    locktime::absolute::LockTime,
    secp256k1::{Keypair, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Witness,
};
use bitcoincore_rpc::{Client, RpcApi};
use secp256k1::{rand::rngs::OsRng, Message};
use strata_l1_envelope_fmt::builder::EnvelopeScriptBuilder;
use strata_l1_txfmt::{MagicBytes, ParseConfig, SubprotocolId, TagDataRef, TxType};
use tracing::info;

use super::constants::{ENVELOPE_CHANGE_SATS, ENVELOPE_FEE_SATS};

/// Build and broadcast an SPS-50 taproot envelope transaction embedding arbitrary payload.
pub(crate) fn build_and_broadcast_envelope_tx(
    client: &Client,
    magic: MagicBytes,
    subprotocol_id: SubprotocolId,
    tx_type: TxType,
    payload: &[u8],
    network: Network,
) -> Result<bitcoin::Txid> {
    let secp = Secp256k1::new();

    // Generate ephemeral keypair
    let keypair = Keypair::new(&secp, &mut OsRng);
    let (internal_key, _) = XOnlyPublicKey::from_keypair(&keypair);

    // Build reveal script with embedded payload
    let reveal_script = EnvelopeScriptBuilder::with_pubkey(&internal_key.serialize())
        .context("failed to create envelope builder")?
        .add_envelope(payload)
        .context("failed to add envelope payload")?
        .build_without_min_check()
        .context("failed to build reveal script")?;

    // Build taproot with the reveal script as a leaf
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .context("failed to add reveal script leaf")?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow::anyhow!("failed to finalize taproot: {:?}", e))?;

    let taproot_address = Address::p2tr(
        &secp,
        internal_key,
        taproot_spend_info.merkle_root(),
        network,
    );

    // === Commit: fund the taproot address ===
    let fee = Amount::from_sat(ENVELOPE_FEE_SATS);
    let change = Amount::from_sat(ENVELOPE_CHANGE_SATS);
    let funding_amount = fee + change;

    let commit_txid = client
        .send_to_address(
            &taproot_address,
            funding_amount,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .context("failed to fund taproot address")?;

    info!(event = "commit tx broadcast", %commit_txid);

    // Find the vout in the commit tx
    let commit_tx = client
        .get_raw_transaction(&commit_txid, None)
        .context("failed to get commit tx")?;

    let commit_vout = commit_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == taproot_address.script_pubkey())
        .context("commit output not found")? as u32;

    // === Reveal: spend via script path ===
    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .context("failed to create control block")?;

    // Build SPS-50 compliant OP_RETURN tag
    let tag_data = TagDataRef::new(subprotocol_id, tx_type, &[])
        .map_err(|e| anyhow::anyhow!("failed to create tag data: {:?}", e))?;
    let parse_config = ParseConfig::new(magic);
    let op_return_script = parse_config
        .encode_script_buf(&tag_data)
        .map_err(|e| anyhow::anyhow!("failed to encode OP_RETURN script: {:?}", e))?;

    let op_return_output = TxOut {
        value: Amount::ZERO,
        script_pubkey: op_return_script,
    };

    let change_address = client
        .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
        .context("failed to get change address")?
        .assume_checked();

    let change_output = TxOut {
        value: funding_amount - fee,
        script_pubkey: change_address.script_pubkey(),
    };

    // Build unsigned reveal tx
    let tx_input = TxIn {
        previous_output: OutPoint::new(commit_txid, commit_vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let mut reveal_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_input],
        output: vec![op_return_output, change_output],
    };

    // Sign the reveal transaction (script-path spend)
    let prevouts = vec![commit_tx.output[commit_vout as usize].clone()];
    let mut sighash_cache = SighashCache::new(&reveal_tx);
    let leaf_hash = TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .context("failed to compute sighash")?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr(&msg, &keypair);

    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    witness.push(reveal_script.as_bytes());
    witness.push(control_block.serialize());
    reveal_tx.input[0].witness = witness;

    // Broadcast reveal tx
    let reveal_txid = client
        .send_raw_transaction(&reveal_tx)
        .context("failed to broadcast reveal tx")?;

    info!(event = "reveal tx broadcast", %reveal_txid);

    Ok(reveal_txid)
}
