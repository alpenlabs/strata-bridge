//! Reclaims a deposit request output through the depositor's takeback tapscript.
//!
//! Rebuilds the DRT taproot exactly as `bridge-in` did (N-of-N internal key, single
//! `and_v(v:pk(recovery),older(recovery_delay))` leaf) and refuses to sign unless it matches the
//! on-chain output, so a wrong secret or params file fails before anything is broadcast.

use std::str::FromStr;

use anyhow::{ensure, Context, Result};
use bitcoin::{
    hashes::Hash,
    locktime::absolute::LockTime,
    secp256k1::{Keypair, Message, Parity, SecretKey, XOnlyPublicKey, SECP256K1},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut,
    Witness,
};
use bitcoincore_rpc::{json::AddressType, RpcApi};
use strata_bridge_common::params::Params;
use strata_bridge_primitives::scripts::general::{drt_take_back, get_aggregated_pubkey};
use tracing::info;

use crate::{cli::DrtTakebackArgs, handlers::rpc};

/// Index of the deposit request output in a DRT (output 0 is the SPS-50 OP_RETURN).
const DRT_OUTPUT_INDEX: u32 = 1;

/// Schnorr signature length with the default sighash type, used to size the fee.
const SCHNORR_SIG_LEN: usize = 64;

pub(crate) fn handle_drt_takeback(args: DrtTakebackArgs) -> Result<()> {
    let params = Params::from_path(&args.params)?;
    let client = rpc::get_btc_client(
        &args.btc_args.url,
        args.btc_args.user.clone(),
        args.btc_args.pass.clone(),
    )?;

    let secret = SecretKey::from_str(&args.recovery_secret).context("invalid recovery secret")?;
    let keypair = Keypair::from_secret_key(SECP256K1, &secret);
    let (recovery_pk, _) = keypair.x_only_public_key();
    let covenant_keys: Vec<XOnlyPublicKey> =
        params.keys.covenant.iter().map(|c| c.musig2).collect();
    let (takeback_script, spend_info) =
        drt_taproot(&covenant_keys, params.protocol.recovery_delay, recovery_pk);
    let expected_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    let drt = client
        .get_raw_transaction_info(&args.drt_txid, None)
        .context("failed to fetch DRT")?;
    let drt_out = drt
        .vout
        .get(DRT_OUTPUT_INDEX as usize)
        .context("DRT has no deposit request output")?;
    let drt_spk = drt_out.script_pub_key.script()?;
    ensure!(
        drt_spk == expected_spk,
        "DRT output {} does not match the takeback taproot derived from this secret and params",
        drt_spk.to_hex_string()
    );
    let confirmations = drt.confirmations.unwrap_or(0);
    let delay = u32::from(params.protocol.recovery_delay);
    ensure!(
        confirmations >= delay,
        "timelock not expired: {confirmations} confirmations, need {delay}"
    );

    let destination = match args.destination {
        Some(addr) => addr
            .require_network(params.network)
            .context("destination does not belong to the params network")?,
        None => client
            .get_new_address(None, Some(AddressType::Bech32m))
            .context("failed to get wallet address")?
            .require_network(params.network)
            .context("wallet address does not belong to the params network")?,
    };

    let prevout = TxOut {
        value: drt_out.value,
        script_pubkey: expected_spk,
    };
    let control_block = spend_info
        .control_block(&(takeback_script.clone(), LeafVersion::TapScript))
        .expect("takeback leaf is in the tree");
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(args.drt_txid, DRT_OUTPUT_INDEX),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(params.protocol.recovery_delay),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: destination.script_pubkey(),
        }],
    };

    // Size the fee with a placeholder witness of the final shape.
    tx.input[0].witness =
        takeback_witness(&[0u8; SCHNORR_SIG_LEN], &takeback_script, &control_block);
    let fee = Amount::from_sat(args.fee_rate * tx.vsize() as u64);
    tx.output[0].value = prevout
        .value
        .checked_sub(fee)
        .context("DRT output too small to cover the fee")?;

    let leaf_hash = TapLeafHash::from_script(&takeback_script, LeafVersion::TapScript);
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .context("failed to compute sighash")?;
    let sig = SECP256K1.sign_schnorr(&Message::from_digest(sighash.to_byte_array()), &keypair);
    tx.input[0].witness = takeback_witness(sig.as_ref(), &takeback_script, &control_block);

    let txid = client
        .send_raw_transaction(&tx)
        .context("failed to broadcast takeback tx")?;
    info!(event = "takeback tx broadcast", %txid, %destination, amount = %tx.output[0].value, %fee);
    println!("txid = {txid}");
    Ok(())
}

/// The DRT's takeback leaf and taproot, built the same way `bridge-in` builds the DRT address.
fn drt_taproot(
    covenant_keys: &[XOnlyPublicKey],
    recovery_delay: u16,
    recovery_pk: XOnlyPublicKey,
) -> (ScriptBuf, TaprootSpendInfo) {
    let takeback_script = drt_take_back(recovery_pk, recovery_delay);
    let n_of_n = get_aggregated_pubkey(covenant_keys.iter().map(|k| k.public_key(Parity::Even)));
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, takeback_script.clone())
        .expect("single leaf")
        .finalize(SECP256K1, n_of_n)
        .expect("complete taproot tree");
    (takeback_script, spend_info)
}

fn takeback_witness(
    sig: &[u8],
    script: &ScriptBuf,
    control_block: &bitcoin::taproot::ControlBlock,
) -> Witness {
    let mut witness = Witness::new();
    witness.push(sig);
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());
    witness
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Covenant musig2 keys and recovery delay of the opnet sweep-test deployment.
    const OPNET_COVENANT_KEYS: [&str; 3] = [
        "085aab0cd930db8cddf4ea08daf49b45ef28aefdd5b9591b87de3837ec54d1a6",
        "c2d030ea3d8fe77b8d736e919b7e1cb503061d2c3a90d1d2a99d8dc3976e9098",
        "f4cb09f5b997018c280ef9423d5effb01cc83505b4bf76e17f98e1c8c6547eec",
    ];
    const OPNET_RECOVERY_DELAY: u16 = 6;

    /// Two DRTs broadcast on the opnet signet on 2026-09-13: recovery key from the OP_RETURN aux
    /// and the scriptPubKey of output 1 as confirmed in block 15800.
    const OPNET_DRTS: [(&str, &str); 2] = [
        (
            "446ef01e65723b7314c2bcf9948261b627ea9a3fab44230866c356c8f6869310",
            "51207bbdf8fb97e08ae99e09ba7b2a8780da23c69156163f2dcfd7845b072a3b51d1",
        ),
        (
            "dd6a2d468f8985d5794ae7c7ee7630a7d847c3eb9d8c565a176939c540a25cf9",
            "51204b9d923f67c58c409bcf7a6e26b6508e0b4675e30607d5265e54a37c158ac432",
        ),
    ];

    /// The rebuilt taproot must reproduce the on-chain DRT output, otherwise the takeback spend
    /// would be signing against the wrong tree.
    #[test]
    fn drt_taproot_matches_onchain_opnet_drts() {
        let keys: Vec<XOnlyPublicKey> = OPNET_COVENANT_KEYS
            .iter()
            .map(|k| k.parse().unwrap())
            .collect();
        for (recovery_pk, expected_spk) in OPNET_DRTS {
            let (_, spend_info) =
                drt_taproot(&keys, OPNET_RECOVERY_DELAY, recovery_pk.parse().unwrap());
            let spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
            assert_eq!(spk.to_hex_string(), expected_spk);
        }
    }

    /// The leaf must be spendable through the tree the control block commits to.
    #[test]
    fn takeback_leaf_has_control_block() {
        let keys: Vec<XOnlyPublicKey> = OPNET_COVENANT_KEYS
            .iter()
            .map(|k| k.parse().unwrap())
            .collect();
        let (script, spend_info) = drt_taproot(
            &keys,
            OPNET_RECOVERY_DELAY,
            OPNET_DRTS[0].0.parse().unwrap(),
        );
        assert!(spend_info
            .control_block(&(script, LeafVersion::TapScript))
            .is_some());
    }
}
