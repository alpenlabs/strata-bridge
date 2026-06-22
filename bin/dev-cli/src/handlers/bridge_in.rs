//! Bridge-in handler using SPS-50 metadata format.

use std::str::FromStr;

use alloy::primitives::Address as EvmAddress;
use anyhow::{bail, Result};
use bitcoin::{hex::DisplayHex, taproot::TaprootBuilder, Address, Network, ScriptBuf};
use bitcoincore_rpc::RpcApi;
use miniscript::Miniscript;
use musig2::KeyAggContext;
use secp256k1::{Keypair, Parity, XOnlyPublicKey, SECP256K1};
use strata_asm_proto_bridge_v1_txs::deposit_request::DrtHeaderAux;
use strata_bridge_common::params::Params;
use strata_bridge_primitives::{
    operator_set_schedule::OperatorSetSchedule,
    types::{BitcoinBlockHeight, OperatorIdx},
};
use strata_bridge_tx_graph::transactions::deposit::DepositTx;
use strata_identifiers::{AccountSerial, SubjectIdBytes};
use strata_l1_txfmt::{MagicBytes, ParseConfig};
use strata_ol_bridge_types::DepositDescriptor;
use tracing::info;

use crate::{
    cli::BridgeInArgs,
    handlers::{
        rpc,
        wallet::{self, PsbtWallet},
    },
};

pub(crate) fn handle_bridge_in(args: BridgeInArgs) -> Result<()> {
    let BridgeInArgs {
        btc_args,
        ee_address,
        params,
    } = args;
    let rpc_client = rpc::get_btc_client(&btc_args.url, btc_args.user, btc_args.pass)?;
    let params = Params::from_path(params)?;
    let current_height = rpc_client.get_block_count()?;

    let psbt_wallet = wallet::BitcoinRpcWallet::new(rpc_client);

    info!(action = "Initiating bridge-in", %ee_address);

    let ee_address = EvmAddress::from_str(&ee_address)?;
    let recovery_pubkey = get_recovery_pubkey();

    let metadata =
        build_sps50_metadata(params.protocol.magic_bytes, &ee_address, &recovery_pubkey)?;

    let timelock_script =
        build_timelock_miniscript(params.protocol.recovery_delay, recovery_pubkey);

    let covenant_keys = active_covenant_keys(&params.keys.operators, current_height)?;
    let agg_key = KeyAggContext::new(
        covenant_keys
            .into_iter()
            .map(|k| k.public_key(Parity::Even)),
    )
    .expect("must be able to aggregate keys")
    .aggregated_pubkey();
    let taproot_address = generate_taproot_address(params.network, timelock_script, agg_key);

    // The DRT must include `deposit_amount + deposit_fee` so the bridge's deposit
    // transaction can pay its own fee.
    let drt_amount = DepositTx::drt_required(params.protocol.deposit_amount);
    let psbt =
        psbt_wallet.create_drt_psbt(drt_amount, &taproot_address, metadata, &params.network)?;
    psbt_wallet.sign_and_broadcast_psbt(&psbt)?;

    Ok(())
}

fn active_covenant_keys(
    operator_schedule: &OperatorSetSchedule,
    current_height: BitcoinBlockHeight,
) -> Result<Vec<XOnlyPublicKey>> {
    let active_operators = operator_schedule
        .active_at(current_height)
        .collect::<Vec<_>>();
    if active_operators.is_empty() {
        bail!("no operators are active at Bitcoin height {current_height}");
    }

    let active_operator_indices = active_operators
        .iter()
        .map(|operator| operator.index())
        .collect::<Vec<OperatorIdx>>();
    info!(
        current_height,
        ?active_operator_indices,
        active_operator_count = active_operator_indices.len(),
        "selected active operator set for bridge-in"
    );

    Ok(active_operators
        .into_iter()
        .map(|operator| operator.covenant_key())
        .collect())
}

/// Builds the SPS-50 OP_RETURN metadata for the deposit request transaction.
///
/// Format: `magic(4) + subprotocol(1) + tx_type(1) + recovery_pk(32) + destination(variable)`
fn build_sps50_metadata(
    magic_bytes: MagicBytes,
    ee_address: &EvmAddress,
    recovery_pubkey: &XOnlyPublicKey,
) -> Result<Vec<u8>> {
    let alpen_subject_bytes =
        SubjectIdBytes::try_new(ee_address.to_vec()).expect("must be valid subject bytes");

    // 0..127 are reserved, 128 is for `Alpen`
    let alpen_account_serial: AccountSerial = AccountSerial::reserved(127).incr();
    let deposit_descriptor = DepositDescriptor::new(alpen_account_serial, alpen_subject_bytes)
        .expect("AccountSerial for Alpen is always within valid range");
    let destination = deposit_descriptor.encode_to_varvec();

    let header_aux = DrtHeaderAux::new(recovery_pubkey.serialize(), destination)
        .expect("header aux creation must succeed");

    let tag_data = header_aux.build_tag_data();
    info!(tag_data=%tag_data.aux_data().to_lower_hex_string(), "built SPS-50 aux data for DRT");

    let config = ParseConfig::new(magic_bytes);
    let encoded = config.encode_tag_buf(&tag_data.as_ref())?;
    info!(encoded=%encoded.to_lower_hex_string(), "encoded SPS-50 metadata for OP_RETURN");

    Ok(encoded)
}

fn generate_taproot_address(
    network: Network,
    timelock_script: ScriptBuf,
    agg_pubkey: XOnlyPublicKey,
) -> Address {
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, timelock_script.clone())
        .expect("failed to add timelock script");

    let taproot_info = taproot_builder.finalize(SECP256K1, agg_pubkey).unwrap();
    let merkle_root = taproot_info.merkle_root();

    Address::p2tr(SECP256K1, agg_pubkey, merkle_root, network)
}

fn build_timelock_miniscript(
    refund_delay: u16,
    recovery_xonly_pubkey: XOnlyPublicKey,
) -> ScriptBuf {
    let script = format!("and_v(v:pk({recovery_xonly_pubkey}),older({refund_delay}))");
    let miniscript = Miniscript::<XOnlyPublicKey, miniscript::Tap>::from_str(&script).unwrap();
    miniscript.encode()
}

fn get_recovery_pubkey() -> XOnlyPublicKey {
    let keypair = Keypair::new(
        &bitcoin::secp256k1::Secp256k1::new(),
        &mut bitcoin::key::rand::thread_rng(),
    );
    let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    let secret_key = keypair.secret_bytes().to_lower_hex_string();

    info!(event = "generated random x-only pubkey for recovery", %secret_key, %xonly_pubkey);

    xonly_pubkey
}

#[cfg(test)]
mod tests {
    use bitcoin_bosd::Descriptor;
    use strata_bridge_primitives::{
        operator_set_schedule::ScheduledOperator, types::P2POperatorPubKey,
    };

    use super::*;

    const XONLY_KEY_1: &str = "b49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d";
    const XONLY_KEY_2: &str = "1e62d54af30569fd7269c14b6766f74d85ea00c911c4e1a423d4ba2ae4c34dc4";
    const P2P_KEY_1: &str = "0de7729dcbeb5069136ee4bff1c4f2fd822fe8fbc9b518df434d4f0c6312d8f5";
    const P2P_KEY_2: &str = "255ab0da6d468a22910a7cf54021763417c63c28bbafd4e2359daf103bb61e9d";

    #[test]
    fn active_covenant_keys_use_current_operator_set() {
        let schedule = operator_schedule();

        let keys = active_covenant_keys(&schedule, 150)
            .expect("height 150 should have one active operator");

        assert_eq!(
            keys,
            vec![xonly_key(XONLY_KEY_1)],
            "bridge-in should aggregate only operators active at the current Bitcoin height"
        );
    }

    #[test]
    fn active_covenant_keys_exclude_deactivated_operators_at_rotation_height() {
        let schedule = operator_schedule();

        let keys = active_covenant_keys(&schedule, 200)
            .expect("height 200 should have one active operator after rotation");

        assert_eq!(
            keys,
            vec![xonly_key(XONLY_KEY_2)],
            "bridge-in should stop aggregating an operator at its deactivation height"
        );
    }

    #[test]
    fn active_covenant_keys_fail_when_no_operator_is_active() {
        let schedule = operator_schedule();

        let err = active_covenant_keys(&schedule, 100)
            .expect_err("height 100 should be before every operator activation");

        assert!(
            err.to_string().contains("no operators are active"),
            "bridge-in should fail rather than build a DRT address with an empty operator set"
        );
    }

    fn operator_schedule() -> OperatorSetSchedule {
        OperatorSetSchedule::new(vec![
            scheduled_operator(0, XONLY_KEY_1, P2P_KEY_1, 101, Some(200)),
            scheduled_operator(1, XONLY_KEY_2, P2P_KEY_2, 200, None),
        ])
        .expect("test operator schedule should be valid")
    }

    fn scheduled_operator(
        index: OperatorIdx,
        covenant_key: &str,
        p2p_key: &str,
        activation_height: BitcoinBlockHeight,
        deactivation_height: Option<BitcoinBlockHeight>,
    ) -> ScheduledOperator {
        ScheduledOperator::new(
            index,
            xonly_key(covenant_key),
            P2POperatorPubKey::from(
                hex::decode(p2p_key).expect("test p2p key should be valid hex"),
            ),
            p2tr_descriptor(covenant_key),
            activation_height,
            deactivation_height,
        )
        .expect("test scheduled operator should be valid")
    }

    fn xonly_key(hex_key: &str) -> XOnlyPublicKey {
        let key_bytes = hex::decode(hex_key).expect("test x-only key should be valid hex");
        XOnlyPublicKey::from_slice(&key_bytes).expect("test x-only key should be valid")
    }

    fn p2tr_descriptor(xonly_hex: &str) -> Descriptor {
        let pk_bytes: [u8; 32] = hex::decode(xonly_hex)
            .expect("test descriptor key should be valid hex")
            .try_into()
            .expect("test descriptor key should be 32 bytes");
        Descriptor::new_p2tr(&pk_bytes).expect("test descriptor should be valid")
    }
}
