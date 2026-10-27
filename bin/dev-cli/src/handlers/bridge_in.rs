//! Bridge-in handler using SPS-50 metadata format.

use std::{str::FromStr, time::Duration};

use algebra::retry::{retry_with, RetryAction, Strategy};
use alloy::primitives::Address as EvmAddress;
use anyhow::{anyhow, bail, Result};
use bitcoin::{hex::DisplayHex, Address};
use jsonrpsee::http_client::HttpClient;
use secp256k1::{Keypair, Parity, XOnlyPublicKey};
use strata_asm_proto_bridge_txs::deposit_request::{
    create_deposit_request_locking_script, DrtHeaderAux,
};
use strata_bridge_common::params::Params;
use strata_bridge_primitives::scripts::general::get_aggregated_pubkey;
use strata_bridge_rpc::{
    traits::StrataBridgeMonitoringApiClient,
    types::{RpcCovenantAdmission, RpcCurrentCovenant},
};
use strata_bridge_tx_graph::transactions::deposit::DepositTx;
use strata_codec::VarVec;
use strata_l1_txfmt::{MagicBytes, ParseConfig};
use strata_ol_bridge_types::DepositDescriptor;
use strata_ol_identifiers::{AccountSerial, SubjectIdBytes};
use tracing::{info, warn};

use crate::{
    cli::BridgeInArgs,
    handlers::{
        rpc,
        wallet::{self, PsbtWallet},
    },
};

pub(crate) async fn handle_bridge_in(args: BridgeInArgs) -> Result<()> {
    let BridgeInArgs {
        btc_args,
        ee_address,
        params,
        bridge_node_url,
        unchecked,
    } = args;
    let rpc_client = rpc::get_btc_client(&btc_args.url, btc_args.user, btc_args.pass)?;
    let params = Params::from_path(params)?;

    let psbt_wallet = wallet::BitcoinRpcWallet::new(rpc_client);

    let aggregate_key = match (bridge_node_url, unchecked) {
        (None, true) => {
            let aggregate_key = params_aggregate_key(&params);
            warn!(%aggregate_key, "not checking that the params' covenant is current and ready");
            aggregate_key
        }
        (Some(bridge_node_url), false) => current_ready_aggregate_key(&bridge_node_url).await?,
        _ => bail!("exactly one of --bridge-node-url and --unchecked is required"),
    };

    info!(action = "Initiating bridge-in", %ee_address);

    let ee_address = EvmAddress::from_str(&ee_address)?;
    let recovery_pubkey = get_recovery_pubkey();

    let metadata =
        build_sps50_metadata(params.protocol.magic_bytes, &ee_address, &recovery_pubkey)?;

    let locking_script = create_deposit_request_locking_script(
        &recovery_pubkey.serialize(),
        aggregate_key,
        params.protocol.recovery_delay,
    );
    let drt_address = Address::from_script(&locking_script, params.network)?;

    // The DRT must include `deposit_amount + deposit_fee` so the bridge's deposit
    // transaction can pay its own fee.
    let drt_amount = DepositTx::drt_required(params.protocol.deposit_amount);
    let psbt = psbt_wallet.create_drt_psbt(drt_amount, &drt_address, metadata, &params.network)?;
    psbt_wallet.sign_and_broadcast_psbt(&psbt)?;

    Ok(())
}

/// Returns the aggregate key of every operator in the params file.
fn params_aggregate_key(params: &Params) -> XOnlyPublicKey {
    get_aggregated_pubkey(
        params
            .keys
            .operators
            .iter()
            .map(|operator| operator.covenant_key().public_key(Parity::Even)),
    )
}

/// How many times to ask again while the bridge node's view of the covenant is still settling.
const UNSETTLED_RETRIES: usize = 5;

/// How long to wait before asking again; functional-test nodes refresh their view every second.
const UNSETTLED_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Why the bridge node's current covenant cannot be used for a deposit request.
#[derive(Debug)]
enum Refusal {
    /// Readiness is still settling, so asking again may succeed.
    Unsettled(anyhow::Error),
    /// Asking again will not help.
    Final(anyhow::Error),
}

/// Returns the aggregate key of the covenant that the bridge node reports as current, refusing
/// unless that covenant admits deposits.
async fn current_ready_aggregate_key(bridge_node_url: &str) -> Result<XOnlyPublicKey> {
    let client = rpc::get_bridge_client(bridge_node_url)?;
    let strategy = Strategy::new(|refusal, _attempt| match refusal {
        Refusal::Unsettled(err) => {
            warn!(%err, "asking again");
            RetryAction::Retry(UNSETTLED_RETRY_DELAY)
        }
        Refusal::Final(_) => RetryAction::Stop,
    })
    .with_max_retries(UNSETTLED_RETRIES);
    let bridge_node_url = bridge_node_url.to_owned();
    retry_with(strategy, move || {
        ready_aggregate_key(client.clone(), bridge_node_url.clone())
    })
    .await
    .map_err(|(Refusal::Unsettled(err) | Refusal::Final(err))| err)
}

/// Asks the bridge node once for its current covenant and returns its aggregate key if the
/// covenant admits deposits.
async fn ready_aggregate_key(
    client: HttpClient,
    bridge_node_url: String,
) -> Result<XOnlyPublicKey, Refusal> {
    let RpcCurrentCovenant {
        processed_height,
        covenant,
        members,
        admission,
    } = client
        .get_current_covenant()
        .await
        .map_err(|e| {
            Refusal::Final(anyhow!(
                "failed to fetch the current covenant from {bridge_node_url}: {e}"
            ))
        })?
        .ok_or_else(|| {
            Refusal::Final(anyhow!(
                "bridge node {bridge_node_url} has no current covenant"
            ))
        })?;

    match admission {
        RpcCovenantAdmission::Ready { aggregate_pubkey } => {
            info!(
                %covenant,
                %aggregate_pubkey,
                ?members,
                processed_height,
                "building the deposit request for the bridge node's current covenant"
            );
            Ok(aggregate_pubkey)
        }
        RpcCovenantAdmission::SafeHarbour => Err(Refusal::Final(anyhow!(
            "covenant {covenant} does not admit deposits after block {processed_height}: safe \
             harbour is active"
        ))),
        RpcCovenantAdmission::DepositCapReached => Err(Refusal::Final(anyhow!(
            "covenant {covenant} does not admit deposits after block {processed_height}: the \
             bridge node's deposit cap is full"
        ))),
        RpcCovenantAdmission::Unready { shortfalls } => {
            let shortfalls: Vec<_> = shortfalls
                .iter()
                .map(|shortfall| {
                    format!("operator {} {:?}", shortfall.operator_idx, shortfall.reason)
                })
                .collect();
            Err(Refusal::Final(anyhow!(
                "covenant {covenant} is not ready after block {processed_height}: {}",
                shortfalls.join(", ")
            )))
        }
        RpcCovenantAdmission::Unsettled { operators } => Err(Refusal::Unsettled(anyhow!(
            "readiness of covenant {covenant} after block {processed_height} is still settling \
             for operators {operators:?}"
        ))),
    }
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
    let destination = VarVec::from_vec(deposit_descriptor.encode_to_vec())
        .expect("descriptor length (max 36 bytes) is always within VARINT_MAX bound");

    let header_aux = DrtHeaderAux::new(recovery_pubkey.serialize(), destination)
        .expect("header aux creation must succeed");

    let tag_data = header_aux.build_tag_data();
    info!(tag_data=%tag_data.aux_data().to_lower_hex_string(), "built SPS-50 aux data for DRT");

    let config = ParseConfig::new(magic_bytes);
    let encoded = config.encode_tag_buf(&tag_data.as_ref())?;
    info!(encoded=%encoded.to_lower_hex_string(), "encoded SPS-50 metadata for OP_RETURN");

    Ok(encoded)
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
