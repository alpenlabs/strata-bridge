//! Startup consistency checks.
//!
//! The checks over local config ([`verify_timelock_ordering`], [`check_fee_config`]) always run.
//! The other checks do not run in dev mode.
use std::fmt::Debug;

use algebra::retry::{Strategy, retry_with};
use anyhow::{Context, Result, anyhow, bail, ensure};
use bitcoin::{Address, Amount, FeeRate, Script, secp256k1::SECP256K1};
use bitcoin_bosd::Descriptor;
use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use jsonrpsee::http_client::HttpClient;
use mosaic_rpc_api::MosaicRpcClient;
use mosaic_rpc_types::RpcCircuitInfoEntry;
use operator_wallet::{OperatorWallet, REPLACEMENT_INCREMENT_SAT_PER_VB, SqliteStore};
use secp256k1::XOnlyPublicKey;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use serde::Deserialize;
use strata_asm_params::AsmParams;
use strata_asm_rpc::traits::AsmControlApiClient;
use strata_bridge_asm_events::config::AsmRpcConfig;
use strata_bridge_common::params::Params;
use strata_bridge_counterproof::BridgeCounterproofHost;
use strata_bridge_exec::fees::FeeSourceConfig;
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_proof::BridgeProofHost;
use strata_predicate::PredicateKey;
use tokio::time;
use tracing::warn;

use crate::config::{Config, MosaicConfig};

/// Oldest Bitcoin Core the bridge runs against, in `getnetworkinfo.version` form. The RPC client
/// parses v30 response shapes, and v30 raised the `OP_RETURN` size that the bridge proof needs.
/// TRUC and package relay, which the CPFP path depends on, date from v28.
const MIN_CORE_VERSION: u32 = 300_000;

/// The replacement increment of the child fee planner, as sat per kvB. Core rejects a replacement
/// that pays less than its own `incrementalfee`, so a node above this value refuses small bumps.
/// Those rejections read as a lost anchor race and log at debug only.
const ASSUMED_INCREMENTAL_FEE: Amount = Amount::from_sat(REPLACEMENT_INCREMENT_SAT_PER_VB * 1_000);

/// Required `maxdatacarriersize`: Core v30's default. The bridge proof is one OP_RETURN with no
/// size bound in the protocol, so the check asks for the default and not for a guessed proof size.
const MIN_DATA_CARRIER_BYTES: u64 = 100_000;

/// The fields of `getnetworkinfo` that the bridge depends on.
#[derive(Debug, Deserialize)]
struct NodeNetworkInfo {
    version: u32,
    /// Core reports this in BTC per kvB. It is held here as the amount per kvB.
    #[serde(rename = "incrementalfee", with = "bitcoin::amount::serde::as_btc")]
    incremental_fee: Amount,
}

/// The field of `getindexinfo` that the bridge depends on. Core lists an index only if it is on.
#[derive(Debug, Deserialize)]
struct NodeIndexInfo {
    txindex: Option<NodeIndexStatus>,
}

#[derive(Debug, Deserialize)]
struct NodeIndexStatus {
    synced: bool,
}

/// Returns the recovery note of a covenant payout descriptor that pays another script than the
/// wallet's own, or `None` when both pay the same script. The note names the secret-service general
/// key only when the covenant descriptor is the tap-tweaked P2TR of that key.
fn check_payout_descriptor(
    covenant: &Descriptor,
    wallet: &Descriptor,
    general_key_script: &Script,
) -> Option<&'static str> {
    let covenant_script = covenant.to_script();
    if covenant_script == wallet.to_script() {
        return None;
    }
    Some(if covenant_script == *general_key_script {
        "those outputs stay recoverable through the secret-service general key"
    } else {
        "those outputs are spendable only with the key behind the params descriptor"
    })
}

/// Checks the loaded wallet against params.
///
/// A covenant payout descriptor that differs from the wallet's own only warns. An operator may
/// register any descriptor it controls; this node then neither tracks nor bumps the presigned-graph
/// payouts to it, and the operator bumps them out of band.
pub(in crate::mode) async fn verify_wallet(
    params: &Params,
    s2_client: &SecretServiceClient,
    pov_idx: OperatorIdx,
    wallet: &OperatorWallet<SqliteStore>,
) -> Result<()> {
    let general_pubkey = s2_client
        .general_wallet_signer()
        .pubkey()
        .await
        .map_err(|e| anyhow!("failed to fetch operator general wallet pubkey from s2: {e:?}"))?;
    let own_covenant = params
        .keys
        .operators
        .get(pov_idx)
        .ok_or_else(|| anyhow!("operator {pov_idx:?} is not in the operator table"))?;

    let wallet_descriptor = wallet
        .descriptor()
        .map_err(|e| anyhow!("the general wallet script is not a payout descriptor: {e}"))?;
    let general_key_script =
        Address::p2tr(SECP256K1, general_pubkey, None, params.network).script_pubkey();
    let recovery = check_payout_descriptor(
        own_covenant.payout_descriptor(),
        &wallet_descriptor,
        &general_key_script,
    );
    if let Some(recovery) = recovery {
        warn!(
            covenant_descriptor = %own_covenant.payout_descriptor(),
            %wallet_descriptor,
            "the covenant payout descriptor pays another script than the general wallet; this node \
             cannot bump presigned-graph payouts, nor broadcast one that needs a child to relay; \
             {recovery}"
        );
    }
    Ok(())
}

/// Checks the connected node against what the bridge's transactions depend on.
///
/// A node below Core v30, a data-carrier limit below the v30 default, or a transaction index that
/// is missing or still building aborts startup. An incremental relay fee above the replacement
/// increment of the child planner only warns: the node then refuses the smallest bumps, and larger
/// ones still relay.
pub(in crate::mode) async fn verify_bitcoin_node(client: &BitcoinClient) -> Result<()> {
    let network = client
        .call_raw("getnetworkinfo", &[])
        .await
        .map_err(|e| anyhow!("could not read getnetworkinfo from the bitcoin node: {e:?}"))?;
    check_core_version(&network)?;
    if let Err(finding) = check_incremental_fee(&network) {
        warn!(%finding, "bitcoin node policy differs from what the bridge assumes");
    }
    let mempool = client
        .get_mempool_info()
        .await
        .map_err(|e| anyhow!("could not read getmempoolinfo from the bitcoin node: {e:?}"))?;
    check_data_carrier_size(mempool.max_data_carrier_size)?;
    let indexes = client
        .call_raw("getindexinfo", &[])
        .await
        .map_err(|e| anyhow!("could not read getindexinfo from the bitcoin node: {e:?}"))?;
    check_index_info(&indexes)
}

/// Checks the release first, because an older node omits fields that the later reads need.
fn check_core_version(network: &NodeNetworkInfo) -> Result<()> {
    ensure!(
        network.version >= MIN_CORE_VERSION,
        "bitcoin node version {} is below the required {MIN_CORE_VERSION} (Core v30)",
        network.version
    );
    Ok(())
}

fn check_incremental_fee(network: &NodeNetworkInfo) -> Result<()> {
    ensure!(
        network.incremental_fee <= ASSUMED_INCREMENTAL_FEE,
        "bitcoin node incrementalfee {} per kvB exceeds the {} per kvB that the CPFP replacement \
         fee assumes; lower -incrementalrelayfee",
        network.incremental_fee,
        ASSUMED_INCREMENTAL_FEE
    );
    Ok(())
}

fn check_data_carrier_size(max_data_carrier_size: Option<u64>) -> Result<()> {
    let size = max_data_carrier_size
        .ok_or_else(|| anyhow!("bitcoin node does not report maxdatacarriersize"))?;
    ensure!(
        size >= MIN_DATA_CARRIER_BYTES,
        "bitcoin node maxdatacarriersize {size} is below the {MIN_DATA_CARRIER_BYTES} bytes that \
         the bridge requires for a proof; raise -datacarriersize",
    );
    Ok(())
}

fn check_index_info(indexes: &NodeIndexInfo) -> Result<()> {
    match &indexes.txindex {
        None => bail!(
            "bitcoin node has no transaction index, which CPFP parent fee lookups need; set \
             txindex=1"
        ),
        Some(status) if status.synced => Ok(()),
        Some(_) => bail!(
            "bitcoin node's transaction index is still building, and CPFP parent fee lookups \
             fail until it syncs; restart once it has synced"
        ),
    }
}

/// Runs the consistency checks against ASM and Mosaic; a failure aborts node startup.
pub(in crate::mode) async fn verify_external_components(
    params: &Params,
    config: &Config,
    asm_rpc_client: &HttpClient,
    mosaic_rpc_client: &HttpClient,
    counterproof_host: &BridgeCounterproofHost,
) -> Result<()> {
    let asm_params = fetch_asm_params(asm_rpc_client, &config.asm_rpc)
        .await
        .context("fetching ASM params for startup consistency check")?;
    verify_asm_params(params, config, &asm_params).context("bridge/ASM params mismatch")?;

    let circuit_defs = fetch_mosaic_circuit_defs(mosaic_rpc_client, &config.mosaic)
        .await
        .context("fetching Mosaic circuit definitions for startup consistency check")?;
    verify_mosaic_vkey(counterproof_host.vkey_hash(), &circuit_defs)
        .context("bridge/Mosaic counterproof vkey mismatch")?;
    Ok(())
}

/// The params' timelocks satisfy the orderings the game graph relies on, unless the config opts
/// out.
pub(in crate::mode) fn verify_timelock_ordering(params: &Params, config: &Config) -> Result<()> {
    if config.allow_unsafe_timelocks {
        warn!("skipping timelock ordering checks");
        return Ok(());
    }

    params
        .protocol
        .validate_timelock_ordering()
        .context("unsafe params timelocks")
}

/// The fee limits of this node, checked against each other.
#[derive(Debug)]
pub(in crate::mode) struct FeeLimits {
    /// The true maximum rate of every transaction.
    pub(in crate::mode) max_fee_rate: FeeRate,
    /// The lowest package rate that the CPFP ladder targets.
    pub(in crate::mode) min_package_fee_rate: FeeRate,
}

/// Checks the fee config and returns the fee limits. A package floor above the cap, or a fixed
/// source rate above the cap, warns here once: the cap wins over both, and a node with such a
/// config starts and bumps at the cap. The duties refuse a fixed rate above the cap.
///
/// A zero bump interval panics `tokio::time::interval` inside the tx driver's task, and a bad
/// fee source config otherwise surfaces only after every service has started.
pub(in crate::mode) fn check_fee_config(config: &Config) -> Result<FeeLimits> {
    ensure!(
        !config.cpfp_bump_check_interval.is_zero(),
        "cpfp_bump_check_interval must not be zero"
    );
    config
        .fee_source
        .validate()
        .context("invalid fee_source config")?;
    let max_fee_rate = FeeRate::from_sat_per_vb(config.max_fee_rate).ok_or_else(|| {
        anyhow!(
            "max_fee_rate = {} sat/vB is not a valid fee rate",
            config.max_fee_rate
        )
    })?;
    let min_package_fee_rate = FeeRate::from_sat_per_vb(config.cpfp_min_package_fee_rate)
        .ok_or_else(|| {
            anyhow!(
                "cpfp_min_package_fee_rate = {} sat/vB is not a valid fee rate",
                config.cpfp_min_package_fee_rate
            )
        })?;
    if min_package_fee_rate > max_fee_rate {
        warn!(
            cpfp_min_package_fee_rate = config.cpfp_min_package_fee_rate,
            max_fee_rate = config.max_fee_rate,
            "cpfp_min_package_fee_rate exceeds max_fee_rate; every CPFP bump prices at the cap"
        );
    }
    let fixed_above_cap = match config.fee_source {
        FeeSourceConfig::Fixed { fee_rate } if fee_rate > config.max_fee_rate => Some(fee_rate),
        _ => None,
    };
    if let Some(fee_rate) = fixed_above_cap {
        warn!(
            fee_rate,
            max_fee_rate = config.max_fee_rate,
            "fee_source fixed rate exceeds max_fee_rate; every wallet-funded duty refuses"
        );
    }
    Ok(FeeLimits {
        max_fee_rate,
        min_package_fee_rate,
    })
}

async fn fetch_asm_params(client: &HttpClient, config: &AsmRpcConfig) -> Result<AsmParams> {
    let timeout = config.request_timeout;
    let client = client.clone();
    retry_with(config.retry_strategy(), move || {
        let client = client.clone();
        async move {
            match time::timeout(timeout, client.get_params()).await {
                Ok(Ok(params)) => Ok(params),
                Ok(Err(err)) => Err(anyhow::Error::from(err)),
                Err(_) => Err(anyhow!("request timed out after {timeout:?}")),
            }
            .map_err(|err| {
                warn!(%err, "failed to fetch ASM params");
                err
            })
        }
    })
    .await
}

async fn fetch_mosaic_circuit_defs(
    client: &HttpClient,
    config: &MosaicConfig,
) -> Result<Vec<RpcCircuitInfoEntry>> {
    let client = client.clone();
    let retry_strategy =
        Strategy::fixed_delay(config.retry_delay).with_max_retries(config.max_retries);
    retry_with(retry_strategy, move || {
        let client = client.clone();
        async move {
            client
                .get_circuit_defs()
                .await
                .map_err(anyhow::Error::from)
                .map_err(|err| {
                    warn!(%err, "failed to fetch Mosaic circuit definitions");
                    err
                })
        }
    })
    .await
}

/// Each proof host's loaded guest ELF matches its corresponding verification predicate.
pub(in crate::mode) fn verify_predicates(
    params: &Params,
    bridge_proof_host: &BridgeProofHost,
    counterproof_host: &BridgeCounterproofHost,
) -> Result<()> {
    ensure_predicate_match(
        "bridge-proof",
        bridge_proof_host.sp1_predicate()?,
        &params.protocol.bridge_proof_predicate,
    )?;
    ensure_predicate_match(
        "bridge-counterproof",
        counterproof_host.sp1_predicate()?,
        &params.protocol.counterproof_predicate,
    )
}

/// The bridge params and local fulfillment window are compatible with the ASM instance.
fn verify_asm_params(params: &Params, config: &Config, asm: &AsmParams) -> Result<()> {
    let Some(bridge) = asm.bridge_config() else {
        anyhow::bail!(
            "ASM params carry no bridge-v1 subprotocol config; point the bridge at an ASM \
             instance that runs the bridge protocol"
        );
    };

    ensure_eq("network", params.network, asm.anchor.network)?;
    ensure_eq("magic_bytes", params.protocol.magic_bytes, asm.magic)?;
    ensure_eq(
        "deposit_amount",
        params.protocol.deposit_amount,
        Amount::from(bridge.denomination),
    )?;
    ensure_eq(
        "operator_fee",
        params.protocol.operator_fee,
        Amount::from(bridge.operator_fee),
    )?;
    ensure_eq(
        "recovery_delay",
        params.protocol.recovery_delay,
        bridge.recovery_delay,
    )?;
    if config.min_withdrawal_fulfillment_window >= u64::from(bridge.assignment_duration) {
        anyhow::bail!(
            "min_withdrawal_fulfillment_window: bridge config value \
             {} must be less than ASM assignment_duration {}",
            config.min_withdrawal_fulfillment_window,
            bridge.assignment_duration
        );
    }

    ensure_eq(
        "genesis_height",
        params.genesis_height,
        u64::from(asm.anchor.block.height()),
    )?;

    // ASM indexes its genesis operators by list position, and assignments route by operator
    // index, so the registrations active at genesis must match them in content and order.
    // Registrations activating later are enacted on ASM through admin updates.
    // FIXME: <https://alpenlabs.atlassian.net/browse/STR-3621>
    // Check against membership at current covenant activation window.
    let bridge_operators: Vec<(OperatorIdx, XOnlyPublicKey)> = params
        .keys
        .operators
        .active_at(params.genesis_height)
        .map(|op| (op.index(), op.covenant_key()))
        .collect();
    let asm_operators: Vec<(OperatorIdx, XOnlyPublicKey)> = (0..)
        .zip(bridge.operators.iter().map(|op| (*op).into()))
        .collect();
    ensure_eq("genesis_operators", bridge_operators, asm_operators)
}

/// The configured Mosaic circuit is pinned to the counterproof host's verifying key.
fn verify_mosaic_vkey(expected: [u8; 32], circuit_defs: &[RpcCircuitInfoEntry]) -> Result<()> {
    let [circuit] = circuit_defs else {
        anyhow::bail!(
            "Mosaic returned {} circuit definitions; expected exactly one",
            circuit_defs.len()
        );
    };
    let actual = *circuit.vk_hash.inner();
    if expected != actual {
        anyhow::bail!(
            "counterproof_vkey: bridge proof host value {} does not match Mosaic circuit `{}` \
             value {}",
            hex::encode(expected),
            circuit.name,
            hex::encode(actual),
        );
    }
    Ok(())
}

/// Errors unless the ELF's `derived` predicate matches the `expected` params one. `None` (native
/// host or non-`sp1` build) pins no ELF — nothing to check.
fn ensure_predicate_match(
    label: &str,
    derived: Option<PredicateKey>,
    expected: &PredicateKey,
) -> Result<()> {
    let Some(derived) = derived else {
        return Ok(());
    };
    if derived.id() != expected.id() || derived.condition() != expected.condition() {
        anyhow::bail!(
            "{label}: loaded SP1 guest ELF does not match the configured predicate; regenerate it \
             with `proof-datatool sp1-predicate <elf>` or point at the matching ELF"
        );
    }
    Ok(())
}

/// Ensures the bridge-side and peer-side values of the named field are equal.
fn ensure_eq<T: PartialEq + Debug>(label: &str, bridge_value: T, peer_value: T) -> Result<()> {
    if bridge_value != peer_value {
        anyhow::bail!(
            "{label}: bridge params value {bridge_value:?} does not match peer value \
             {peer_value:?}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;
    use mosaic_rpc_types::{RpcByte32, RpcCircuitInfo};
    use strata_asm_params::{BridgeInitConfig, SubprotocolInstance};
    use strata_bridge_common::params::TimelockOrderingError;
    use strata_bridge_primitives::operator_set_schedule::{OperatorSetSchedule, ScheduledOperator};
    use strata_bridge_test_utils::arbitrary_generator::ArbitraryGenerator;
    use strata_l1_txfmt::MagicBytes;

    use super::*;
    use crate::{config::test_config, mode::services::test_fixtures::test_params};

    const ASSIGNMENT_DURATION: u16 = 144;

    fn node_network(version: u32, incremental_sat_per_kvb: u64) -> NodeNetworkInfo {
        NodeNetworkInfo {
            version,
            incremental_fee: Amount::from_sat(incremental_sat_per_kvb),
        }
    }

    fn node_indexes(synced: Option<bool>) -> NodeIndexInfo {
        NodeIndexInfo {
            txindex: synced.map(|synced| NodeIndexStatus { synced }),
        }
    }

    #[test]
    fn a_default_core_v30_node_passes() {
        let network = node_network(300_200, 100);
        check_core_version(&network).expect("v30");
        check_incremental_fee(&network).expect("the v30 default increment");
        check_data_carrier_size(Some(100_000)).expect("the v30 default");
        check_index_info(&node_indexes(Some(true))).expect("a synced txindex");
    }

    #[test]
    fn a_node_below_core_v30_is_rejected() {
        let err = check_core_version(&node_network(299_999, 100)).expect_err("below v30");
        assert!(err.to_string().contains("Core v30"), "got: {err}");
    }

    #[test]
    fn an_incremental_fee_above_the_planner_increment_is_reported() {
        check_incremental_fee(&node_network(300_000, 1_000))
            .expect("the increment itself is valid");
        let err = check_incremental_fee(&node_network(300_000, 1_001))
            .expect_err("a higher increment refuses small bumps");
        assert!(err.to_string().contains("incrementalfee"), "got: {err}");
    }

    #[test]
    fn a_data_carrier_limit_below_the_v30_default_is_rejected() {
        let err = check_data_carrier_size(Some(83))
            .expect_err("a v30 node at -datacarriersize=83 refuses a bridge proof");
        assert!(err.to_string().contains("datacarriersize"), "got: {err}");
    }

    #[test]
    fn a_node_without_txindex_is_rejected() {
        let err = check_index_info(&node_indexes(None)).expect_err("fee lookups need txindex");
        assert!(err.to_string().contains("txindex=1"), "got: {err}");
    }

    #[test]
    fn a_transaction_index_still_building_is_rejected() {
        let err = check_index_info(&node_indexes(Some(false)))
            .expect_err("fee lookups fail until the index syncs");
        assert!(err.to_string().contains("still building"), "got: {err}");
    }

    #[test]
    fn node_rpc_answers_parse_into_the_checked_fields() {
        let network: NodeNetworkInfo = serde_json::from_value(serde_json::json!({
            "version": 300200,
            "subversion": "/Satoshi:30.2.0/",
            "incrementalfee": 0.00000100,
            "relayfee": 0.00000100,
        }))
        .unwrap();
        assert_eq!(network.version, 300_200, "the version parses as reported");
        assert_eq!(
            network.incremental_fee,
            Amount::from_sat(100),
            "the BTC per kvB amount parses into sats per kvB"
        );

        let indexed: NodeIndexInfo = serde_json::from_value(serde_json::json!({
            "txindex": { "synced": true, "best_block_height": 7 },
        }))
        .unwrap();
        assert!(
            indexed.txindex.is_some_and(|status| status.synced),
            "a listed txindex parses with its sync state"
        );

        let unindexed: NodeIndexInfo = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(
            unindexed.txindex.is_none(),
            "Core lists no txindex when the index is off"
        );
    }

    fn p2tr_descriptor(byte: u8) -> Descriptor {
        Descriptor::new_p2tr(&[byte; 32]).expect("valid x-only payload")
    }

    fn p2wpkh_descriptor(byte: u8) -> Descriptor {
        Descriptor::new_p2wpkh(&[byte; 20])
    }

    #[test]
    fn a_matching_payout_descriptor_passes() {
        let descriptor = p2tr_descriptor(1);
        assert_eq!(
            check_payout_descriptor(&descriptor, &descriptor, &ScriptBuf::new()),
            None,
            "a wallet that pays the covenant descriptor needs no note"
        );
    }

    #[test]
    fn a_payout_descriptor_mismatch_warns_and_does_not_abort() {
        let same_type =
            check_payout_descriptor(&p2tr_descriptor(1), &p2tr_descriptor(2), &ScriptBuf::new());
        assert!(
            same_type.is_some(),
            "a covenant descriptor of another key of the same type is the operator's choice"
        );

        let cross_type = check_payout_descriptor(
            &p2tr_descriptor(1),
            &p2wpkh_descriptor(2),
            &ScriptBuf::new(),
        );
        assert!(
            cross_type.is_some(),
            "a covenant descriptor of another type is the operator's choice"
        );
    }

    #[test]
    fn a_mismatch_names_the_general_key_only_when_it_can_recover() {
        let covenant = p2tr_descriptor(1);
        let wallet = p2wpkh_descriptor(2);
        let recoverable = check_payout_descriptor(&covenant, &wallet, &covenant.to_script())
            .expect("a mismatch carries a note");
        assert!(
            recoverable.contains("secret-service general key"),
            "the general key recovers a covenant descriptor that is its tap-tweaked P2TR: {recoverable}"
        );

        let other_key = check_payout_descriptor(&covenant, &wallet, &ScriptBuf::new())
            .expect("a mismatch carries a note");
        assert!(
            !other_key.contains("secret-service general key"),
            "another key recovers any other covenant descriptor: {other_key}"
        );
    }

    #[test]
    fn a_fixed_fee_rate_above_the_cap_is_accepted() {
        let mut config = test_config();
        config.max_fee_rate = 10;
        config.fee_source = FeeSourceConfig::Fixed { fee_rate: 11 };
        check_fee_config(&config).expect("the rate is a warning, and the duties refuse");
    }

    #[test]
    fn an_invalid_fee_source_config_is_rejected() {
        let mut config = test_config();
        config.fee_source = FeeSourceConfig::Fixed { fee_rate: u64::MAX };
        assert!(check_fee_config(&config).is_err());
    }

    #[test]
    fn a_zero_bump_interval_is_rejected() {
        let mut config = test_config();
        config.cpfp_bump_check_interval = std::time::Duration::ZERO;
        assert!(
            check_fee_config(&config).is_err(),
            "a zero interval would panic the driver's timer"
        );
    }

    #[test]
    fn a_package_floor_above_the_fee_cap_is_accepted() {
        let mut config = test_config();
        config.max_fee_rate = 10;
        config.cpfp_min_package_fee_rate = 11;
        check_fee_config(&config).expect("the floor is a warning, and the cap wins");
    }

    /// Arbitrary [`AsmParams`] with every *compared* field overwritten from `params`; the
    /// uncompared fields stay arbitrary on purpose — they must not affect the verdict.
    fn matching_asm(params: &Params) -> AsmParams {
        let mut asm: AsmParams = ArbitraryGenerator::new().generate();
        asm.magic = params.protocol.magic_bytes;
        asm.anchor.network = params.network;
        asm.anchor.block.height =
            u32::try_from(params.genesis_height).expect("test genesis_height fits in u32");
        let bridge = bridge_cfg_mut(&mut asm);
        bridge.denomination = params.protocol.deposit_amount.into();
        bridge.operator_fee = params.protocol.operator_fee.into();
        bridge.recovery_delay = params.protocol.recovery_delay;
        bridge.assignment_duration = ASSIGNMENT_DURATION;
        bridge.operators = params
            .keys
            .operators
            .active_at(params.genesis_height)
            .map(|op| op.covenant_key().into())
            .collect();
        asm
    }

    fn bridge_cfg_mut(asm: &mut AsmParams) -> &mut BridgeInitConfig {
        asm.subprotocols
            .iter_mut()
            .find_map(|s| match s {
                SubprotocolInstance::Bridge(cfg) => Some(cfg),
                _ => None,
            })
            .expect("arbitrary AsmParams always carries a bridge subprotocol")
    }

    fn circuit_def(vkey_hash: [u8; 32]) -> RpcCircuitInfoEntry {
        RpcCircuitInfoEntry {
            name: "bridge".to_owned(),
            commitment: RpcByte32::new([0; 32]),
            vk_hash: RpcByte32::new(vkey_hash),
            info: RpcCircuitInfo {
                total_size_bytes: 0,
                total_gates: 0,
                xor_gates: 0,
                and_gates: 0,
                num_input_wires: 0,
                num_output_wires: 0,
            },
        }
    }

    #[test]
    fn matching_params_pass() {
        let params = test_params();
        verify_asm_params(&params, &test_config(), &matching_asm(&params))
            .expect("matching params must verify");
    }

    #[test]
    fn misordered_timelocks_fail_unless_allowed() {
        let mut params = test_params();
        let mut config = test_config();
        verify_timelock_ordering(&params, &config).expect("ordered timelocks must verify");

        params.protocol.ack_timelock = params.protocol.proof_timelock;
        let err =
            verify_timelock_ordering(&params, &config).expect_err("misordered timelocks must fail");
        assert!(
            matches!(
                err.downcast_ref(),
                Some(TimelockOrderingError::ProofTimeoutAfterPayout { .. })
            ),
            "unexpected error: {err:?}"
        );

        config.allow_unsafe_timelocks = true;
        verify_timelock_ordering(&params, &config).expect("opt-out must skip the check");
    }

    #[test]
    fn withdrawal_fulfillment_window_must_be_less_than_assignment_duration() {
        let params = test_params();
        let mut config = test_config();
        let asm = matching_asm(&params);

        for window in [
            u64::from(ASSIGNMENT_DURATION),
            u64::from(ASSIGNMENT_DURATION) + 1,
        ] {
            config.min_withdrawal_fulfillment_window = window;
            let err = verify_asm_params(&params, &config, &asm)
                .unwrap_err()
                .to_string();
            assert!(
                err.starts_with("min_withdrawal_fulfillment_window"),
                "expected withdrawal fulfillment window error, got: {err}"
            );
        }
    }

    #[test]
    fn each_mismatched_field_fails_with_its_label() {
        type Mutator = fn(&mut AsmParams);
        let cases: &[(&str, Mutator)] = &[
            ("network", |asm| {
                asm.anchor.network = bitcoin::Network::Bitcoin
            }),
            ("magic_bytes", |asm| asm.magic = MagicBytes::new(*b"XXXX")),
            ("deposit_amount", |asm| {
                bridge_cfg_mut(asm).denomination = Amount::from_sat(1).into()
            }),
            ("operator_fee", |asm| {
                bridge_cfg_mut(asm).operator_fee = Amount::from_sat(1).into()
            }),
            ("recovery_delay", |asm| {
                bridge_cfg_mut(asm).recovery_delay += 1
            }),
            ("genesis_height", |asm| asm.anchor.block.height += 1),
            // Same key set, different order: still a consensus split.
            ("genesis_operators", |asm| {
                bridge_cfg_mut(asm).operators.reverse()
            }),
            ("genesis_operators", |asm| {
                bridge_cfg_mut(asm).operators.pop();
            }),
        ];

        let params = test_params();
        let config = test_config();
        for (label, mutate) in cases {
            let mut asm = matching_asm(&params);
            mutate(&mut asm);
            let err = verify_asm_params(&params, &config, &asm)
                .unwrap_err()
                .to_string();
            assert!(
                err.starts_with(label),
                "expected `{label}` mismatch, got: {err}"
            );
        }
    }

    #[test]
    fn registrations_activating_after_genesis_are_not_compared() {
        let mut params = test_params();
        let joining = params
            .keys
            .operators
            .iter()
            .map(ScheduledOperator::index)
            .max()
            .expect("the fixture schedules operators");
        let operators = params
            .keys
            .operators
            .iter()
            .map(|op| {
                let activation_height = if op.index() == joining {
                    params.genesis_height + 1
                } else {
                    op.activation_height()
                };
                ScheduledOperator::new(
                    op.index(),
                    op.covenant_key(),
                    op.p2p_key().clone(),
                    op.payout_descriptor().clone(),
                    activation_height,
                    op.deactivation_height(),
                )
                .expect("rescheduling a valid operator keeps it valid")
            })
            .collect();
        params.keys.operators =
            OperatorSetSchedule::new(operators).expect("rescheduled operators form a schedule");

        verify_asm_params(&params, &test_config(), &matching_asm(&params))
            .expect("a registration activating after genesis must not be compared with ASM");
    }

    #[test]
    fn missing_bridge_subprotocol_fails() {
        let params = test_params();
        let config = test_config();
        let mut asm = matching_asm(&params);
        asm.subprotocols
            .retain(|s| !matches!(s, SubprotocolInstance::Bridge(_)));

        let err = verify_asm_params(&params, &config, &asm)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no bridge-v1 subprotocol"), "got: {err}");
    }

    #[test]
    fn native_vkey_matches_zeroed_mosaic_vkey() {
        verify_mosaic_vkey([0; 32], &[circuit_def([0; 32])])
            .expect("native vkey must match a zeroed Mosaic circuit vkey");
    }

    #[test]
    fn native_vkey_rejects_nonzero_mosaic_vkey() {
        let err = verify_mosaic_vkey([0; 32], &[circuit_def([1; 32])])
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("counterproof_vkey"), "got: {err}");
    }

    #[test]
    fn mosaic_must_return_exactly_one_circuit() {
        for defs in [vec![], vec![circuit_def([0; 32]), circuit_def([0; 32])]] {
            let err = verify_mosaic_vkey([0; 32], &defs).unwrap_err().to_string();
            assert!(err.contains("expected exactly one"), "got: {err}");
        }
    }
}
