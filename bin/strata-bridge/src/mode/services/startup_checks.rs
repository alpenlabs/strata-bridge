//! Startup consistency checks between the bridge and its external components.
use std::fmt::Debug;

use algebra::retry::{Strategy, retry_with};
use anyhow::{Context, Result, anyhow};
use bitcoin::{Amount, FeeRate};
use jsonrpsee::http_client::HttpClient;
use mosaic_rpc_api::MosaicRpcClient;
use mosaic_rpc_types::RpcCircuitInfoEntry;
use secp256k1::XOnlyPublicKey;
use strata_asm_params::AsmParams;
use strata_asm_rpc::traits::AsmControlApiClient;
use strata_bridge_asm_events::config::AsmRpcConfig;
use strata_bridge_common::params::Params;
use strata_bridge_counterproof::BridgeCounterproofHost;
use strata_bridge_proof::BridgeProofHost;
use strata_predicate::PredicateKey;
use tokio::time;
use tracing::warn;

use crate::config::{Config, MosaicConfig};

/// Runs every startup consistency check; a failure aborts node startup.
pub(in crate::mode) async fn verify(
    params: &Params,
    config: &Config,
    asm_rpc_client: &HttpClient,
    mosaic_rpc_client: &HttpClient,
    bridge_proof_host: &BridgeProofHost,
    counterproof_host: &BridgeCounterproofHost,
) -> Result<()> {
    verify_cpfp_fee_config(config)?;

    verify_predicates(params, bridge_proof_host, counterproof_host)?;

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

/// The CPFP fee knobs must not contradict each other: a package floor above the cap would
/// clamp every bump to the cap and the operator's two settings would fight. Checked at
/// startup so the mismatch aborts the node instead of surfacing as a warn on every bump.
fn verify_cpfp_fee_config(config: &Config) -> Result<()> {
    let cap = FeeRate::from_sat_per_vb(config.max_fee_rate).ok_or_else(|| {
        anyhow!(
            "max_fee_rate = {} sat/vB is not a valid fee rate",
            config.max_fee_rate
        )
    })?;
    let floor = FeeRate::from_sat_per_vb(config.cpfp_min_package_fee_rate).ok_or_else(|| {
        anyhow!(
            "cpfp_min_package_fee_rate = {} sat/vB is not a valid fee rate",
            config.cpfp_min_package_fee_rate
        )
    })?;
    if floor > cap {
        anyhow::bail!(
            "cpfp_min_package_fee_rate = {} sat/vB exceeds max_fee_rate = {} sat/vB; \
             the floor would clamp every CPFP bump to the cap",
            config.cpfp_min_package_fee_rate,
            config.max_fee_rate
        );
    }
    Ok(())
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
fn verify_predicates(
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

    // The operator lists must match in content and order: assignments route by operator
    // index, so a reordering is as consensus-breaking as a different key set.
    let bridge_operators: Vec<XOnlyPublicKey> =
        params.keys.covenant.iter().map(|k| k.musig2).collect();
    let asm_operators: Vec<XOnlyPublicKey> =
        bridge.operators.iter().map(|op| (*op).into()).collect();
    ensure_eq("operators", bridge_operators, asm_operators)
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
    use bitcoin_bosd::Descriptor;
    use mosaic_rpc_types::{RpcByte32, RpcCircuitInfo};
    use strata_asm_params::{BridgeInitConfig, SubprotocolInstance};
    use strata_bridge_test_utils::arbitrary_generator::ArbitraryGenerator;
    use strata_l1_txfmt::MagicBytes;

    use super::*;
    use crate::config::test_config;

    // Valid x-only/ed25519 test keys, same fixtures as `strata_bridge_common::params` tests.
    const XONLY_KEY_1: &str = "b49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d";
    const XONLY_KEY_2: &str = "1e62d54af30569fd7269c14b6766f74d85ea00c911c4e1a423d4ba2ae4c34dc4";
    const P2P_KEY_1: &str = "0de7729dcbeb5069136ee4bff1c4f2fd822fe8fbc9b518df434d4f0c6312d8f5";
    const P2P_KEY_2: &str = "255ab0da6d468a22910a7cf54021763417c63c28bbafd4e2359daf103bb61e9d";
    const ASSIGNMENT_DURATION: u16 = 144;

    fn test_params() -> Params {
        let p2tr = |xonly_hex: &str| {
            let pk: [u8; 32] = hex::decode(xonly_hex).unwrap().try_into().unwrap();
            Descriptor::new_p2tr(&pk).unwrap().to_string()
        };
        let (desc_1, desc_2) = (p2tr(XONLY_KEY_1), p2tr(XONLY_KEY_2));

        toml::from_str(&format!(
            r#"
            network = "signet"
            genesis_height = 101

            [keys.admin]
            pubkeys = ["{XONLY_KEY_1}", "{XONLY_KEY_2}"]
            threshold = 2

            [[keys.covenant]]
            musig2 = "{XONLY_KEY_1}"
            p2p = "{P2P_KEY_1}"
            payout_descriptor = "{desc_1}"

            [[keys.covenant]]
            musig2 = "{XONLY_KEY_2}"
            p2p = "{P2P_KEY_2}"
            payout_descriptor = "{desc_2}"

            [protocol]
            bury_depth = 6
            magic_bytes = "ALPN"
            deposit_amount = 100_000_000
            stake_amount = 100_000_000
            operator_fee = 1_000_000
            recovery_delay = 1_008
            contest_timelock = 144
            proof_timelock = 144
            ack_timelock = 144
            nack_timelock = 144
            contested_payout_timelock = 1_008
            unstaking_timelock = 2_016
            sweep_fee_rate = 10
            "#
        ))
        .expect("valid test params")
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
            .covenant
            .iter()
            .map(|k| k.musig2.into())
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
            ("operators", |asm| bridge_cfg_mut(asm).operators.reverse()),
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
