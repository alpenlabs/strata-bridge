use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bitcoin::{hex::DisplayHex, Network};
use libp2p::identity::ed25519::PublicKey as Libp2pKey;
use musig2::secp256k1::XOnlyPublicKey as Musig2Key;
use serde::{Deserialize, Deserializer, Serialize};
use strata_params::RollupParams;

/// The consensus-critical parameters that dictate the behavior of the bridge node.
///
/// These parameters are configurable and can be changed by the operator but note that differences
/// in how these are configured among the bridge operators in the network will lead to different
/// behavior that will prevent the bridge from functioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Params {
    /// The network on which the bridge is operating.
    pub network: Network,

    /// The height at which the bridge node starts scanning for relevant transactions.
    pub genesis_height: u32,

    /// The keys used by operators.
    #[serde(deserialize_with = "deserialize_keys")]
    #[serde(serialize_with = "serialize_keys")]
    pub keys: KeyParams,

    /// The parameters that dictate the nature of the peg-out graph.
    ///
    /// Difference in these values among the bridge operators will lead to different peg-out graphs
    /// and thereby, invalid signatures being exchanged.
    pub tx_graph: PegOutGraphParams,

    /// The parameters that dictate the nature of the stake chain.
    ///
    /// Difference in these values among the bridge operators will lead to different stake chain
    /// structures and thereby, invalid signatures being exchanged.
    pub stake_chain: StakeChainParams,

    /// The consensus-critical parameters that define the locking conditions for each connector.
    pub connectors: ConnectorParams,

    /// Consensus parameters that don't change for the lifetime of the network
    /// (unless there's some weird hard fork).
    pub sidesystem: RollupParams,
}

/// The keys used by the operators encoded in hex strings for convenience.
/// The keys used by the operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyParams {
    /// The keys used for the musig2 signing corresponding to the N-of-N covenant enforcement.
    pub(crate) musig2: Vec<Musig2Key>,

    /// The keys used for authenticated p2p communication.
    pub(crate) p2p: Vec<Libp2pKey>,
}

/// Serialize the keys into hex-encoded bytes.
fn serialize_keys<S>(keys: &KeyParams, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct EncodedKeyParams {
        musig2: Vec<String>,
        p2p: Vec<String>,
    }

    let encoded_keys = EncodedKeyParams {
        musig2: keys
            .musig2
            .iter()
            .map(|key| key.serialize().to_lower_hex_string())
            .collect(),
        p2p: keys
            .p2p
            .iter()
            .map(|key| key.to_bytes().to_lower_hex_string())
            .collect(),
    };

    encoded_keys.serialize(serializer)
}

/// Deserialize the hex-encoded bytes of keys.
fn deserialize_keys<'de, D>(deserializer: D) -> Result<KeyParams, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct EncodedKeyParams {
        musig2: Vec<String>,
        p2p: Vec<String>,
    }

    let encoded_keys = EncodedKeyParams::deserialize(deserializer)?;

    let musig2 = encoded_keys
        .musig2
        .into_iter()
        .map(|key| {
            let key = hex::decode(key).expect("Failed to decode hex key");
            Musig2Key::from_slice(&key).expect("Failed to create Musig2Key from slice")
        })
        .collect();

    let p2p = encoded_keys
        .p2p
        .into_iter()
        .map(|key| {
            dbg!(&key);
            let key = hex::decode(key).expect("Failed to decode hex key");
            Libp2pKey::try_from_bytes(&key).expect("Failed to decode Libp2pKey from slice")
        })
        .collect();

    Ok(KeyParams { musig2, p2p })
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;

    use super::*;

    #[test]
    fn test_params_serde_toml() {
        let deposit_amount = Amount::from_int_btc(1).to_sat();

        let params = format!(
            r#"
            network = "signet"
            genesis_height = 101

            [keys]
            musig2 = ["c46132cbb3ef14caeac8f724fea1449d802133495ef1675f210b0742f5ee8164", "d57243dbb3ef14caeac8f724fea1449d802133495ef1675f210b074206ff9275"]
            p2p = ["ab1d0c44056036dce1b783d2db0c42876b60948c7ae2002476fcb61e15d6f7d7", "6f83c5863297da5f9d859898cfeb66f8a1cb719b6e8f599301788481c0d8f523"]

            [tx_graph]
            tag = "alpn"
            deposit_amount = {deposit_amount}
            operator_fee = 1_000_000
            challenge_cost = 10_000_000
            refund_delay = 1_008

            [stake_chain]
            stake_amount      = 100_000_000
            burn_amount       = 10_000_000
            delta             = {{ Blocks = 6 }}
            slash_stake_count = 24

            [connectors]
            payout_optimistic_timelock = 1_008
            pre_assert_timelock = 1_152
            payout_timelock = 1_008

            [sidesystem]
            magic_bytes = "ALPN"
            block_time = 1_000
            da_tag = "alpen-bridge-da"
            checkpoint_tag = "alpen-bridge-checkpoint"
            cred_rule = "unchecked"
            horizon_l1_height = 1_000
            genesis_l1_height = 1_000
            l1_reorg_safe_depth = 1_000
            target_l2_batch_size = 1_000
            max_address_length = 20
            deposit_amount = {deposit_amount}
            dispatch_assignment_dur = 1000
            proof_publish_mode = "strict"
            checkpoint_predicate = "AlwaysAccept"
            max_deposits_in_block = 20
            network = "signet"
            evm_genesis_block_hash = "0x46c0dc60fb131be4ccc55306a345fcc20e44233324950f978ba5f185aa2af4dc"
            evm_genesis_block_state_root = "0x351714af72d74259f45cd7eab0b04527cd40e74836a45abcae50f92d919d988f"
            rollup_vk.native = "0x0000000000000000000000000000000000000000000000000000000000000000"
            operator_config.static = [{{ signing_pk = "0x69d6917eece56dfe15921c4ce2b6d7d41f9fa82706d78a2933f1365d07615463", wallet_pk = "0x30377cf0fe6db23123099fc89006bf8b18263e5579f914e53dce451af94cc0ea" }}, {{ signing_pk = "0x50b9c486ac70b7b343847c34ef9bb7b216328a691fbd413c4b3efdd389bdc71a", wallet_pk = "0xf4c9ed887e5bf6c756dc2d5de8c55f2a05a176f88951d2e355236d6af2df111b" }}]

            [sidesystem.genesis_l1_view.blk]
            height = 100
            blkid = "f2c22acbe3b24e429349296b958c40b692356436086750bd7564ebfceb915100"

            [sidesystem.genesis_l1_view]
            next_target = 545259519
            epoch_start_timestamp = 1296688602
            last_11_timestamps = [
                1764086031,
                1764086031,
                1764086032,
                1764086032,
                1764086032,
                1764086032,
                1764086032,
                1764086032,
                1764086033,
                1764086033,
                1764086033
            ]
    "#
        );

        let deserialized = toml::from_str::<Params>(&params);

        assert!(
            deserialized.is_ok(),
            "must be able to deserialize params from toml but got: {}",
            deserialized.unwrap_err()
        );

        let deserialized = deserialized.unwrap();
        let serialized = toml::to_string(&deserialized).unwrap();
        let params = toml::from_str::<Params>(&serialized).unwrap();

        // TODO(@MdTeach):
        // This assertion is temporarily disabled because `strata_params::RollupParams`
        // no longer implements `PartialEq`, so we can't directly compare the
        // deserialized value against `params`.
        // Re-enable this once Strata restores or provides an alternative for
        // structural equality.
        //
        // assert_eq!(
        //     deserialized, params,
        //     "must be able to serialize and deserialize params to toml"
        // );

        assert_eq!(
            Amount::from_sat(deposit_amount),
            params.tx_graph.deposit_amount,
            "deposit amounts must match across serialization"
        );
    }
}
