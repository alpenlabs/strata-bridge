//! The consensus-critical parameters that dictate the behavior of the bridge node.
//!
//! These parameters while configurable cannot be changed after genesis as any such change will
//! result in a consensus failure among the bridge nodes.
use std::{fs, path::Path, str::FromStr};

use bitcoin::{hex::DisplayHex, Amount, Network};
use bitcoin_bosd::Descriptor;
use secp256k1::XOnlyPublicKey;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use strata_bridge_primitives::{
    operator_set_schedule::{OperatorSetSchedule, ScheduledOperator},
    types::P2POperatorPubKey,
};
use strata_l1_txfmt::MagicBytes;
use strata_predicate::PredicateKey;

/// The consensus-critical parameters that dictate the behavior of the bridge node.
///
/// These parameters are configurable and can be changed by the operator but note that differences
/// in how these are configured among the bridge operators in the network will lead to different
/// behavior that will prevent the bridge from functioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Params {
    /// The network on which the bridge is operating.
    pub network: Network,

    /// The height at which the bridge node starts scanning for relevant transactions.
    pub genesis_height: u64,

    /// The keys used by operators.
    ///
    /// These are part of the protocol but more malleable than the core protocol parameters.
    #[serde(deserialize_with = "deserialize_keys")]
    #[serde(serialize_with = "serialize_keys")]
    pub keys: KeyParams,

    /// The core protocol parameters that define the transaction graph and covenant behavior.
    pub protocol: ProtocolParams,
}

impl Params {
    /// Reads and parses a TOML params file from the given path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let contents = fs::read_to_string(path)?;
        let params: Self = toml::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse params file: {e}"))?;

        Ok(params)
    }
}

/// The core protocol parameters for the bridge.
///
/// These define the fundamental rules of the bridge protocol including amounts, timelocks,
/// and identifiers. Unlike keys, these are less malleable and changes here will immediately
/// break consensus among bridge operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolParams {
    /// The number of blocks that must be built on top of a block before the bridge considers it
    /// "final".
    pub bury_depth: usize,

    /// The "magic bytes" used in the OP_RETURN of the transactions to identify it as relevant to
    /// the bridge.
    #[serde(serialize_with = "serialize_magic_bytes")]
    #[serde(deserialize_with = "deserialize_magic_bytes")]
    pub magic_bytes: MagicBytes,

    /// The denomination of deposits in the bridge.
    pub deposit_amount: Amount,

    /// The amount staked by an operator.
    pub stake_amount: Amount,

    /// The fee amount that the operator charges for fronting a user.
    pub operator_fee: Amount,

    /// The number of blocks after the deposit request after which the user can take back their
    /// deposit request.
    pub recovery_delay: u16,

    /// The number blocks after claim until which a contest is allowed.
    pub contest_timelock: u16,

    /// The number of blocks within which an operator must publish the proof after a contest is
    /// initiated.
    pub proof_timelock: u16,

    /// The number of blocks within which watchtower must ACK their counterproof to prevent a
    /// payout.
    pub ack_timelock: u16,

    /// The number of blocks within which the operator must NACK the counterproof or be slashed.
    pub nack_timelock: u16,

    /// The number of blocks after the contest timelock until which the payout after which slashing
    /// becomes viable.
    pub contested_payout_timelock: u16,

    /// Predicate key used to verify bridge proof.
    #[serde(default = "PredicateKey::always_accept")]
    pub bridge_proof_predicate: PredicateKey,

    /// Predicate key used to verify bridge counterproof.
    #[serde(default = "PredicateKey::always_accept")]
    pub counterproof_predicate: PredicateKey,
}

/// The keys used by the operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyParams {
    /// The admin key used to block payouts in case of a malicious operator flooding the network
    /// with invalid claims and overwhelming the watchtowers.
    pub admin: XOnlyPublicKey,

    /// The configured operator set schedule.
    pub operators: OperatorSetSchedule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedScheduledOperator {
    index: u32,
    signing_key: String,
    p2p_key: String,
    payout_descriptor: String,
    activation_height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deactivation_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedKeyParams {
    admin: String,
    operators: Vec<EncodedScheduledOperator>,
}

/// Serialize the keys into hex-encoded bytes.
fn serialize_keys<S>(keys: &KeyParams, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded_keys = EncodedKeyParams {
        admin: keys.admin.serialize().to_lower_hex_string(),
        operators: keys
            .operators
            .iter()
            .map(|operator| EncodedScheduledOperator {
                index: operator.index(),
                signing_key: operator.signing_key().serialize().to_lower_hex_string(),
                p2p_key: operator.p2p_key().as_ref().to_lower_hex_string(),
                payout_descriptor: operator.payout_descriptor().to_string(),
                activation_height: operator.activation_height(),
                deactivation_height: operator.deactivation_height(),
            })
            .collect(),
    };

    encoded_keys.serialize(serializer)
}

/// Deserialize the hex-encoded bytes of keys.
fn deserialize_keys<'de, D>(deserializer: D) -> Result<KeyParams, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded_keys = EncodedKeyParams::deserialize(deserializer)?;

    let admin = hex::decode(&encoded_keys.admin)
        .map_err(|err| D::Error::custom(format!("failed to decode hex admin key: {err}")))?;
    let admin = XOnlyPublicKey::from_slice(&admin)
        .map_err(|err| D::Error::custom(format!("failed to create admin x-only key: {err}")))?;

    let operators = encoded_keys
        .operators
        .into_iter()
        .enumerate()
        .map(|(i, k)| {
            let signing_key = hex::decode(&k.signing_key).map_err(|err| {
                D::Error::custom(format!("failed to decode signing_key at entry {i}: {err}"))
            })?;
            let signing_key = XOnlyPublicKey::from_slice(&signing_key).map_err(|err| {
                D::Error::custom(format!(
                    "failed to create signing x-only key at entry {i}: {err}"
                ))
            })?;

            let p2p_key = hex::decode(&k.p2p_key).map_err(|err| {
                D::Error::custom(format!("failed to decode p2p_key at entry {i}: {err}"))
            })?;
            let p2p_key = P2POperatorPubKey::from(p2p_key);

            let payout_descriptor: Descriptor = k.payout_descriptor.parse().map_err(|err| {
                D::Error::custom(format!(
                    "failed to parse payout_descriptor at entry {i}: {err:?}"
                ))
            })?;

            ScheduledOperator::new(
                k.index,
                signing_key,
                p2p_key,
                payout_descriptor,
                k.activation_height,
                k.deactivation_height,
            )
            .map_err(|err| D::Error::custom(format!("invalid operator at entry {i}: {err}")))
        })
        .collect::<Result<Vec<_>, D::Error>>()?;

    let operators = OperatorSetSchedule::new(operators).map_err(D::Error::custom)?;

    Ok(KeyParams { admin, operators })
}

fn serialize_magic_bytes<S>(magic_bytes: &MagicBytes, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let s = std::str::from_utf8(magic_bytes.as_bytes()).expect("magic bytes must be valid UTF-8");
    serializer.serialize_str(s)
}

fn deserialize_magic_bytes<'de, D>(deserializer: D) -> Result<MagicBytes, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    MagicBytes::from_str(&s).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;

    use super::*;

    // Two valid x-only public keys for test fixtures (take from docker/vol).
    const XONLY_KEY_1: &str = "b49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d";
    const XONLY_KEY_2: &str = "1e62d54af30569fd7269c14b6766f74d85ea00c911c4e1a423d4ba2ae4c34dc4";

    // Two valid ed25519 public keys for test fixtures (taken from docker/vol).
    const P2P_KEY_1: &str = "0de7729dcbeb5069136ee4bff1c4f2fd822fe8fbc9b518df434d4f0c6312d8f5";
    const P2P_KEY_2: &str = "255ab0da6d468a22910a7cf54021763417c63c28bbafd4e2359daf103bb61e9d";

    #[test]
    fn test_params_serde_toml() {
        let deposit_amount = Amount::from_int_btc(1).to_sat();
        let desc_1 = p2tr_descriptor(XONLY_KEY_1);
        let desc_2 = p2tr_descriptor(XONLY_KEY_2);

        let params = format!(
            r#"
            network = "signet"
            genesis_height = 101

            [keys]
            admin = "{XONLY_KEY_1}"

            [[keys.operators]]
            index = 0
            signing_key = "{XONLY_KEY_1}"
            p2p_key = "{P2P_KEY_1}"
            payout_descriptor = "{desc_1}"
            activation_height = 101

            [[keys.operators]]
            index = 1
            signing_key = "{XONLY_KEY_2}"
            p2p_key = "{P2P_KEY_2}"
            payout_descriptor = "{desc_2}"
            activation_height = 200
            deactivation_height = 300

            [protocol]
            bury_depth = 6
            magic_bytes = "ALPN"
            deposit_amount = {deposit_amount}
            stake_amount = 100_000_000
            operator_fee = 1_000_000
            recovery_delay = 1_008
            contest_timelock = 144
            proof_timelock = 144
            ack_timelock = 144
            nack_timelock = 144
            contested_payout_timelock = 1_008
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

        assert_eq!(
            Amount::from_sat(deposit_amount),
            params.protocol.deposit_amount,
            "deposit amounts must match across serialization"
        );

        assert_eq!(
            params.keys.operators.len(),
            2,
            "must have 2 scheduled operator entries"
        );

        assert_eq!(
            params.keys.operators.active_at(100).count(),
            0,
            "no operator must be active before activation"
        );
        assert_eq!(
            params.keys.operators.active_at(101).count(),
            1,
            "activation height must be inclusive"
        );
        assert_eq!(
            params.keys.operators.active_at(200).count(),
            2,
            "multiple active scheduled operators must be returned"
        );
        assert_eq!(
            params.keys.operators.active_at(300).count(),
            1,
            "deactivation height must be exclusive"
        );
        assert_eq!(params.protocol.bury_depth, 6, "bury depth must round-trip");
    }

    /// Construct a P2TR BOSD descriptor string from an x-only public key hex string.
    fn p2tr_descriptor(xonly_hex: &str) -> String {
        let pk_bytes: [u8; 32] = hex::decode(xonly_hex)
            .expect("valid hex")
            .try_into()
            .expect("x-only public key must be 32 bytes");

        Descriptor::new_p2tr(&pk_bytes)
            .expect("valid p2tr descriptor")
            .to_string()
    }
}
