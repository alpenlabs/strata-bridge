//! The consensus-critical parameters that dictate the behavior of the bridge node.
//!
//! These parameters while configurable cannot be changed after genesis as any such change will
//! result in a consensus failure among the bridge nodes.
use std::str::FromStr;

use bitcoin::{Amount, Network, hex::DisplayHex};
use bitcoin_bosd::Descriptor;
use libp2p::identity::ed25519::PublicKey as Libp2pKey;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Deserializer, Serialize};
use strata_l1_txfmt::MagicBytes;

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

/// The core protocol parameters for the bridge.
///
/// These define the fundamental rules of the bridge protocol including amounts, timelocks,
/// and identifiers. Unlike keys, these are less malleable and changes here will immediately
/// break consensus among bridge operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProtocolParams {
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
}

/// The keys used by the operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyParams {
    /// The admin key used to block payouts in case of a malicious operator flooding the network
    /// with invalid claims and overwhelming the watchtowers.
    pub(crate) admin: XOnlyPublicKey,

    /// The per-operator keys that form the N-of-N covenant.
    pub(crate) covenant: Vec<CovenantKeys>,
}

/// The per-entity keys that form the N-of-N covenant.
///
/// Each entry corresponds to a single operator's set of keys used in various aspects of the
/// covenant enforcement. This includes keys required for signer, operator and watchtower roles
/// until such a time as these roles become split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CovenantKeys {
    /// The key used for musig2 signing corresponding to the N-of-N covenant enforcement.
    pub(crate) musig2: XOnlyPublicKey,

    /// The key used for authenticated p2p communication.
    pub(crate) p2p: Libp2pKey,

    /// The key for which to generate adaptors when submitting a counterproof.
    // NOTE: (@Rajil1213) we might get this from mosaic instead.
    pub(crate) adaptor: XOnlyPublicKey,

    /// The watchtower public key whose corresponding private key is revealed in case of a faulty
    /// counterproof.
    pub(crate) watchtower_fault: XOnlyPublicKey,

    /// The operator payout descriptor.
    pub(crate) payout_descriptor: Descriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncodedCovenantKeys {
    musig2: String,
    p2p: String,
    adaptor: String,
    watchtower_fault: String,
    payout_descriptor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncodedKeyParams {
    admin: String,
    covenant: Vec<EncodedCovenantKeys>,
}

/// Serialize the keys into hex-encoded bytes.
fn serialize_keys<S>(keys: &KeyParams, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded_keys = EncodedKeyParams {
        admin: keys.admin.serialize().to_lower_hex_string(),
        covenant: keys
            .covenant
            .iter()
            .map(|k| EncodedCovenantKeys {
                musig2: k.musig2.serialize().to_lower_hex_string(),
                p2p: k.p2p.to_bytes().to_lower_hex_string(),
                adaptor: k.adaptor.serialize().to_lower_hex_string(),
                watchtower_fault: k.watchtower_fault.serialize().to_lower_hex_string(),
                payout_descriptor: k.payout_descriptor.to_string(),
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

    let admin = hex::decode(&encoded_keys.admin).expect("Failed to decode hex admin key");
    let admin =
        XOnlyPublicKey::from_slice(&admin).expect("Failed to create admin xonly pk from slice");

    let covenant = encoded_keys
        .covenant
        .into_iter()
        .enumerate()
        .map(|(i, k)| {
            let musig2 = hex::decode(&k.musig2)
                .unwrap_or_else(|_| panic!("Failed to decode hex musig2 key at index {i}"));
            let musig2 = XOnlyPublicKey::from_slice(&musig2)
                .unwrap_or_else(|_| panic!("Failed to create musig2 xonly pk at index {i}"));

            let p2p = hex::decode(&k.p2p)
                .unwrap_or_else(|_| panic!("Failed to decode hex p2p key at index {i}"));
            let p2p = Libp2pKey::try_from_bytes(&p2p)
                .unwrap_or_else(|_| panic!("Failed to decode Libp2pKey at index {i}"));

            let adaptor = hex::decode(&k.adaptor)
                .unwrap_or_else(|_| panic!("Failed to decode hex adaptor key at index {i}"));
            let adaptor = XOnlyPublicKey::from_slice(&adaptor)
                .unwrap_or_else(|_| panic!("Failed to create adaptor xonly pk at index {i}"));

            let watchtower_fault = hex::decode(&k.watchtower_fault).unwrap_or_else(|_| {
                panic!("Failed to decode hex watchtower_fault key at index {i}")
            });
            let watchtower_fault =
                XOnlyPublicKey::from_slice(&watchtower_fault).unwrap_or_else(|_| {
                    panic!("Failed to create watchtower_fault xonly pk at index {i}")
                });

            let payout_descriptor = k
                .payout_descriptor
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse payout descriptor at index {i}"));

            CovenantKeys {
                musig2,
                p2p,
                adaptor,
                watchtower_fault,
                payout_descriptor,
            }
        })
        .collect();

    Ok(KeyParams { admin, covenant })
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

            [[keys.covenant]]
            musig2 = "{XONLY_KEY_1}"
            p2p = "{P2P_KEY_1}"
            adaptor = "{XONLY_KEY_1}"
            watchtower_fault = "{XONLY_KEY_1}"
            payout_descriptor = "{desc_1}"

            [[keys.covenant]]
            musig2 = "{XONLY_KEY_2}"
            p2p = "{P2P_KEY_2}"
            adaptor = "{XONLY_KEY_2}"
            watchtower_fault = "{XONLY_KEY_2}"
            payout_descriptor = "{desc_2}"

            [protocol]
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
            params.keys.covenant.len(),
            2,
            "must have 2 covenant key entries"
        );
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
