use std::{fs, path::Path, str::FromStr};

use alpen_bridge_params::types::Tag;
use anyhow::anyhow;
use bitcoin::{relative::LockTime, secp256k1::XOnlyPublicKey, Amount, Network};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Params {
    pub(crate) network: Network,
    pub(crate) bridge_out_addr: String,
    pub(crate) deposit_amount: Amount,
    pub(crate) burn_amount: Amount,
    pub(crate) stake_amount: Amount,
    pub(crate) stake_chain_delta: LockTime,
    pub(crate) payout_timelock: u32,
    pub(crate) refund_delay: u16,

    #[serde(serialize_with = "serialize_tag")]
    #[serde(deserialize_with = "deserialize_tag")]
    pub(crate) tag: Tag,

    #[serde(serialize_with = "serialize_keys")]
    #[serde(deserialize_with = "deserialize_keys")]
    pub(crate) musig2_keys: Vec<XOnlyPublicKey>,
}

fn serialize_tag<S>(tag: &Tag, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&tag.to_string())
}

fn deserialize_tag<'de, D>(deserializer: D) -> Result<Tag, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let tag_str = String::deserialize(deserializer)?;
    Tag::try_from(tag_str).map_err(serde::de::Error::custom)
}

fn serialize_keys<S>(keys: &[XOnlyPublicKey], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex_keys: Vec<String> = keys.iter().map(|key| key.to_string()).collect();
    hex_keys.serialize(serializer)
}

fn deserialize_keys<'de, D>(deserializer: D) -> Result<Vec<XOnlyPublicKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_keys: Vec<String> = Vec::deserialize(deserializer)?;
    hex_keys
        .into_iter()
        .map(|key| XOnlyPublicKey::from_str(&key).map_err(serde::de::Error::custom))
        .collect()
}

impl Params {
    pub(crate) fn from_path(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let contents = fs::read_to_string(path)?;
        let params: Self = toml::from_str(&contents)
            .map_err(|e| anyhow!(format!("Failed to parse params file: {}", e)))?;

        Ok(params)
    }
}
