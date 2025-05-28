//! This module contains parameters required to construct the peg-out graph.

use bitcoin::Amount;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use super::default::{BRIDGE_DENOMINATION, CHALLENGE_COST, OPERATOR_FEE, REFUND_DELAY};
use crate::{default::BRIDGE_TAG, types::Tag};

fn serialize_tag<S>(tag: &Tag, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let tag_string: String = tag.into();
    serializer.serialize_str(&tag_string)
}

fn deserialize_tag<'de, D>(deserializer: D) -> Result<Tag, D::Error>
where
    D: Deserializer<'de>,
{
    let tag_string = String::deserialize(deserializer)?;
    Tag::try_from(tag_string.as_str()).map_err(|e| D::Error::custom(e.to_string()))
}

/// The parameters required to construct a peg-out graph.
///
/// These parameters are consensus-critical meaning that these are values that are agreed upon by
/// all operators and verifiers in the bridge.
// TODO: move this to the primitives crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegOutGraphParams {
    /// The tag, also known as "magic bytes".
    #[serde(serialize_with = "serialize_tag")]
    #[serde(deserialize_with = "deserialize_tag")]
    pub tag: Tag,

    /// The amount that is locked in the bridge address at the deposit time.
    pub deposit_amount: Amount,

    /// The fee charged by an operator for processing a withdrawal.
    pub operator_fee: Amount,

    /// The output amount for the challenge transaction that is paid to the operator being
    /// challenged.
    pub challenge_cost: Amount,

    /// The number of blocks for which the Deposit Request output must be locked before it can be
    /// taken back by the user.
    pub refund_delay: u16,
}

impl Default for PegOutGraphParams {
    fn default() -> Self {
        Self {
            tag: BRIDGE_TAG
                .try_into()
                .expect("Default bridge tag must be valid"),
            deposit_amount: BRIDGE_DENOMINATION,
            operator_fee: OPERATOR_FEE,
            challenge_cost: CHALLENGE_COST,
            refund_delay: REFUND_DELAY,
        }
    }
}
