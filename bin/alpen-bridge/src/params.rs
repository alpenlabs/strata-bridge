use serde::{Deserialize, Serialize};
use strata_bridge_primitives::params::prelude::StakeChainParams;
use strata_bridge_tx_graph::peg_out_graph::PegOutGraphParams;

/// The consensus-critical parameters that dictate the behavior of the bridge node.
///
/// These parameters are configurable and can be changed by the operator but note that differences
/// in how these are configured among the bridge operators in the network will lead to different
/// behavior that will prevent the bridge from functioning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Params {
    /// The tag that is used to identify bridge-specific transactions in the Bitcoin blockchain.
    ///
    /// This is chiefly used to identify Deposit Request and Deposit transactions.
    pub tx_tag: String,

    /// The height at which the bridge node starts scanning for relevant transactions.
    pub genesis_height: u32,
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
            tx_tag = "bridge-tag"
            genesis_height = 101

            [tx_graph]
            deposit_amount = {}
            funding_amount = 32340

            [stake_chain]
            stake_amount      = 100000000
            burn_amount       = 10000000
            delta             = {{ Blocks = 6 }} # escape curly braces
            slash_stake_count = 24
        "#,
            deposit_amount
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
            deserialized, params,
            "must be able to serialize and deserialize params to toml"
        );

        assert_eq!(
            Amount::from_sat(deposit_amount),
            params.tx_graph.deposit_amount,
            "deposit amounts must match across serialization"
        );
    }
}
