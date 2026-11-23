//! Configuration of stake state machines.

use serde::{Deserialize, Serialize};
use strata_bridge_tx_graph::stake_graph::ProtocolParams;

/// Configuration for a stake state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeSMCfg {
    /// The static configurations of the unstaking graph that are inherent to the protocol.
    pub protocol_params: ProtocolParams,
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, Network, relative};
    use strata_bridge_test_utils::bridge_fixtures::TEST_MAGIC_BYTES;

    use super::*;

    /// `Network` and `MagicBytes` serialize differently depending on `is_human_readable`, and this
    /// config is persisted with postcard (non-human-readable). An upstream bump that switched
    /// either to a string-only impl would otherwise only surface when a node failed to recover its
    /// state machines.
    #[test]
    fn postcard_roundtrip() {
        let cfg = StakeSMCfg {
            protocol_params: ProtocolParams {
                network: Network::Regtest,
                magic_bytes: TEST_MAGIC_BYTES.into(),
                unstaking_timelock: relative::Height::from_height(144),
                stake_amount: Amount::from_sat(100_000_000),
            },
        };

        let bytes = postcard::to_allocvec(&cfg).expect("config must serialize");
        let decoded: StakeSMCfg = postcard::from_bytes(&bytes).expect("config must deserialize");

        assert_eq!(cfg, decoded);
    }
}
