use bitcoin::{Network, ScriptBuf};
use secp256k1::XOnlyPublicKey;
use strata_bridge_primitives::scripts::prelude::*;

/// Connector output from the Claim transaction that is used for slashing.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorC1 {
    n_of_n_agg_pubkey: XOnlyPublicKey,
    network: Network,
}

impl ConnectorC1 {
    /// Constructs a new instance of this connector.
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
        }
    }

    /// Constructs the locking script for this connector.
    pub fn generate_locking_script(&self) -> ScriptBuf {
        let (taproot_address, _) = create_taproot_addr(
            &self.network,
            SpendPath::KeySpend {
                internal_key: self.n_of_n_agg_pubkey,
            },
        )
        .expect("should be able to create taproot address");

        taproot_address.script_pubkey()
    }
}
