use bitcoin::{psbt::Input, Address, Network};
use secp256k1::{schnorr::Signature, XOnlyPublicKey};
use strata_bridge_primitives::scripts::prelude::*;

/// The connector to move the operator's stake across transactions.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorS {
    /// The N-of-N aggregated public key for the operator set.
    n_of_n_agg_pubkey: XOnlyPublicKey,

    /// The bitcoin network on which the connector operates.
    network: Network,
}

impl ConnectorS {
    /// Creates a new `ConnectorS` with the given N-of-N aggregated public key and the
    /// bitcoin network.
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
        }
    }

    /// Creates a taproot address with key spend path for the given operator set.
    pub fn create_taproot_address(&self) -> Address {
        let (addr, _spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::KeySpend {
                internal_key: self.n_of_n_agg_pubkey,
            },
        )
        .expect("must be able to create taproot address");

        addr
    }

    /// Finalizes a psbt input where this connector is used with the provided signature.
    ///
    /// # Note
    ///
    /// This method does not check if the signature is valid for the input. It is the caller's
    /// responsibility to ensure that the signature is valid.
    ///
    /// If the psbt input is already in the final state, then this method overrides the signature.
    pub fn create_tx_input(&self, signature: Signature, input: &mut Input) {
        finalize_input(input, [signature.as_ref()]);
    }
}
