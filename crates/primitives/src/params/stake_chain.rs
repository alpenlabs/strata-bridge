//! Parameters for the Stake Chain protocol such as the staking amount, `n_of_n_agg_pubkey`, network
//! and `delta`.

use bitcoin::{relative, Amount, Network, XOnlyPublicKey};

/// The Stake Chain public parameters that are inherent from the protocol and does not need to be
/// interactively shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakeChainParams {
    /// The Staking [`Amount`].
    // TODO: make this configurable with a fallback const `D_BTC`.
    pub stake_amount: Amount,

    /// The n-of-n aggregate public key.
    pub n_of_n_agg_pubkey: XOnlyPublicKey,

    /// The delta value used for the stake chain.
    // TODO: make this configurable with a fallback const like FINALITY_DEPTH to something like
    //       `6`.
    pub delta: relative::LockTime,

    /// The bitcoin network for the addresses generated by the connector.
    pub network: Network,
}
