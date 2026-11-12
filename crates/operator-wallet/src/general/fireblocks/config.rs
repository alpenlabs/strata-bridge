//! The connection and identity configuration of a Fireblocks vault account.

use std::fmt;

use bdk_wallet::bitcoin::secp256k1::PublicKey;

/// Connection + identity configuration for a Fireblocks BTC vault account.
pub struct FireblocksConfig {
    /// API host root, **without** the `/v1` path segment, e.g. `https://api.fireblocks.io`.
    /// Requests append `/v1/<path>` themselves so the JWT `uri` claim and the request URL
    /// stay in lockstep. [`FireblocksSigner::new`](super::FireblocksSigner::new) rejects anything
    /// but a bare `https` origin.
    pub base_url: String,
    /// Fireblocks API key (sent as the `X-API-Key` header).
    pub api_key: String,
    /// Vault account id holding the BTC asset.
    pub vault_account_id: String,
    /// Asset id for the network: `BTC` on mainnet, and on a test network the id that the vault
    /// shows. The vendor gives no fixed id per test network.
    pub asset_id: String,
    /// Public key of the default address of the vault account. It defines the P2WPKH script that
    /// the node tracks, and that script is the operator's receive and change address.
    /// [`CheckedVault::check`](super::CheckedVault::check) rejects a key that the vault does not
    /// hold.
    pub vault_pubkey: PublicKey,
}

impl fmt::Debug for FireblocksConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact the API key; everything else is non-secret operational config.
        f.debug_struct("FireblocksConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .field("vault_account_id", &self.vault_account_id)
            .field("asset_id", &self.asset_id)
            .field("vault_pubkey", &self.vault_pubkey)
            .finish()
    }
}
