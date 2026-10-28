//! Admin-tool settings and Bitcoin Core authentication.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use bitcoin::{hashes::sha256, XOnlyPublicKey};
use bitcoincore_rpc::{Auth, Client};
use serde::Deserialize;
use strata_bridge_admin_signing::AdminSigningParams;
use strata_bridge_common::params::Params;

/// Claim's internal key and the RPC connection used by this binary.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Untweaked N-of-N internal public key.
    pub n_of_n_pubkey: XOnlyPublicKey,
    /// Read-only Bitcoin Core connection.
    pub rpc: RpcConfig,
}

impl Config {
    /// Reads this tool's TOML configuration.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("could not read config {}", path.display()))?;
        toml::from_str(&text).context("invalid admin-tool TOML config")
    }

    /// Combines bridge params with the claim-specific connector information.
    pub(crate) fn signing_params(
        &self,
        params: &Params,
        unstaking_hash: sha256::Hash,
    ) -> AdminSigningParams {
        AdminSigningParams {
            network: params.network,
            n_of_n_pubkey: self.n_of_n_pubkey,
            admin_pubkeys: params.keys.admin.pubkeys.clone(),
            threshold: params.keys.admin.threshold,
            unstaking_hash,
        }
    }
}

/// Bitcoin Core RPC connection local to this binary.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RpcConfig {
    /// Bitcoin Core HTTP RPC endpoint.
    pub url: String,
    /// RPC username.
    pub username: String,
    /// RPC password.
    pub password: String,
}

impl RpcConfig {
    /// Connects using username/password authentication.
    pub(crate) fn client(&self) -> Result<Client> {
        let auth = Auth::UserPass(self.username.clone(), self.password.clone());
        Client::new(&self.url, auth).context("could not initialize Bitcoin Core RPC client")
    }
}
