//! Shared public signing parameters and Bitcoin Core authentication.

use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use bitcoin::{hashes::sha256, Network, XOnlyPublicKey};
use bitcoincore_rpc::{Auth, Client};
use serde::Deserialize;
use strata_bridge_admin_signing::AdminSigningParams;

/// Settings shared by the admins signing this claim.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Bitcoin network; must match the connected node.
    pub network: Network,
    /// Untweaked N-of-N internal public key.
    pub n_of_n_pubkey: XOnlyPublicKey,
    /// Admin public keys in the target claim's script order.
    pub admin_pubkeys: Vec<XOnlyPublicKey>,
    /// Required number of distinct admin signatures.
    pub threshold: usize,
    /// Read-only Bitcoin Core connection.
    pub rpc: RpcConfig,
}

impl Config {
    /// Reads the configuration; relative cookie paths resolve against this file.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("could not read config {}", path.display()))?;
        let mut config: Self = toml::from_str(&text).context("invalid admin-tool TOML config")?;
        if let Some(cookie) = &mut config.rpc.cookie_file {
            if cookie.is_relative() {
                *cookie = path.parent().unwrap_or(Path::new(".")).join(&*cookie);
            }
        }
        Ok(config)
    }

    /// Combines shared settings with the claim-specific public unstaking hash.
    pub(crate) fn signing_params(&self, unstaking_hash: sha256::Hash) -> AdminSigningParams {
        AdminSigningParams {
            network: self.network,
            n_of_n_pubkey: self.n_of_n_pubkey,
            admin_pubkeys: self.admin_pubkeys.clone(),
            threshold: self.threshold,
            unstaking_hash,
        }
    }
}

/// RPC endpoint with either cookie authentication or a username/password pair.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RpcConfig {
    /// Bitcoin Core HTTP RPC endpoint.
    pub url: String,
    /// Cookie file; mutually exclusive with username and password.
    pub cookie_file: Option<std::path::PathBuf>,
    /// RPC username when not using a cookie.
    pub username: Option<String>,
    /// RPC password when not using a cookie.
    pub password: Option<String>,
}

impl RpcConfig {
    /// Connects using exactly one complete authentication method.
    pub(crate) fn client(&self) -> Result<Client> {
        let auth = match (&self.cookie_file, &self.username, &self.password) {
            (Some(cookie), None, None) => Auth::CookieFile(cookie.clone()),
            (None, Some(user), Some(password)) => Auth::UserPass(user.clone(), password.clone()),
            _ => bail!("RPC config requires either cookie_file or username and password"),
        };
        Client::new(&self.url, auth).context("could not initialize Bitcoin Core RPC client")
    }
}
