use std::str::FromStr;

use bitcoin::{base58, bip32::Xpriv, Address, Network};
use clap::Parser;
use corepc_node::serde_json;
use strata_key_derivation::sequencer::SequencerKeys;
use strata_primitives::{buf::Buf32, keys::ZeroizableXpriv};
use strata_state::bridge_state::DepositEntry;

#[derive(Clone, Debug)]
pub(crate) struct DepEntries(pub Vec<DepositEntry>);

impl DepEntries {
    pub(crate) fn into_inner(self) -> Vec<DepositEntry> {
        self.0
    }
}

/// Command line arguments.
#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
pub(crate) struct Args {
    /// Bitcoin RPC endpoint URL
    #[arg(long, default_value = "http://localhost:18444")]
    pub bitcoin_url: String,

    /// Bitcoin RPC username
    #[arg(long, default_value = "rpcuser")]
    pub bitcoin_username: String,

    /// Bitcoin RPC password
    #[arg(long, default_value = "rpcpassword")]
    pub bitcoin_password: String,

    /// Fee rate in sats/vbyte
    #[arg(long, default_value = "100")]
    pub fee_rate: u64,

    /// Sequencer address, to send reveal funds to
    #[arg(long, default_value = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", value_parser = validate_address)]
    pub sequencer_address: Address,

    /// Bitcoin network (mainnet, testnet, signet, regtest)
    #[arg(long, default_value = "regtest")]
    pub network: Network,

    /// DA tag
    #[arg(long, default_value = "alpn_da")]
    pub da_tag: String,

    /// Checkpoint tag
    #[arg(long, default_value = "alpn_ckpt")]
    pub checkpoint_tag: String,

    /// Sequencer private key (hex string, 32 bytes)
    #[arg(long, env = "SEQUENCER_PRIVATE_KEY", value_parser = validate_private_key)]
    pub sequencer_private_key: Buf32,

    /// Path to file containing JSON-serialized entries
    #[arg(long, value_parser = validate_deposit_entries)]
    pub deposit_entries: DepEntries,
}

pub(crate) fn validate_private_key(str_buf: &str) -> anyhow::Result<Buf32> {
    let buf = base58::decode_check(str_buf)?;
    let master_xpriv = ZeroizableXpriv::new(Xpriv::decode(&buf)?);

    // Actually do the key derivation from the root key and then derive the pubkey from that.
    let seq_keys = SequencerKeys::new(&master_xpriv)?;
    let seq_xpriv = seq_keys.derived_xpriv();

    Ok(Buf32::from(seq_xpriv.private_key.secret_bytes()))
}

/// Validate sequencer address. Assumes network checked.
fn validate_address(s: &str) -> Result<Address, String> {
    let addr = Address::from_str(s).map_err(|e| format!("Invalid bitcoin address: {e}"))?;
    Ok(addr.assume_checked())
}

/// Parse and validate deposit entries json file.
pub(crate) fn validate_deposit_entries(file_path: &str) -> Result<DepEntries, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let deposit_entries = serde_json::from_str(&content)
        .map_err(|e| format!("Deposit entries parse error in file {file_path}: {e}"))?;
    Ok(DepEntries(deposit_entries))
}
