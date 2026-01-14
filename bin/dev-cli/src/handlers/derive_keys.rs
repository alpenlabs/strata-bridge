//! Derives operator keys from a seed and outputs a valid keys.json entry.
//!
//! This uses the same derivation as the secret-service to ensure keys match.

use anyhow::{bail, Result};
use bitcoin::{bip32::Xpriv, hex::DisplayHex, Network};
use libp2p_identity::ed25519::{Keypair as EdKeypair, SecretKey as EdSecretKey};
use strata_bridge_key_deriv::{Musig2Keys, WalletKeys};
use strata_key_derivation::operator::OperatorKeys;

use crate::cli::DeriveKeysArgs;

/// Handles the derive-keys command.
pub(crate) fn handle_derive_keys(args: DeriveKeysArgs) -> Result<()> {
    let seed_hex = &args.seed;

    // Parse the seed
    let seed_bytes = hex::decode(seed_hex)?;

    if seed_bytes.len() != 32 {
        bail!(
            "Seed must be exactly 32 bytes (64 hex chars), got {} bytes",
            seed_bytes.len()
        );
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    // Derive keys using OperatorKeys from strata-key-derivation
    let xpriv = Xpriv::new_master(Network::Regtest, &seed)?;
    let keys = OperatorKeys::new(&xpriv)?;
    let base_xpriv = keys.base_xpriv();

    // Derive wallet keys using key-deriv crate
    let wallet_keys = WalletKeys::derive(base_xpriv)?;
    let general_wallet = wallet_keys
        .general_p2tr_address(Network::Regtest)
        .to_string();
    let stake_chain_wallet = wallet_keys
        .stakechain_p2tr_address(Network::Regtest)
        .to_string();

    // Derive MuSig2 keys using key-deriv crate
    let musig2_keys = Musig2Keys::derive(base_xpriv)?;
    let musig2_pubkey_hex = musig2_keys.pubkey().serialize().to_lower_hex_string();

    // P2P_KEY: ed25519 key from message signing key
    let msg_signing_key = keys.message_signing_key();
    let mut key_bytes = msg_signing_key.to_bytes();
    let ed_secret = EdSecretKey::try_from_bytes(&mut key_bytes)?;
    let ed_keypair = EdKeypair::from(ed_secret);
    let p2p_pubkey = ed_keypair.public().to_bytes().to_lower_hex_string();

    // Output the JSON entry
    println!(
        r#"{{
    "SEED": "{}",
    "GENERAL_WALLET": "{}",
    "STAKE_CHAIN_WALLET": "{}",
    "MUSIG2_KEY": "{}",
    "P2P_KEY": "{}"
}}"#,
        seed.to_lower_hex_string(),
        general_wallet,
        stake_chain_wallet,
        musig2_pubkey_hex,
        p2p_pubkey
    );

    Ok(())
}
