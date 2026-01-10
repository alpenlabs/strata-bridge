//! Derives operator keys from a seed and outputs a valid keys.json entry.
//!
//! This uses the same derivation as the secret-service to ensure keys match.

use anyhow::{bail, Result};
use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Xpriv},
    hex::DisplayHex,
    key::TapTweak,
    Address, Network,
};
use libp2p_identity::ed25519::{Keypair as EdKeypair, SecretKey as EdSecretKey};
use secp256k1::SECP256K1;
use strata_bridge_primitives::secp::EvenSecretKey;
use strata_key_derivation::operator::OperatorKeys;

use crate::cli::DeriveKeysArgs;

/// Path for the Musig2 key (from secret-service paths.rs)
fn musig2_key_path() -> DerivationPath {
    vec![
        ChildNumber::Hardened { index: 20 },
        ChildNumber::Hardened { index: 101 },
    ]
    .into()
}

/// Path for the general wallet key (from secret-service paths.rs)
fn general_wallet_key_path() -> DerivationPath {
    vec![
        ChildNumber::Hardened { index: 20 },
        ChildNumber::Hardened { index: 102 },
    ]
    .into()
}

/// Path for the stakechain wallet key (from secret-service paths.rs)
fn stakechain_wallet_key_path() -> DerivationPath {
    vec![
        ChildNumber::Hardened { index: 20 },
        ChildNumber::Hardened { index: 103 },
    ]
    .into()
}

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

    // GENERAL_WALLET: derived from base_xpriv at GENERAL_WALLET_KEY_PATH
    let general_child = base_xpriv.derive_priv(SECP256K1, &general_wallet_key_path())?;
    let general_kp = secp256k1::Keypair::from_secret_key(
        SECP256K1,
        &EvenSecretKey::from(general_child.private_key),
    );
    let (general_tweaked, _) = general_kp.x_only_public_key().0.tap_tweak(SECP256K1, None);
    let general_wallet = Address::p2tr_tweaked(general_tweaked, Network::Regtest).to_string();

    // STAKE_CHAIN_WALLET: derived from base_xpriv at STAKECHAIN_WALLET_KEY_PATH
    let stake_child = base_xpriv.derive_priv(SECP256K1, &stakechain_wallet_key_path())?;
    let stake_kp = secp256k1::Keypair::from_secret_key(
        SECP256K1,
        &EvenSecretKey::from(stake_child.private_key),
    );
    let (stake_tweaked, _) = stake_kp.x_only_public_key().0.tap_tweak(SECP256K1, None);
    let stake_chain_wallet = Address::p2tr_tweaked(stake_tweaked, Network::Regtest).to_string();

    // MUSIG2_KEY: derived from base_xpriv at MUSIG2_KEY_PATH
    let musig2_child = base_xpriv.derive_priv(SECP256K1, &musig2_key_path())?;
    let musig2_kp = secp256k1::Keypair::from_secret_key(
        SECP256K1,
        &EvenSecretKey::from(musig2_child.private_key),
    );
    let musig2_pubkey_hex = musig2_kp
        .x_only_public_key()
        .0
        .serialize()
        .to_lower_hex_string();

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
