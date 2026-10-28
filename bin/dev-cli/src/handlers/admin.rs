//! Publishes ASM admin (governance) transactions.
//!
//! Currently only Defcon1, the Security Council's immediate safe-harbour activation used to
//! trigger the hard bridge upgrade in functional tests.

use anyhow::{Context, Result};
use bitcoin::{bip32::Xpriv, Network, Txid};
use bitcoincore_rpc::{Auth, Client};
use secp256k1::{rand::rngs::OsRng, Keypair, SecretKey, SECP256K1};
use strata_asm_proto_admin_txs::{
    actions::{updates::Defcon1Update, MultisigAction, UpdateAction},
    parser::SignedPayload,
    test_utils::create_signature_set,
};
use strata_bridge_key_deriv::{Musig2Keys, OperatorKeys};
use strata_bridge_primitives::constants::BRIDGE_TAG;
use strata_l1_txfmt::MagicBytes;
use tracing::info;

use crate::{
    cli::{BtcArgs, Defcon1Args},
    handlers::checkpoint::envelope::build_and_broadcast_envelope_tx,
};

/// Handles the defcon1 command: builds, signs, and broadcasts the admin envelope tx.
pub(crate) fn handle_defcon1(args: Defcon1Args) -> Result<()> {
    let action = MultisigAction::Update(UpdateAction::Defcon1(Defcon1Update));
    let txid = sign_and_broadcast_admin_action(
        &args.btc_args,
        &args.seed,
        action,
        args.seqno,
        args.network,
    )
    .context("failed to broadcast defcon1 envelope tx")?;

    info!(event = "defcon1 admin tx broadcast", %txid);
    println!("txid = {txid}");

    Ok(())
}

/// Signs `action` as the admin signer derived from `seed` and broadcasts it in an SPS-50
/// envelope tx.
///
/// Test deployments configure every admin role as the operators' musig2 keys with threshold 1,
/// so the signer is derived exactly like an operator key (signer index 0 = operator 0).
fn sign_and_broadcast_admin_action(
    btc_args: &BtcArgs,
    seed: &str,
    action: MultisigAction,
    seqno: u64,
    network: Network,
) -> Result<Txid> {
    let client = Client::new(
        &btc_args.url,
        Auth::UserPass(btc_args.user.clone(), btc_args.pass.clone()),
    )
    .context("failed to create bitcoin client")?;

    let tag = action.tag();
    let payload = signed_admin_payload(seed, action, seqno, network)?;

    let magic: MagicBytes = BRIDGE_TAG.parse().expect("valid magic bytes");
    let envelope_keypair = Keypair::new(SECP256K1, &mut OsRng);
    build_and_broadcast_envelope_tx(
        &client,
        &envelope_keypair,
        magic,
        tag.subproto_id(),
        tag.tx_type(),
        &payload.into_envelope_bytes(),
        network,
    )
}

/// Signs `action` at `seqno` as the admin signer derived from `seed`.
fn signed_admin_payload(
    seed: &str,
    action: MultisigAction,
    seqno: u64,
    network: Network,
) -> Result<SignedPayload> {
    let signer = derive_admin_signer(seed, network)?;
    let signatures = create_signature_set(&[signer], &[0], &action, seqno, network);
    Ok(SignedPayload::new(seqno, action, signatures))
}

/// Derives the admin signing key from an operator's hex-encoded seed.
fn derive_admin_signer(seed: &str, network: Network) -> Result<SecretKey> {
    let seed_bytes = hex::decode(seed).context("invalid hex seed")?;
    let xpriv =
        Xpriv::new_master(network, &seed_bytes).context("failed to derive master key from seed")?;
    let operator_keys = OperatorKeys::new(&xpriv).context("failed to derive operator keys")?;
    let musig2 =
        Musig2Keys::derive(operator_keys.base_xpriv()).context("failed to derive musig2 keys")?;
    Ok(musig2.keypair.secret_key())
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use bitcoin::{Network, PublicKey};
    use strata_asm_admin_threshold_sig::{
        verify_threshold_signatures, P2wpkhAddress, ThresholdConfig,
    };

    use super::*;

    /// Signing with the derived musig2 secret must verify against the council key the test
    /// params derive from it (`02` || x-only), mirroring `build_asm_params` in the fn tests.
    #[test]
    fn defcon1_signature_verifies_against_derived_council_key() {
        let seed = [7u8; 32];
        let xpriv = Xpriv::new_master(bitcoin::Network::Regtest, &seed).unwrap();
        let operator_keys = OperatorKeys::new(&xpriv).unwrap();
        let musig2 = Musig2Keys::derive(operator_keys.base_xpriv()).unwrap();
        let council_sk = musig2.keypair.secret_key();

        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&musig2.pubkey().serialize());
        let council_key = PublicKey::from_slice(&compressed).unwrap().inner;
        let config = ThresholdConfig::try_new(
            vec![P2wpkhAddress::from_pubkey(&council_key)],
            NonZero::new(1).unwrap(),
        )
        .unwrap();

        let seqno = 1;
        let action = MultisigAction::Update(UpdateAction::Defcon1(Defcon1Update));
        let signatures =
            create_signature_set(&[council_sk], &[0], &action, seqno, Network::Regtest);

        let message_hash = strata_asm_proto_admin_txs::signing_message::SigningMessage::for_action(
            &action,
            seqno,
            Network::Regtest,
        )
        .compute_sighash();

        verify_threshold_signatures(&config, signatures.signatures(), &message_hash.0)
            .expect("defcon1 signature must verify against the derived council key");
    }

    /// Same flow pinned against the committed fixture (operator 0 in
    /// `functional-tests/artifacts/keys.json`); fails if the fixture or derivation path drifts.
    #[test]
    fn defcon1_signature_verifies_for_fixture_operator_0() {
        let seed = hex::decode("195a61de8fdac38f9c97e493c03718c98a3c85a977b49192ceac32e429f6c409")
            .unwrap();
        let xpriv = Xpriv::new_master(bitcoin::Network::Regtest, &seed).unwrap();
        let operator_keys = OperatorKeys::new(&xpriv).unwrap();
        let musig2 = Musig2Keys::derive(operator_keys.base_xpriv()).unwrap();
        assert_eq!(
            hex::encode(musig2.pubkey().serialize()),
            "ac407ba319846e25d69c1c0cb2a845ab75ef93ad2e9e846cdc5cf6da766e00b2",
            "derived musig2 key must match the fixture"
        );
        let council_sk = musig2.keypair.secret_key();

        let compressed =
            hex::decode("02ac407ba319846e25d69c1c0cb2a845ab75ef93ad2e9e846cdc5cf6da766e00b2")
                .unwrap();
        let council_key = PublicKey::from_slice(&compressed).unwrap().inner;
        let config = ThresholdConfig::try_new(
            vec![P2wpkhAddress::from_pubkey(&council_key)],
            NonZero::new(1).unwrap(),
        )
        .unwrap();

        let seqno = 1;
        let action = MultisigAction::Update(UpdateAction::Defcon1(Defcon1Update));
        let signatures =
            create_signature_set(&[council_sk], &[0], &action, seqno, Network::Regtest);

        let message_hash = strata_asm_proto_admin_txs::signing_message::SigningMessage::for_action(
            &action,
            seqno,
            Network::Regtest,
        )
        .compute_sighash();

        verify_threshold_signatures(&config, signatures.signatures(), &message_hash.0)
            .expect("defcon1 signature must verify for fixture operator 0");
    }
}
