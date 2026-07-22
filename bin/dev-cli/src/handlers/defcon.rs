//! Publishes ASM admin (governance) transactions.
//!
//! Currently only Defcon1, the Security Council's immediate safe-harbour activation used to
//! trigger the hard bridge upgrade in functional tests.

use anyhow::{Context, Result};
use bitcoin::bip32::Xpriv;
use bitcoincore_rpc::{Auth, Client};
use ssz::Encode;
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_asm_proto_admin_txs::{
    actions::{updates::Defcon1Update, MultisigAction, UpdateAction},
    constants::ADMINISTRATION_SUBPROTOCOL_ID,
    parser::SignedPayload,
    test_utils::create_signature_set,
};
use strata_bridge_key_deriv::{Musig2Keys, OperatorKeys};
use strata_bridge_primitives::constants::BRIDGE_TAG;
use strata_l1_txfmt::MagicBytes;
use tracing::info;

use crate::{cli::Defcon1Args, handlers::checkpoint::envelope::build_and_broadcast_envelope_tx};

/// Handles the defcon1 command: builds, signs, and broadcasts the admin envelope tx.
///
/// Test deployments configure the security council as the operators' musig2 keys with
/// threshold 1, so the council signer is derived exactly like an operator key (signer
/// index 0 = operator 0).
pub(crate) fn handle_defcon1(args: Defcon1Args) -> Result<()> {
    let client = Client::new(
        &args.btc_args.url,
        Auth::UserPass(args.btc_args.user.clone(), args.btc_args.pass.clone()),
    )
    .context("failed to create bitcoin client")?;

    let seed_bytes = hex::decode(&args.seed).context("invalid hex seed")?;
    let xpriv = Xpriv::new_master(args.network, &seed_bytes)
        .context("failed to derive master key from seed")?;
    let operator_keys = OperatorKeys::new(&xpriv).context("failed to derive operator keys")?;
    let musig2 =
        Musig2Keys::derive(operator_keys.base_xpriv()).context("failed to derive musig2 keys")?;
    let council_sk = musig2.keypair.secret_key();

    let action = MultisigAction::Update(UpdateAction::Defcon1(Defcon1Update));
    let signatures = create_signature_set(&[council_sk], &[0], &action, args.seqno);
    let payload = SignedPayload::new(args.seqno, action, signatures);

    let magic: MagicBytes = BRIDGE_TAG.parse().expect("valid magic bytes");
    let txid = build_and_broadcast_envelope_tx(
        &client,
        magic,
        ADMINISTRATION_SUBPROTOCOL_ID,
        AdminTxType::Update(UpdateTxType::Defcon1).into(),
        &payload.as_ssz_bytes(),
        args.network,
    )
    .context("failed to broadcast defcon1 envelope tx")?;

    info!(event = "defcon1 admin tx broadcast", %txid);
    println!("txid = {txid}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use strata_crypto::{
        keys::compressed::CompressedPublicKey,
        threshold_signature::{verify_threshold_signatures, ThresholdConfig},
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
        let council_key = CompressedPublicKey::from_slice(&compressed).unwrap();
        let config = ThresholdConfig::try_new(vec![council_key], NonZero::new(1).unwrap()).unwrap();

        let seqno = 1;
        let action = MultisigAction::Update(UpdateAction::Defcon1(Defcon1Update));
        let signatures = create_signature_set(&[council_sk], &[0], &action, seqno);

        let message_hash =
            strata_asm_proto_admin_txs::signing_message::SigningMessage::for_action(&action, seqno)
                .compute_sighash();

        verify_threshold_signatures(&config, signatures.signatures(), &message_hash.into())
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
        let council_key = CompressedPublicKey::from_slice(&compressed).unwrap();
        let config = ThresholdConfig::try_new(vec![council_key], NonZero::new(1).unwrap()).unwrap();

        let seqno = 1;
        let action = MultisigAction::Update(UpdateAction::Defcon1(Defcon1Update));
        let signatures = create_signature_set(&[council_sk], &[0], &action, seqno);

        let message_hash =
            strata_asm_proto_admin_txs::signing_message::SigningMessage::for_action(&action, seqno)
                .compute_sighash();

        verify_threshold_signatures(&config, signatures.signatures(), &message_hash.into())
            .expect("defcon1 signature must verify for fixture operator 0");
    }
}
