//! Publishes ASM admin (governance) transactions used to drive the hard bridge upgrade in
//! tests: Defcon1 (security council) and the safe harbour address rotation (strata
//! administrator).

use anyhow::{ensure, Context, Result};
use bitcoin::{
    address::NetworkUnchecked, bip32::Xpriv, secp256k1::SecretKey, Address, Network, Txid,
};
use bitcoin_bosd::Descriptor;
use bitcoincore_rpc::{Auth, Client};
use ssz::Encode;
use strata_asm_admin_types::AdminTxType;
use strata_asm_bridge_types::SafeHarbourAddress;
use strata_asm_proto_admin_txs::{
    actions::{
        updates::{Defcon1Update, SafeHarbourAddressUpdate},
        MultisigAction, UpdateAction,
    },
    constants::ADMINISTRATION_SUBPROTOCOL_ID,
    parser::SignedPayload,
    signing_message::SigningMessage,
    test_utils::sign_ecdsa_bip137,
};
use strata_bridge_key_deriv::{Musig2Keys, OperatorKeys};
use strata_bridge_primitives::constants::BRIDGE_TAG;
use strata_crypto::threshold_signature::{IndexedSignature, SignatureSet};
use strata_l1_txfmt::MagicBytes;
use tracing::info;

use crate::{
    cli::{AdminTxArgs, BtcArgs, Defcon1Args, SafeHarbourAddressUpdateArgs},
    handlers::checkpoint::envelope::build_and_broadcast_envelope_tx,
};

/// Handles the defcon1 command: activates the safe harbour, freezing its current address.
pub(crate) fn handle_defcon1(args: Defcon1Args) -> Result<()> {
    let txid = publish_update(
        &args.admin,
        &args.btc_args,
        args.network,
        UpdateAction::Defcon1(Defcon1Update),
    )?;
    info!(event = "defcon1 admin tx broadcast", %txid);
    println!("txid = {txid}");
    Ok(())
}

/// Handles the safe-harbour-address-update command.
///
/// The ASM queues the update for its configured confirmation depth and rejects it once the
/// safe harbour is activated, so it must be enacted before Defcon1.
pub(crate) fn handle_safe_harbour_address_update(args: SafeHarbourAddressUpdateArgs) -> Result<()> {
    let address = parse_safe_harbour_address(args.address, args.network)?;
    let update = SafeHarbourAddressUpdate::new(address);
    let txid = publish_update(
        &args.admin,
        &args.btc_args,
        args.network,
        UpdateAction::SafeHarbourAddress(update),
    )?;
    info!(event = "safe harbour address update admin tx broadcast", %txid);
    println!("txid = {txid}");
    Ok(())
}

/// Converts a user-supplied address into the P2TR-only descriptor the ASM accepts.
fn parse_safe_harbour_address(
    address: Address<NetworkUnchecked>,
    network: Network,
) -> Result<SafeHarbourAddress> {
    let address = address
        .require_network(network)
        .context("address does not belong to --network")?;
    let descriptor = Descriptor::try_from(address).context("unsupported address type")?;
    SafeHarbourAddress::try_from(descriptor).context("safe harbour address must be P2TR")
}

/// Signs `update` with the configured signers and broadcasts it as an admin envelope tx.
///
/// Test deployments configure every multisig role as the operators' musig2 keys, so each
/// signer is derived exactly like an operator key. One `--seed` per signer (at least the
/// role's threshold); `--signer-idx` maps each to its key index when the seeds are not
/// simply members `0..n` in order.
fn publish_update(
    admin: &AdminTxArgs,
    btc_args: &BtcArgs,
    network: Network,
    update: UpdateAction,
) -> Result<Txid> {
    let client = Client::new(
        &btc_args.url,
        Auth::UserPass(btc_args.user.clone(), btc_args.pass.clone()),
    )
    .context("failed to create bitcoin client")?;

    let signer_indices: Vec<u8> = if admin.signer_idx.is_empty() {
        (0..admin.seed.len())
            .map(u8::try_from)
            .collect::<Result<_, _>>()
            .context("too many signers")?
    } else {
        ensure!(
            admin.signer_idx.len() == admin.seed.len(),
            "--signer-idx count ({}) must match --seed count ({})",
            admin.signer_idx.len(),
            admin.seed.len()
        );
        admin.signer_idx.clone()
    };
    let signers = signer_indices
        .into_iter()
        .zip(&admin.seed)
        .map(|(idx, seed)| Ok((idx, derive_signer_sk(seed, network)?)))
        .collect::<Result<Vec<_>>>()?;

    let tx_type = AdminTxType::Update(update.update_tx_type());
    let action = MultisigAction::Update(update);
    let signatures = sign_action(&action, admin.seqno, &signers)?;
    let payload = SignedPayload::new(admin.seqno, action, signatures);

    let magic: MagicBytes = BRIDGE_TAG.parse().expect("valid magic bytes");
    build_and_broadcast_envelope_tx(
        &client,
        magic,
        ADMINISTRATION_SUBPROTOCOL_ID,
        tx_type.into(),
        &payload.as_ssz_bytes(),
        network,
    )
    .context("failed to broadcast admin envelope tx")
}

/// Derives a multisig signer's secret key from an operator seed (its musig2 key).
fn derive_signer_sk(seed_hex: &str, network: Network) -> Result<SecretKey> {
    let seed_bytes = hex::decode(seed_hex).context("invalid hex seed")?;
    let xpriv =
        Xpriv::new_master(network, &seed_bytes).context("failed to derive master key from seed")?;
    let operator_keys = OperatorKeys::new(&xpriv).context("failed to derive operator keys")?;
    let musig2 =
        Musig2Keys::derive(operator_keys.base_xpriv()).context("failed to derive musig2 keys")?;
    Ok(musig2.keypair.secret_key())
}

/// Signs `action` with each `(key index, secret key)` pair.
fn sign_action(
    action: &MultisigAction,
    seqno: u64,
    signers: &[(u8, SecretKey)],
) -> Result<SignatureSet> {
    let digest: [u8; 32] = SigningMessage::for_action(action, seqno)
        .compute_sighash()
        .into();
    let signatures = signers
        .iter()
        .map(|(idx, sk)| IndexedSignature::new(*idx, sign_ecdsa_bip137(&digest, sk)))
        .collect();
    SignatureSet::new(signatures).context("invalid signature set")
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use bitcoin::secp256k1::SECP256K1;
    use strata_crypto::{
        keys::compressed::CompressedPublicKey,
        threshold_signature::{verify_threshold_signatures, ThresholdConfig},
    };

    use super::*;

    const SEQNO: u64 = 1;
    const SIGNET_P2TR: &str = "tb1ps82grza8santzw96u6502ylfwrv4tzv4aaq66f685fq6n8uzpwasa40ue7";
    const SIGNET_P2WPKH: &str = "tb1qxm2vqsfefgxhdyfupg6egztz6wqq4u7kw3z6rc";

    /// Multisig key as the fn-test params derive it from the operator's musig2 key
    /// (`02` || x-only), mirroring `build_asm_params`.
    fn council_key(sk: &SecretKey) -> CompressedPublicKey {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&sk.x_only_public_key(SECP256K1).0.serialize());
        CompressedPublicKey::from_slice(&compressed).unwrap()
    }

    fn defcon1_action() -> MultisigAction {
        MultisigAction::Update(UpdateAction::Defcon1(Defcon1Update))
    }

    fn safe_harbour_update_action() -> MultisigAction {
        let address =
            parse_safe_harbour_address(SIGNET_P2TR.parse().unwrap(), Network::Signet).unwrap();
        MultisigAction::Update(UpdateAction::SafeHarbourAddress(
            SafeHarbourAddressUpdate::new(address),
        ))
    }

    fn sighash(action: &MultisigAction) -> [u8; 32] {
        SigningMessage::for_action(action, SEQNO)
            .compute_sighash()
            .into()
    }

    /// Signing with the derived musig2 secret must verify against the council key the test
    /// params derive from it.
    #[test]
    fn defcon1_signature_verifies_against_derived_council_key() {
        let sk = derive_signer_sk(&hex::encode([7u8; 32]), Network::Regtest).unwrap();
        let config =
            ThresholdConfig::try_new(vec![council_key(&sk)], NonZero::new(1).unwrap()).unwrap();

        let action = defcon1_action();
        let signatures = sign_action(&action, SEQNO, &[(0, sk)]).unwrap();

        verify_threshold_signatures(&config, signatures.signatures(), &sighash(&action))
            .expect("defcon1 signature must verify against the derived council key");
    }

    /// Same flow pinned against the committed fixture (operator 0 in
    /// `functional-tests/artifacts/keys.json`); fails if the fixture or derivation path drifts.
    #[test]
    fn defcon1_signature_verifies_for_fixture_operator_0() {
        let sk = derive_signer_sk(
            "195a61de8fdac38f9c97e493c03718c98a3c85a977b49192ceac32e429f6c409",
            Network::Regtest,
        )
        .unwrap();
        let compressed =
            hex::decode("02ac407ba319846e25d69c1c0cb2a845ab75ef93ad2e9e846cdc5cf6da766e00b2")
                .unwrap();
        let fixture_key = CompressedPublicKey::from_slice(&compressed).unwrap();
        assert_eq!(
            council_key(&sk),
            fixture_key,
            "derived musig2 key must match the fixture"
        );
        let config = ThresholdConfig::try_new(vec![fixture_key], NonZero::new(1).unwrap()).unwrap();

        let action = defcon1_action();
        let signatures = sign_action(&action, SEQNO, &[(0, sk)]).unwrap();

        verify_threshold_signatures(&config, signatures.signatures(), &sighash(&action))
            .expect("defcon1 signature must verify for fixture operator 0");
    }

    /// A 2-of-3 council signed by non-contiguous members must verify, and a single signer
    /// must be rejected for falling short of the threshold.
    #[test]
    fn defcon1_threshold_2_verifies_with_explicit_signer_indices() {
        let sks: Vec<SecretKey> = (1u8..=3)
            .map(|b| derive_signer_sk(&hex::encode([b; 32]), Network::Regtest).unwrap())
            .collect();
        let keys = sks.iter().map(council_key).collect();
        let config = ThresholdConfig::try_new(keys, NonZero::new(2).unwrap()).unwrap();

        let action = defcon1_action();
        let signatures = sign_action(&action, SEQNO, &[(0, sks[0]), (2, sks[2])]).unwrap();
        verify_threshold_signatures(&config, signatures.signatures(), &sighash(&action))
            .expect("signers 0 and 2 must satisfy a 2-of-3 council");

        let short = sign_action(&action, SEQNO, &[(1, sks[1])]).unwrap();
        verify_threshold_signatures(&config, short.signatures(), &sighash(&action))
            .expect_err("one signer must not satisfy a 2-of-3 council");
    }

    /// The address rotation goes through the same threshold signing as Defcon1.
    #[test]
    fn safe_harbour_address_update_verifies_with_threshold_2() {
        let sks: Vec<SecretKey> = (1u8..=3)
            .map(|b| derive_signer_sk(&hex::encode([b; 32]), Network::Regtest).unwrap())
            .collect();
        let keys = sks.iter().map(council_key).collect();
        let config = ThresholdConfig::try_new(keys, NonZero::new(2).unwrap()).unwrap();

        let action = safe_harbour_update_action();
        let signatures = sign_action(&action, SEQNO, &[(0, sks[0]), (1, sks[1])]).unwrap();
        verify_threshold_signatures(&config, signatures.signatures(), &sighash(&action))
            .expect("signers 0 and 1 must satisfy a 2-of-3 administrator multisig");
    }

    /// Only P2TR destinations on the requested network are accepted.
    #[test]
    fn safe_harbour_address_parsing_enforces_p2tr_and_network() {
        parse_safe_harbour_address(SIGNET_P2TR.parse().unwrap(), Network::Signet)
            .expect("signet P2TR address accepted");
        parse_safe_harbour_address(SIGNET_P2WPKH.parse().unwrap(), Network::Signet)
            .expect_err("P2WPKH must be rejected");
        parse_safe_harbour_address(SIGNET_P2TR.parse().unwrap(), Network::Regtest)
            .expect_err("network mismatch must be rejected");
    }
}
