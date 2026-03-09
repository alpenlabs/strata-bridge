use anyhow::{Context, Result};
use bitcoin::bip32::Xpriv;
use ssz::Encode;
use strata_l1_txfmt::MagicBytes;

use crate::cli::CreateAndPublishMockCheckpointArgs;

pub(crate) mod envelope;
pub(crate) mod mock_checkpoint;

/// Checkpoint v0 subprotocol ID (from strata-asm-txs-checkpoint constants).
const CHECKPOINT_V0_SUBPROTOCOL_ID: u8 = 1;
/// OL STF checkpoint tx type.
const OL_STF_CHECKPOINT_TX_TYPE: u8 = 1;

/// Keys file format for `keys.json`.
#[derive(serde::Deserialize)]
struct KeysFile {
    #[allow(dead_code)]
    pk: String,
    sk: String,
}

pub(crate) async fn handle_create_and_publish_mock_checkpoint(
    args: CreateAndPublishMockCheckpointArgs,
) -> Result<()> {
    // Load keys from file.
    let keys_data = std::fs::read_to_string(&args.keys_path)
        .with_context(|| format!("failed to read keys file: {:?}", args.keys_path))?;
    let keys: KeysFile =
        serde_json::from_str(&keys_data).context("failed to parse keys.json")?;
    let xpriv: Xpriv = keys.sk.parse().context("invalid xpriv in keys.json sk field")?;

    // Connect to bitcoind.
    let btc_client = bitcoincore_rpc::Client::new(
        &args.btc_args.url,
        bitcoincore_rpc::Auth::UserPass(args.btc_args.user.clone(), args.btc_args.pass.clone()),
    )
    .context("failed to connect to bitcoind")?;

    // Build mock checkpoint.
    let harness =
        mock_checkpoint::CheckpointTestHarness::new_with_genesis_height(args.genesis_l1_height, &xpriv);
    let new_tip = harness.gen_new_tip();
    let payload = harness.build_payload_with_tip(new_tip, args.num_withdrawals);
    let signed_payload = harness.sign_payload(payload);

    // Encode and broadcast via taproot envelope.
    let encoded = signed_payload.as_ssz_bytes();
    eprintln!(
        "broadcasting mock checkpoint: epoch={}, num_withdrawals={}, payload_size={}",
        new_tip.epoch, args.num_withdrawals, encoded.len()
    );

    let magic: MagicBytes = "ALPN".parse().expect("valid magic bytes");
    let reveal_txid = envelope::build_and_broadcast_envelope_tx(
        &btc_client,
        magic,
        CHECKPOINT_V0_SUBPROTOCOL_ID,
        OL_STF_CHECKPOINT_TX_TYPE,
        &encoded,
    )
    .context("failed to broadcast checkpoint envelope")?;

    eprintln!("mock checkpoint published: reveal_txid={reveal_txid}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::bip32::Xpriv;
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use ssz::Encode;
    use strata_l1_txfmt::MagicBytes;

    use super::{
        envelope::build_and_broadcast_envelope_tx, mock_checkpoint::CheckpointTestHarness,
        CHECKPOINT_V0_SUBPROTOCOL_ID, OL_STF_CHECKPOINT_TX_TYPE,
    };

    /// Test sequencer xpriv (regtest only).
    const TEST_XPRIV: &str = "tprv8ezKDhpQHojBcUwXVZHBHBMg3QJQieAneQt9kkSMBoxdWdfBi1oBTiDev4J1ebeWH9hVV64fDeddyaLjMe7tjuS16QKPwykFAAiM66RcZWi";

    /// End-to-end test: creates a mock signed checkpoint payload and posts it
    /// via the taproot envelope to a regtest bitcoind.
    ///
    /// Run: `cargo test -p dev-cli -- --ignored test_mock_checkpoint_envelope_e2e`
    #[test]
    #[ignore = "requires running regtest bitcoind"]
    fn test_mock_checkpoint_envelope_e2e() {
        let xpriv: Xpriv = TEST_XPRIV.parse().expect("valid test xpriv");

        let client = Client::new(
            "http://localhost:18443/wallet/default",
            Auth::UserPass("rpcuser".into(), "rpcpassword".into()),
        )
        .expect("failed to create rpc client");

        // Ensure the wallet has funds
        let address = client
            .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
            .expect("failed to get address")
            .assume_checked();
        client
            .generate_to_address(110, &address)
            .expect("failed to mine blocks");

        // Build a mock signed checkpoint with 3 withdrawal logs
        let genesis_height = 110;
        let harness = CheckpointTestHarness::new_with_genesis_height(genesis_height, &xpriv);
        let new_tip = harness.gen_new_tip();
        let payload = harness.build_payload_with_tip(new_tip, 3);
        let signed_payload = harness.sign_payload(payload);
        let envelope_bytes = signed_payload.as_ssz_bytes();

        // Post via envelope
        let magic: MagicBytes = "ALPN".parse().expect("valid magic");
        let txid = build_and_broadcast_envelope_tx(
            &client,
            magic,
            CHECKPOINT_V0_SUBPROTOCOL_ID,
            OL_STF_CHECKPOINT_TX_TYPE,
            &envelope_bytes,
        )
        .expect("envelope tx should succeed");

        // Mine and confirm
        let block_hashes = client
            .generate_to_address(1, &address)
            .expect("failed to mine block");

        let tx_info = client
            .get_raw_transaction_info(&txid, block_hashes.first().map(|h| h))
            .expect("failed to get tx info");
        assert!(
            tx_info.confirmations.unwrap_or(0) > 0,
            "reveal tx should be confirmed"
        );
    }
}
