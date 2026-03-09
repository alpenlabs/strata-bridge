pub(crate) mod envelope;
pub(crate) mod mock_checkpoint;

pub(crate) use mock_checkpoint::handle_create_and_publish_mock_checkpoint;

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use ssz::Encode;
    use strata_l1_txfmt::MagicBytes;

    use super::{envelope::build_and_broadcast_envelope_tx, mock_checkpoint::CheckpointTestHarness};

    /// Checkpoint v0 subprotocol ID (from strata-asm-txs-checkpoint constants).
    const CHECKPOINT_V0_SUBPROTOCOL_ID: u8 = 1;
    /// OL STF checkpoint tx type.
    const OL_STF_CHECKPOINT_TX_TYPE: u8 = 1;

    /// End-to-end test: creates a mock signed checkpoint payload and posts it
    /// via the taproot envelope to a regtest bitcoind.
    ///
    /// Run: `cargo test -p dev-cli -- --ignored test_mock_checkpoint_envelope_e2e`
    #[test]
    #[ignore = "requires running regtest bitcoind"]
    fn test_mock_checkpoint_envelope_e2e() {
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
        let harness = CheckpointTestHarness::new_with_genesis_height(genesis_height);
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
