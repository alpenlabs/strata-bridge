use anyhow::{bail, Context, Result};
use ssz::Encode;
use strata_l1_txfmt::MagicBytes;
use tracing::info;

use crate::{cli::CreateAndPublishMockCheckpointArgs, handlers::checkpoint::constants::BRIDGE_TAG};

mod constants;
pub(crate) mod envelope;
pub(crate) mod mock_checkpoint;

use strata_asm_txs_checkpoint::{CHECKPOINT_SUBPROTOCOL_ID, OL_STF_CHECKPOINT_TX_TYPE};

pub(crate) async fn handle_create_and_publish_mock_checkpoint(
    args: CreateAndPublishMockCheckpointArgs,
) -> Result<()> {
    if args.ol_end_slot < args.ol_start_slot {
        bail!(
            "ol_end_slot ({}) must be >= ol_start_slot ({})",
            args.ol_end_slot,
            args.ol_start_slot
        );
    }

    // Connect to bitcoind.
    let btc_client = bitcoincore_rpc::Client::new(
        &args.btc_args.url,
        bitcoincore_rpc::Auth::UserPass(args.btc_args.user.clone(), args.btc_args.pass.clone()),
    )
    .context("failed to connect to bitcoind")?;

    // Build mock checkpoint.
    let builder = mock_checkpoint::MockCheckpointBuilder::new();
    let (prev_tip, new_tip) = builder.gen_tips(
        args.epoch,
        args.genesis_l1_height,
        args.ol_start_slot,
        args.ol_end_slot,
    );
    let payload = builder.build_payload(&prev_tip, &new_tip, args.num_withdrawals);
    let signed_payload = builder.sign_payload(payload);

    // Encode and broadcast via taproot envelope.
    let encoded_checkpoint = signed_payload.as_ssz_bytes();
    info!(
        epoch = new_tip.epoch,
        num_withdrawals = args.num_withdrawals,
        payload_size = encoded_checkpoint.len(),
        "broadcasting mock checkpoint"
    );

    let magic: MagicBytes = BRIDGE_TAG.parse().expect("valid magic bytes");
    let reveal_txid = envelope::build_and_broadcast_envelope_tx(
        &btc_client,
        magic,
        CHECKPOINT_SUBPROTOCOL_ID,
        OL_STF_CHECKPOINT_TX_TYPE,
        &encoded_checkpoint,
        args.network,
    )
    .context("failed to broadcast checkpoint envelope")?;

    info!(%reveal_txid, "mock checkpoint published");
    Ok(())
}
