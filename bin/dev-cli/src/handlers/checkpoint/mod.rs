use anyhow::{bail, Context, Result};
use ssz::Encode;
use strata_checkpoint_types_ssz::CheckpointPayload;
use strata_codec::{encode_to_vec, Varint};
use strata_l1_txfmt::MagicBytes;
use tracing::info;

use crate::{cli::CreateAndPublishMockCheckpointArgs, handlers::checkpoint::constants::BRIDGE_TAG};

mod constants;
pub(crate) mod envelope;
pub(crate) mod mock_checkpoint;

use strata_asm_txs_checkpoint::{CHECKPOINT_SUBPROTOCOL_ID, OL_STF_CHECKPOINT_TX_TYPE};

fn encode_checkpoint_payload(payload: &CheckpointPayload) -> Result<Vec<u8>> {
    let checkpoint_ssz = payload.as_ssz_bytes();
    let payload_len = Varint::new_usize(checkpoint_ssz.len())
        .context("checkpoint payload too large to encode as varint")?;
    let mut encoded_checkpoint =
        encode_to_vec(&payload_len).context("failed to encode checkpoint payload length")?;
    encoded_checkpoint.extend_from_slice(&checkpoint_ssz);
    Ok(encoded_checkpoint)
}

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

    // Connect to bitcoind using minreq transport so the Host header preserves the
    // original hostname, which is required when bitcoind sits behind a reverse proxy.
    let btc_client = crate::rpc::new_btc_client(&args.btc_args)
        .context("failed to connect to bitcoind")?;

    // Build mock checkpoint.
    let builder = mock_checkpoint::MockCheckpointBuilder::new();
    let (prev_tip, new_tip) = builder.gen_tips(
        args.epoch,
        args.genesis_l1_height,
        args.ol_start_slot,
        args.ol_end_slot,
    );
    let payload = builder.build_payload(
        &prev_tip,
        &new_tip,
        args.num_withdrawals,
        args.assignee_node_idx,
    );

    // Encode and broadcast via taproot envelope.
    let encoded_checkpoint = encode_checkpoint_payload(&payload)?;
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
