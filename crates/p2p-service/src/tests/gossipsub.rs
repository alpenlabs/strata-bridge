use bitcoin::{hashes::Hash, OutPoint, Txid};
use strata_bridge_common::logging::{self, LoggerConfig};
use strata_bridge_p2p_types::{
    NagRequest, NagRequestPayload, PayoutDescriptor, UnsignedGossipsubMsg,
};
use strata_bridge_primitives::types::{GraphIdx, P2POperatorPubKey};
use tokio::sync::oneshot;

use super::common::{verify_dispatch, Setup};

fn mock_nonce() -> musig2::PubNonce {
    musig2::SecNonce::build([0u8; 32]).build().public_nonce()
}

fn mock_partial() -> musig2::PartialSignature {
    musig2::PartialSignature::from(secp256k1::Scalar::ONE)
}

/// Tests the full message handler dispatch (sign, ouroboros, gossip) for all message types.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn dispatch_all_message_types() -> anyhow::Result<()> {
    const OPERATORS_NUM: usize = 2;

    logging::init(LoggerConfig::new("p2p-test-dispatch-all".to_string()));

    let Setup {
        mut operators,
        cancel,
        tasks,
    } = Setup::all_to_all(OPERATORS_NUM).await?;

    let deposit_idx = 0;
    let graph_idx = GraphIdx {
        deposit: deposit_idx,
        operator: 0,
    };

    // 1. Payout descriptor
    for op in operators.iter_mut() {
        op.handler
            .send_payout_descriptor(deposit_idx, 0, PayoutDescriptor::new(vec![1, 2, 3]), None)
            .await;
    }
    verify_dispatch(&mut operators, OPERATORS_NUM, "payout_descriptor", |msg| {
        matches!(msg, UnsignedGossipsubMsg::PayoutDescriptorExchange { .. })
    })
    .await?;

    // 2. Graph data
    for op in operators.iter_mut() {
        op.handler
            .send_graph_data(graph_idx, OutPoint::new(Txid::all_zeros(), 0), None)
            .await;
    }
    verify_dispatch(&mut operators, OPERATORS_NUM, "graph_data", |msg| {
        matches!(msg, UnsignedGossipsubMsg::GraphDataExchange { .. })
    })
    .await?;

    // 3. Deposit nonce
    for op in operators.iter_mut() {
        op.handler
            .send_deposit_nonce(deposit_idx, mock_nonce(), None)
            .await;
    }
    verify_dispatch(&mut operators, OPERATORS_NUM, "deposit_nonce", |msg| {
        matches!(
            msg,
            UnsignedGossipsubMsg::Musig2NoncesExchange(
                strata_bridge_p2p_types::MuSig2Nonce::Deposit { .. }
            )
        )
    })
    .await?;

    // 4. Deposit partial
    for op in operators.iter_mut() {
        op.handler
            .send_deposit_partial(deposit_idx, mock_partial(), None)
            .await;
    }
    verify_dispatch(&mut operators, OPERATORS_NUM, "deposit_partial", |msg| {
        matches!(
            msg,
            UnsignedGossipsubMsg::Musig2SignaturesExchange(
                strata_bridge_p2p_types::MuSig2Partial::Deposit { .. }
            )
        )
    })
    .await?;

    // 5. Payout nonce
    for op in operators.iter_mut() {
        op.handler
            .send_payout_nonce(deposit_idx, mock_nonce(), None)
            .await;
    }
    verify_dispatch(&mut operators, OPERATORS_NUM, "payout_nonce", |msg| {
        matches!(
            msg,
            UnsignedGossipsubMsg::Musig2NoncesExchange(
                strata_bridge_p2p_types::MuSig2Nonce::Payout { .. }
            )
        )
    })
    .await?;

    // 6. Payout partial
    for op in operators.iter_mut() {
        op.handler
            .send_payout_partial(deposit_idx, mock_partial(), None)
            .await;
    }
    verify_dispatch(&mut operators, OPERATORS_NUM, "payout_partial", |msg| {
        matches!(
            msg,
            UnsignedGossipsubMsg::Musig2SignaturesExchange(
                strata_bridge_p2p_types::MuSig2Partial::Payout { .. }
            )
        )
    })
    .await?;

    // 7. Graph nonces (vec)
    for op in operators.iter_mut() {
        op.handler
            .send_graph_nonces(graph_idx, vec![mock_nonce(), mock_nonce()], None)
            .await;
    }
    verify_dispatch(&mut operators, OPERATORS_NUM, "graph_nonces", |msg| {
        matches!(
            msg,
            UnsignedGossipsubMsg::Musig2NoncesExchange(
                strata_bridge_p2p_types::MuSig2Nonce::Graph { .. }
            )
        )
    })
    .await?;

    // 8. Graph partials (vec)
    for op in operators.iter_mut() {
        op.handler
            .send_graph_partials(graph_idx, vec![mock_partial(), mock_partial()], None)
            .await;
    }
    verify_dispatch(&mut operators, OPERATORS_NUM, "graph_partials", |msg| {
        matches!(
            msg,
            UnsignedGossipsubMsg::Musig2SignaturesExchange(
                strata_bridge_p2p_types::MuSig2Partial::Graph { .. }
            )
        )
    })
    .await?;

    // 9. Nag request
    for op in operators.iter_mut() {
        op.handler
            .send_nag_request(
                NagRequest {
                    recipient: P2POperatorPubKey::from(vec![0u8; 32]),
                    payload: NagRequestPayload::DepositNonce { deposit_idx },
                },
                None,
            )
            .await;
    }
    verify_dispatch(&mut operators, OPERATORS_NUM, "nag_request", |msg| {
        matches!(msg, UnsignedGossipsubMsg::NagRequestExchange(_))
    })
    .await?;

    cancel.cancel();
    tasks.wait().await;

    Ok(())
}

/// Tests the direct-peer dispatch path (via oneshot channel instead of gossip broadcast).
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn dispatch_direct_peer() -> anyhow::Result<()> {
    const OPERATORS_NUM: usize = 2;

    logging::init(LoggerConfig::new("p2p-test-dispatch-direct".to_string()));

    let Setup {
        mut operators,
        cancel,
        tasks,
    } = Setup::all_to_all(OPERATORS_NUM).await?;

    let deposit_idx = 0;

    // Send via the direct-peer (oneshot) path from operator 0
    let (tx, rx) = oneshot::channel();
    operators[0]
        .handler
        .send_payout_descriptor(
            deposit_idx,
            0,
            PayoutDescriptor::new(vec![4, 5, 6]),
            Some(tx),
        )
        .await;

    // Verify ouroboros received the unsigned message
    let ouroboros_msg = operators[0]
        .ouroboros_rx
        .try_recv()
        .expect("ouroboros should have a message");
    assert!(matches!(
        ouroboros_msg.publish,
        UnsignedGossipsubMsg::PayoutDescriptorExchange { .. }
    ));

    // Verify the oneshot channel received the signed serialized bytes
    let data = rx.await.expect("oneshot should have received data");
    let archived = rkyv::access::<
        rkyv::Archived<strata_bridge_p2p_types::GossipsubMsg>,
        rkyv::rancor::Error,
    >(&data)
    .expect("must be able to access archived msg");
    let msg =
        rkyv::deserialize::<strata_bridge_p2p_types::GossipsubMsg, rkyv::rancor::Error>(archived)
            .expect("must be able to deserialize msg");
    assert!(matches!(
        msg.unsigned,
        UnsignedGossipsubMsg::PayoutDescriptorExchange { .. }
    ));

    // Verify that operator 1 did NOT receive anything via gossip (it was direct, not broadcast)
    assert!(operators[1].gossip_handle.events_is_empty());

    cancel.cancel();
    tasks.wait().await;

    Ok(())
}
