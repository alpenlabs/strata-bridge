//! GetMessage tests.

use anyhow::bail;
use futures::SinkExt;
use p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId};
use p2p_wire::p2p::v1::{
    ArchivedGetMessageRequest, ArchivedGossipsubMsg, GetMessageRequest, GossipsubMsg,
    UnsignedGossipsubMsg,
};
use strata_bridge_common::logging::{self, LoggerConfig};
use strata_p2p::{
    commands::{GossipCommand, RequestResponseCommand},
    events::{GossipEvent, ReqRespEvent},
};
use tracing::info;

use super::common::{
    exchange_deposit_nonces, exchange_deposit_setup, exchange_deposit_sigs,
    exchange_stake_chain_info, mock_deposit_nonces, mock_deposit_setup, mock_deposit_sigs,
    mock_stake_chain_info, Setup,
};

/// Tests the get message request-response flow.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn request_response() -> anyhow::Result<()> {
    const OPERATORS_NUM: usize = 2;

    logging::init(LoggerConfig::new(
        "p2p-impl-test_request_response".to_string(),
    ));

    let Setup {
        mut operators,
        cancel,
        tasks,
    } = Setup::all_to_all(OPERATORS_NUM).await?;

    let stake_chain_id = StakeChainId::hash(b"stake_chain_id");
    let scope = Scope::hash(b"scope");
    let session_id = SessionId::hash(b"session_id");

    // last operator won't send his info to others
    exchange_stake_chain_info(
        &mut operators[..OPERATORS_NUM - 1],
        OPERATORS_NUM - 1,
        stake_chain_id,
    )
    .await?;
    exchange_deposit_setup(
        &mut operators[..OPERATORS_NUM - 1],
        OPERATORS_NUM - 1,
        scope,
    )
    .await?;
    exchange_deposit_nonces(
        &mut operators[..OPERATORS_NUM - 1],
        OPERATORS_NUM - 1,
        session_id,
    )
    .await?;
    exchange_deposit_sigs(
        &mut operators[..OPERATORS_NUM - 1],
        OPERATORS_NUM - 1,
        session_id,
    )
    .await?;

    // create command to request info from the first operator
    let operator_pk: P2POperatorPubKey = operators[0].kp.public().clone().into();
    let command_stake_chain = GetMessageRequest::StakeChainExchange {
        stake_chain_id,
        operator_pk: operator_pk.clone(),
    };
    let command_deposit_setup = GetMessageRequest::DepositSetup {
        scope,
        operator_pk: operator_pk.clone(),
    };
    let command_deposit_nonces = GetMessageRequest::Musig2NoncesExchange {
        session_id,
        operator_pk: operator_pk.clone(),
    };
    let command_deposit_sigs = GetMessageRequest::Musig2SignaturesExchange {
        session_id,
        operator_pk: operator_pk.clone(),
    };

    // Send stake chain request and handle response from the last operator
    let mut data = Vec::new();
    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&command_stake_chain, &mut data)
        .expect("must be able to serialize get message request to archived data");
    operators[OPERATORS_NUM - 1]
        .req_resp_handle
        .send(RequestResponseCommand {
            target_transport_id: command_stake_chain.peer_id(),
            data,
        })
        .await?;

    // Wait for request on the first operator
    let event = operators[0]
        .req_resp_handle
        .next_event()
        .await
        .ok_or_else(|| anyhow::anyhow!("no req_resp_handle event"))?;
    match event {
        ReqRespEvent::ReceivedRequest(raw_request, _) => {
            let archived =
                rkyv::access::<ArchivedGetMessageRequest, rkyv::rancor::Error>(&raw_request)
                    .expect("must be able to access archived data");
            let request = rkyv::deserialize::<GetMessageRequest, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize archived data");
            match request {
                GetMessageRequest::StakeChainExchange {
                    stake_chain_id: req_stake_chain_id,
                    operator_pk: req_operator_pk,
                } if req_stake_chain_id == stake_chain_id && req_operator_pk == operator_pk => {
                    // Construct and send response
                    let mock_msg = mock_stake_chain_info(&operators[0].kp.clone(), stake_chain_id);
                    let msg = GossipsubMsg::from(mock_msg);
                    let mut data = Vec::new();
                    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&msg, &mut data)
                        .expect("must be able to serialize gossipsub message to archived data");
                    operators[0]
                        .gossip_handle
                        .send(GossipCommand { data })
                        .await?;
                }
                _ => bail!("Got unexpected request in the first operator"),
            }
        }
        _ => bail!("Got unexpected event in the first operator"),
    }

    // Wait for response on the last operator
    let event = operators[OPERATORS_NUM - 1]
        .gossip_handle
        .next_event()
        .await?;
    match event {
        GossipEvent::ReceivedMessage(raw_msg) => {
            let archived = rkyv::access::<ArchivedGossipsubMsg, rkyv::rancor::Error>(&raw_msg)
                .expect("must be able to access archived data");
            let msg = rkyv::deserialize::<GossipsubMsg, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize archived data");
            match &msg.unsigned {
                UnsignedGossipsubMsg::StakeChainExchange {
                    stake_chain_id: received_id,
                    ..
                } if msg.key == operator_pk && *received_id == stake_chain_id => {
                    info!("Got stake chain info from the last operator")
                }
                _ => bail!("Got event other than expected 'stake_chain_info' in the last operator"),
            }
        }
    }

    // Send deposit setup request and handle response from the last operator
    let mut data = Vec::new();
    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&command_deposit_setup, &mut data)
        .expect("must be able to serialize get message request to archived data");
    operators[OPERATORS_NUM - 1]
        .req_resp_handle
        .send(RequestResponseCommand {
            target_transport_id: command_deposit_setup.peer_id(),
            data,
        })
        .await?;

    // Wait for request on the first operator
    let event = operators[0]
        .req_resp_handle
        .next_event()
        .await
        .ok_or_else(|| anyhow::anyhow!("no req_resp_handle event"))?;
    match event {
        ReqRespEvent::ReceivedRequest(raw_request, _) => {
            let archived =
                rkyv::access::<ArchivedGetMessageRequest, rkyv::rancor::Error>(&raw_request)
                    .expect("must be able to access archived data");
            let request = rkyv::deserialize::<GetMessageRequest, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize archived data");
            match request {
                GetMessageRequest::DepositSetup {
                    scope: req_scope,
                    operator_pk: req_operator_pk,
                } if req_scope == scope && req_operator_pk == operator_pk => {
                    // Construct and send response
                    let mock_msg = mock_deposit_setup(&operators[0].kp.clone(), scope);
                    let msg = GossipsubMsg::from(mock_msg);
                    let mut data = Vec::new();
                    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&msg, &mut data)
                        .expect("must be able to serialize gossipsub message to archived data");
                    operators[0]
                        .gossip_handle
                        .send(GossipCommand { data })
                        .await?;
                }
                _ => bail!("Got unexpected request in the first operator"),
            }
        }
        _ => bail!("Got unexpected event in the first operator"),
    }

    // Wait for response on the last operator
    let GossipEvent::ReceivedMessage(raw_msg) = operators[OPERATORS_NUM - 1]
        .gossip_handle
        .next_event()
        .await?;
    let archived = rkyv::access::<ArchivedGossipsubMsg, rkyv::rancor::Error>(&raw_msg)
        .expect("must be able to access archived data");
    let msg = rkyv::deserialize::<GossipsubMsg, rkyv::rancor::Error>(archived)
        .expect("must be able to deserialize archived data");
    match &msg.unsigned {
        UnsignedGossipsubMsg::DepositSetup {
            scope: received_scope,
            ..
        } if msg.key == operator_pk && *received_scope == scope => {
            info!("Got deposit setup info from the last operator")
        }
        _ => bail!("Got event other than expected 'deposit_setup' in the last operator"),
    }

    // Send deposit nonces request and handle response from the last operator
    let mut data = Vec::new();
    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&command_deposit_nonces, &mut data)
        .expect("must be able to serialize get message request to archived data");
    operators[OPERATORS_NUM - 1]
        .req_resp_handle
        .send(RequestResponseCommand {
            target_transport_id: command_deposit_nonces.peer_id(),
            data,
        })
        .await?;

    // Wait for request on the first operator
    let event = operators[0]
        .req_resp_handle
        .next_event()
        .await
        .ok_or_else(|| anyhow::anyhow!("no req_resp_handle event"))?;
    match event {
        ReqRespEvent::ReceivedRequest(raw_request, _) => {
            let archived =
                rkyv::access::<ArchivedGetMessageRequest, rkyv::rancor::Error>(&raw_request)
                    .expect("must be able to access archived data");
            let request = rkyv::deserialize::<GetMessageRequest, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize archived data");
            match request {
                GetMessageRequest::Musig2NoncesExchange {
                    session_id: req_session_id,
                    operator_pk: req_operator_pk,
                } if req_session_id == session_id && req_operator_pk == operator_pk => {
                    // Construct and send response
                    let mock_msg = mock_deposit_nonces(&operators[0].kp.clone(), session_id);
                    let msg = GossipsubMsg::from(mock_msg);
                    let mut data = Vec::new();
                    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&msg, &mut data)
                        .expect("must be able to serialize gossipsub message to archived data");
                    operators[0]
                        .gossip_handle
                        .send(GossipCommand { data })
                        .await?;
                }
                _ => bail!("Got unexpected request in the first operator"),
            }
        }
        _ => bail!("Got unexpected event in the first operator"),
    }

    // Wait for response on the last operator
    let GossipEvent::ReceivedMessage(raw_msg) = operators[OPERATORS_NUM - 1]
        .gossip_handle
        .next_event()
        .await?;
    let archived = rkyv::access::<ArchivedGossipsubMsg, rkyv::rancor::Error>(&raw_msg)
        .expect("must be able to access archived data");
    let msg = rkyv::deserialize::<GossipsubMsg, rkyv::rancor::Error>(archived)
        .expect("must be able to deserialize archived data");
    match &msg.unsigned {
        UnsignedGossipsubMsg::Musig2NoncesExchange {
            session_id: received_session_id,
            ..
        } if msg.key == operator_pk && *received_session_id == session_id => {
            info!("Got deposit pubnonces from the last operator")
        }
        _ => bail!("Got event other than expected 'deposit_pubnonces' in the last operator"),
    }

    // Send deposit signatures request and handle response from the last operator
    let mut data = Vec::new();
    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&command_deposit_sigs, &mut data)
        .expect("must be able to serialize get message request to archived data");
    operators[OPERATORS_NUM - 1]
        .req_resp_handle
        .send(RequestResponseCommand {
            target_transport_id: command_deposit_sigs.peer_id(),
            data,
        })
        .await?;

    // Wait for request on the first operator
    let event = operators[0]
        .req_resp_handle
        .next_event()
        .await
        .ok_or_else(|| anyhow::anyhow!("no req_resp_handle event"))?;
    match event {
        ReqRespEvent::ReceivedRequest(raw_request, _) => {
            let archived =
                rkyv::access::<ArchivedGetMessageRequest, rkyv::rancor::Error>(&raw_request)
                    .expect("must be able to access archived data");
            let request = rkyv::deserialize::<GetMessageRequest, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize archived data");
            match request {
                GetMessageRequest::Musig2SignaturesExchange {
                    session_id: req_session_id,
                    operator_pk: req_operator_pk,
                } if req_session_id == session_id && req_operator_pk == operator_pk => {
                    // Construct and send response
                    let mock_msg = mock_deposit_sigs(&operators[0].kp.clone(), session_id);
                    let msg = GossipsubMsg::from(mock_msg);
                    let mut data = Vec::new();
                    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&msg, &mut data)
                        .expect("must be able to serialize gossipsub message to archived data");
                    operators[0]
                        .gossip_handle
                        .send(GossipCommand { data })
                        .await?;
                }
                _ => bail!("Got unexpected request in the first operator"),
            }
        }
        _ => bail!("Got unexpected event in the first operator"),
    }

    // Wait for response on the last operator
    let GossipEvent::ReceivedMessage(raw_msg) = operators[OPERATORS_NUM - 1]
        .gossip_handle
        .next_event()
        .await?;
    let archived = rkyv::access::<ArchivedGossipsubMsg, rkyv::rancor::Error>(&raw_msg)
        .expect("must be able to access archived data");
    let msg = rkyv::deserialize::<GossipsubMsg, rkyv::rancor::Error>(archived)
        .expect("must be able to deserialize archived data");
    match &msg.unsigned {
        UnsignedGossipsubMsg::Musig2SignaturesExchange {
            session_id: received_session_id,
            ..
        } if msg.key == operator_pk && *received_session_id == session_id => {
            info!("Got deposit partial signatures from the last operator")
        }
        _ => bail!("Got event other than expected 'deposit_partial_sigs' in the last operator"),
    }

    cancel.cancel();
    tasks.wait().await;

    Ok(())
}
