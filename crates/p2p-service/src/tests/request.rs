//! GetMessage tests.

use anyhow::bail;
use strata_common::logging::{self, LoggerConfig};
use strata_p2p::{commands::Command, events::Event};
use strata_p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId};
use strata_p2p_wire::p2p::v1::{GetMessageRequest, UnsignedGossipsubMsg};
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
    let command_stake_chain = Command::RequestMessage(GetMessageRequest::StakeChainExchange {
        stake_chain_id,
        operator_pk: operator_pk.clone(),
    });
    let command_deposit_setup = Command::RequestMessage(GetMessageRequest::DepositSetup {
        scope,
        operator_pk: operator_pk.clone(),
    });
    let command_deposit_nonces = Command::RequestMessage(GetMessageRequest::Musig2NoncesExchange {
        session_id,
        operator_pk: operator_pk.clone(),
    });
    let command_deposit_sigs =
        Command::RequestMessage(GetMessageRequest::Musig2SignaturesExchange {
            session_id,
            operator_pk: operator_pk.clone(),
        });

    // Send stake chain request and handle response from the last operator
    operators[OPERATORS_NUM - 1]
        .handle
        .send_command(command_stake_chain)
        .await;

    // Wait for request on the first operator
    let event = operators[0].handle.next_event().await?;
    match event {
        Event::ReceivedRequest(request) => match request {
            GetMessageRequest::StakeChainExchange {
                stake_chain_id: req_stake_chain_id,
                operator_pk: req_operator_pk,
            } if req_stake_chain_id == stake_chain_id && req_operator_pk == operator_pk => {
                // Construct and send response
                let mock_msg = mock_stake_chain_info(&operators[0].kp.clone(), stake_chain_id);
                if let Command::PublishMessage(msg) = mock_msg {
                    operators[0]
                        .handle
                        .send_command(Command::PublishMessage(msg))
                        .await;
                }
            }
            _ => bail!("Got unexpected request in the first operator"),
        },
        _ => bail!("Got unexpected event in the first operator"),
    }

    // Wait for response on the last operator
    let event = operators[OPERATORS_NUM - 1].handle.next_event().await?;
    match event {
        Event::ReceivedMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::StakeChainExchange {
                stake_chain_id: received_id,
                ..
            } if msg.key == operator_pk && *received_id == stake_chain_id => {
                info!("Got stake chain info from the last operator")
            }
            _ => bail!("Got event other than expected 'stake_chain_info' in the last operator"),
        },
        _ => bail!("Got event other than expected 'stake_chain_info' in the last operator"),
    }

    // Send deposit setup request and handle response from the last operator
    operators[OPERATORS_NUM - 1]
        .handle
        .send_command(command_deposit_setup)
        .await;

    // Wait for request on the first operator
    let event = operators[0].handle.next_event().await?;
    match event {
        Event::ReceivedRequest(request) => match request {
            GetMessageRequest::DepositSetup {
                scope: req_scope,
                operator_pk: req_operator_pk,
            } if req_scope == scope && req_operator_pk == operator_pk => {
                // Construct and send response
                let mock_msg = mock_deposit_setup(&operators[0].kp.clone(), scope);
                if let Command::PublishMessage(msg) = mock_msg {
                    operators[0]
                        .handle
                        .send_command(Command::PublishMessage(msg))
                        .await;
                }
            }
            _ => bail!("Got unexpected request in the first operator"),
        },
        _ => bail!("Got unexpected event in the first operator"),
    }

    // Wait for response on the last operator
    let event = operators[OPERATORS_NUM - 1].handle.next_event().await?;
    match event {
        Event::ReceivedMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::DepositSetup {
                scope: received_scope,
                ..
            } if msg.key == operator_pk && *received_scope == scope => {
                info!("Got deposit setup info from the last operator")
            }
            _ => bail!("Got event other than expected 'deposit_setup' in the last operator"),
        },
        _ => bail!("Got event other than expected 'deposit_setup' in the last operator"),
    }

    // Send deposit nonces request and handle response from the last operator
    operators[OPERATORS_NUM - 1]
        .handle
        .send_command(command_deposit_nonces)
        .await;

    // Wait for request on the first operator
    let event = operators[0].handle.next_event().await?;
    match event {
        Event::ReceivedRequest(request) => match request {
            GetMessageRequest::Musig2NoncesExchange {
                session_id: req_session_id,
                operator_pk: req_operator_pk,
            } if req_session_id == session_id && req_operator_pk == operator_pk => {
                // Construct and send response
                let mock_msg = mock_deposit_nonces(&operators[0].kp.clone(), session_id);
                if let Command::PublishMessage(msg) = mock_msg {
                    operators[0]
                        .handle
                        .send_command(Command::PublishMessage(msg))
                        .await;
                }
            }
            _ => bail!("Got unexpected request in the first operator"),
        },
        _ => bail!("Got unexpected event in the first operator"),
    }

    // Wait for response on the last operator
    let event = operators[OPERATORS_NUM - 1].handle.next_event().await?;
    match event {
        Event::ReceivedMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::Musig2NoncesExchange {
                session_id: received_session_id,
                ..
            } if msg.key == operator_pk && *received_session_id == session_id => {
                info!("Got deposit pubnonces from the last operator")
            }
            _ => bail!("Got event other than expected 'deposit_pubnonces' in the last operator"),
        },
        _ => bail!("Got event other than expected 'deposit_pubnonces' in the last operator"),
    }

    // Send deposit signatures request and handle response from the last operator
    operators[OPERATORS_NUM - 1]
        .handle
        .send_command(command_deposit_sigs)
        .await;

    // Wait for request on the first operator
    let event = operators[0].handle.next_event().await?;
    match event {
        Event::ReceivedRequest(request) => match request {
            GetMessageRequest::Musig2SignaturesExchange {
                session_id: req_session_id,
                operator_pk: req_operator_pk,
            } if req_session_id == session_id && req_operator_pk == operator_pk => {
                // Construct and send response
                let mock_msg = mock_deposit_sigs(&operators[0].kp.clone(), session_id);
                if let Command::PublishMessage(msg) = mock_msg {
                    operators[0]
                        .handle
                        .send_command(Command::PublishMessage(msg))
                        .await;
                }
            }
            _ => bail!("Got unexpected request in the first operator"),
        },
        _ => bail!("Got unexpected event in the first operator"),
    }

    // Wait for response on the last operator
    let event = operators[OPERATORS_NUM - 1].handle.next_event().await?;
    match event {
        Event::ReceivedMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::Musig2SignaturesExchange {
                session_id: received_session_id,
                ..
            } if msg.key == operator_pk && *received_session_id == session_id => {
                info!("Got deposit partial signatures from the last operator")
            }
            _ => bail!("Got event other than expected 'deposit_partial_sigs' in the last operator"),
        },
        _ => bail!("Got event other than expected 'deposit_partial_sigs' in the last operator"),
    }

    cancel.cancel();
    tasks.wait().await;

    Ok(())
}
