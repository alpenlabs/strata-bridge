use anyhow::bail;
use strata_common::logging::{self, LoggerConfig};
use strata_p2p::{
    commands::{Command, UnsignedPublishMessage},
    events::Event,
};
use strata_p2p_db::{
    sled::AsyncDB, DepositSetupEntry, NoncesEntry, PartialSignaturesEntry, RepositoryExt,
    StakeChainEntry,
};
use strata_p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId};
use strata_p2p_wire::p2p::v1::{GetMessageRequest, UnsignedGossipsubMsg};
use tracing::info;

use super::common::{
    exchange_deposit_nonces, exchange_deposit_setup, exchange_deposit_sigs,
    exchange_stake_chain_info, mock_deposit_nonces, mock_deposit_setup, mock_deposit_sigs,
    mock_stake_chain_info, Setup,
};

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

    // create command to request info from the last operator
    let operator_pk: P2POperatorPubKey = operators[OPERATORS_NUM - 1].kp.public().clone().into();
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

    // put data in the last operator, so that he can respond it
    match mock_stake_chain_info(&operators[OPERATORS_NUM - 1].kp.clone(), stake_chain_id) {
        Command::PublishMessage(msg) => match msg.msg {
            UnsignedPublishMessage::StakeChainExchange {
                stake_chain_id,
                pre_stake_txid,
                pre_stake_vout,
            } => {
                let entry = StakeChainEntry {
                    entry: (pre_stake_txid, pre_stake_vout),
                    signature: msg.signature,
                    key: msg.key,
                };
                <AsyncDB as RepositoryExt>::set_stake_chain_info_if_not_exists::<'_, '_>(
                    &operators[OPERATORS_NUM - 1].db,
                    stake_chain_id,
                    entry,
                )
                .await?;
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
    operators[0].handle.send_command(command_stake_chain).await;
    let event = operators[0].handle.next_event().await?;
    match event {
        Event::ReceivedMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::StakeChainExchange {
                stake_chain_id: received_id,
                ..
            } if msg.key == operator_pk && *received_id == stake_chain_id => {
                info!("Got stake chain info from the last operator")
            }
            _ => bail!("Got event other than expected 'stake_chain_info'",),
        },
    }

    // put data in the last operator, so that he can respond it
    match mock_deposit_setup(&operators[OPERATORS_NUM - 1].kp.clone(), scope) {
        Command::PublishMessage(msg) => match msg.msg {
            UnsignedPublishMessage::DepositSetup {
                scope,
                hash,
                funding_txid,
                funding_vout,
                operator_pk,
                wots_pks,
            } => {
                let entry = DepositSetupEntry {
                    signature: msg.signature,
                    key: msg.key,
                    hash,
                    funding_txid,
                    funding_vout,
                    operator_pk,
                    wots_pks,
                };
                <AsyncDB as RepositoryExt>::set_deposit_setup_if_not_exists::<'_, '_>(
                    &operators[OPERATORS_NUM - 1].db,
                    scope,
                    entry,
                )
                .await?;
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
    operators[0]
        .handle
        .send_command(command_deposit_setup)
        .await;
    let event = operators[0].handle.next_event().await?;
    match event {
        Event::ReceivedMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::DepositSetup {
                scope: received_scope,
                ..
            } if msg.key == operator_pk && *received_scope == scope => {
                info!("Got deposit setup info from the last operator")
            }
            _ => bail!("Got event other than expected 'deposit_setup'",),
        },
    }

    // put data in the last operator, so that he can respond it
    match mock_deposit_nonces(&operators[OPERATORS_NUM - 1].kp.clone(), session_id) {
        Command::PublishMessage(msg) => match msg.msg {
            UnsignedPublishMessage::Musig2NoncesExchange {
                session_id,
                pub_nonces,
            } => {
                let entry = NoncesEntry {
                    signature: msg.signature,
                    key: msg.key,
                    entry: pub_nonces,
                };
                <AsyncDB as RepositoryExt>::set_pub_nonces_if_not_exist::<'_, '_>(
                    &operators[OPERATORS_NUM - 1].db,
                    session_id,
                    entry,
                )
                .await?;
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
    operators[0]
        .handle
        .send_command(command_deposit_nonces)
        .await;
    let event = operators[0].handle.next_event().await?;
    match event {
        Event::ReceivedMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::Musig2NoncesExchange {
                session_id: received_session_id,
                ..
            } if msg.key == operator_pk && *received_session_id == session_id => {
                info!("Got deposit pubnonces from the last operator")
            }
            _ => bail!("Got event other than expected 'deposit_pubnonces'",),
        },
    }

    // put data in the last operator, so that he can respond it
    match mock_deposit_sigs(&operators[OPERATORS_NUM - 1].kp.clone(), session_id) {
        Command::PublishMessage(msg) => match msg.msg {
            UnsignedPublishMessage::Musig2SignaturesExchange {
                session_id,
                partial_sigs,
            } => {
                let entry = PartialSignaturesEntry {
                    signature: msg.signature,
                    key: msg.key,
                    entry: partial_sigs,
                };
                <AsyncDB as RepositoryExt>::set_partial_signatures_if_not_exists::<'_, '_>(
                    &operators[OPERATORS_NUM - 1].db,
                    session_id,
                    entry,
                )
                .await?;
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
    operators[0].handle.send_command(command_deposit_sigs).await;
    let event = operators[0].handle.next_event().await?;
    match event {
        Event::ReceivedMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::Musig2SignaturesExchange {
                session_id: received_session_id,
                ..
            } if msg.key == operator_pk && *received_session_id == session_id => {
                info!("Got deposit partial signatures from the last operator")
            }
            _ => bail!("Got event other than expected 'deposit_partial_sigs'",),
        },
    }
    cancel.cancel();

    tasks.wait().await;

    Ok(())
}
