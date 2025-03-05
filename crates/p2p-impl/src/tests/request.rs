use anyhow::bail;
use strata_common::logging::{self, LoggerConfig};
use strata_p2p::{
    commands::{Command, UnsignedPublishMessage},
    events::Event,
};
use strata_p2p_db::{sled::AsyncDB, RepositoryExt, StakeChainEntry};
use strata_p2p_types::{OperatorPubKey, StakeChainId};
use strata_p2p_wire::p2p::v1::{GetMessageRequest, UnsignedGossipsubMsg};
use tracing::info;

use crate::tests::common::{exchange_stake_chain_info, mock_stake_chain_info, Setup};

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

    // last operator won't send his info to others
    let stake_chain_id = StakeChainId::hash(b"stake_chain_id");
    exchange_stake_chain_info(
        &mut operators[..OPERATORS_NUM - 1],
        OPERATORS_NUM - 1,
        stake_chain_id,
    )
    .await?;

    // create command to request info from the last operator
    let operator_pk: OperatorPubKey = operators[OPERATORS_NUM - 1].kp.public().clone().into();
    let stake_chain_id = StakeChainId::hash(b"stake_chain_id");
    let command = Command::RequestMessage(GetMessageRequest::StakeChainExchange {
        stake_chain_id,
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

    operators[0].handle.send_command(command).await;

    let event = operators[0].handle.next_event().await?;

    match event {
        Event::ReceivedMessage(msg)
            if matches!(
                msg.unsigned,
                UnsignedGossipsubMsg::StakeChainExchange { .. }
            ) && msg.key == operator_pk =>
        {
            info!("Got stake chain info from the last operator")
        }

        _ => bail!("Got event other than 'stake_chain_info' - {:?}", event),
    }

    cancel.cancel();

    tasks.wait().await;

    Ok(())
}
