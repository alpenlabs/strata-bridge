use strata_bridge_common::logging::{self, LoggerConfig};
use strata_bridge_p2p_types::{Scope, SessionId, StakeChainId};

use super::common::{
    exchange_deposit_nonces, exchange_deposit_setup, exchange_deposit_sigs,
    exchange_stake_chain_info, Setup,
};

/// Tests the gossip protocol in an all to all connected network with a single ID.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn all_to_all_one_id() -> anyhow::Result<()> {
    const OPERATORS_NUM: usize = 2;

    logging::init(LoggerConfig::new(
        "p2p-impl-test_all_to_all_one_scope".to_string(),
    ));

    let Setup {
        mut operators,
        cancel,
        tasks,
    } = Setup::all_to_all(OPERATORS_NUM).await?;

    let stake_chain_id = StakeChainId::hash(b"stake_chain_id");
    let scope = Scope::hash(b"scope");
    let session_id = SessionId::hash(b"session_id");

    exchange_stake_chain_info(&mut operators, OPERATORS_NUM, stake_chain_id).await?;
    exchange_deposit_setup(&mut operators, OPERATORS_NUM, scope).await?;
    exchange_deposit_nonces(&mut operators, OPERATORS_NUM, session_id).await?;
    exchange_deposit_sigs(&mut operators, OPERATORS_NUM, session_id).await?;

    cancel.cancel();

    tasks.wait().await;

    Ok(())
}

/// Tests the gossip protocol in an all to all connected network with multiple IDs.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn all_to_all_multiple_ids() -> anyhow::Result<()> {
    const OPERATORS_NUM: usize = 2;

    logging::init(LoggerConfig::new(
        "p2p-impl-test_all_to_all_one_scope".to_string(),
    ));

    let Setup {
        mut operators,
        cancel,
        tasks,
    } = Setup::all_to_all(OPERATORS_NUM).await?;

    let stake_chain_ids = (0..OPERATORS_NUM)
        .map(|i| StakeChainId::hash(format!("stake_chain_id_{i}").as_bytes()))
        .collect::<Vec<_>>();
    let scopes = (0..OPERATORS_NUM)
        .map(|i| Scope::hash(format!("scope_{i}").as_bytes()))
        .collect::<Vec<_>>();

    let session_ids = (0..OPERATORS_NUM)
        .map(|i| SessionId::hash(format!("session_{i}").as_bytes()))
        .collect::<Vec<_>>();

    for stake_chain_id in &stake_chain_ids {
        exchange_stake_chain_info(&mut operators, OPERATORS_NUM, *stake_chain_id).await?;
    }

    for scope in &scopes {
        exchange_deposit_setup(&mut operators, OPERATORS_NUM, *scope).await?;
    }
    for session_id in &session_ids {
        exchange_deposit_nonces(&mut operators, OPERATORS_NUM, *session_id).await?;
    }
    for session_id in &session_ids {
        exchange_deposit_sigs(&mut operators, OPERATORS_NUM, *session_id).await?;
    }

    cancel.cancel();

    tasks.wait().await;

    Ok(())
}
