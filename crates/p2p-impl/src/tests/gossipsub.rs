use strata_common::logging::{self, LoggerConfig};
use strata_p2p_types::{Scope, SessionId, StakeChainId};

use crate::tests::common::{
    exchange_deposit_nonces, exchange_deposit_setup, exchange_deposit_sigs,
    exchange_stake_chain_info, Setup,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn all_to_all_one_scope() -> anyhow::Result<()> {
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
