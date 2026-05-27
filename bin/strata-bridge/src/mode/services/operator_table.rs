//! Provides operator table initialization.

use anyhow::Context;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_common::params::Params;
use strata_bridge_primitives::operator_table::OperatorTable;
use tracing::info;

pub(in crate::mode) async fn init_operator_table(
    params: &Params,
    s2_client: &SecretServiceClient,
) -> Result<OperatorTable, anyhow::Error> {
    let my_btc_key = s2_client
        .musig2_signer()
        .pubkey()
        .await
        .context("could not fetch btc key from s2")?;
    info!(%my_btc_key, "fetched musig2 key from secret service");
    let p2p_and_covenant_keys = params.keys.operators.iter().map(|operator| {
        (
            operator.index(),
            operator.p2p_key().clone(),
            operator.covenant_public_key(),
        )
    });

    OperatorTable::new(
        p2p_and_covenant_keys.collect(),
        OperatorTable::select_btc_x_only(my_btc_key),
    )
    .context("could not build OperatorTable")
}
