//! Provides operator table initialization.

use anyhow::Context;
use secp256k1::Parity;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{OperatorIdx, P2POperatorPubKey},
};
use tracing::info;

use crate::params::Params;

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
    let p2p_and_musig_keys = params.keys.covenant.iter().enumerate().map(|(i, cov)| {
        (
            i as OperatorIdx,
            P2POperatorPubKey::from(cov.p2p.clone()),
            cov.musig2.public_key(Parity::Even),
        )
    });

    OperatorTable::new(
        p2p_and_musig_keys.collect(),
        OperatorTable::select_btc_x_only(my_btc_key),
    )
    .context("could not build OperatorTable")
}
