//! Contains functions to handle WOTS keys generation and signing.

use bitcoin::Txid;
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use futures::future::{join3, join_all};
use secret_service_client::{wots::WotsClient, SecretServiceClient};
use secret_service_proto::v1::traits::*;
use strata_bridge_primitives::wots::{self, Assertions};
use strata_p2p_types::{Wots128PublicKey, Wots256PublicKey, WotsPublicKeys};
use tracing::info;

use crate::{
    errors::ContractManagerErr,
    executors::constants::{DEPOSIT_VOUT, WITHDRAWAL_FULFILLMENT_PK_IDX},
};

pub(super) async fn get_wots_pks(
    deposit_idx: u32,
    deposit_txid: Txid,
    s2_client: &SecretServiceClient,
) -> Result<WotsPublicKeys, ContractManagerErr> {
    let wots_client = s2_client.wots_signer();
    let withdrawal_fulfillment_pk =
        get_withdrawal_fulfillment_wots_pk(deposit_txid, &wots_client).await?;

    const NUM_FQS: usize = NUM_U256;
    const NUM_PUB_INPUTS: usize = NUM_PUBS;
    const NUM_HASHES: usize = NUM_HASH;

    let public_inputs_ftrs: [_; NUM_PUB_INPUTS] = std::array::from_fn(|i| {
        wots_client.get_256_public_key(deposit_txid, DEPOSIT_VOUT, i as u32)
    });
    let fqs_ftrs: [_; NUM_FQS] = std::array::from_fn(|i| {
        wots_client.get_256_public_key(deposit_txid, DEPOSIT_VOUT, (i + NUM_PUB_INPUTS) as u32)
    });
    let hashes_ftrs: [_; NUM_HASHES] = std::array::from_fn(|i| {
        wots_client.get_128_public_key(deposit_txid, DEPOSIT_VOUT, i as u32)
    });
    let (public_inputs, fqs, hashes) = join3(
        join_all(public_inputs_ftrs),
        join_all(fqs_ftrs),
        join_all(hashes_ftrs),
    )
    .await;

    info!(%deposit_txid, %deposit_idx, "constructing wots keys");
    let public_inputs = public_inputs
        .into_iter()
        .map(|result| result.map(|bytes| Wots256PublicKey::from_flattened_bytes(&bytes)))
        .collect::<Result<_, _>>()?;
    let fqs = fqs
        .into_iter()
        .map(|result| result.map(|bytes| Wots256PublicKey::from_flattened_bytes(&bytes)))
        .collect::<Result<_, _>>()?;
    let hashes = hashes
        .into_iter()
        .map(|result| result.map(|bytes| Wots128PublicKey::from_flattened_bytes(&bytes)))
        .collect::<Result<_, _>>()?;

    let wots_pks = WotsPublicKeys::new(withdrawal_fulfillment_pk, public_inputs, fqs, hashes);

    Ok(wots_pks)
}

pub(super) async fn get_withdrawal_fulfillment_wots_pk(
    deposit_txid: Txid,
    wots_client: &WotsClient,
) -> Result<Wots256PublicKey, ContractManagerErr> {
    let withdrawal_fulfillment_pk = &wots_client
        .get_256_public_key(deposit_txid, DEPOSIT_VOUT, WITHDRAWAL_FULFILLMENT_PK_IDX)
        .await?;

    let withdrawal_fulfillment_pk =
        Wots256PublicKey::from_flattened_bytes(withdrawal_fulfillment_pk);

    Ok(withdrawal_fulfillment_pk)
}

pub(super) async fn sign_assertions(
    _wots_client: &WotsClient,
    _assertions: Assertions,
) -> Result<wots::Signatures, ContractManagerErr> {
    todo!()
}
