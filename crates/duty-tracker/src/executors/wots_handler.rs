//! Contains functions to handle WOTS keys generation and signing.

use bitcoin::Txid;
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use futures::future::{join3, join_all};
use secret_service_client::{wots::WotsClient, SecretServiceClient};
use secret_service_proto::v2::traits::*;
use strata_bridge_p2p_types::{Wots128PublicKey, Wots256PublicKey, WotsPublicKeys};
use strata_bridge_primitives::wots::{self, Assertions};
use tracing::info;

use crate::{
    errors::ContractManagerErr,
    executors::constants::{DEPOSIT_VOUT, WITHDRAWAL_FULFILLMENT_PK_IDX},
};

pub(super) async fn get_wots_pks(
    deposit_txid: Txid,
    s2_client: &SecretServiceClient,
) -> Result<WotsPublicKeys, ContractManagerErr> {
    let wots_client = s2_client.wots_signer();
    let withdrawal_fulfillment_pk =
        get_withdrawal_fulfillment_wots_pk(deposit_txid, &wots_client).await?;

    let public_inputs_ftrs: [_; NUM_PUBS] = std::array::from_fn(|i| {
        wots_client.get_256_public_key(
            deposit_txid,
            DEPOSIT_VOUT,
            WITHDRAWAL_FULFILLMENT_PK_IDX + i as u32,
        )
    });
    let fqs_ftrs: [_; NUM_U256] = std::array::from_fn(|i| {
        wots_client.get_256_public_key(
            deposit_txid,
            DEPOSIT_VOUT,
            WITHDRAWAL_FULFILLMENT_PK_IDX + (NUM_PUBS + i) as u32,
        )
    });
    let hashes_ftrs: [_; NUM_HASH] = std::array::from_fn(|i| {
        wots_client.get_128_public_key(deposit_txid, DEPOSIT_VOUT, i as u32)
    });
    let (public_inputs, fqs, hashes) = join3(
        join_all(public_inputs_ftrs),
        join_all(fqs_ftrs),
        join_all(hashes_ftrs),
    )
    .await;

    info!(%deposit_txid, "constructing wots keys");
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
    deposit_txid: Txid,
    wots_client: &WotsClient,
    assertions: Assertions,
) -> Result<wots::Signatures, ContractManagerErr> {
    let Assertions {
        withdrawal_fulfillment,
        groth16: (public_params, field_elems, hashes),
    } = assertions;

    let withdrawal_fulfillment_sig = wots_client
        .get_256_signature(
            deposit_txid,
            DEPOSIT_VOUT,
            WITHDRAWAL_FULFILLMENT_PK_IDX,
            &withdrawal_fulfillment,
        )
        .await?;

    let public_params_sigs_futures = public_params.iter().enumerate().map(|(i, public_param)| {
        wots_client.get_256_signature(
            deposit_txid,
            DEPOSIT_VOUT,
            WITHDRAWAL_FULFILLMENT_PK_IDX + i as u32,
            public_param,
        )
    });

    let field_elems_sigs_futures = field_elems.iter().enumerate().map(|(i, field_elem)| {
        wots_client.get_256_signature(
            deposit_txid,
            DEPOSIT_VOUT,
            WITHDRAWAL_FULFILLMENT_PK_IDX + NUM_PUBS as u32 + i as u32,
            field_elem,
        )
    });

    let hash_sigs_futures = hashes
        .iter()
        .enumerate()
        .map(|(i, hash)| wots_client.get_128_signature(deposit_txid, DEPOSIT_VOUT, i as u32, hash));

    let (public_params_sigs, field_elems_sigs, hash_sigs) = join3(
        join_all(public_params_sigs_futures),
        join_all(field_elems_sigs_futures),
        join_all(hash_sigs_futures),
    )
    .await;

    let public_params_sigs = public_params_sigs
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    if public_params_sigs.len() != NUM_PUBS {
        return Err(ContractManagerErr::FatalErr(format!(
            "public params signatures must have the right size, expected: {NUM_PUBS}, got: {}",
            public_params_sigs.len()
        )));
    }

    let public_params_sigs = public_params_sigs
        .try_into()
        .expect("public params signatures must have the right size");

    let field_elems_sigs = field_elems_sigs
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    if field_elems_sigs.len() != NUM_U256 {
        return Err(ContractManagerErr::FatalErr(format!(
            "field element signatures must have the right size, expected: {NUM_U256}, got: {}",
            field_elems_sigs.len()
        )));
    }

    let field_elems_sigs = field_elems_sigs
        .try_into()
        .expect("field element signatures must have the right size");

    let hash_sigs = hash_sigs.into_iter().collect::<Result<Vec<_>, _>>()?;

    if hash_sigs.len() != NUM_HASH {
        return Err(ContractManagerErr::FatalErr(format!(
            "hash signatures must have the right size, expected: {NUM_HASH}, got: {}",
            hash_sigs.len()
        )));
    }

    let hash_sigs = hash_sigs
        .try_into()
        .expect("hash signatures must have the right size");

    let wots_sigs = wots::Signatures {
        withdrawal_fulfillment: wots::Wots256Sig(withdrawal_fulfillment_sig),
        groth16: wots::Groth16Sigs((
            Box::new(public_params_sigs),
            Box::new(field_elems_sigs),
            Box::new(hash_sigs),
        )),
    };

    Ok(wots_sigs)
}
