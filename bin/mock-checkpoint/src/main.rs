/*! doc crate */

mod args;
mod chainstate;
mod checkpoint;
mod params;

use std::{process::exit, sync::Arc};

use anyhow::Context;
use bitcoin::Transaction;
use bitcoind_async_client::{
    traits::{Broadcaster, Wallet},
    Client,
};
use clap::Parser;
use strata_btcio::writer::builder::{create_envelope_transactions, EnvelopeParams};
use strata_primitives::l1::payload::L1Payload;

use crate::{
    args::Args,
    chainstate::{create_chainstate, update_chainstate},
    checkpoint::{create_checkpoint, sign_checkpoint},
    params::create_params,
};

fn create_bitcoin_client(args: &Args) -> Client {
    let max_retries = Some(3);
    let retry_interval = Some(3);
    Client::new(
        args.bitcoin_url.clone(),
        args.bitcoin_username.clone(),
        args.bitcoin_password.clone(),
        max_retries,
        retry_interval,
    )
    .expect("Could not create bitcoin client")
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let chainstate = create_chainstate();
    let new_chainstate = update_chainstate(chainstate, &args);
    let checkpoint = create_checkpoint(new_chainstate);
    let signed_checkpoint = sign_checkpoint(checkpoint, &args.sequencer_private_key);
    let l1p = L1Payload::new_checkpoint(borsh::to_vec(&signed_checkpoint).unwrap());

    let rollup_params = create_params(&args);
    let env_params = EnvelopeParams::new(
        Arc::new(rollup_params),
        args.sequencer_address.clone(),
        args.network,
        args.fee_rate,
    );

    let bitcoin_client = create_bitcoin_client(&args);
    let utxos = bitcoin_client
        .get_utxos()
        .await
        .expect("Could not get wallet utxos");
    let (commit_tx, reveal_tx) = create_envelope_transactions(&env_params, &[l1p], utxos).unwrap();

    if let Err(e) = publish_txs(&bitcoin_client, commit_tx, reveal_tx).await {
        eprintln!("Failed to publish txs: {e}");
        exit(1);
    }
}

async fn publish_txs(
    client: &bitcoind_async_client::Client,
    commit_tx: Transaction,
    reveal_tx: Transaction,
) -> anyhow::Result<()> {
    client
        .send_raw_transaction(&commit_tx)
        .await
        .context("Could not publish commit tx")?;
    client
        .send_raw_transaction(&reveal_tx)
        .await
        .context("Could not publish reveal tx")?;
    Ok(())
}
