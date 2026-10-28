//! Signing-only CLI for claim payout interventions.

mod args;
mod config;
mod signer;
mod signing;

use std::io::{self, Write};

use anyhow::{ensure, Context, Result};
use bitcoin::{hex::DisplayHex, Network};
use bitcoincore_rpc::RpcApi;
use clap::Parser;
// Used by the separate integration test, rather than this binary's unit tests.
#[cfg(test)]
use corepc_node as _;
use serde_json::json;
use strata_bridge_common::params::Params;

use crate::{
    args::{ClaimArgs, Cli, Command},
    config::Config,
    signer::{AdminSigner, FileAdminSigner},
    signing::SigningRequest,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let config = Config::load(&args.config)?;
    let params = Params::from_path(&args.params)
        .with_context(|| format!("could not load bridge params {}", args.params.display()))?;
    let rpc = config.rpc.client()?;

    let claim = match &args.command {
        Command::Inspect(claim) | Command::Sign { claim, .. } => claim,
    };
    let (request, confirmations) = load_request(&rpc, &config, &params, claim)?;

    match args.command {
        Command::Inspect(_) => {
            write_summary(&mut io::stdout(), params.network, &request, confirmations)?;
        }
        Command::Sign { signer_file, .. } => {
            let signer = FileAdminSigner::from_path(&signer_file)
                .context("could not load the admin private key file")?;
            let public_key = signer.public_key().await?;

            let mut summary = io::stderr();
            write_summary(&mut summary, params.network, &request, confirmations)?;
            writeln!(summary, "Signing admin:     {public_key}")?;
            summary.flush()?;

            let signature = request.sign(&signer, public_key).await?;
            let output = json!({
                "claim_outpoint": request.claim_outpoint().to_string(),
                "admin_public_key": public_key.to_string(),
                "admin_index": signature.pubkey_index,
                "signing_digest": request.digest().to_lower_hex_string(),
                "sighash_type": "0x82",
                "signature": signature.signature.serialize().to_lower_hex_string(),
            });

            serde_json::to_writer_pretty(io::stdout(), &output)?;
            println!();
        }
    }

    Ok(())
}

/// Fetches and validates the claim and its currently unspent payout output.
fn load_request(
    rpc: &impl RpcApi,
    config: &Config,
    params: &Params,
    args: &ClaimArgs,
) -> Result<(SigningRequest, u32)> {
    let chain = rpc
        .get_blockchain_info()
        .context("could not read Bitcoin chain information")?;
    ensure!(
        chain.chain == params.network,
        "Bitcoin node is on {}, bridge params expect {}",
        chain.chain,
        params.network
    );

    let claim = rpc.get_raw_transaction(&args.claim_txid, None).context(
        "could not fetch claim transaction; confirmed claims require a node with txindex=1",
    )?;
    let request = SigningRequest::new(
        args.claim_txid,
        &claim,
        config.signing_params(params, args.unstaking_hash),
    )?;

    let outpoint = request.claim_outpoint();
    let unspent = rpc
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
        .context("could not check the claim payout UTXO")?
        .context("claim payout output is spent or unavailable (including mempool spends)")?;
    let prevout = &claim.output[outpoint.vout as usize];

    ensure!(
        unspent.value == prevout.value && unspent.script_pub_key.script()? == prevout.script_pubkey,
        "node's unspent output does not match the validated claim payout"
    );

    Ok((request, unspent.confirmations))
}

/// Shows the target and scope of the authorization before any signature is requested.
fn write_summary(
    output: &mut impl Write,
    network: Network,
    request: &SigningRequest,
    confirmations: u32,
) -> Result<()> {
    let admins = request
        .admin_pubkeys()
        .iter()
        .enumerate()
        .map(|(index, key)| format!("Admin [{index}]:         {key}"))
        .collect::<Vec<_>>()
        .join("\n");

    write!(
        output,
        "Network:           {network}\n\
         Claim output:      {outpoint}\n\
         Connector check:   Matches claim output; currently unspent\n\
         Confirmations:     {confirmations}\n\
         Admin threshold:   {threshold} of {count}\n\
         {admins}\n\
         Signing digest:    {digest}\n\
         Sighash:           NONE | ANYONECANPAY (0x82)\n\n\
         Spending this connector blocks this claim's reimbursement payout.\n\
         The publisher can add funding and choose outputs and fees later.\n",
        outpoint = request.claim_outpoint(),
        threshold = request.threshold(),
        count = request.admin_pubkeys().len(),
        digest = request.digest().to_lower_hex_string(),
    )?;

    Ok(())
}
