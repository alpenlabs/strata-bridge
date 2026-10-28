//! Signing-only CLI for claim payout interventions.

mod args;
mod config;

use std::io::{self, Write};

use anyhow::{ensure, Context, Result};
use bitcoin::{hex::DisplayHex, Network};
use bitcoincore_rpc::RpcApi;
use clap::Parser;
use serde::Serialize;
use strata_bridge_admin_signing::{AdminSigner, AdminSigningRequest, FileAdminSigner};
use strata_bridge_common::params::Params;

use crate::{
    args::{ClaimArgs, Cli, Command},
    config::Config,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let config = Config::load(&args.config)?;
    let params = Params::from_path(&args.params)
        .with_context(|| format!("could not load bridge params {}", args.params.display()))?;
    let rpc = config.rpc.client()?;
    match args.command {
        Command::Inspect(claim) => {
            let (request, confirmations) = load_request(&rpc, &config, &params, &claim)?;
            write_summary(&mut io::stdout(), params.network, &request, confirmations)?;
        }
        Command::Sign { claim, signer_file } => {
            // A previous inspection never substitutes for validation at signing time.
            let (request, confirmations) = load_request(&rpc, &config, &params, &claim)?;
            let signer = FileAdminSigner::from_path(&signer_file)
                .context("could not load the admin private key file")?;
            let public_key = signer.public_key().await?;

            let mut summary = io::stderr();
            write_summary(&mut summary, params.network, &request, confirmations)?;
            writeln!(summary, "Signing admin:     {public_key}")?;
            summary.flush()?;

            let signature = request.sign(&signer).await?;
            let output = SignatureOutput {
                claim_outpoint: request.claim_outpoint().to_string(),
                admin_public_key: public_key.to_string(),
                admin_index: signature.pubkey_index,
                signing_digest: request.digest().to_lower_hex_string(),
                sighash_type: "0x82",
                signature: signature.signature.serialize().to_lower_hex_string(),
            };
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
) -> Result<(AdminSigningRequest, u32)> {
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
    let request = AdminSigningRequest::new(
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
    request: &AdminSigningRequest,
    confirmations: u32,
) -> Result<()> {
    writeln!(output, "Network:           {network}")?;
    writeln!(output, "Claim output:      {}", request.claim_outpoint())?;
    writeln!(
        output,
        "Connector check:   Matches claim output; currently unspent"
    )?;
    writeln!(output, "Confirmations:     {confirmations}")?;
    writeln!(
        output,
        "Admin threshold:   {} of {}",
        request.threshold(),
        request.admin_pubkeys().len()
    )?;
    for (index, key) in request.admin_pubkeys().iter().enumerate() {
        writeln!(output, "Admin [{index}]:         {key}")?;
    }
    writeln!(
        output,
        "Signing digest:    {}",
        request.digest().to_lower_hex_string()
    )?;
    writeln!(output, "Sighash:           NONE | ANYONECANPAY (0x82)")?;
    writeln!(
        output,
        "\nSpending this connector blocks this claim's reimbursement payout."
    )?;
    writeln!(
        output,
        "The publisher can add funding and choose outputs and fees later."
    )?;
    Ok(())
}

/// Public signature metadata for exchange outside this tool.
#[derive(Serialize)]
struct SignatureOutput {
    /// Specific payout connector authorized for spending.
    claim_outpoint: String,
    /// Untweaked admin signing key.
    admin_public_key: String,
    /// Zero-based position in the admin script.
    admin_index: usize,
    /// Transaction digest signed by this admin.
    signing_digest: String,
    /// Explicit non-default Taproot sighash flag.
    sighash_type: &'static str,
    /// 65-byte Taproot signature encoded as hex, including the final 82 byte.
    signature: String,
}
