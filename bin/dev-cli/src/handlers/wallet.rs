//! Wallet utilities for the bridge-in command.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use bitcoin::{
    absolute::LockTime,
    address::{Address, NetworkUnchecked},
    consensus::encode::serialize_hex,
    key::TapTweak,
    opcodes::all::OP_RETURN,
    script::{Builder, PushBytesBuf},
    secp256k1::{Keypair, Message, XOnlyPublicKey, SECP256K1},
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, Network, OutPoint, PrivateKey, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use bitcoincore_rpc::{
    json::{
        CreateRawTransactionInput, WalletCreateFundedPsbtOptions, WalletCreateFundedPsbtResult,
    },
    Client, RpcApi,
};
use serde::Deserialize;
use tracing::{debug, info};

pub(crate) trait PsbtWallet {
    fn create_drt_psbt(
        &self,
        deposit_amount: Amount,
        destination_address: &Address,
        metadata: Vec<u8>,
        network: &Network,
    ) -> Result<String>;

    fn sign_and_broadcast_psbt(&self, psbt: &str) -> Result<Txid>;
}

pub(crate) struct BitcoinRpcWallet {
    client: Client,
}

impl BitcoinRpcWallet {
    pub(crate) const fn new(client: Client) -> Self {
        Self { client }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransactionOutcome {
    pub(crate) txid: Txid,
    pub(crate) tx_url: String,
    pub(crate) broadcasted: bool,
}

pub(crate) fn generate_private_key_file(
    output: &Path,
    network: Network,
    force: bool,
) -> Result<()> {
    debug!(
        output = %output.display(),
        %network,
        force,
        "opening WIF private key output file"
    );

    let private_key = PrivateKey::generate(network);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(force);

    if !force {
        options.create_new(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    let mut file = options
        .open(output)
        .with_context(|| format!("failed to open {} for private key output", output.display()))?;
    writeln!(file, "{}", private_key.to_wif())
        .with_context(|| format!("failed to write private key to {}", output.display()))?;

    Ok(())
}

pub(crate) fn read_private_key_file(path: &Path, network: Network) -> Result<PrivateKey> {
    debug!(
        key_file = %path.display(),
        %network,
        "reading WIF private key file"
    );

    let wif = fs::read_to_string(path)
        .with_context(|| format!("failed to read private key file {}", path.display()))?;
    let private_key = PrivateKey::from_wif(wif.trim())
        .with_context(|| format!("failed to parse WIF private key in {}", path.display()))?;

    if private_key.network != network.into() {
        bail!(
            "private key network does not match requested network {}; WIF only distinguishes mainnet from test networks",
            network
        );
    }

    debug!(
        key_file = %path.display(),
        %network,
        "validated WIF private key network"
    );

    Ok(private_key)
}

pub(crate) fn p2tr_address_from_private_key(private_key: &PrivateKey, network: Network) -> Address {
    Address::p2tr(
        SECP256K1,
        xonly_pubkey_from_private_key(private_key),
        None,
        network,
    )
}

pub(crate) fn xonly_pubkey_from_private_key(private_key: &PrivateKey) -> XOnlyPublicKey {
    let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&untweaked_keypair(private_key));
    xonly_pubkey
}

fn untweaked_keypair(private_key: &PrivateKey) -> Keypair {
    Keypair::from_secret_key(SECP256K1, &private_key.inner)
}

#[derive(Clone)]
pub(crate) struct LocalBridgeInWallet {
    private_key: PrivateKey,
    funding_address: Address,
    change_address: Address,
    fee_rate_sats_per_vbyte: u64,
    api: MempoolApi,
}

impl LocalBridgeInWallet {
    pub(crate) fn new(
        private_key: PrivateKey,
        network: Network,
        change_address: Option<&str>,
        fee_rate_sats_per_vbyte: u64,
        esplora_url: Option<&str>,
    ) -> Result<Self> {
        if fee_rate_sats_per_vbyte == 0 {
            bail!("fee rate must be greater than zero");
        }

        let funding_address = p2tr_address_from_private_key(&private_key, network);
        let change_address = match change_address {
            Some(address) => parse_address(address, network)?,
            None => funding_address.clone(),
        };

        let api_url = esplora_url.unwrap_or(default_esplora_url(network)?);
        let api = MempoolApi::new(api_url);

        info!(
            %network,
            %funding_address,
            %change_address,
            api_url,
            fee_rate_sat_vb = fee_rate_sats_per_vbyte,
            "initialized local WIF wallet"
        );

        Ok(Self {
            private_key,
            funding_address,
            change_address,
            fee_rate_sats_per_vbyte,
            api,
        })
    }

    pub(crate) async fn sign_and_maybe_broadcast_drt(
        &self,
        amount: Amount,
        destination_address: &Address,
        metadata: Vec<u8>,
        dry_run: bool,
    ) -> Result<TransactionOutcome> {
        if amount == Amount::ZERO {
            bail!("amount must be greater than zero");
        }

        info!(
            kind = "bridge-in",
            funding_address = %self.funding_address,
            destination_address = %destination_address,
            amount_sats = amount.to_sat(),
            metadata_bytes = metadata.len(),
            fee_rate_sat_vb = self.fee_rate_sats_per_vbyte,
            dry_run,
            "preparing local transaction"
        );

        let utxos = self.api.get_address_utxos(&self.funding_address).await?;
        if utxos.is_empty() {
            bail!(
                "no UTXOs found for funding address {}",
                self.funding_address
            );
        }
        log_utxo_summary("bridge-in", &self.funding_address, &utxos);

        let op_return_script = op_return_script(metadata)?;
        let funding_script = self.funding_address.script_pubkey();
        let change_script = self.change_address.script_pubkey();
        let outputs = drt_outputs(amount, destination_address, op_return_script);

        let plan = select_utxos(
            utxos,
            &outputs,
            &change_script,
            self.fee_rate_sats_per_vbyte,
        )?;
        log_funding_plan("bridge-in", &plan, &outputs, self.fee_rate_sats_per_vbyte)?;

        let mut tx = build_unsigned_transaction(
            &plan.selected_utxos,
            outputs,
            plan.change_amount,
            &change_script,
        );

        sign_p2tr_key_spend_inputs(
            &mut tx,
            &plan.selected_utxos,
            &funding_script,
            &self.private_key,
        )
        .context("failed to sign local bridge-in transaction")?;

        self.maybe_broadcast_signed_transaction(&tx, &plan, dry_run, "bridge-in")
            .await
    }

    pub(crate) async fn sign_and_maybe_broadcast_payment(
        &self,
        amount: Amount,
        destination_address: &Address,
        dry_run: bool,
    ) -> Result<TransactionOutcome> {
        if amount == Amount::ZERO {
            bail!("amount must be greater than zero");
        }

        info!(
            kind = "payment",
            funding_address = %self.funding_address,
            destination_address = %destination_address,
            amount_sats = amount.to_sat(),
            fee_rate_sat_vb = self.fee_rate_sats_per_vbyte,
            dry_run,
            "preparing local transaction"
        );

        let destination_script = destination_address.script_pubkey();
        let dust_threshold = destination_script.minimal_non_dust();
        if amount < dust_threshold {
            bail!(
                "amount {} sats is below the dust threshold of {} sats for {}",
                amount.to_sat(),
                dust_threshold.to_sat(),
                destination_address
            );
        }

        let utxos = self.api.get_address_utxos(&self.funding_address).await?;
        if utxos.is_empty() {
            bail!(
                "no UTXOs found for funding address {}",
                self.funding_address
            );
        }
        log_utxo_summary("payment", &self.funding_address, &utxos);

        let funding_script = self.funding_address.script_pubkey();
        let change_script = self.change_address.script_pubkey();
        let outputs = payment_outputs(amount, destination_address);
        let plan = select_utxos(
            utxos,
            &outputs,
            &change_script,
            self.fee_rate_sats_per_vbyte,
        )?;
        log_funding_plan("payment", &plan, &outputs, self.fee_rate_sats_per_vbyte)?;

        let mut tx = build_unsigned_transaction(
            &plan.selected_utxos,
            outputs,
            plan.change_amount,
            &change_script,
        );

        sign_p2tr_key_spend_inputs(
            &mut tx,
            &plan.selected_utxos,
            &funding_script,
            &self.private_key,
        )
        .context("failed to sign local payment transaction")?;

        self.maybe_broadcast_signed_transaction(&tx, &plan, dry_run, "payment")
            .await
    }

    async fn maybe_broadcast_signed_transaction(
        &self,
        tx: &Transaction,
        plan: &FundingPlan,
        dry_run: bool,
        kind: &str,
    ) -> Result<TransactionOutcome> {
        let txid = tx.compute_txid();
        let tx_url = self.api.tx_url(&txid);
        let raw_tx = serialize_hex(&tx);
        let input_total: u64 = plan.selected_utxos.iter().map(|utxo| utxo.value).sum();
        let output_total: u64 = tx.output.iter().map(|output| output.value.to_sat()).sum();
        let fee = input_total.saturating_sub(output_total);

        debug!(?tx, kind = kind, "built signed transaction");

        info!(
            %txid,
            kind = kind,
            inputs = plan.selected_utxos.len(),
            fee_sats = fee,
            vbytes = tx.vsize(),
            change_sats = plan.change_amount.map(|amount| amount.to_sat()).unwrap_or_default(),
            %tx_url,
            "built signed transaction"
        );

        if !dry_run {
            let broadcast_txid = self.api.broadcast_raw_tx(&raw_tx, tx.vsize()).await?;
            let broadcast_tx_url = self.api.tx_url(&broadcast_txid);
            info!(
                %broadcast_txid,
                %broadcast_tx_url,
                kind = kind,
                "broadcast transaction through mempool/Esplora"
            );
        } else {
            info!(%raw_tx, %tx_url, kind = kind, "dry run: transaction not broadcast");
        }

        Ok(TransactionOutcome {
            txid,
            tx_url,
            broadcasted: !dry_run,
        })
    }
}

#[derive(Debug, Clone)]
struct MempoolApi {
    client: reqwest::Client,
    base_url: String,
}

impl MempoolApi {
    fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn tx_url(&self, txid: &Txid) -> String {
        mempool_tx_url_from_api_url(&self.base_url, txid)
    }

    async fn get_address_utxos(&self, address: &Address) -> Result<Vec<AddressUtxo>> {
        let url = format!("{}/address/{address}/utxo", self.base_url);
        info!(%address, %url, "fetching address UTXOs");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failed to fetch UTXOs from {url}"))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("failed to read UTXO response body")?;
        if !status.is_success() {
            bail!("UTXO lookup failed with HTTP {status}: {body}");
        }

        let utxos = serde_json::from_str::<Vec<AddressUtxo>>(&body)
            .context("failed to parse UTXO response")?;
        info!(%address, utxos = utxos.len(), "fetched address UTXOs");

        Ok(utxos)
    }

    async fn broadcast_raw_tx(&self, raw_tx: &str, vsize: usize) -> Result<Txid> {
        let url = format!("{}/tx", self.base_url);
        info!(
            %url,
            vbytes = vsize,
            "broadcasting raw transaction"
        );

        let response = self
            .client
            .post(&url)
            .header("content-type", "text/plain")
            .body(raw_tx.to_owned())
            .send()
            .await
            .with_context(|| format!("failed to POST transaction to {url}"))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("failed to read broadcast response body")?;
        if !status.is_success() {
            bail!("transaction broadcast failed with HTTP {status}: {body}");
        }

        Txid::from_str(body.trim()).context("broadcast response was not a txid")
    }
}

#[derive(Debug, Clone, Deserialize)]
struct AddressUtxo {
    txid: Txid,
    vout: u32,
    value: u64,
    status: UtxoStatus,
}

#[derive(Debug, Clone, Deserialize)]
struct UtxoStatus {
    confirmed: bool,
}

#[derive(Debug, Clone)]
struct FundingPlan {
    selected_utxos: Vec<AddressUtxo>,
    change_amount: Option<Amount>,
}

fn log_utxo_summary(kind: &str, funding_address: &Address, utxos: &[AddressUtxo]) {
    let total_sats = utxos
        .iter()
        .fold(0u64, |total, utxo| total.saturating_add(utxo.value));
    let confirmed_utxos = utxos.iter().filter(|utxo| utxo.status.confirmed).count();
    let confirmed_sats = utxos
        .iter()
        .filter(|utxo| utxo.status.confirmed)
        .fold(0u64, |total, utxo| total.saturating_add(utxo.value));

    info!(
        kind = kind,
        %funding_address,
        utxos = utxos.len(),
        confirmed_utxos,
        unconfirmed_utxos = utxos.len().saturating_sub(confirmed_utxos),
        total_sats,
        confirmed_sats,
        "loaded funding address UTXOs"
    );
}

fn log_funding_plan(
    kind: &str,
    plan: &FundingPlan,
    target_outputs: &[TxOut],
    fee_rate_sats_per_vbyte: u64,
) -> Result<()> {
    let input_sats = plan
        .selected_utxos
        .iter()
        .fold(0u64, |total, utxo| total.saturating_add(utxo.value));
    let output_sats = output_total_sats(target_outputs)?;
    let change_sats = plan
        .change_amount
        .map(|amount| amount.to_sat())
        .unwrap_or_default();
    let fee_sats = input_sats.saturating_sub(output_sats.saturating_add(change_sats));
    let confirmed_inputs = plan
        .selected_utxos
        .iter()
        .filter(|utxo| utxo.status.confirmed)
        .count();

    info!(
        kind = kind,
        selected_inputs = plan.selected_utxos.len(),
        confirmed_inputs,
        input_sats,
        output_sats,
        change_sats,
        fee_sats,
        fee_rate_sat_vb = fee_rate_sats_per_vbyte,
        "selected funding plan"
    );
    debug!(
        kind = kind,
        selected_utxos = ?plan.selected_utxos,
        "selected funding UTXOs"
    );

    Ok(())
}

fn select_utxos(
    mut utxos: Vec<AddressUtxo>,
    target_outputs: &[TxOut],
    change_script: &ScriptBuf,
    fee_rate_sats_per_vbyte: u64,
) -> Result<FundingPlan> {
    let target_sats = output_total_sats(target_outputs)?;
    debug!(
        available_utxos = utxos.len(),
        target_sats,
        fee_rate_sat_vb = fee_rate_sats_per_vbyte,
        "selecting funding UTXOs"
    );

    // Prefer confirmed UTXOs, then larger UTXOs, to keep the input set small.
    utxos.sort_by(|a, b| {
        b.status
            .confirmed
            .cmp(&a.status.confirmed)
            .then_with(|| b.value.cmp(&a.value))
    });

    let mut selected = Vec::new();
    let mut input_total = 0u64;

    for utxo in utxos {
        input_total = input_total
            .checked_add(utxo.value)
            .context("input amount overflow")?;
        selected.push(utxo);
        let selected_utxo = selected.last().expect("selected UTXO was just pushed");
        debug!(
            txid = %selected_utxo.txid,
            vout = selected_utxo.vout,
            value_sats = selected_utxo.value,
            confirmed = selected_utxo.status.confirmed,
            selected_inputs = selected.len(),
            input_total_sats = input_total,
            "considering funding UTXO"
        );

        if let Some(plan) = funding_plan_for_selected(
            selected.clone(),
            input_total,
            target_outputs,
            change_script,
            fee_rate_sats_per_vbyte,
        )? {
            return Ok(plan);
        }
    }

    bail!(
        "insufficient funds: selected {} sats, need at least {} sats plus miner fee",
        input_total,
        output_total_sats(target_outputs)?
    );
}

fn funding_plan_for_selected(
    selected_utxos: Vec<AddressUtxo>,
    input_total: u64,
    target_outputs: &[TxOut],
    change_script: &ScriptBuf,
    fee_rate_sats_per_vbyte: u64,
) -> Result<Option<FundingPlan>> {
    let input_count = selected_utxos.len();
    let target_sats = output_total_sats(target_outputs)?;
    let no_change_fee = estimate_fee_sats(
        input_count,
        false,
        target_outputs,
        change_script,
        fee_rate_sats_per_vbyte,
    )?;

    let Some(no_change_needed) = target_sats.checked_add(no_change_fee) else {
        bail!("target amount plus fee overflow");
    };
    if input_total < no_change_needed {
        return Ok(None);
    }

    let with_change_fee = estimate_fee_sats(
        input_count,
        true,
        target_outputs,
        change_script,
        fee_rate_sats_per_vbyte,
    )?;
    let change_sats = input_total.saturating_sub(target_sats.saturating_add(with_change_fee));
    let dust_threshold = change_script.minimal_non_dust().to_sat();

    if input_total >= target_sats.saturating_add(with_change_fee) && change_sats >= dust_threshold {
        Ok(Some(FundingPlan {
            selected_utxos,
            change_amount: Some(Amount::from_sat(change_sats)),
        }))
    } else {
        Ok(Some(FundingPlan {
            selected_utxos,
            change_amount: None,
        }))
    }
}

fn estimate_fee_sats(
    input_count: usize,
    include_change: bool,
    target_outputs: &[TxOut],
    change_script: &ScriptBuf,
    fee_rate_sats_per_vbyte: u64,
) -> Result<u64> {
    let mut tx = dummy_signed_transaction(
        input_count,
        target_outputs,
        include_change.then_some(change_script),
    );
    for input in &mut tx.input {
        input.witness.push([0u8; 64]);
    }

    let vbytes = u64::try_from(tx.vsize()).context("transaction vsize overflow")?;
    fee_rate_sats_per_vbyte
        .checked_mul(vbytes)
        .context("fee amount overflow")
}

fn dummy_signed_transaction(
    input_count: usize,
    target_outputs: &[TxOut],
    change_script: Option<&ScriptBuf>,
) -> Transaction {
    let dummy_utxos = (0..input_count)
        .map(|_| TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        })
        .collect::<Vec<_>>();

    let mut output = target_outputs.to_vec();
    if let Some(change_script) = change_script {
        output.push(TxOut {
            value: Amount::from_sat(change_script.minimal_non_dust().to_sat()),
            script_pubkey: change_script.clone(),
        });
    }

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: dummy_utxos,
        output,
    }
}

fn build_unsigned_transaction(
    selected_utxos: &[AddressUtxo],
    mut output: Vec<TxOut>,
    change_amount: Option<Amount>,
    change_script: &ScriptBuf,
) -> Transaction {
    let input = selected_utxos
        .iter()
        .map(|utxo| TxIn {
            previous_output: OutPoint::new(utxo.txid, utxo.vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        })
        .collect::<Vec<_>>();

    if let Some(change_amount) = change_amount {
        output.push(TxOut {
            value: change_amount,
            script_pubkey: change_script.clone(),
        });
    }

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    }
}

fn output_total_sats(outputs: &[TxOut]) -> Result<u64> {
    outputs.iter().try_fold(0u64, |total, output| {
        total
            .checked_add(output.value.to_sat())
            .context("output amount overflow")
    })
}

fn drt_outputs(
    target_amount: Amount,
    destination_address: &Address,
    op_return_script: ScriptBuf,
) -> Vec<TxOut> {
    vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return_script,
        },
        TxOut {
            value: target_amount,
            script_pubkey: destination_address.script_pubkey(),
        },
    ]
}

fn payment_outputs(target_amount: Amount, destination_address: &Address) -> Vec<TxOut> {
    vec![TxOut {
        value: target_amount,
        script_pubkey: destination_address.script_pubkey(),
    }]
}

fn sign_p2tr_key_spend_inputs(
    tx: &mut Transaction,
    selected_utxos: &[AddressUtxo],
    funding_script: &ScriptBuf,
    private_key: &PrivateKey,
) -> Result<()> {
    debug!(inputs = tx.input.len(), "signing taproot key-spend inputs");

    let prevouts = selected_utxos
        .iter()
        .map(|utxo| TxOut {
            value: Amount::from_sat(utxo.value),
            script_pubkey: funding_script.clone(),
        })
        .collect::<Vec<_>>();
    let signing_keypair = untweaked_keypair(private_key)
        .tap_tweak(SECP256K1, None)
        .to_keypair();

    for input_index in 0..tx.input.len() {
        let sighash = {
            let mut sighash_cache = SighashCache::new(&*tx);
            sighash_cache.taproot_key_spend_signature_hash(
                input_index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )?
        };
        let msg = Message::from_digest_slice(sighash.as_ref())
            .context("failed to create message from taproot sighash")?;
        let signature = signing_keypair.sign_schnorr(msg);
        tx.input[input_index].witness.push(signature.serialize());

        debug!(input_index, "signed taproot key-spend input");
    }

    Ok(())
}

fn op_return_script(metadata: Vec<u8>) -> Result<ScriptBuf> {
    let mut push_data = PushBytesBuf::new();
    push_data
        .extend_from_slice(&metadata)
        .context("failed to encode OP_RETURN push data")?;

    Ok(Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push_data)
        .into_script())
}

pub(crate) fn parse_address(address: &str, network: Network) -> Result<Address> {
    address
        .parse::<Address<NetworkUnchecked>>()?
        .require_network(network)
        .with_context(|| format!("address {address} is not valid for {network}"))
}

pub(crate) fn default_mempool_tx_url(network: Network, txid: &Txid) -> Option<String> {
    Some(mempool_tx_url_from_api_url(
        default_esplora_url(network).ok()?,
        txid,
    ))
}

fn mempool_tx_url_from_api_url(api_url: &str, txid: &Txid) -> String {
    let base_url = api_url.trim_end_matches('/');
    let explorer_url = base_url.strip_suffix("/api").unwrap_or(base_url);

    format!("{explorer_url}/tx/{txid}")
}

fn default_esplora_url(network: Network) -> Result<&'static str> {
    match network {
        Network::Bitcoin => Ok("https://mempool.space/api"),
        Network::Testnet | Network::Testnet4 => Ok("https://mempool.space/testnet/api"),
        Network::Signet => Ok("https://mempool.space/signet/api"),
        Network::Regtest => {
            bail!("regtest requires --api-url when using a WIF key")
        }
    }
}

impl PsbtWallet for BitcoinRpcWallet {
    fn create_drt_psbt(
        &self,
        amount: Amount,
        destination_address: &Address,
        metadata: Vec<u8>,
        network: &Network,
    ) -> Result<String> {
        let change_address = self
            .client
            .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
            .context("Failed to get new address from RPC client")?
            .require_network(*network)
            .context("Failed to get change address");

        let inputs: Vec<CreateRawTransactionInput> = vec![];
        // SPS-50 spec: OP_RETURN must be at index 0, P2TR at index 1
        let outputs = vec![
            serde_json::Map::from_iter(vec![(
                "data".to_string(),
                serde_json::to_value(hex::encode(metadata))?,
            )]),
            serde_json::Map::from_iter(vec![(
                destination_address.to_string(),
                serde_json::to_value(amount.to_btc())?,
            )]),
        ];

        let options = WalletCreateFundedPsbtOptions {
            replaceable: Some(true),
            change_address: Some(change_address.unwrap().as_unchecked().clone()),
            change_position: Some(2),
            ..Default::default()
        };

        let args: Vec<serde_json::Value> = vec![
            serde_json::to_value(inputs)?,
            serde_json::to_value(outputs)?,
            serde_json::Value::Null,
            serde_json::to_value(options)?,
            serde_json::Value::Null,
        ];

        let psbt: WalletCreateFundedPsbtResult =
            self.client.call("walletcreatefundedpsbt", &args)?;
        Ok(psbt.psbt)
    }

    fn sign_and_broadcast_psbt(&self, psbt: &str) -> Result<Txid> {
        let signed_psbt = self
            .client
            .wallet_process_psbt(psbt, None, None, None)
            .context("Failed to process psbt")?;
        let finalized_psbt = self.client.finalize_psbt(&signed_psbt.psbt, None).unwrap();

        let tx = finalized_psbt.transaction();
        debug!(event = "finalized psbt", ?tx);

        let raw_tx = finalized_psbt.hex.unwrap();
        let txid = self.client.send_raw_transaction(&raw_tx).unwrap();
        info!(event = "transaction broadcasted with txid", %txid);

        Ok(txid)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, secp256k1::SecretKey};

    use super::*;

    fn test_private_key() -> PrivateKey {
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        PrivateKey::new(secret_key, Network::Signet)
    }

    fn test_utxo(value: u64, confirmed: bool) -> AddressUtxo {
        AddressUtxo {
            txid: Txid::from_slice(&[1u8; 32]).unwrap(),
            vout: 0,
            value,
            status: UtxoStatus { confirmed },
        }
    }

    #[test]
    fn p2tr_address_uses_requested_network() {
        let private_key = test_private_key();
        let address = p2tr_address_from_private_key(&private_key, Network::Signet);

        assert_eq!(address.to_string().split('1').next(), Some("tb"));
    }

    #[test]
    fn select_utxos_adds_change_when_above_dust() {
        let private_key = test_private_key();
        let destination = p2tr_address_from_private_key(&private_key, Network::Signet);
        let change_script = destination.script_pubkey();
        let outputs = drt_outputs(
            Amount::from_sat(10_000),
            &destination,
            op_return_script(vec![1, 2, 3]).unwrap(),
        );

        let plan =
            select_utxos(vec![test_utxo(20_000, true)], &outputs, &change_script, 2).unwrap();

        assert_eq!(plan.selected_utxos.len(), 1);
        assert!(plan.change_amount.is_some());
    }

    #[test]
    fn select_utxos_supports_plain_payment() {
        let private_key = test_private_key();
        let destination = p2tr_address_from_private_key(&private_key, Network::Signet);
        let change_script = destination.script_pubkey();
        let outputs = payment_outputs(Amount::from_sat(10_000), &destination);

        let plan =
            select_utxos(vec![test_utxo(15_000, true)], &outputs, &change_script, 2).unwrap();

        assert_eq!(plan.selected_utxos.len(), 1);
    }

    #[test]
    fn mempool_tx_url_strips_api_suffix() {
        let txid = Txid::from_slice(&[2u8; 32]).unwrap();

        assert_eq!(
            mempool_tx_url_from_api_url("https://mempool.space/signet/api/", &txid),
            format!("https://mempool.space/signet/tx/{txid}")
        );
    }
}
