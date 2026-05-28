//! Fireblocks-backed [`GeneralWallet`](super::GeneralWallet) implementation.
//!
//! Custodies the operator's general-purpose (fee-paying / earnings) wallet in a Fireblocks
//! BTC vault account instead of a local BDK wallet. All bridge protocol keys (anchors,
//! presigned-tx keys) remain in secret-service; Fireblocks only ever contributes a funding
//! input + optional change to cover fees and to top up internal pools.
//!
//! ## Why RAW signing
//!
//! Fireblocks can produce a BTC transaction two ways. The `TRANSFER` + `inputsSelection`
//! flow has Fireblocks build *and broadcast* its own transaction — unusable here, because we
//! must inject a foreign Taproot anchor input, force v3/TRUC, control exact outputs, and get
//! the PSBT back to package with the parent. So this backend uses **`RAW` signing**: it builds
//! the unsigned bitcoin transaction itself (input selection, change, sighashes), sends the
//! sighashes to Fireblocks for ECDSA signing, and assembles the witnesses.
//!
//! Fireblocks BTC is ECDSA secp256k1, so vault addresses are **P2WPKH**; funding witnesses are
//! `[DER-sig + SIGHASH_ALL byte, compressed pubkey]`. The anchor input stays Taproot and is
//! left unsigned for secret-service (per the [`GeneralWallet`](super::GeneralWallet) signing
//! contract).
//!
//! ## Auth
//!
//! Every request carries `X-API-Key: <api key>` and `Authorization: Bearer <JWT>`, where the
//! JWT is RS256-signed with the operator's Fireblocks API secret (an RSA private key) and
//! carries `{ uri, nonce, iat, exp, sub = api key, bodyHash = SHA256(raw body) }`.

mod auth;
mod dto;
mod sign;
mod tx;

use std::{collections::HashSet, fmt, str::FromStr, time::Duration};

use bdk_wallet::bitcoin::{
    address::NetworkUnchecked, Address, Amount, Denomination, FeeRate, Network, OutPoint, Psbt,
    Script, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use reqwest::Method;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tx::FundingInput;

use super::{AnchorInfo, FundedPsbt, GeneralWallet, UtxoInfo};

/// How often to poll a RAW-signing transaction for completion.
const SIGN_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Maximum number of poll attempts before giving up on a RAW-signing transaction (~2 min at
/// the 2s interval). Fireblocks signing latency depends on the workspace's Transaction
/// Authorization Policy; an auto-approve rule keeps this well within budget.
const SIGN_MAX_POLL_ATTEMPTS: u32 = 60;

/// Connection + identity configuration for a Fireblocks BTC vault account.
#[derive(Clone)]
pub struct FireblocksConfig {
    /// API host root, **without** the `/v1` path segment, e.g. `https://api.fireblocks.io`.
    /// Requests append `/v1/<path>` themselves so the JWT `uri` claim and the request URL
    /// stay in lockstep.
    pub base_url: String,
    /// Fireblocks API key (sent as the `X-API-Key` header).
    pub api_key: String,
    /// Vault account id holding the BTC asset.
    pub vault_account_id: String,
    /// Asset id for the network — `BTC` on mainnet, `BTC_TEST` on test networks.
    pub asset_id: String,
    /// Bitcoin network the vault operates on. Used to parse/validate the deposit address.
    pub network: Network,
    /// The vault account's BTC deposit address (P2WPKH). Operator-provided so
    /// [`FireblocksGeneralWallet::script_pubkey`](super::GeneralWallet::script_pubkey) stays
    /// synchronous and infallible.
    pub deposit_address: String,
}

impl fmt::Debug for FireblocksConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact the API key; everything else is non-secret operational config.
        f.debug_struct("FireblocksConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .field("vault_account_id", &self.vault_account_id)
            .field("asset_id", &self.asset_id)
            .field("network", &self.network)
            .field("deposit_address", &self.deposit_address)
            .finish()
    }
}

/// Errors produced by the Fireblocks backend.
#[derive(Debug, Error)]
pub enum FireblocksError {
    /// Failed to construct the RS256 signing key from the provided API secret PEM.
    #[error("invalid Fireblocks API secret (RSA PEM): {0}")]
    SigningKey(String),
    /// The configured deposit address could not be parsed or did not match the network.
    #[error("invalid deposit address: {0}")]
    DepositAddress(String),
    /// JWT construction failed.
    #[error("jwt: {0}")]
    Jwt(String),
    /// HTTP transport error talking to the Fireblocks API.
    #[error("http: {0}")]
    Http(String),
    /// Fireblocks returned a non-success status or an error body.
    #[error("fireblocks api: {0}")]
    Api(String),
    /// A response body could not be deserialized into the expected shape.
    #[error("decode response: {0}")]
    Decode(String),
    /// Transaction construction (selection / change / sighash) failed.
    #[error("tx build: {0}")]
    TxBuild(String),
    /// Witness assembly from a returned signature failed.
    #[error("witness: {0}")]
    Witness(String),
    /// A signing request did not reach a usable signed state within the allotted time.
    #[error("signing timed out for tx {0}")]
    SigningTimeout(String),
}

/// A Fireblocks-backed general wallet.
///
/// Holds the REST client + signing material and a cached snapshot of the vault's unspent
/// inputs (refreshed by [`sync`](super::GeneralWallet::sync)).
pub struct FireblocksGeneralWallet {
    config: FireblocksConfig,
    http: reqwest::Client,
    /// RS256 signing key derived from the operator's Fireblocks API secret. Used to mint the
    /// per-request JWT.
    signing_key: jsonwebtoken::EncodingKey,
    /// Receive script derived from the vault deposit address. Returned by `script_pubkey` and
    /// used for change outputs.
    script_pubkey: ScriptBuf,
    /// BOSD payout descriptor (P2WPKH) for the vault address, prebuilt at construction so the
    /// trait accessor is infallible.
    payout_descriptor: bitcoin_bosd::Descriptor,
    /// Snapshot of the vault's spendable UTXOs from the most recent `sync`.
    cached_utxos: Vec<super::UtxoInfo>,
}

impl fmt::Debug for FireblocksGeneralWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FireblocksGeneralWallet")
            .field("config", &self.config)
            .field("signing_key", &"<redacted>")
            .field("script_pubkey", &self.script_pubkey)
            .field("cached_utxos", &self.cached_utxos.len())
            .finish()
    }
}

impl FireblocksGeneralWallet {
    /// Builds a Fireblocks general wallet from `config` and the operator's API secret
    /// (`api_secret_pem`, an RSA private key in PEM form used to sign request JWTs).
    ///
    /// Parses and network-checks the deposit address up-front so `script_pubkey` can be
    /// infallible. Does not perform any network I/O — call
    /// [`sync`](super::GeneralWallet::sync) to populate the UTXO cache.
    pub fn new(config: FireblocksConfig, api_secret_pem: &[u8]) -> Result<Self, FireblocksError> {
        let signing_key = jsonwebtoken::EncodingKey::from_rsa_pem(api_secret_pem)
            .map_err(|e| FireblocksError::SigningKey(e.to_string()))?;

        let address = config
            .deposit_address
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|e| FireblocksError::DepositAddress(e.to_string()))?
            .require_network(config.network)
            .map_err(|e| FireblocksError::DepositAddress(e.to_string()))?;
        let script_pubkey = address.script_pubkey();

        // The backend assumes a P2WPKH vault (Fireblocks BTC is ECDSA secp256k1). Validate
        // up-front and build the payout descriptor from the witness-program hash so the trait
        // accessor stays infallible and we don't couple to bosd's `bitcoin` version.
        if !script_pubkey.is_p2wpkh() {
            return Err(FireblocksError::DepositAddress(format!(
                "deposit address must be P2WPKH (got {address})"
            )));
        }
        let mut wpkh = [0u8; 20];
        // P2WPKH scriptPubKey is `OP_0 PUSH20 <hash160>`; the 20-byte hash starts at byte 2.
        wpkh.copy_from_slice(&script_pubkey.as_bytes()[2..22]);
        let payout_descriptor = bitcoin_bosd::Descriptor::new_p2wpkh(&wpkh);

        Ok(Self {
            config,
            http: reqwest::Client::new(),
            signing_key,
            script_pubkey,
            payout_descriptor,
            cached_utxos: Vec::new(),
        })
    }

    /// Builds the full request URL and the matching JWT `uri` claim for an API `subpath`
    /// (the part after `/v1`, e.g. `/vault/accounts/0/BTC/unspent_inputs`).
    fn url_and_uri(&self, subpath: &str) -> (String, String) {
        let uri = format!("/v1{subpath}");
        let url = format!("{}{}", self.config.base_url, uri);
        (url, uri)
    }

    /// Issues an authenticated request to `subpath` and deserializes the JSON response into
    /// `T`. `body` is the request body for `POST`/`PUT` (the same bytes are hashed into the
    /// JWT); pass `None` for bodyless `GET`s.
    ///
    /// Non-2xx responses surface as [`FireblocksError::Api`] carrying the status + body;
    /// deserialization failures as [`FireblocksError::Decode`].
    async fn signed_request<T: DeserializeOwned>(
        &self,
        method: Method,
        subpath: &str,
        body: Option<&str>,
    ) -> Result<T, FireblocksError> {
        let (url, uri) = self.url_and_uri(subpath);
        let body_bytes = body.map_or(&b""[..], str::as_bytes);
        let jwt = auth::build_jwt(&uri, body_bytes, &self.config.api_key, &self.signing_key)?;

        let mut req = self
            .http
            .request(method, &url)
            .header("X-API-Key", &self.config.api_key)
            .bearer_auth(jwt);
        if let Some(body) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| FireblocksError::Http(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| FireblocksError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(FireblocksError::Api(format!("{status}: {text}")));
        }
        serde_json::from_str(&text)
            .map_err(|e| FireblocksError::Decode(format!("{e}; body={text}")))
    }

    /// Converts a Fireblocks unspent-input record into a backend-neutral [`UtxoInfo`],
    /// deriving the `script_pubkey` from the record's address.
    fn unspent_to_utxo_info(
        &self,
        u: &dto::UnspentInputsResponse,
    ) -> Result<UtxoInfo, FireblocksError> {
        let txid = Txid::from_str(&u.input.tx_hash)
            .map_err(|e| FireblocksError::Decode(format!("bad txHash {}: {e}", u.input.tx_hash)))?;
        let amount = Amount::from_str_in(&u.amount, Denomination::Bitcoin)
            .map_err(|e| FireblocksError::Decode(format!("bad amount {}: {e}", u.amount)))?;
        let script_pubkey = u
            .address
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|e| FireblocksError::Decode(format!("bad address {}: {e}", u.address)))?
            .require_network(self.config.network)
            .map_err(|e| {
                FireblocksError::Decode(format!("address {} wrong network: {e}", u.address))
            })?
            .script_pubkey();
        // Fireblocks reports confirmations as an unbounded integer; clamp to u32 (the depth at
        // which the exact count stops mattering for any bridge predicate).
        let confirmations = u32::try_from(u.confirmations).unwrap_or(u32::MAX);
        Ok(UtxoInfo {
            outpoint: OutPoint {
                txid,
                vout: u.input.index,
            },
            amount,
            confirmations,
            script_pubkey,
        })
    }

    /// Signs `sighashes` via a Fireblocks `RAW` transaction: submits the messages, then polls
    /// the transaction until the signatures are available (or it fails / times out). Returns
    /// the signed messages in request order.
    async fn raw_sign(
        &self,
        sighashes: &[[u8; 32]],
    ) -> Result<Vec<dto::SignedMessage>, FireblocksError> {
        let messages = sighashes
            .iter()
            .map(|h| dto::UnsignedRawMessage {
                content: hex::encode(h),
            })
            .collect();
        let request = dto::RawSignRequest {
            operation: "RAW",
            asset_id: self.config.asset_id.clone(),
            source: dto::TransferPeer {
                peer_type: "VAULT_ACCOUNT",
                id: self.config.vault_account_id.clone(),
            },
            extra_parameters: dto::ExtraParameters {
                raw_message_data: dto::RawMessageData {
                    messages,
                    algorithm: "MPC_ECDSA_SECP256K1",
                },
            },
        };
        let body = serde_json::to_string(&request)
            .map_err(|e| FireblocksError::TxBuild(format!("serialize raw-sign request: {e}")))?;
        let created: dto::CreateTransactionResponse = self
            .signed_request(Method::POST, "/transactions", Some(&body))
            .await?;

        let subpath = format!("/transactions/{}", created.id);
        for _ in 0..SIGN_MAX_POLL_ATTEMPTS {
            let details: dto::TransactionDetails =
                self.signed_request(Method::GET, &subpath, None).await?;
            if is_failure_status(&details.status) {
                return Err(FireblocksError::Api(format!(
                    "raw-sign transaction {} reached failure status {}",
                    created.id, details.status
                )));
            }
            if details.signed_messages.len() >= sighashes.len() {
                return Ok(details.signed_messages);
            }
            tokio::time::sleep(SIGN_POLL_INTERVAL).await;
        }
        Err(FireblocksError::SigningTimeout(created.id))
    }

    /// Populates `witness_utxo` on every PSBT input, RAW-signs the inputs at
    /// `fb_input_indices`, and writes their P2WPKH witnesses. Inputs not listed (e.g. a CPFP
    /// anchor) are left for downstream signing per the [`GeneralWallet`] contract.
    ///
    /// `prevouts[i]` must be the output spent by `psbt.unsigned_tx.input[i]`.
    async fn sign_fb_inputs(
        &self,
        psbt: &mut Psbt,
        fb_input_indices: &[usize],
        prevouts: &[TxOut],
    ) -> Result<(), FireblocksError> {
        for (i, prevout) in prevouts.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(prevout.clone());
        }
        if fb_input_indices.is_empty() {
            return Ok(());
        }
        let sighashes = fb_input_indices
            .iter()
            .map(|&i| tx::p2wpkh_sighash(psbt, i, prevouts))
            .collect::<Result<Vec<_>, _>>()?;
        let signed = self.raw_sign(&sighashes).await?;
        if signed.len() < fb_input_indices.len() {
            return Err(FireblocksError::Api(format!(
                "expected {} signatures, got {}",
                fb_input_indices.len(),
                signed.len()
            )));
        }
        for (n, &i) in fb_input_indices.iter().enumerate() {
            let msg = &signed[n];
            let witness = sign::assemble_p2wpkh_witness(&msg.signature.full_sig, &msg.public_key)?;
            psbt.inputs[i].final_script_witness = Some(witness);
        }
        Ok(())
    }

    /// Builds [`FundingInput`]s for an explicit input set, looking each outpoint up in the
    /// cached UTXO set, and computes the change amount (dropping change below dust into fee).
    fn funding_from_explicit(
        &self,
        explicit_inputs: &[OutPoint],
        recipient_outputs: &[TxOut],
        change_spk: &Script,
        fee_rate: FeeRate,
    ) -> Result<(Vec<FundingInput>, Option<Amount>), FireblocksError> {
        let mut funding = Vec::with_capacity(explicit_inputs.len());
        let mut total_in = Amount::ZERO;
        for op in explicit_inputs {
            let u = self
                .cached_utxos
                .iter()
                .find(|u| u.outpoint == *op)
                .ok_or_else(|| {
                    FireblocksError::TxBuild(format!("explicit input {op} not in wallet UTXO set"))
                })?;
            funding.push(FundingInput {
                outpoint: *op,
                prevout: TxOut {
                    value: u.amount,
                    script_pubkey: u.script_pubkey.clone(),
                },
            });
            total_in = total_in
                .checked_add(u.amount)
                .ok_or_else(|| FireblocksError::TxBuild("input total overflows".into()))?;
        }

        let recipient_total = recipient_outputs
            .iter()
            .try_fold(Amount::ZERO, |acc, o| acc.checked_add(o.value))
            .ok_or_else(|| FireblocksError::TxBuild("recipient output total overflows".into()))?;
        let recipient_lens: Vec<usize> = recipient_outputs
            .iter()
            .map(|o| o.script_pubkey.len())
            .collect();
        let fee_with_change = tx::fee_for(
            funding.len(),
            &recipient_lens,
            Some(change_spk.len()),
            fee_rate,
        )?;
        let fee_no_change = tx::fee_for(funding.len(), &recipient_lens, None, fee_rate)?;

        if total_in < recipient_total + fee_no_change {
            return Err(FireblocksError::TxBuild(format!(
                "explicit inputs total {total_in} cannot cover {recipient_total} + fee"
            )));
        }
        let change = total_in
            .checked_sub(recipient_total)
            .and_then(|r| r.checked_sub(fee_with_change))
            .filter(|rem| *rem >= change_spk.minimal_non_dust());
        Ok((funding, change))
    }

    /// Selects P2WPKH funding inputs for a CPFP child so the `[parent, child]` package reaches
    /// `target_pkg_fee_rate`. The child spends the combined input (value `combined_value`)
    /// plus the selected inputs and pays a single change output; its fee is the package
    /// shortfall after the parent's own fee.
    ///
    /// `combined_is_p2wpkh` distinguishes the two combined-input shapes for the fee estimate:
    /// the operator's own P2WPKH payout (every input is P2WPKH) vs. a foreign keyed-Taproot
    /// anchor (one P2TR input + the P2WPKH funding inputs).
    ///
    /// Returns the funding inputs (possibly empty when the combined input alone covers the
    /// fee) and the child's output (change) value.
    #[expect(
        clippy::too_many_arguments,
        reason = "cohesive CPFP fee-selection inputs; bundling into a struct would only add indirection"
    )]
    fn select_cpfp_funding(
        &self,
        exclude: &HashSet<OutPoint>,
        combined_value: Amount,
        combined_is_p2wpkh: bool,
        parent_vsize: u64,
        parent_fee: Amount,
        target_pkg_fee_rate: FeeRate,
        change_spk: &Script,
    ) -> Result<(Vec<FundingInput>, Amount), FireblocksError> {
        let dust = change_spk.minimal_non_dust();
        let change_len = change_spk.len();

        // Child output (change) for `n_funding` P2WPKH funding inputs contributing
        // `funding_total`; `None` if it can't clear dust or the arithmetic overflows.
        let try_fit = |n_funding: usize, funding_total: Amount| -> Option<Amount> {
            let n_p2wpkh = n_funding + usize::from(combined_is_p2wpkh);
            let child_vsize = tx::cpfp_child_vsize(n_p2wpkh, !combined_is_p2wpkh, change_len);
            let package_fee =
                target_pkg_fee_rate.fee_vb(parent_vsize.saturating_add(child_vsize))?;
            // The child only needs to make up the package shortfall after the parent's fee.
            let child_fee = package_fee.checked_sub(parent_fee).unwrap_or(Amount::ZERO);
            combined_value
                .checked_add(funding_total)
                .and_then(|t| t.checked_sub(child_fee))
                .filter(|out| *out >= dust)
        };

        // The combined input alone may already cover the package fee — common when CPFP-ing a
        // payout whose value dwarfs the bump fee.
        if let Some(child_output) = try_fit(0, Amount::ZERO) {
            return Ok((Vec::new(), child_output));
        }

        let mut eligible: Vec<&UtxoInfo> = self
            .cached_utxos
            .iter()
            .filter(|u| u.script_pubkey == self.script_pubkey && !exclude.contains(&u.outpoint))
            .collect();
        eligible.sort_by_key(|u| std::cmp::Reverse(u.amount));

        let mut selected: Vec<FundingInput> = Vec::new();
        let mut funding_total = Amount::ZERO;
        for u in eligible {
            selected.push(FundingInput {
                outpoint: u.outpoint,
                prevout: TxOut {
                    value: u.amount,
                    script_pubkey: u.script_pubkey.clone(),
                },
            });
            funding_total = funding_total
                .checked_add(u.amount)
                .ok_or_else(|| FireblocksError::TxBuild("input total overflows".into()))?;
            if let Some(child_output) = try_fit(selected.len(), funding_total) {
                return Ok((selected, child_output));
            }
        }
        Err(FireblocksError::TxBuild(
            "insufficient funds to build CPFP child at target package fee rate".into(),
        ))
    }
}

/// Whether a Fireblocks transaction status is terminal-failure (so polling should stop).
fn is_failure_status(status: &str) -> bool {
    matches!(
        status,
        "FAILED" | "REJECTED" | "BLOCKED" | "CANCELLED" | "CANCELLING" | "TIMEOUT"
    )
}

impl GeneralWallet for FireblocksGeneralWallet {
    type Error = FireblocksError;

    async fn sync(&mut self) -> Result<(), Self::Error> {
        let subpath = format!(
            "/vault/accounts/{}/{}/unspent_inputs",
            self.config.vault_account_id, self.config.asset_id
        );
        let resp: dto::GetUnspentInputsResponse =
            self.signed_request(Method::GET, &subpath, None).await?;
        self.cached_utxos = resp
            .iter()
            .map(|u| self.unspent_to_utxo_info(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }

    fn script_pubkey(&self) -> ScriptBuf {
        self.script_pubkey.clone()
    }

    fn payout_descriptor(&self) -> bitcoin_bosd::Descriptor {
        // Earnings land in the Fireblocks vault (P2WPKH), where the operator can spend them
        // via Fireblocks ECDSA signing — the same address used for funding.
        self.payout_descriptor.clone()
    }

    fn list_utxos(&self) -> Vec<UtxoInfo> {
        self.cached_utxos.clone()
    }

    async fn fund_v3_transaction(
        &mut self,
        outputs: Vec<TxOut>,
        explicit_inputs: Option<&[OutPoint]>,
        fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        let change_spk = self.script_pubkey.clone();
        let (funding, change) = match explicit_inputs {
            Some(inputs) => self.funding_from_explicit(inputs, &outputs, &change_spk, fee_rate)?,
            None => {
                let exclude_set: HashSet<OutPoint> = exclude.iter().copied().collect();
                tx::select_funding(
                    &self.cached_utxos,
                    &exclude_set,
                    &self.script_pubkey,
                    &outputs,
                    &change_spk,
                    fee_rate,
                )?
            }
        };

        let txins: Vec<TxIn> = funding.iter().map(|f| tx::txin(f.outpoint)).collect();
        let prevouts: Vec<TxOut> = funding.iter().map(|f| f.prevout.clone()).collect();
        let change_output = change.map(|value| TxOut {
            value,
            script_pubkey: change_spk,
        });
        let unsigned = tx::build_unsigned_v3(&txins, outputs, change_output);
        let mut psbt = Psbt::from_unsigned_tx(unsigned)
            .map_err(|e| FireblocksError::TxBuild(format!("psbt from unsigned tx: {e}")))?;

        // Every input is a Fireblocks-controlled funding input.
        let fb_indices: Vec<usize> = (0..funding.len()).collect();
        self.sign_fb_inputs(&mut psbt, &fb_indices, &prevouts)
            .await?;
        Ok(FundedPsbt { psbt })
    }

    async fn build_cpfp_child(
        &mut self,
        parent: &Transaction,
        parent_fee: Amount,
        anchor: AnchorInfo,
        target_pkg_fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        let anchor_prevout = parent
            .output
            .get(anchor.vout as usize)
            .ok_or_else(|| {
                FireblocksError::TxBuild(format!("anchor vout {} out of range", anchor.vout))
            })?
            .clone();
        let anchor_outpoint = OutPoint {
            txid: parent.compute_txid(),
            vout: anchor.vout,
        };
        let change_spk = self.script_pubkey.clone();
        // cast: tx vsize is bounded by the 4 MWU consensus limit, far inside u64.
        let parent_vsize = parent.vsize() as u64;

        // If the combined output pays our own vault script, it's the operator's P2WPKH payout
        // (the `ParentTxCombined` case) which Fireblocks signs itself. Otherwise it's a foreign
        // keyed-Taproot anchor (`AnchorBearing`) left unsigned for secret-service.
        let combined_is_ours = anchor_prevout.script_pubkey == self.script_pubkey;

        let mut exclude_set: HashSet<OutPoint> = exclude.iter().copied().collect();
        // Never re-select the combined input as a funding input.
        exclude_set.insert(anchor_outpoint);

        let (funding, child_output_value) = self.select_cpfp_funding(
            &exclude_set,
            anchor_prevout.value,
            combined_is_ours,
            parent_vsize,
            parent_fee,
            target_pkg_fee_rate,
            &change_spk,
        )?;

        // Input 0 is the combined input; inputs 1.. are the Fireblocks funding inputs.
        let mut txins = Vec::with_capacity(funding.len() + 1);
        let mut prevouts = Vec::with_capacity(funding.len() + 1);
        txins.push(tx::txin(anchor_outpoint));
        prevouts.push(anchor_prevout);
        for f in &funding {
            txins.push(tx::txin(f.outpoint));
            prevouts.push(f.prevout.clone());
        }

        let child_output = TxOut {
            value: child_output_value,
            script_pubkey: change_spk,
        };
        let unsigned = tx::build_unsigned_v3(&txins, vec![child_output], None);
        let mut psbt = Psbt::from_unsigned_tx(unsigned)
            .map_err(|e| FireblocksError::TxBuild(format!("psbt from unsigned tx: {e}")))?;

        if combined_is_ours {
            // The payout output is ours: every input (payout + funding) is an FB-signed P2WPKH.
            let fb_indices: Vec<usize> = (0..=funding.len()).collect();
            self.sign_fb_inputs(&mut psbt, &fb_indices, &prevouts)
                .await?;
        } else {
            // Fireblocks signs the funding inputs; the anchor input (0) is left unsigned with
            // witness_utxo + tap_internal_key for the operator's secret-service to key-path-sign.
            let fb_indices: Vec<usize> = (1..=funding.len()).collect();
            self.sign_fb_inputs(&mut psbt, &fb_indices, &prevouts)
                .await?;
            psbt.inputs[0].tap_internal_key = Some(anchor.internal_key);
        }
        Ok(FundedPsbt { psbt })
    }
}
