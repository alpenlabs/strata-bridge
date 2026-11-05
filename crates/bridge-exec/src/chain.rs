//! Shared Bitcoin chain helpers for executors.

use bitcoin::{
    Amount, FeeRate, OutPoint, Psbt, TapSighashType, Transaction, TxOut, Txid,
    sighash::{Prevouts, SighashCache},
    transaction::InputWeightPrediction,
};
use bitcoind_async_client::{Client as BitcoinClient, error::ClientError, traits::Reader};
use btc_tracker::{event::TxStatus, tx_driver::TxDriver};
use operator_wallet::{FundingInput, Lease, LeaseOwner, OperatorWallet, WalletStore};
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_primitives::scripts::taproot::create_key_spend_hash;
use tracing::{debug, error, info, warn};

use crate::{errors::ExecutorError, output_handles::OutputHandles};

/// The fee of `tx` once one wallet input of `wallet_input` size is added, at `fee_rate`. `None`
/// when the fee does not fit an [`Amount`].
///
/// A caller that hand-builds a transaction with one connector input uses this to size the wallet
/// funding it needs before the planner sees the transaction.
pub(crate) fn funded_tx_fee(
    tx: &Transaction,
    wallet_input: InputWeightPrediction,
    fee_rate: FeeRate,
) -> Option<Amount> {
    fee_rate.fee_wu(tx.weight() + wallet_input.weight())
}

/// The prevouts of a wallet-funded PSBT, in input order. The planner sets `witness_utxo` on every
/// input, which is what a signer reads.
pub(crate) fn psbt_prevouts(psbt: &Psbt) -> Vec<TxOut> {
    psbt.inputs
        .iter()
        .map(|input| {
            input
                .witness_utxo
                .clone()
                .expect("a wallet-funded PSBT carries witness_utxo on every input")
        })
        .collect()
}

/// Signs the general-wallet inputs at `input_indices` of `tx`.
///
/// The custody signs the inputs it holds the key for first. Every input it leaves unsigned is a
/// `tr(general_key)` input that the secret-service general signer signs with the default sighash.
pub(crate) async fn sign_general_inputs(
    output_handles: &OutputHandles,
    tx: &Transaction,
    input_indices: &[usize],
    prevouts: &[TxOut],
) -> Result<Transaction, ExecutorError> {
    let signer = output_handles.wallet.read().await.general_signer();
    let signer_witnesses = signer
        .sign_owned_inputs(tx, input_indices, prevouts)
        .await
        .map_err(|e| ExecutorError::WalletErr(format!("wallet signing failed: {e}")))?;

    let prevouts = Prevouts::All(prevouts);
    let mut sighash_cache = SighashCache::new(tx);
    let s2_signer = output_handles.s2_client.general_wallet_signer();

    let mut signed_tx = tx.clone();
    for (&input_index, signer_witness) in input_indices.iter().zip(signer_witnesses) {
        if let Some(witness) = signer_witness {
            signed_tx.input[input_index].witness = witness;
            continue;
        }
        let sighash = create_key_spend_hash(
            &mut sighash_cache,
            prevouts.clone(),
            TapSighashType::Default,
            input_index,
        )
        .map_err(|e| ExecutorError::WalletErr(format!("key spend hash: {e}")))?;
        let signature = s2_signer
            .sign(sighash.as_ref(), None)
            .await
            .map_err(ExecutorError::SecretServiceErr)?;
        signed_tx.input[input_index]
            .witness
            .push(signature.serialize());
    }

    Ok(signed_tx)
}

/// Returns the confirmation count of a transaction that the node knows, or `None` for an unknown
/// transaction. A mempool transaction has zero. A confirmed transaction stays known after its
/// outputs are spent, which takes `txindex=1`.
pub(crate) async fn tx_confirmations(
    bitcoind_rpc_client: &BitcoinClient,
    txid: &Txid,
) -> Result<Option<u64>, ClientError> {
    debug!(%txid, "reading tx confirmations");
    match bitcoind_rpc_client
        .get_raw_transaction_verbosity_one(txid)
        .await
    {
        Ok(tx) => Ok(Some(tx.confirmations.unwrap_or(0))),
        Err(e) if e.is_tx_not_found() => Ok(None),
        Err(e) => {
            warn!(%txid, ?e, "could not read tx confirmations");
            Err(e)
        }
    }
}

/// Returns whether the provided transaction ID already exists on chain (confirmed or in the
/// mempool).
pub(crate) async fn is_txid_onchain(
    bitcoind_rpc_client: &BitcoinClient,
    txid: &Txid,
) -> Result<bool, ClientError> {
    Ok(tx_confirmations(bitcoind_rpc_client, txid).await?.is_some())
}

/// Returns whether `outpoint` is currently unspent on chain or in the mempool.
///
/// Wraps Bitcoin Core's `gettxout`. A `null` result (spent or non-existent UTXO) maps to
/// `Ok(false)`; transport, RPC, or parse failures propagate as `Err` so callers do not mistake a
/// transient blip for a confirmed spend.
pub(crate) async fn is_outpoint_unspent(
    bitcoind_rpc_client: &BitcoinClient,
    outpoint: &OutPoint,
) -> Result<bool, ClientError> {
    debug!(%outpoint, "checking if outpoint is unspent");
    match bitcoind_rpc_client
        .get_tx_out(&outpoint.txid, outpoint.vout, true)
        .await
    {
        Ok(_) => Ok(true),
        // bitcoind returns `null` for a spent or non-existent UTXO; the client surfaces that
        // through this specific `Other` variant because the JSON-RPC response carries no `result`
        // field.
        Err(ClientError::Other(ref msg)) if msg == "Empty data received" => Ok(false),
        Err(e) => {
            warn!(%outpoint, ?e, "could not read outpoint");
            Err(e)
        }
    }
}

/// Publishes a signed transaction and waits until its status meets `wait_condition`.
pub(crate) async fn publish_signed_transaction(
    tx_driver: &TxDriver,
    signed_tx: &Transaction,
    label: &str,
    wait_condition: fn(&TxStatus) -> bool,
) -> Result<(), ExecutorError> {
    let txid = signed_tx.compute_txid();
    info!(%txid, %label, "publishing transaction");

    tx_driver
        .drive(signed_tx.clone(), wait_condition)
        .await
        .map_err(|e| {
            warn!(%txid, %label, ?e, "failed to publish transaction");
            ExecutorError::TxDriverErr(e)
        })?;

    info!(%txid, %label, "transaction reached target status");
    Ok(())
}

/// Publishes a transaction whose wallet inputs `lease` holds.
///
/// Success commits the lease: the transaction spends the inputs, and the lease stays in place
/// until a sync shows that spend buried. A failure releases the lease through
/// [`release_after_sync`]: a failed publish can still have reached a mempool, so the inputs return
/// to the pool only against a fresh view, and they stay held when that view cannot be read.
pub(crate) async fn publish_leased_transaction(
    output_handles: &OutputHandles,
    signed_tx: &Transaction,
    label: &str,
    wait_condition: fn(&TxStatus) -> bool,
    lease: Lease,
) -> Result<(), ExecutorError> {
    let result =
        publish_signed_transaction(&output_handles.tx_driver, signed_tx, label, wait_condition)
            .await;
    match result {
        Ok(()) => lease.commit(),
        Err(_) => {
            let mut wallet = output_handles.wallet.write().await;
            if let Err(e) = release_after_sync(&mut wallet, lease).await {
                warn!(%label, ?e, "wallet sync failed after a failed publish; the inputs stay held");
            }
        }
    }
    result
}

/// Syncs, then gives up `lease` on the inputs of a transaction that can be on the network.
///
/// A successful sync makes the wallet view authoritative: the wallet hides the inputs of a
/// broadcast transaction, and dropping the lease returns only the inputs that no transaction
/// spends. A failed sync leaves the view stale, and a release against stale data hands a live
/// transaction's inputs to the next duty, which then broadcasts a conflicting spend. The lease
/// commits in that case. An input of a transaction that never reached the network then stays out
/// of selection until a restart, so this logs the outpoints at error, and the operator restarts
/// when funding runs out.
pub(crate) async fn release_after_sync<P: WalletStore>(
    wallet: &mut OperatorWallet<P>,
    lease: Lease,
) -> Result<(), operator_wallet::Error> {
    if let Err(e) = wallet.sync().await {
        error!(inputs = ?lease.outpoints(), "wallet sync failed; holding the inputs");
        lease.commit();
        return Err(e);
    }
    Ok(())
}

/// One general-wallet input that funds a transaction with a connector input, and the change that
/// it leaves.
#[derive(Debug)]
pub(crate) struct ConnectorFunding {
    /// The selected input.
    pub(crate) input: FundingInput,
    /// The lease on [`Self::input`].
    pub(crate) lease: Lease,
    /// The change output, always above dust.
    pub(crate) change: TxOut,
}

/// Selects and leases a confirmed general-wallet UTXO that, with `connector_value`, pays the fee
/// of `template` at `fee_rate` and leaves non-dust change.
///
/// One wallet input funds the transaction, because the callers hand-build a fixed shape. A wallet
/// with enough total value in smaller outputs fails here, and the log states that total.
///
/// `template` is the funded transaction as [`funded_tx_fee`] reads it. The selection reads
/// confirmed outputs only: these transactions are v3, and TRUC rejects a v3 transaction on an
/// unconfirmed non-v3 parent.
pub(crate) fn select_connector_funding<P: WalletStore>(
    wallet: &mut OperatorWallet<P>,
    owner: LeaseOwner,
    template: &Transaction,
    connector_value: Amount,
    fee_rate: FeeRate,
) -> Result<ConnectorFunding, ExecutorError> {
    let overflow = || ExecutorError::WalletErr("connector funding amount overflow".into());
    let change_script = wallet.general().script_pubkey();
    let fee = funded_tx_fee(
        template,
        wallet.general_signer().input_prediction(),
        fee_rate,
    )
    .ok_or_else(overflow)?;
    let min_funding = fee
        .checked_add(change_script.minimal_non_dust())
        .ok_or_else(overflow)?
        .checked_sub(connector_value)
        .unwrap_or(Amount::ZERO);

    let (input, lease) = wallet
        .select_general_utxo(owner, min_funding)
        .ok_or_else(|| {
            let confirmed_total: Amount = wallet
                .general()
                .list_utxos()
                .iter()
                .filter(|utxo| utxo.confirmations > 0)
                .map(|utxo| utxo.amount)
                .sum();
            error!(
                %fee,
                %fee_rate,
                %min_funding,
                %confirmed_total,
                ?owner,
                "no single general wallet UTXO covers this fee"
            );
            ExecutorError::WalletErr(format!(
                "no general wallet UTXO of at least {min_funding} funds {owner:?}"
            ))
        })?;
    let change_value = connector_value
        .checked_add(input.txout.value)
        .and_then(|inputs| inputs.checked_sub(fee))
        .ok_or_else(overflow)?;
    info!(funding = %input.outpoint, %fee, %fee_rate, ?owner, "leased general wallet funding");
    Ok(ConnectorFunding {
        input,
        lease,
        change: TxOut {
            value: change_value,
            script_pubkey: change_script,
        },
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Amount, OutPoint, Transaction, Txid, consensus::encode::deserialize_hex, hashes::Hash,
    };
    use bitcoind_async_client::{Auth, Client as BitcoinClient, traits::Reader};
    use corepc_node::{Conf, Input, Node, Output};

    use super::{is_outpoint_unspent, is_txid_onchain, tx_confirmations};

    /// Per-coinbase reward on regtest before any halving.
    const REGTEST_COINBASE_AMOUNT: Amount = Amount::from_sat(50 * 100_000_000);

    fn setup_btc_client(bitcoind: &Node) -> BitcoinClient {
        let cookie = bitcoind
            .params
            .get_cookie_values()
            .expect("cookie file should be readable")
            .expect("cookie file should contain credentials");
        let auth = Auth::UserPass(cookie.user, cookie.password);

        BitcoinClient::new(bitcoind.rpc_url(), auth, None, None, None)
            .expect("async bitcoin rpc client should initialize")
    }

    fn missing_txid() -> Txid {
        Txid::from_slice(&[7; 32]).expect("txid bytes should be valid")
    }

    /// An unknown transaction has no depth, one in the mempool has depth zero, and a mined one has
    /// depth one or more.
    #[tokio::test]
    async fn tx_confirmations_reads_unknown_mempool_and_mined_transactions() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind should start");
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("wallet address should be generated");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");
        let recipient = bitcoind
            .client
            .new_address()
            .expect("recipient address should be generated");
        let txid = bitcoind
            .client
            .send_to_address(&recipient, Amount::ONE_BTC)
            .expect("wallet transaction should be created")
            .txid()
            .expect("wallet transaction result should expose a txid");
        let rpc_client = setup_btc_client(&bitcoind);

        assert_eq!(
            tx_confirmations(&rpc_client, &missing_txid())
                .await
                .expect("an unknown txid reads"),
            None,
            "an unknown transaction has no depth"
        );
        assert_eq!(
            tx_confirmations(&rpc_client, &txid)
                .await
                .expect("a mempool txid reads"),
            Some(0),
            "a mempool transaction has depth zero"
        );

        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("transaction should be mined");
        assert!(
            tx_confirmations(&rpc_client, &txid)
                .await
                .expect("a mined txid reads")
                .is_some_and(|depth| depth >= 1),
            "a mined transaction has depth one or more"
        );
    }

    #[tokio::test]
    async fn is_txid_onchain_returns_false_for_missing_and_true_for_mined_transactions() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind should start");
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("wallet address should be generated");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");

        let recipient = bitcoind
            .client
            .new_address()
            .expect("recipient address should be generated");
        let mined_txid = bitcoind
            .client
            .send_to_address(&recipient, Amount::ONE_BTC)
            .expect("wallet transaction should be created")
            .txid()
            .expect("wallet transaction result should expose a txid");
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("transaction should be mined");

        let rpc_client = setup_btc_client(&bitcoind);
        assert!(
            !is_txid_onchain(&rpc_client, &missing_txid())
                .await
                .expect("unknown txids should be treated as missing"),
            "an unknown transaction is not on chain"
        );

        assert!(
            is_txid_onchain(&rpc_client, &mined_txid)
                .await
                .expect("mined transactions should be found"),
            "a mined transaction is on chain"
        );

        assert!(
            is_txid_onchain(&rpc_client, &mined_txid)
                .await
                .expect("duplicate lookups should remain stable"),
            "a repeated lookup gives the same answer"
        );
    }

    /// Tracks the source outpoint of a single spending transaction across its
    /// full lifecycle — locally signed (not broadcast), in mempool, and mined —
    /// and asserts both `is_outpoint_unspent` and the spending tx's
    /// confirmation count at each stage. Also covers the missing-outpoint case.
    #[tokio::test]
    async fn is_outpoint_unspent_tracks_spending_tx_lifecycle() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind should start");
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("wallet address should be generated");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");

        let rpc_client = setup_btc_client(&bitcoind);

        // The matured coinbase output is the source outpoint we'll track.
        let first_block = rpc_client
            .get_block_at(1)
            .await
            .expect("first mined block should be retrievable");
        let coinbase_tx = first_block
            .coinbase()
            .expect("first mined block should contain a coinbase transaction");
        let source_outpoint = OutPoint {
            txid: coinbase_tx.compute_txid(),
            vout: 0,
        };

        // Outpoints whose txid does not exist on chain are reported as not unspent.
        let missing_outpoint = OutPoint {
            txid: missing_txid(),
            vout: 0,
        };
        assert!(
            !is_outpoint_unspent(&rpc_client, &missing_outpoint)
                .await
                .expect("rpc call should succeed for missing outpoint"),
            "missing outpoint should be reported as not unspent"
        );

        // Build a spending tx that sweeps the coinbase to a fresh wallet address
        // (minus a small fee). With only one matured UTXO available, this is the
        // only spend the wallet can produce.
        let recipient = bitcoind
            .client
            .new_address()
            .expect("recipient address should be generated");
        let inputs = [Input {
            txid: source_outpoint.txid,
            vout: u64::from(source_outpoint.vout),
            sequence: None,
        }];
        let outputs = [Output::new(
            recipient,
            Amount::from_sat(REGTEST_COINBASE_AMOUNT.to_sat() - 2_000),
        )];
        let unsigned_tx = bitcoind
            .client
            .create_raw_transaction(&inputs, &outputs)
            .expect("create raw tx")
            .transaction()
            .expect("decode unsigned tx");

        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&unsigned_tx)
            .expect("wallet should sign the spending tx");
        assert!(
            signed.complete,
            "wallet should produce a complete signature"
        );
        let signed_tx: Transaction =
            deserialize_hex(&signed.hex).expect("signed tx hex should deserialize");
        let spending_txid = signed_tx.compute_txid();

        // STAGE 1: signed locally but not broadcast.
        // Source outpoint is still unspent. Spending tx is unknown to the node.
        assert!(
            is_outpoint_unspent(&rpc_client, &source_outpoint)
                .await
                .expect("rpc call must succeed"),
            "stage 1 (unbroadcast): source outpoint should still be unspent"
        );
        assert!(
            rpc_client
                .get_raw_transaction_verbosity_one(&spending_txid)
                .await
                .is_err(),
            "stage 1 (unbroadcast): spending tx should not be retrievable"
        );

        // STAGE 2: broadcast to mempool, not yet mined.
        // Source outpoint is reported as spent because we query gettxout with
        // include_mempool=true. Spending tx exists with no confirmations.
        bitcoind
            .client
            .send_raw_transaction(&signed_tx)
            .expect("broadcast spending tx");
        assert!(
            !is_outpoint_unspent(&rpc_client, &source_outpoint)
                .await
                .expect("rpc"),
            "stage 2 (mempool): source outpoint should be reported as spent"
        );
        let mempool_status = rpc_client
            .get_raw_transaction_verbosity_one(&spending_txid)
            .await
            .expect("spending tx should be retrievable from mempool");
        assert_eq!(
            mempool_status.confirmations, None,
            "stage 2 (mempool): spending tx should have no confirmations"
        );

        // STAGE 3: mined.
        // Source outpoint is consumed on chain. Spending tx has at least one
        // confirmation.
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("mine the spending tx");
        assert!(
            !is_outpoint_unspent(&rpc_client, &source_outpoint)
                .await
                .expect("rpc"),
            "stage 3 (mined): source outpoint should be reported as spent"
        );
        let mined_status = rpc_client
            .get_raw_transaction_verbosity_one(&spending_txid)
            .await
            .expect("mined spending tx should be retrievable");
        assert!(
            mined_status.confirmations.is_some_and(|c| c >= 1),
            "stage 3 (mined): spending tx should have ≥1 confirmation, got {:?}",
            mined_status.confirmations
        );
    }
}
