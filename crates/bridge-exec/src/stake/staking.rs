//! Duties related to staking.
//!
//! This covers all duties related to the collection of unstaking signatures upto the publication of
//! the stake transaction.

use bitcoin::{
    Amount, FeeRate, Network, OutPoint, Psbt, TapSighashType, Transaction, TxOut,
    hashes::{Hash, sha256},
    secp256k1::{Message, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
};
use bitcoind_async_client::traits::Reader;
use btc_tracker::event::TxStatus;
use futures::{FutureExt, future::try_join_all};
use musig2::{AggNonce, PubNonce};
use operator_wallet::{GeneralUtxoPolicy, LeaseOwner, LeasedPsbt, OperatorWallet, SqliteStore};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SchnorrSigner, SecretService};
use strata_bridge_connectors::prelude::UnstakingIntentOutput;
use strata_bridge_db::{
    traits::BridgeDb,
    types::{FundingAssignment, StakeFundingReservation},
};
use strata_bridge_p2p_types::UnstakingInput;
use strata_bridge_primitives::{
    covenant::StakeKey,
    scripts::taproot::{TaprootTweak, create_key_spend_hash},
};
use strata_bridge_tx_graph::{fee, musig_functor::StakeFunctor, transactions::prelude::StakeTx};
use tracing::{error, info, warn};

use crate::{
    chain::{self, publish_signed_transaction},
    config::ExecutionConfig,
    errors::ExecutorError,
    output_handles::OutputHandles,
    stake::utils::get_preimage,
};

pub(crate) async fn publish_stake_data(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    stake_key: StakeKey,
) -> Result<(), ExecutorError> {
    let operator_idx = stake_key.operator;
    info!(%stake_key, "executing duty to publish stake data");

    let reservation = read_or_create_stake_funding(cfg, output_handles, stake_key).await?;

    let stake_funding_txid = reservation.unsigned_tx.compute_txid();
    let stake_funds = OutPoint {
        txid: stake_funding_txid,
        vout: reservation.stake_output_vout,
    };

    info!(%operator_idx, %stake_funding_txid, "submitting stake funding transaction");
    let signed_tx = chain::sign_general_inputs(
        output_handles,
        &reservation.unsigned_tx,
        &(0..reservation.unsigned_tx.input.len()).collect::<Vec<_>>(),
        &reservation.prevouts,
    )
    .await?;
    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_tx,
        "stake funding tx",
        TxStatus::is_buried,
    )
    .await?;

    info!("fetching unstaking intent preimage from secret-service");
    let preimage = get_preimage(&output_handles.s2_client, stake_funds).await?;
    let unstaking_image = sha256::Hash::hash(&preimage);
    info!(%unstaking_image, "fetched unstaking intent preimage and computed the unstaking image");

    info!("constructing the unstaking output descriptor");
    // Custody-aware receive destination: where this operator gets its unstaking funds, so the
    // funds land somewhere it can actually spend: the general wallet's own receive script.
    let output_desc = output_handles
        .wallet
        .read()
        .await
        .descriptor()
        .map_err(|e| {
            ExecutorError::WalletErr(format!("failed to create unstaking descriptor: {e}"))
        })?;
    info!(%output_desc, "constructed the unstaking output descriptor");

    let unstaking_input = UnstakingInput {
        stake_funds,
        unstaking_image,
        unstaking_operator_desc: output_desc.into(),
    };

    info!(%stake_key, "broadcasting the unstaking input to the p2p network");
    let mut msg_handler = output_handles.msg_handler.write().await;
    msg_handler
        .send_unstaking_input(stake_key, unstaking_input, None)
        .await?;

    Ok(())
}

async fn read_or_create_stake_funding(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    stake_key: StakeKey,
) -> Result<StakeFundingReservation, ExecutorError> {
    let operator_idx = stake_key.operator;
    let funding_amount = stake_funding_amount(cfg.network, cfg.stake_amount);
    let mut wallet = output_handles.wallet.write().await;

    match wallet.sync().await {
        Ok(()) => info!("synced wallet successfully"),
        Err(e) => error!(
            ?e,
            "could not sync wallet before stake funding lookup; still attempting"
        ),
    }

    if let Some(reservation) = output_handles
        .db
        .get_stake_funding_reservation(stake_key)
        .await?
    {
        info!(%operator_idx, "reusing persisted stake funding reservation");
        validate_reservation(
            &reservation,
            &wallet.reserved_script_pubkey(),
            funding_amount,
        )?;
        let inputs: Vec<OutPoint> = reservation
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect();
        // The database row keeps this reservation across restarts, so the lease has no owning
        // value to drop. Startup rehydration holds the same outpoints. This call covers the case
        // where the row was written after startup read the funds.
        wallet.lease_committed(inputs, LeaseOwner::StakeFunding);
        return Ok(reservation);
    }

    info!(%operator_idx, "no persisted stake funding reservation; creating a new funding tx");
    let fee_rate = estimate_funding_fee_rate(cfg, output_handles).await?;

    info!(%fee_rate, %funding_amount, "creating stake funding transaction");
    // `candidate` holds the inputs that the wallet selected. Each path below that does not
    // become the stored reservation drops it, which returns those inputs to the pool.
    let candidate = select_stake_funding(&mut wallet, fee_rate, funding_amount)?;
    let (candidate_psbt, candidate_lease) = candidate.into_parts();
    let reservation = reservation_from_psbt(&candidate_psbt);

    info!(%operator_idx, "persisting stake funding reservation");
    let assignment = output_handles
        .db
        .get_or_set_stake_funding_reservation(stake_key, reservation.clone())
        .await;

    match assignment {
        Ok(FundingAssignment::Created(reservation)) => {
            candidate_lease.commit();
            Ok(reservation)
        }
        Ok(FundingAssignment::Existing(reservation)) => {
            info!(%operator_idx, "using existing stake funding reservation saved by another duty");
            // The candidate's inputs return to the pool; the stored row names the inputs to hold.
            drop(candidate_lease);
            validate_reservation(
                &reservation,
                &wallet.reserved_script_pubkey(),
                funding_amount,
            )?;
            let assigned_inputs: Vec<OutPoint> = reservation
                .unsigned_tx
                .input
                .iter()
                .map(|txin| txin.previous_output)
                .collect();
            wallet.lease_committed(assigned_inputs, LeaseOwner::StakeFunding);
            Ok(reservation)
        }
        Err(err) => Err(err.into()),
    }
}

async fn estimate_funding_fee_rate(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
) -> Result<FeeRate, ExecutorError> {
    info!("fetching fee rate from bitcoind");
    let smart_fee = output_handles
        .bitcoind_rpc_client
        .estimate_smart_fee(1)
        .await?;
    info!(?smart_fee, "fetched fee rate from bitcoind");

    // Bound the rate from below by `fee::FEE_RATE` so this v3 (TRUC) funding transaction
    // always meets the bridge's hardcoded minimum, even on networks like signet where
    // `estimatesmartfee` may return a value below `minrelaytxfee`.
    let fee_rate = smart_fee
        .fee_rate
        .unwrap_or(fee::FEE_RATE)
        .max(fee::FEE_RATE);

    if fee_rate > cfg.maximum_fee_rate {
        return Err(ExecutorError::FeeRateTooHigh {
            fee_rate,
            max: cfg.maximum_fee_rate,
        });
    }

    Ok(fee_rate)
}

/// Funds one reserved-wallet output of `funding_amount` from confirmed general-wallet outputs.
///
/// The funding transaction is v3, and TRUC rejects a v3 transaction with an unconfirmed non-v3
/// parent, so an unconfirmed input can make it unrelayable.
fn select_stake_funding(
    wallet: &mut OperatorWallet<SqliteStore>,
    fee_rate: FeeRate,
    funding_amount: Amount,
) -> Result<LeasedPsbt, ExecutorError> {
    wallet
        .create_reserved_utxos(
            fee_rate,
            funding_amount,
            1,
            GeneralUtxoPolicy::ConfirmedOnly,
            LeaseOwner::StakeFunding,
        )
        .map_err(|e| ExecutorError::WalletErr(format!("stake funding failed: {e}")))
}

fn validate_reservation(
    reservation: &StakeFundingReservation,
    expected_stake_script: &bitcoin::ScriptBuf,
    expected_funding_amount: Amount,
) -> Result<(), ExecutorError> {
    if reservation.prevouts.len() != reservation.unsigned_tx.input.len() {
        return Err(ExecutorError::InvalidTxStructure(format!(
            "stake funding reservation prevouts ({}) do not match input count ({})",
            reservation.prevouts.len(),
            reservation.unsigned_tx.input.len(),
        )));
    }
    let stake_output = reservation
        .unsigned_tx
        .output
        .get(reservation.stake_output_vout as usize)
        .ok_or_else(|| {
            ExecutorError::InvalidTxStructure(format!(
                "stake funding reservation vout {} out of range ({} outputs)",
                reservation.stake_output_vout,
                reservation.unsigned_tx.output.len(),
            ))
        })?;
    if stake_output.script_pubkey != *expected_stake_script {
        return Err(ExecutorError::InvalidTxStructure(
            "stake funding reservation output script does not match reserved wallet".into(),
        ));
    }
    if stake_output.value != expected_funding_amount {
        return Err(ExecutorError::InvalidTxStructure(format!(
            "stake funding reservation output value {} != expected {}",
            stake_output.value, expected_funding_amount,
        )));
    }
    Ok(())
}

fn reservation_from_psbt(psbt: &Psbt) -> StakeFundingReservation {
    // The stake funding PSBT has a single recipient at index 0; change (if any) follows it.
    StakeFundingReservation {
        unsigned_tx: psbt.unsigned_tx.clone(),
        prevouts: chain::psbt_prevouts(psbt),
        stake_output_vout: 0,
    }
}

pub(crate) async fn publish_unstaking_nonces(
    output_handles: &OutputHandles,
    stake_key: StakeKey,
    graph_inpoints: StakeFunctor<OutPoint>,
    graph_tweaks: StakeFunctor<TaprootTweak>,
    sighashes: StakeFunctor<Message>,
    ordered_pubkeys: Vec<XOnlyPublicKey>,
) -> Result<(), ExecutorError> {
    info!(%stake_key, "generating and publishing unstaking nonces for the stake graph");

    let musig_signer = output_handles.s2_client.musig2_signer();

    let nonce_futures = StakeFunctor::zip3(graph_inpoints, graph_tweaks, sighashes)
        .into_iter()
        .map(|(inpoint, tweak, sighash)| {
            let params = Musig2Params {
                ordered_pubkeys: ordered_pubkeys.clone(),
                tweak,
                sighash: *sighash.as_ref(),
            };

            musig_signer.get_pub_nonce(params).map(move |res| match res {
                Ok(inner) => inner.map_err(|_| {
                    warn!(%stake_key, %inpoint, "failed to get pub nonce from secret-service: our pubkey missing from params");
                    ExecutorError::OurPubKeyNotInParams
                }),
                Err(e) => {
                    warn!(%stake_key, %inpoint, ?e, "failed to get pub nonce from secret-service");
                    Err(ExecutorError::SecretServiceErr(e))
                }
            })
        });

    let nonces: Vec<PubNonce> = try_join_all(nonce_futures).await?;

    output_handles
        .msg_handler
        .write()
        .await
        .send_unstaking_nonces(stake_key, nonces, None)
        .await?;
    info!(%stake_key, "successfully published unstaking nonces for the stake graph");

    Ok(())
}

pub(crate) async fn publish_unstaking_partials(
    output_handles: &OutputHandles,
    stake_key: StakeKey,
    graph_inpoints: StakeFunctor<OutPoint>,
    graph_tweaks: StakeFunctor<TaprootTweak>,
    sighashes: StakeFunctor<Message>,
    agg_nonces: StakeFunctor<AggNonce>,
    ordered_pubkeys: Vec<XOnlyPublicKey>,
) -> Result<(), ExecutorError> {
    info!(%stake_key, "generating and publishing unstaking partial signatures for the stake graph");

    let musig_signer = output_handles.s2_client.musig2_signer();

    let partial_futures = StakeFunctor::zip4(graph_inpoints, graph_tweaks, sighashes, agg_nonces)
        .map(|(inpoint, tweak, sighash, agg_nonce)| {
            let params = Musig2Params {
                ordered_pubkeys: ordered_pubkeys.clone(),
                tweak,
                sighash: *sighash.as_ref(),
            };

            musig_signer
                .get_our_partial_sig(params, agg_nonce)
                .map(move |res| match res {
                    Ok(inner) => inner.map_err(|e| match e.to_enum() {
                        terrors::E2::A(_) => {
                            warn!(%stake_key, %inpoint, "secret service rejected partial sig request: our pubkey missing from params");
                            ExecutorError::OurPubKeyNotInParams
                        }
                        terrors::E2::B(_) => {
                            warn!(%stake_key, %inpoint, "secret service rejected partial sig request: self-verification failed");
                            ExecutorError::SelfVerifyFailed
                        }
                    }),
                    Err(e) => {
                        warn!(%stake_key, %inpoint, ?e, "failed to get partial signature from secret-service");
                        Err(ExecutorError::SecretServiceErr(e))
                    }
                })
        },
    );

    let partials = try_join_all(partial_futures).await?;
    info!(%stake_key, "successfully generated unstaking partial signatures for the stake graph");

    output_handles
        .msg_handler
        .write()
        .await
        .send_unstaking_partials(stake_key, partials, None)
        .await?;
    info!(%stake_key, "successfully published unstaking partial signatures for the stake graph");

    Ok(())
}

pub(crate) async fn publish_stake(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    tx: &Transaction,
) -> Result<(), ExecutorError> {
    let stake_txid = tx.compute_txid();
    let funding_input = tx.input[0].previous_output;

    // The stake tx spends a single funding UTXO in the reserved wallet and is not presigned by
    // the covenant, so key-path sign it with the reserved wallet signer before broadcasting.
    // Reconstruct the prevout from known values: the funding UTXO is always at the reserved
    // address with value `stake_amount + unstaking_intent_output.value() + stake_fee`.
    let reserved_script = output_handles.wallet.read().await.reserved_script_pubkey();
    let funding_amount = stake_funding_amount(cfg.network, cfg.stake_amount);
    let prevout = TxOut {
        script_pubkey: reserved_script,
        value: funding_amount,
    };

    info!(
        %stake_txid,
        %funding_input,
        %funding_amount,
        "signing stake transaction with reserved wallet signer"
    );

    let prevouts = Prevouts::All(&[prevout]);
    let mut sighash_cache = SighashCache::new(tx);
    let sighash = create_key_spend_hash(&mut sighash_cache, prevouts, TapSighashType::Default, 0)
        .expect("must be able to create key spend sighash");

    let signature = output_handles
        .s2_client
        .reserved_wallet_signer()
        .sign(sighash.as_ref(), None)
        .await
        .map_err(ExecutorError::SecretServiceErr)?;

    let mut signed_tx = tx.clone();
    signed_tx.input[0].witness.push(signature.serialize());

    info!(%stake_txid, "publishing signed stake transaction");
    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_tx,
        "stake tx",
        TxStatus::is_buried,
    )
    .await?;
    info!(%stake_txid, "stake transaction confirmed on-chain");

    Ok(())
}

/// Returns the wallet UTXO value needed to fund the stake transaction on the given network.
///
/// The stake transaction spends this UTXO into the NOfN stake connector (`stake_amount`), the
/// unstaking-intent connector (with its presigned-tx fee surcharge baked in), a zero-value CPFP
/// anchor, and the stake transaction's own fee.
fn stake_funding_amount(network: Network, stake_amount: Amount) -> Amount {
    // `UnstakingIntentOutput::value()` is the P2TR script's `minimal_non_dust()` plus a surcharge
    // that depends only on the script kind — not on the particular n-of-n key or unstaking image.
    // We supply a dummy x-only pubkey (the generator point's x-coordinate) and a zero image so we
    // can compute the value without a secret-service round trip.
    let dummy_pubkey = XOnlyPublicKey::from_slice(&bitcoin::key::constants::GENERATOR_X)
        .expect("valid x-only key");
    let unstaking_intent_output = UnstakingIntentOutput::new(
        network,
        dummy_pubkey,
        sha256::Hash::all_zeros(),
        fee::unstaking_intent_surcharge(),
    );
    StakeTx::stake_funds_required(stake_amount, &unstaking_intent_output)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as CoreRpcClient};
    use bitcoin::{
        Address, Amount, FeeRate, Network,
        secp256k1::{Keypair, SECP256K1},
    };
    use corepc_node::{Conf, Node};
    use operator_wallet::{
        GeneralCustody, OperatorWallet, OperatorWalletConfig, SqliteStore, WalletKind,
        sync::Backend,
    };

    use super::select_stake_funding;

    /// Stake funding is v3, so a zero-confirmation general output must not fund it.
    #[tokio::test]
    async fn stake_funding_refuses_an_unconfirmed_general_output() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        let data_dir = tempfile::tempdir().expect("temp dir");
        let mut wallet = test_wallet(&bitcoind, &data_dir).await;
        let miner = bitcoind.client.new_address().expect("miner");
        bitcoind
            .client
            .generate_to_address(101, &miner)
            .expect("mature funds");
        let general_address =
            Address::from_script(&wallet.general().script_pubkey(), Network::Regtest)
                .expect("general address");
        bitcoind
            .client
            .send_to_address(&general_address, Amount::from_sat(100_000))
            .expect("fund the general wallet");
        wallet.sync().await.expect("sync sees the mempool credit");

        let fee_rate = FeeRate::from_sat_per_vb(2).expect("valid rate");
        let amount = Amount::from_sat(50_000);
        assert!(
            select_stake_funding(&mut wallet, fee_rate, amount).is_err(),
            "a mempool credit must not fund the stake"
        );

        bitcoind
            .client
            .generate_to_address(1, &miner)
            .expect("confirm the credit");
        wallet.sync().await.expect("sync sees the block");
        assert!(
            select_stake_funding(&mut wallet, fee_rate, amount).is_ok(),
            "a confirmed output funds the stake"
        );
    }

    fn test_key(seed: u8) -> bitcoin::XOnlyPublicKey {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32])
            .expect("valid secret key")
            .x_only_public_key()
            .0
    }

    async fn test_wallet(
        bitcoind: &Node,
        data_dir: &tempfile::TempDir,
    ) -> OperatorWallet<SqliteStore> {
        let core_client = || {
            let auth = Auth::CookieFile(bitcoind.params.cookie_file.clone());
            Arc::new(CoreRpcClient::new(bitcoind.rpc_url().as_str(), auth).expect("core client"))
        };
        let config = OperatorWalletConfig::new(Amount::from_sat(330), 0, Network::Regtest);
        let general_store =
            SqliteStore::open_in_dir(data_dir.path(), WalletKind::General).expect("general store");
        let reserved_store = SqliteStore::open_in_dir(data_dir.path(), WalletKind::Reserved)
            .expect("reserved store");
        OperatorWallet::load_or_create(
            GeneralCustody::SecretService {
                general_key: test_key(1),
                store: general_store,
            },
            test_key(2),
            config,
            Backend::BitcoinCore(core_client()),
            reserved_store,
            None,
            BTreeSet::new(),
        )
        .await
        .expect("operator wallet")
    }
}
