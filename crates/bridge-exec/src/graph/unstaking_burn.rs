//! Executor for the unstaking burn transaction.

use bitcoin::{
    Amount, FeeRate, OutPoint, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut,
    hashes::Hash,
    sighash::{Prevouts, SighashCache},
    taproot,
};
use bitcoind_async_client::traits::Reader;
use btc_tracker::event::TxStatus;
use operator_wallet::AnyOperatorWallet;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_tx_graph::transactions::prelude::UnstakingBurnTx;
use tracing::{debug, info, warn};

use crate::{
    chain::{CpfpKind, publish_signed_transaction},
    config::ExecutionConfig,
    errors::ExecutorError,
    output_handles::OutputHandles,
};

/// Index of the payout connector input in the unfunded burn template.
const CONNECTOR_INPUT_INDEX: usize = 0;

/// Index of the general-wallet funding input after [`attach_wallet_funding`] extends the template.
const WALLET_INPUT_INDEX: usize = 1;

/// General-wallet input selected for a single unstaking burn transaction.
#[derive(Debug)]
struct WalletFunding {
    /// General-wallet outpoint leased for this burn attempt.
    outpoint: OutPoint,
    /// Previous output data for the leased input.
    prevout: TxOut,
}

/// Fixed transaction construction parameters derived before selecting a funding UTXO.
#[derive(Debug)]
struct BurnTxPlan {
    /// Value contributed by the payout connector input.
    payout_connector_value: Amount,
    /// Fee rate used to compute [`Self::fee`].
    fee_rate: FeeRate,
    /// Fee paid by the final burn transaction.
    fee: Amount,
    /// Virtual size used to compute [`Self::fee`].
    estimated_vsize: u64,
    /// Script that receives the remaining value after the burn fee is paid.
    wallet_output_script: ScriptBuf,
}

/// Finalizes and publishes an unstaking burn transaction.
pub(super) async fn publish_unstaking_burn(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    graph_idx: GraphIdx,
    unstaking_burn_tx: UnstakingBurnTx,
    unstaking_preimage: [u8; 32],
) -> Result<(), ExecutorError> {
    info!(%graph_idx, "preparing unstaking burn transaction");

    let fee_rate = burn_fee_rate(output_handles).await?;
    debug!(%graph_idx, %fee_rate, "selected fee rate for unstaking burn transaction");
    if fee_rate > cfg.maximum_fee_rate {
        warn!(
            %graph_idx,
            %fee_rate,
            maximum_fee_rate = %cfg.maximum_fee_rate,
            "fee rate exceeds maximum, skipping unstaking burn"
        );
        return Ok(());
    }

    let (funding, plan) = {
        let mut wallet = output_handles.wallet.write().await;
        select_funding(
            &mut wallet,
            graph_idx,
            &unstaking_burn_tx,
            unstaking_preimage,
            fee_rate,
        )
        .await?
    };

    let sign_result = build_and_sign_tx(
        output_handles,
        graph_idx,
        unstaking_burn_tx,
        unstaking_preimage,
        &funding,
        &plan,
    )
    .await;

    let signed_tx = match sign_result {
        Ok(tx) => tx,
        Err(e) => {
            warn!(
                %graph_idx,
                funding_outpoint = %funding.outpoint,
                %e,
                "failed to sign unstaking burn transaction; releasing wallet funding outpoint"
            );
            output_handles
                .wallet
                .write()
                .await
                .release(&[funding.outpoint]);
            return Err(e);
        }
    };

    info!(%graph_idx, txid = %signed_tx.compute_txid(), "publishing unstaking burn transaction");
    // Preserve this executor's pre-CPFP behaviour: the burn tx is already wallet-funded at the
    // estimated market fee rate, so it broadcasts without a CPFP child. `parent_fee` is the
    // exact fee the plan paid (unused while `cpfp` is `None`, but kept accurate so flipping to
    // a CPFP strategy later is a one-line change).
    let publish_result = publish_signed_transaction(
        output_handles,
        &signed_tx,
        "unstaking burn",
        TxStatus::is_buried,
        plan.fee,
        CpfpKind::None,
    )
    .await;

    if let Err(ref e) = publish_result {
        warn!(
            %graph_idx,
            funding_outpoint = %funding.outpoint,
            %e,
            "failed to publish unstaking burn transaction; releasing wallet funding outpoint"
        );
        output_handles
            .wallet
            .write()
            .await
            .release(&[funding.outpoint]);
    }

    publish_result
}

/// Returns the fee rate used for an unstaking burn attempt.
///
/// The executor asks Bitcoin Core for a one-block estimate and floors missing or low estimates at
/// the network broadcast minimum so the constructed transaction remains relayable.
async fn burn_fee_rate(output_handles: &OutputHandles) -> Result<FeeRate, ExecutorError> {
    let fee_rate = output_handles
        .bitcoind_rpc_client
        .estimate_smart_fee(1)
        .await
        .map_err(|e| {
            warn!(
                ?e,
                "failed to estimate fee rate for unstaking burn transaction"
            );
            ExecutorError::WalletErr(format!("failed to estimate fee: {e}"))
        })?;

    let fee_rate = FeeRate::from_sat_per_vb(fee_rate)
        .unwrap_or(FeeRate::BROADCAST_MIN)
        .max(FeeRate::BROADCAST_MIN);

    debug!(%fee_rate, "computed unstaking burn fee rate");

    Ok(fee_rate)
}

/// Selects and leases a general-wallet UTXO that can pay for the burn transaction.
///
/// The payout connector contributes value but does not necessarily cover relay fees. This helper
/// computes the fixed fee once, filters wallet UTXOs against that fee, and returns both the
/// selected UTXO and the plan used to construct the final transaction.
///
/// The burn transaction constructed by this executor is:
///
/// ```text
/// +----------+-------------------------------------------+-------------------------------------------------+
/// | Inputs   |                                           | Outputs                                         |
/// +----------+-------------------------------------------+-------------------------------------------------+
/// | input 0  | claim payout connector                    | output 0: general-wallet output                 |
/// |          | value: BurnTxPlan::payout_connector_value | value: inputs - BurnTxPlan::fee                 |
/// |          | witness: unstaking_preimage               | script_pubkey: BurnTxPlan::wallet_output_script |
/// +----------+-------------------------------------------+-------------------------------------------------+
/// | input 1  | general-wallet funding UTXO               |                                                 |
/// |          | outpoint: WalletFunding::outpoint         |                                                 |
/// |          | prevout: WalletFunding::prevout           |                                                 |
/// +----------+-------------------------------------------+-------------------------------------------------+
/// ```
///
/// The fee is the difference between total inputs and explicit outputs:
///
/// ```text
/// BurnTxPlan::fee =
///     BurnTxPlan::payout_connector_value
///   + WalletFunding::prevout.value
///   - general_wallet_output_value
/// ```
async fn select_funding(
    wallet: &mut AnyOperatorWallet,
    graph_idx: GraphIdx,
    unstaking_burn_tx: &UnstakingBurnTx,
    unstaking_preimage: [u8; 32],
    fee_rate: FeeRate,
) -> Result<(WalletFunding, BurnTxPlan), ExecutorError> {
    let payout_connector_value = unstaking_burn_tx.prevouts()[CONNECTOR_INPUT_INDEX].value;

    info!(%graph_idx, "syncing wallet before funding unstaking burn transaction");
    if let Err(e) = wallet.sync().await {
        warn!(%graph_idx, ?e, "could not sync wallet before funding unstaking burn");
    }

    let wallet_output_script = wallet.general_script_pubkey();
    let min_output_value = wallet_output_script.minimal_non_dust();
    let fee = estimate_unstaking_burn_fee(
        unstaking_burn_tx,
        unstaking_preimage,
        &wallet_output_script,
        fee_rate,
    )?;
    let plan = BurnTxPlan {
        payout_connector_value,
        fee_rate,
        fee: fee.amount,
        estimated_vsize: fee.vsize,
        wallet_output_script,
    };

    debug!(
        %graph_idx,
        %payout_connector_value,
        fee = %plan.fee,
        %fee_rate,
        estimated_vsize = plan.estimated_vsize,
        %min_output_value,
        "selecting wallet funding UTXO for unstaking burn"
    );

    let funding = wallet.select_and_lease_general_utxo(|utxo| {
        let output_value = match payout_connector_value
            .checked_add(utxo.amount)
            .and_then(|input_value| input_value.checked_sub(plan.fee))
        {
            Some(output_value) => output_value,
            None => {
                debug!(
                    %graph_idx,
                    outpoint = %utxo.outpoint,
                    utxo_value = %utxo.amount,
                    fee = %plan.fee,
                    "wallet UTXO cannot cover unstaking burn fee"
                );
                return false;
            }
        };

        if output_value < min_output_value {
            debug!(
                %graph_idx,
                outpoint = %utxo.outpoint,
                utxo_value = %utxo.amount,
                %output_value,
                %min_output_value,
                fee = %plan.fee,
                "wallet UTXO cannot fund non-dust unstaking burn output"
            );
            return false;
        }

        true
    });

    let Some(funding) = funding else {
        warn!(
            %graph_idx,
            %payout_connector_value,
            fee = %plan.fee,
            %min_output_value,
            %fee_rate,
            "no general wallet UTXO available to fund unstaking burn"
        );
        return Err(ExecutorError::WalletErr(format!(
            "no general wallet UTXO available to fund unstaking burn for graph {graph_idx}; \
             payout connector value {payout_connector_value}, fee {}, minimum output value {}",
            plan.fee, min_output_value
        )));
    };

    let wallet_output_value = payout_connector_value
        .checked_add(funding.amount)
        .and_then(|input_value| input_value.checked_sub(plan.fee))
        .ok_or_else(|| {
            ExecutorError::WalletErr(format!(
                "selected unstaking burn funding UTXO {} cannot cover fee {}",
                funding.outpoint, plan.fee
            ))
        })?;

    info!(
        %graph_idx,
        funding_outpoint = %funding.outpoint,
        funding_value = %funding.amount,
        %wallet_output_value,
        fee = %plan.fee,
        fee_rate = %plan.fee_rate,
        estimated_vsize = plan.estimated_vsize,
        "leased wallet funding UTXO for unstaking burn"
    );

    Ok((
        WalletFunding {
            outpoint: funding.outpoint,
            prevout: funding.into(),
        },
        plan,
    ))
}

/// Builds the funded burn transaction and signs the general-wallet input.
///
/// `finalize_partial` spends the payout connector with the unstaking preimage. The executor then
/// signs the wallet funding input that was appended by [`attach_wallet_funding`].
async fn build_and_sign_tx(
    output_handles: &OutputHandles,
    graph_idx: GraphIdx,
    unstaking_burn_tx: UnstakingBurnTx,
    unstaking_preimage: [u8; 32],
    funding: &WalletFunding,
    plan: &BurnTxPlan,
) -> Result<Transaction, ExecutorError> {
    let wallet_output_value = plan
        .payout_connector_value
        .checked_add(funding.prevout.value)
        .and_then(|input_value| input_value.checked_sub(plan.fee))
        .ok_or_else(|| {
            ExecutorError::WalletErr(format!(
                "selected unstaking burn funding UTXO {} cannot cover fee {}",
                funding.outpoint, plan.fee
            ))
        })?;

    debug!(
        %graph_idx,
        funding_outpoint = %funding.outpoint,
        funding_value = %funding.prevout.value,
        %wallet_output_value,
        fee = %plan.fee,
        "building funded unstaking burn transaction"
    );

    let mut funded_burn = unstaking_burn_tx;
    attach_wallet_funding(
        &mut funded_burn,
        funding.outpoint,
        funding.prevout.clone(),
        TxOut {
            value: wallet_output_value,
            script_pubkey: plan.wallet_output_script.clone(),
        },
    );

    let prevouts = funded_burn.prevouts().to_vec();
    let mut signed_tx = funded_burn.finalize_partial(unstaking_preimage);
    let wallet_signature = sign_wallet_input(output_handles, &signed_tx, &prevouts).await?;
    signed_tx.input[WALLET_INPUT_INDEX]
        .witness
        .push(wallet_signature.to_vec());

    let final_vsize = signed_tx.vsize() as u64;
    let final_fee = plan
        .payout_connector_value
        .checked_add(funding.prevout.value)
        .and_then(|input_value| input_value.checked_sub(wallet_output_value))
        .ok_or_else(|| {
            ExecutorError::WalletErr("final unstaking burn fee calculation underflowed".to_string())
        })?;
    let effective_fee_rate_sat_vb = final_fee.to_sat() as f64 / final_vsize as f64;
    if final_vsize != plan.estimated_vsize {
        warn!(
            %graph_idx,
            txid = %signed_tx.compute_txid(),
            estimated_vsize = plan.estimated_vsize,
            final_vsize,
            fee = %final_fee,
            fee_rate = %plan.fee_rate,
            effective_fee_rate_sat_vb,
            "unstaking burn transaction size differed from fee estimate"
        );
    }

    info!(
        %graph_idx,
        txid = %signed_tx.compute_txid(),
        fee = %final_fee,
        expected_fee = %plan.fee,
        fee_rate = %plan.fee_rate,
        effective_fee_rate_sat_vb = effective_fee_rate_sat_vb,
        final_vsize,
        estimated_vsize = plan.estimated_vsize,
        "finalized unstaking burn transaction fee"
    );

    Ok(signed_tx)
}

/// Estimated fee data for the fixed unstaking burn transaction shape.
#[derive(Debug)]
struct FeeEstimate {
    /// Fee amount at the selected fee rate.
    amount: Amount,
    /// Virtual size of the transaction shape used for fee calculation.
    vsize: u64,
}

/// Estimates the fee for the concrete funded burn transaction.
///
/// The estimate is derived from the actual transaction template: one payout connector input, one
/// general-wallet input, and one output back to the general wallet. The connector witness is
/// populated by `finalize_partial`; the wallet witness is modeled with a 64-byte Schnorr signature.
fn estimate_unstaking_burn_fee(
    unstaking_burn_tx: &UnstakingBurnTx,
    unstaking_preimage: [u8; 32],
    payout_script: &ScriptBuf,
    fee_rate: FeeRate,
) -> Result<FeeEstimate, ExecutorError> {
    let mut unstaking_burn_tx = unstaking_burn_tx.clone();
    let min_output_value = payout_script.minimal_non_dust();
    attach_wallet_funding(
        &mut unstaking_burn_tx,
        OutPoint::null(),
        TxOut {
            value: Amount::ZERO,
            script_pubkey: payout_script.clone(),
        },
        TxOut {
            value: min_output_value,
            script_pubkey: payout_script.clone(),
        },
    );

    // The connector witness is exact after `finalize_partial`; the general wallet witness is a
    // fixed-size Schnorr signature, so a 64-byte dummy witness gives an exact vsize.
    let mut estimated_tx = unstaking_burn_tx.finalize_partial(unstaking_preimage);
    estimated_tx.input[WALLET_INPUT_INDEX]
        .witness
        .push([0u8; 64]);

    let vsize = estimated_tx.vsize() as u64;
    let fee = fee_rate
        .fee_vb(vsize)
        .ok_or_else(|| ExecutorError::WalletErr("unstaking burn fee overflow".into()))?;

    info!(%fee_rate, %vsize, fee = %fee, "estimated unstaking burn transaction fee");

    Ok(FeeEstimate { amount: fee, vsize })
}

/// Appends the general-wallet input and output to the burn template.
///
/// After this runs, input index `0` remains the payout connector and input index `1` is the wallet
/// funding input signed by [`sign_wallet_input`].
fn attach_wallet_funding(
    tx: &mut UnstakingBurnTx,
    funding_outpoint: OutPoint,
    funding_prevout: TxOut,
    output: TxOut,
) {
    tx.push_input(
        TxIn {
            previous_output: funding_outpoint,
            ..Default::default()
        },
        funding_prevout,
    );
    tx.push_output(output);
}

/// Signs the appended general-wallet funding input using the secret service.
///
/// The general wallet uses a taproot key-spend path, so the signature commits to all prevouts and
/// uses the default taproot sighash type.
async fn sign_wallet_input(
    output_handles: &OutputHandles,
    tx: &Transaction,
    prevouts: &[TxOut],
) -> Result<taproot::Signature, ExecutorError> {
    let prevouts = Prevouts::All(prevouts);
    let mut sighash_cache = SighashCache::new(tx);
    let s2_signer = output_handles.s2_client.general_wallet_signer();

    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(WALLET_INPUT_INDEX, &prevouts, TapSighashType::Default)
        .map_err(|e| {
            warn!(%e, "failed to compute unstaking burn wallet-input sighash");
            ExecutorError::WalletErr(format!("unstaking burn sighash error: {e}"))
        })?;
    let signature = s2_signer
        .sign(&sighash.to_byte_array(), None)
        .await
        .map_err(|e| {
            warn!(?e, "failed to sign unstaking burn wallet input");
            ExecutorError::SecretServiceErr(e)
        })?;

    Ok(taproot::Signature {
        signature,
        sighash_type: TapSighashType::Default,
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as CoreRpcClient};
    use bitcoin::{
        Address, Network, Txid, XOnlyPublicKey,
        hashes::{Hash, sha256},
        secp256k1::{Keypair, SECP256K1, SecretKey},
    };
    use corepc_node::{Conf, Node};
    use operator_wallet::{NativeGeneralWallet, OperatorWalletConfig, sync::Backend};
    use strata_bridge_connectors::prelude::ClaimPayoutConnector;
    use strata_bridge_tx_graph::transactions::prelude::UnstakingBurnData;

    use super::*;
    use crate::output_handles::NativeWallet;

    const TEST_GRAPH_IDX: GraphIdx = GraphIdx {
        deposit: 0,
        operator: 0,
    };

    fn setup_bitcoind() -> Node {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        Node::with_conf("bitcoind", &conf).expect("bitcoind should start")
    }

    fn core_rpc_client(bitcoind: &Node) -> CoreRpcClient {
        let cookie = bitcoind
            .params
            .get_cookie_values()
            .expect("cookie file should be readable")
            .expect("cookie file should contain credentials");
        let auth = Auth::UserPass(cookie.user, cookie.password);

        CoreRpcClient::new(bitcoind.rpc_url().as_str(), auth)
            .expect("core rpc client should initialize")
    }

    fn xonly_pubkey(byte: u8) -> XOnlyPublicKey {
        let secret_key = SecretKey::from_slice(&[byte; 32]).expect("secret key should be valid");
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);

        keypair.x_only_public_key().0
    }

    fn wallet(bitcoind: &Node) -> AnyOperatorWallet {
        let general = NativeGeneralWallet::new(
            xonly_pubkey(1),
            Network::Regtest,
            Backend::BitcoinCore(Arc::new(core_rpc_client(bitcoind))),
        );
        NativeWallet::new(
            general,
            xonly_pubkey(2),
            OperatorWalletConfig::new(Amount::from_sat(20_000), Network::Regtest),
            Backend::BitcoinCore(Arc::new(core_rpc_client(bitcoind))),
            BTreeSet::new(),
        )
        .into()
    }

    fn fund_general_wallet(bitcoind: &Node, wallet: &AnyOperatorWallet, amount: Amount) {
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("mining address should be generated");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");

        let general_address =
            Address::from_script(&wallet.general_script_pubkey(), Network::Regtest)
                .expect("general wallet script should be addressable");
        bitcoind
            .client
            .send_to_address(&general_address, amount)
            .expect("general wallet should be funded");
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("general wallet funding should confirm");
    }

    fn unstaking_burn_tx(unstaking_preimage: [u8; 32]) -> UnstakingBurnTx {
        let connector = ClaimPayoutConnector::new(
            Network::Regtest,
            xonly_pubkey(3),
            xonly_pubkey(4),
            sha256::Hash::hash(&unstaking_preimage),
        );
        let data = UnstakingBurnData {
            claim_txid: Txid::from_slice(&[5; 32]).expect("txid should be valid"),
        };

        UnstakingBurnTx::new(data, connector)
    }

    fn wallet_script() -> ScriptBuf {
        Address::p2tr(SECP256K1, xonly_pubkey(6), None, Network::Regtest).script_pubkey()
    }

    #[test]
    fn fee_estimate_matches_final_transaction_shape() {
        let unstaking_preimage = [7; 32];
        let unstaking_burn_tx = unstaking_burn_tx(unstaking_preimage);
        let payout_script = wallet_script();
        let fee_rate = FeeRate::from_sat_per_vb(2).expect("fee rate should be valid");

        let fee = estimate_unstaking_burn_fee(
            &unstaking_burn_tx,
            unstaking_preimage,
            &payout_script,
            fee_rate,
        )
        .expect("fee should be estimated");

        let funding_prevout = TxOut {
            value: Amount::from_sat(25_000),
            script_pubkey: payout_script.clone(),
        };
        let output_value = unstaking_burn_tx.prevouts()[CONNECTOR_INPUT_INDEX].value
            + funding_prevout.value
            - fee.amount;
        let mut funded_burn = unstaking_burn_tx;
        attach_wallet_funding(
            &mut funded_burn,
            OutPoint::null(),
            funding_prevout,
            TxOut {
                value: output_value,
                script_pubkey: payout_script,
            },
        );

        let mut tx = funded_burn.finalize_partial(unstaking_preimage);
        tx.input[WALLET_INPUT_INDEX].witness.push([0; 64]);

        assert_eq!(
            tx.vsize() as u64,
            fee.vsize,
            "estimated vsize should match the finalized transaction shape"
        );
        assert_eq!(
            fee.amount,
            fee_rate
                .fee_vb(tx.vsize() as u64)
                .expect("fee should not overflow"),
            "estimated fee should be derived from the selected fee rate and final vsize"
        );
    }

    #[tokio::test]
    async fn select_funding_leases_utxo_that_can_fund_non_dust_output() {
        let bitcoind = setup_bitcoind();
        let mut wallet = wallet(&bitcoind);
        fund_general_wallet(&bitcoind, &wallet, Amount::from_sat(25_000));

        let unstaking_preimage = [8; 32];
        let unstaking_burn_tx = unstaking_burn_tx(unstaking_preimage);
        let fee_rate = FeeRate::from_sat_per_vb(2).expect("fee rate should be valid");
        let min_output_value = wallet.general_script_pubkey().minimal_non_dust();

        let (funding, plan) = select_funding(
            &mut wallet,
            TEST_GRAPH_IDX,
            &unstaking_burn_tx,
            unstaking_preimage,
            fee_rate,
        )
        .await
        .expect("wallet should have a suitable funding UTXO");
        let wallet_output_value = plan.payout_connector_value + funding.prevout.value - plan.fee;

        assert_eq!(
            plan.fee_rate, fee_rate,
            "funding plan should retain the selected fee rate"
        );
        assert!(
            wallet_output_value >= min_output_value,
            "selected funding should leave a non-dust wallet output"
        );
        assert_eq!(
            plan.payout_connector_value,
            unstaking_burn_tx.prevouts()[CONNECTOR_INPUT_INDEX].value,
            "funding plan should retain the payout connector input value"
        );
        assert!(
            wallet.leased_outpoints().contains(&funding.outpoint),
            "selected funding outpoint should be leased"
        );
    }
}
