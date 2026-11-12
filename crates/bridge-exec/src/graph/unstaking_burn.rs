//! Executor for the unstaking burn transaction.

use bitcoin::{FeeRate, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};
use btc_tracker::cpfp::DeadlineClass;
use operator_wallet::{FundingInput, LeaseOwner, OperatorWallet, SqliteStore};
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_tx_graph::transactions::prelude::UnstakingBlockPayoutTx;
use tracing::{debug, info, warn};

use crate::{
    chain::{self, ConnectorFunding, CpfpKind},
    config::ExecutionConfig,
    errors::ExecutorError,
    fees::funding_fee_rate,
    output_handles::OutputHandles,
};

/// Index of the payout connector input in the unfunded burn template.
const CONNECTOR_INPUT_INDEX: usize = 0;

/// Index of the general-wallet funding input after [`attach_wallet_funding`] extends the template.
const WALLET_INPUT_INDEX: usize = 1;

/// Finalizes and publishes an unstaking burn transaction.
///
/// The burn pays the next-block rate. In a claimed
/// graph the uncontested payout of the owner can spend the same connector, so a burn that waits in
/// the mempool can lose it. The state machine then sees the payout.
pub(super) async fn publish_unstaking_burn(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    graph_idx: GraphIdx,
    unstaking_burn_tx: UnstakingBlockPayoutTx,
    unstaking_preimage: [u8; 32],
) -> Result<(), ExecutorError> {
    info!(%graph_idx, "preparing unstaking burn transaction");

    let fee_rate = match funding_fee_rate(&cfg.fee_quotes, cfg.maximum_fee_rate).await {
        Err(ExecutorError::FeeRateTooHigh { fee_rate, max }) => {
            warn!(%fee_rate, maximum_fee_rate = %max, "fee rate exceeds maximum, skipping unstaking burn");
            return Ok(());
        }
        rate => rate?,
    };
    debug!(%graph_idx, %fee_rate, "selected fee rate for unstaking burn transaction");

    // `lease` holds the wallet UTXO that pays for the burn. A failure before the publish drops
    // it, which returns the UTXO to the pool.
    let ConnectorFunding {
        input,
        lease,
        change,
        fee,
    } = {
        let mut wallet = output_handles.wallet.write().await;
        select_funding(
            &mut wallet,
            &unstaking_burn_tx,
            unstaking_preimage,
            fee_rate,
        )
        .await?
    };

    let mut funded_burn = unstaking_burn_tx;
    attach_wallet_funding(&mut funded_burn, &input, change);
    let prevouts = funded_burn.prevouts().to_vec();
    let finalized = funded_burn.finalize_partial(unstaking_preimage);
    let signed_tx =
        chain::sign_general_inputs(output_handles, &finalized, &[WALLET_INPUT_INDEX], &prevouts)
            .await?;

    info!(%graph_idx, txid = %signed_tx.compute_txid(), "publishing unstaking burn transaction");
    // The change at vout 0 is above dust, so a child can spend it.
    chain::publish_leased_transaction(
        output_handles,
        &signed_tx,
        "unstaking burn",
        CpfpKind::PayoutCombined {
            payout_vout: 0,
            parent_fee: chain::ParentFee::Exact(fee),
            deadline: DeadlineClass::Deadline,
        },
        lease,
    )
    .await
}

/// Selects and leases a general-wallet UTXO that can pay for the burn transaction.
///
/// The payout connector contributes value but does not necessarily cover relay fees.
///
/// The burn transaction constructed by this executor is:
///
/// ```text
/// +----------+-----------------------------+---------------------------------------+
/// | Inputs   |                             | Outputs                               |
/// +----------+-----------------------------+---------------------------------------+
/// | input 0  | claim payout connector      | output 0: general-wallet change       |
/// |          | witness: unstaking_preimage | value: inputs - ConnectorFunding::fee |
/// +----------+-----------------------------+---------------------------------------+
/// | input 1  | general-wallet funding UTXO |                                       |
/// +----------+-----------------------------+---------------------------------------+
/// ```
async fn select_funding(
    wallet: &mut OperatorWallet<SqliteStore>,
    unstaking_burn_tx: &UnstakingBlockPayoutTx,
    unstaking_preimage: [u8; 32],
    fee_rate: FeeRate,
) -> Result<ConnectorFunding, ExecutorError> {
    if let Err(e) = wallet.sync().await {
        warn!(
            ?e,
            "could not sync wallet before funding unstaking burn; selecting anyway"
        );
    }

    let template = funded_template(
        unstaking_burn_tx,
        unstaking_preimage,
        &wallet.general().script_pubkey(),
    );
    chain::select_connector_funding(
        wallet,
        LeaseOwner::UnstakingBurn,
        &template,
        unstaking_burn_tx.prevouts()[CONNECTOR_INPUT_INDEX].value,
        fee_rate,
    )
}

/// Returns the funded burn with placeholder values, which gives its size. The connector witness
/// is exact after `finalize_partial`, and the empty wallet input stays unsigned.
fn funded_template(
    unstaking_burn_tx: &UnstakingBlockPayoutTx,
    unstaking_preimage: [u8; 32],
    payout_script: &ScriptBuf,
) -> Transaction {
    let mut template = unstaking_burn_tx.clone();
    let placeholder = TxOut {
        value: payout_script.minimal_non_dust(),
        script_pubkey: payout_script.clone(),
    };
    let input = FundingInput {
        outpoint: OutPoint::null(),
        txout: placeholder.clone(),
    };
    attach_wallet_funding(&mut template, &input, placeholder);
    template.finalize_partial(unstaking_preimage)
}

/// Appends the general-wallet input and output to the burn template.
///
/// After this runs, input index `0` remains the payout connector and input index `1` is the wallet
/// funding input.
fn attach_wallet_funding(tx: &mut UnstakingBlockPayoutTx, funding: &FundingInput, output: TxOut) {
    tx.push_input(
        TxIn {
            previous_output: funding.outpoint,
            ..Default::default()
        },
        funding.txout.clone(),
    );
    tx.push_output(output);
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as CoreRpcClient};
    use bitcoin::{
        Address, Amount, Network, Txid, Weight, XOnlyPublicKey,
        hashes::{Hash, sha256},
        secp256k1::{Keypair, SECP256K1, SecretKey},
        transaction::InputWeightPrediction,
    };
    use corepc_node::{Conf, Node};
    use operator_wallet::{GeneralCustody, OperatorWalletConfig, WalletKind, sync::Backend};
    use strata_bridge_connectors::prelude::ClaimUnstakingPayoutConnector;
    use strata_bridge_tx_graph::transactions::prelude::UnstakingBlockPayoutData;
    use tempfile::TempDir;

    use super::*;

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

    /// Builds a wallet over fresh SQLite stores in a temp dir. The [`TempDir`] must outlive the
    /// wallet, so it is returned alongside.
    async fn wallet(bitcoind: &Node) -> (OperatorWallet<SqliteStore>, TempDir) {
        let data_dir = tempfile::tempdir().expect("temp dir for wallet stores");
        let general_store = SqliteStore::open_in_dir(data_dir.path(), WalletKind::General)
            .expect("general store should open");
        let reserved_store = SqliteStore::open_in_dir(data_dir.path(), WalletKind::Reserved)
            .expect("reserved store should open");
        let config = OperatorWalletConfig::new(0, Network::Regtest);
        let wallet = OperatorWallet::load_or_create(
            GeneralCustody::SecretService {
                general_key: xonly_pubkey(1),
                store: general_store,
            },
            xonly_pubkey(2),
            config,
            Backend::BitcoinCore(Arc::new(core_rpc_client(bitcoind))),
            reserved_store,
            None,
            BTreeSet::new(),
        )
        .await
        .expect("wallet should initialise against empty stores");
        (wallet, data_dir)
    }

    fn fund_general_wallet(bitcoind: &Node, wallet: &OperatorWallet<SqliteStore>, amount: Amount) {
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("mining address should be generated");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");

        let general_address =
            Address::from_script(&wallet.general().script_pubkey(), Network::Regtest)
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

    /// Funds the general wallet with a single unconfirmed credit: mature coinbases, then send
    /// without mining, so the wallet's synced view holds one zero-confirmation UTXO.
    fn fund_general_wallet_unconfirmed(
        bitcoind: &Node,
        wallet: &OperatorWallet<SqliteStore>,
        amount: Amount,
    ) {
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("mining address should be generated");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");

        let general_address =
            Address::from_script(&wallet.general().script_pubkey(), Network::Regtest)
                .expect("general wallet script should be addressable");
        bitcoind
            .client
            .send_to_address(&general_address, amount)
            .expect("general wallet should receive an unconfirmed credit");
    }

    fn unstaking_burn_tx(unstaking_preimage: [u8; 32]) -> UnstakingBlockPayoutTx {
        let connector = ClaimUnstakingPayoutConnector::new(
            Network::Regtest,
            xonly_pubkey(3),
            sha256::Hash::hash(&unstaking_preimage),
        );
        let data = UnstakingBlockPayoutData {
            claim_txid: Txid::from_slice(&[5; 32]).expect("txid should be valid"),
        };

        UnstakingBlockPayoutTx::new(data, connector)
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
        let prediction = InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH;

        let fee = chain::funded_tx_fee(
            &funded_template(&unstaking_burn_tx, unstaking_preimage, &payout_script),
            prediction,
            fee_rate,
        )
        .expect("fee should be estimated");

        let funding_prevout = TxOut {
            value: Amount::from_sat(25_000),
            script_pubkey: payout_script.clone(),
        };
        let output_value =
            unstaking_burn_tx.prevouts()[CONNECTOR_INPUT_INDEX].value + funding_prevout.value - fee;
        let mut funded_burn = unstaking_burn_tx;
        attach_wallet_funding(
            &mut funded_burn,
            &FundingInput {
                outpoint: OutPoint::null(),
                txout: funding_prevout,
            },
            TxOut {
                value: output_value,
                script_pubkey: payout_script,
            },
        );

        let mut tx = funded_burn.finalize_partial(unstaking_preimage);
        tx.input[WALLET_INPUT_INDEX].witness.push([0; 64]);

        assert!(
            fee >= fee_rate.fee_wu(tx.weight()).expect("no overflow"),
            "the fee must reach the rate on the signed transaction"
        );
        assert!(
            fee <= fee_rate
                .fee_wu(tx.weight() + Weight::from_wu(5))
                .expect("no overflow"),
            "the estimate must stay within the overlap of the empty input"
        );
    }

    #[tokio::test]
    async fn select_funding_leases_utxo_that_can_fund_non_dust_output() {
        let bitcoind = setup_bitcoind();
        let (mut wallet, _data_dir) = wallet(&bitcoind).await;
        fund_general_wallet(&bitcoind, &wallet, Amount::from_sat(25_000));

        let unstaking_preimage = [8; 32];
        let unstaking_burn_tx = unstaking_burn_tx(unstaking_preimage);
        let fee_rate = FeeRate::from_sat_per_vb(2).expect("fee rate should be valid");
        let min_output_value = wallet.general().script_pubkey().minimal_non_dust();

        let funding = select_funding(
            &mut wallet,
            &unstaking_burn_tx,
            unstaking_preimage,
            fee_rate,
        )
        .await
        .expect("wallet should have a suitable funding UTXO");

        assert!(
            funding.change.value >= min_output_value,
            "selected funding should leave a non-dust wallet output"
        );
        assert!(
            wallet.leased_outpoints().contains(&funding.input.outpoint),
            "selected funding outpoint should be leased"
        );
    }

    #[tokio::test]
    async fn select_funding_rejects_unconfirmed_wallet_utxo() {
        let bitcoind = setup_bitcoind();
        let (mut wallet, _data_dir) = wallet(&bitcoind).await;
        fund_general_wallet_unconfirmed(&bitcoind, &wallet, Amount::from_sat(25_000));

        // The pin is only strong if the wallet actually sees the zero-confirmation UTXO:
        // a wallet view that never surfaces mempool credits would pass this test with the
        // confirmations gate absent.
        wallet.sync().await.expect("wallet should sync");
        let unconfirmed = wallet
            .general()
            .list_utxos()
            .into_iter()
            .filter(|u| u.confirmations == 0)
            .collect::<Vec<_>>();
        assert_eq!(
            unconfirmed.len(),
            1,
            "the wallet view should hold exactly one zero-confirmation UTXO"
        );

        let unstaking_preimage = [9; 32];
        let unstaking_burn_tx = unstaking_burn_tx(unstaking_preimage);
        let fee_rate = FeeRate::from_sat_per_vb(2).expect("fee rate should be valid");

        let err = select_funding(
            &mut wallet,
            &unstaking_burn_tx,
            unstaking_preimage,
            fee_rate,
        )
        .await
        .expect_err("a zero-confirmation UTXO must not fund the burn (TRUC, BIP-431)");

        match err {
            ExecutorError::WalletErr(msg) => assert!(
                msg.contains("no general wallet UTXO"),
                "rejection should report no available funding, got: {msg}"
            ),
            other => panic!("expected WalletErr, got: {other:?}"),
        }
    }
}
