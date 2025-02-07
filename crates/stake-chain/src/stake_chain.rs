//! The stake chain is a series of transactions that move the stake from one transaction to the
//! next.

use std::ops::{Deref, DerefMut};

use bitcoin::{hashes::sha256, relative, Amount, Network, OutPoint, TxIn, Txid, XOnlyPublicKey};
use strata_bridge_primitives::{scripts::prelude::get_deposit_master_secret_key, wots};
use strata_bridge_tx_graph::connectors::prelude::{ConnectorK, ConnectorP, ConnectorStake};

use crate::prelude::{StakeTx, STAKE_VOUT};

/// A [`StakeChain`] is a series of transactions that move the stake from one transaction to the
/// next.
///
/// It tracks the stake amount and index, the original and current stake prevouts, the current
/// [`StakeTx`] transactions the relative timelock interval to advance the stake chain, and the
/// maximum number of slashing transactions to be created.
///
/// The staking amount is the amount that is staked in the transaction graph for a single stake. It
/// does not need to keep track of the dust output's cost, since it is tracked individually by a
/// dedicated input in each of the [`StakeTx`] transactions.
///
/// The stake index corresponds to the deposit index i.e., the `n`th stake transaction is used to
/// stake in the transaction graph for the `n`th deposit.
///
/// The original stake is the first stake transaction in the chain, which is used to stake in the
/// transaction graph for a single deposit and is moved after a successful deposit, i.e., the
/// operator is not succcesfully challenged and has it's stake slashed.
/// It is the first output of the [`PreStakeTx`](crate::prelude::PreStakeTx).
///
/// The stake chain can be advanced forward by revealing a preimage to a locking script that is
/// also relative timelocked to a certain `ΔS` interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeChain<const M: usize>([StakeTx; M]);

impl<const M: usize> StakeChain<M> {
    /// Creates a new [`StakeChain`] from the provided [`StakeInputs`].
    ///
    /// The provided [`StakeInputs`] must be of length `N`.
    pub fn new<const N: usize>(stake_inputs: &StakeInputs<N>) -> Self
    where
        [(); N - M]:,
    {
        let wots_sk = get_deposit_master_secret_key(
            &stake_inputs.wots_master_sk,
            stake_inputs.pre_stake_txid,
        );
        let wots_pubkey = wots::Wots256PublicKey::new(&wots_sk);
        let connector_k = ConnectorK::new(
            stake_inputs.n_of_n_agg_pubkey,
            stake_inputs.network,
            wots_pubkey,
        );
        let connector_p = ConnectorP::new(
            stake_inputs.n_of_n_agg_pubkey,
            stake_inputs.stake_hashes[0],
            stake_inputs.network,
        );
        let connector_s = ConnectorStake::new(
            stake_inputs.n_of_n_agg_pubkey,
            stake_inputs.operator_pubkey,
            stake_inputs.stake_hashes[0],
            stake_inputs.delta,
            stake_inputs.network,
        );
        let first_stake_tx = StakeTx::new(
            0,
            stake_inputs.original_stake.clone(),
            stake_inputs.amount,
            stake_inputs.operator_funds[0].clone(),
            stake_inputs.operator_pubkey,
            connector_k,
            connector_p,
            connector_s,
            stake_inputs.network,
        );

        // Instantiate a vector with the length `M`.
        let mut stake_chain = Vec::with_capacity(M);
        stake_chain.push(first_stake_tx);

        // for-loop to generate the rest of the `StakeTx`s from the second
        for index in 1..M {
            let previous_stake_tx = stake_chain.get(index -1).expect("always valid since we are starting from 1 (we always have 0) and the length is checked at compile time");
            let previous_stake_txid = previous_stake_tx.compute_txid();
            let wots_sk =
                get_deposit_master_secret_key(&stake_inputs.wots_master_sk, previous_stake_txid);
            let wots_pubkey = wots::Wots256PublicKey::new(&wots_sk);
            let new_stake_tx = generate_new_stake_tx(
                previous_stake_tx,
                stake_inputs.amount,
                stake_inputs.delta,
                stake_inputs.operator_funds[index].clone(),
                stake_inputs.operator_pubkey,
                stake_inputs.n_of_n_agg_pubkey,
                wots_pubkey,
                stake_inputs.stake_hashes[index],
                stake_inputs.network,
            );
            stake_chain.push(new_stake_tx);
        }

        let arr: [StakeTx; M] = stake_chain
            .try_into()
            .expect("stake inputs did not contain exactly M transactions");
        StakeChain(arr)
    }
}

impl<const M: usize> Deref for StakeChain<M> {
    type Target = [StakeTx; M];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const M: usize> DerefMut for StakeChain<M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// An `N`-length [`StakeInputs`] holds all the necessary data to construct an `M < N`-length
/// [`StakeChain`].
///
/// The data that it needs are:
///
/// 1. Stake amount.
/// 2. Operator's public key.
/// 3. N-of-N aggregated bridge public key.
/// 4. WOTS master secret key.
/// 5. `N`-length array of stake hashes.
/// 6. `N`-length array of operator fund prevouts.
/// 7. Original stake prevout.
/// 8. `ΔS` relative timelock interval.
/// 9. Network.
///
/// The staking amount and the `ΔS` relative timelock interval are scalar values and configurable
/// parameters which can be set at compile time to a contracted value.
///
/// The `N`-length WOTS public keys, stake hashes, and operator funds prevouts arrays are needed to
/// construct the transaction graph for the `N` deposits to be claimed while using and advancing the
/// [`StakeChain`].
///
/// The original stake is the first stake transaction in the chain, which is used to stake in the
/// transaction graph for a single deposit and is moved after a successful deposit, i.e., the
/// operator is not succcesfully challenged and has it's stake slashed.
/// It is the first output of the [`PreStakeTx`](crate::prelude::PreStakeTx).
///
/// The network is the bitcoin network on which the stake chain operates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeInputs<const N: usize> {
    /// Staking amount.
    // TODO: make this configurable with a fallback const `D_BTC`.
    amount: Amount,

    /// Operator's public key.
    operator_pubkey: XOnlyPublicKey,

    /// N-of-N aggregated bridge public key.
    n_of_n_agg_pubkey: XOnlyPublicKey,

    /// WOTS master secret key used for the bitcommitment scripts in [`ConnectorK`]s.
    wots_master_sk: String,

    /// Hashes for the `stake_txs` locking scripts.
    stake_hashes: [sha256::Hash; N],

    /// Operator fund prevouts to cover dust outputs for the entirety of the `N`-length
    /// [`StakeChain`].
    operator_funds: [TxIn; N],

    /// Prevout for the first stake transaction.
    original_stake: TxIn,

    /// [`PreStakeTx`](crate::transactions::PreStakeTx)'s [`Txid`].
    pre_stake_txid: Txid,

    /// `ΔS` relative timelock interval to advance the stake chain.
    // TODO: make this configurable with a fallback const like FINALITY_DEPTH to something like
    //       `6`.
    delta: relative::LockTime,

    /// Network on which the stake chain operates.
    network: Network,
}

impl<const N: usize> StakeInputs<N> {
    /// Creates a new N-length [`StakeInputs`].
    ///
    /// # Arguments
    ///
    /// 1. Stake amount.
    /// 2. Operator's public key.
    /// 3. N-of-N aggregated bridge public key.
    /// 4. WOTS master secret key.
    /// 5. `N`-length array of stake hashes.
    /// 6. `N`-length array of operator fund prevouts.
    /// 7. Original stake prevout.
    /// 8. [`PreStakeTx`](crate::transactions::PreStakeTx)'s [`Txid`].
    /// 9. `ΔS` relative timelock interval.
    /// 10. Network.
    ///
    /// For an explanation of the parameters, see the documentation for [`StakeInputs`].
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        amount: Amount,
        operator_pubkey: XOnlyPublicKey,
        n_of_n_agg_pubkey: XOnlyPublicKey,
        wots_master_sk: String,
        stake_hashes: [sha256::Hash; N],
        operator_funds: [TxIn; N],
        original_stake: TxIn,
        pre_stake_txid: Txid,
        delta: relative::LockTime,
        network: Network,
    ) -> Self {
        Self {
            amount,
            operator_pubkey,
            n_of_n_agg_pubkey,
            wots_master_sk,
            stake_hashes,
            operator_funds,
            original_stake,
            pre_stake_txid,
            delta,
            network,
        }
    }

    /// Stake amount.
    ///
    /// The staking amount is the amount that is staked in the transaction graph for a single stake.
    pub fn amount(&self) -> Amount {
        self.amount
    }

    /// Stake hashes for all the [`StakeInputs`]s.
    ///
    /// The stake hashes are used to derive the locking script and must be shared with between
    /// operators so that each operator can compute the transactions deterministically.
    ///
    /// If you only need the stake hash for a single stake, use
    /// [`StakeInputs::stake_hash_at_index`].
    pub fn stake_hashes(&self) -> [sha256::Hash; N] {
        self.stake_hashes
    }

    /// Stake hash for the [`StakeInputs`] at the given index.
    ///
    /// The stake hashes are used to derive the locking script and must be shared with between
    /// operators so that each operator can compute the transactions deterministically.
    ///
    /// If you need the stake hash for all the stakes, use [`StakeInputs::stake_hashes`].
    pub fn stake_hash_at_index(&self, index: usize) -> sha256::Hash {
        self.stake_hashes[index]
    }

    /// Operator funds for all the [`StakeInputs`]s.
    ///
    /// The operator funds are the inputs to cover the dust outputs for the entirety of the
    /// [`StakeInputs`]s.
    ///
    /// If you only need the operator funds for a single stake, use
    /// [`StakeInputs::operator_funds_at_index`] since it vastly reduces the allocations.
    pub fn operator_funds(&self) -> [TxIn; N] {
        self.operator_funds.clone()
    }

    /// Operator funds for the [`StakeInputs`] at the given index.
    ///
    /// The operator funds are the inputs to cover the dust outputs for the entirety of the
    /// [`StakeInputs`]s.
    ///
    /// If you need the operator funds for all the stakes, use [`StakeInputs::operator_funds`].
    pub fn operator_funds_at_index(&self, index: usize) -> TxIn {
        self.operator_funds[index].clone()
    }

    /// Original stake.
    ///
    /// The original stake is the first stake transaction in the chain, which is used to stake in
    /// the transaction graph for a single deposit and is moved after a successful deposit, i.e.,
    /// the operator is not succcesfully challenged and has it's stake slashed.
    /// It is the first output of the [`PreStakeTx`](crate::prelude::PreStakeTx).
    pub fn original_stake(&self) -> TxIn {
        self.original_stake.clone()
    }

    /// Relative timelock interval to advance the stake chain.
    ///
    /// The stake chain can be advanced forward by revealing a preimage to a locking script that is
    /// also relative timelocked to a certain `ΔS` interval.
    pub fn delta(&self) -> relative::LockTime {
        self.delta
    }
}

/// Generates a new [`StakeTx`] transaction for the given current [`StakeTx`] transaction.
#[expect(clippy::too_many_arguments)]
fn generate_new_stake_tx(
    current_stake_tx: &StakeTx,
    stake_amount: Amount,
    delta: relative::LockTime,
    operator_funds: TxIn,
    operator_pubkey: XOnlyPublicKey,
    n_of_n_agg_pubkey: XOnlyPublicKey,
    wots_public_key: wots::Wots256PublicKey,
    stake_hash: sha256::Hash,
    network: Network,
) -> StakeTx {
    // Get data from current `StakeTx`.
    let current_index = current_stake_tx.index;
    let stake_input = TxIn {
        previous_output: OutPoint {
            txid: current_stake_tx.compute_txid(),
            vout: STAKE_VOUT,
        },
        // Important: set the relative timelock to match the delta from the previous stake tx.
        sequence: delta.into(),
        ..Default::default()
    };

    // Connectors.
    let connector_k = ConnectorK::new(n_of_n_agg_pubkey, network, wots_public_key);
    let connector_p = ConnectorP::new(n_of_n_agg_pubkey, stake_hash, network);
    let connector_s = ConnectorStake::new(
        n_of_n_agg_pubkey,
        operator_pubkey,
        stake_hash,
        delta,
        network,
    );
    StakeTx::new(
        current_index + 1,
        stake_input,
        stake_amount,
        operator_funds,
        operator_pubkey,
        connector_k,
        connector_p,
        connector_s,
        network,
    )
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute,
        bip32::DerivationPath,
        consensus,
        hashes::Hash,
        key::TapTweak,
        sighash::{self, Prevouts, SighashCache},
        taproot::{self, LeafVersion},
        transaction, Address, Amount, BlockHash, OutPoint, TapLeafHash, Transaction, TxIn, TxOut,
        Witness,
    };
    use corepc_node::{serde_json::json, AddressType, Conf, Node};
    use secp256k1::{Message, SECP256K1};
    use strata_bridge_test_utils::prelude::{generate_keypair, get_client_async};
    use strata_btcio::rpc::{traits::SignerRpc, types::SignRawTransactionWithWallet};
    use strata_common::logging::{self, LoggerConfig};
    use tracing::{info, trace};

    use super::*;
    use crate::prelude::{PreStakeTx, OPERATOR_FUNDS};

    #[tokio::test]
    async fn stake_chain_advancement() {
        logging::init(LoggerConfig::new("stake_chain_advancement".to_string()));

        // Setup Bitcoin node
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        // Let's not deal with CPFP 1P1C TRUC relay annoyances for this test
        conf.args.push("-minrelaytxfee=0.0");
        conf.args.push("-blockmintxfee=0.0");
        conf.args.push("-dustrelayfee=0.0");
        let bitcoind = Node::from_downloaded_with_conf(&conf).unwrap();
        let btc_client = &bitcoind.client;
        let async_client = get_client_async(&bitcoind);

        // Get network
        let network = btc_client
            .get_blockchain_info()
            .expect("must get blockchain info")
            .chain;
        let network = network.parse::<Network>().expect("network must be valid");

        // get the xpriv
        let xpriv = async_client.get_xpriv().await.unwrap().unwrap();
        trace!(%xpriv, "xpriv");
        let operator_keypair = xpriv.to_keypair(SECP256K1);

        // Mine until maturity
        let funded_address = btc_client
            .new_address_with_type(AddressType::Bech32m)
            .unwrap();
        let change_address = btc_client
            .new_address_with_type(AddressType::Bech32m)
            .unwrap();
        let coinbase_block = btc_client
            .generate_to_address(101, &funded_address)
            .expect("must be able to generate blocks")
            .0
            .first()
            .expect("must be able to get the blocks")
            .parse::<BlockHash>()
            .expect("must parse");
        let coinbase_txid = btc_client
            .get_block(coinbase_block)
            .expect("must be able to get coinbase block")
            .coinbase()
            .expect("must be able to get the coinbase transaction")
            .compute_txid();

        // Generate keys
        let n_of_n_keypair = generate_keypair();
        // let operator_keypair = generate_keypair();
        let n_of_n_pubkey = n_of_n_keypair.x_only_public_key().0;
        let operator_pubkey = operator_keypair.x_only_public_key().0;

        // Create relative timelock (e.g., 6 blocks)
        let delta = relative::LockTime::from_height(6);

        // Create funding transaction
        let pre_stake_address = btc_client
            .new_address_with_type(AddressType::Bech32m)
            .unwrap();
        let funding_input = OutPoint {
            txid: coinbase_txid,
            vout: 0,
        };
        let coinbase_amount = Amount::from_btc(50.0).expect("must be valid amount");
        let stake_amount = Amount::from_btc(25.0).expect("must be a valid amount");
        let fees = Amount::from_sat(1_000);

        let inputs = vec![TxIn {
            previous_output: funding_input,
            ..Default::default()
        }];
        // 2 OPERATOR_FUNDS outputs:
        // 1 with the regular bitcoind wallet for the first StakeTx
        // 1 using `rust-bitcoin` keypair from the derivation path below for the second StakeTx
        // The address that is holding the operator_funds[1] (for the stake_1 tx) is the 5th
        // generated wallet address. It is a BIP86 regtest address.
        let derivation_path = "86'/1'/0'/0/4".parse::<DerivationPath>().unwrap();
        let operator_fund_1_keypair = xpriv
            .derive_priv(SECP256K1, &derivation_path)
            .unwrap()
            .to_keypair(SECP256K1);
        let operator_fund_1_address = Address::p2tr(
            SECP256K1,
            operator_fund_1_keypair.x_only_public_key().0,
            None,
            network,
        );
        let operator_funds_addresses = [
            btc_client
                .new_address_with_type(AddressType::Bech32m)
                .unwrap(),
            operator_fund_1_address,
        ];
        let outputs_funding = vec![
            TxOut {
                value: stake_amount,
                script_pubkey: pre_stake_address.script_pubkey(),
            },
            TxOut {
                value: OPERATOR_FUNDS,
                script_pubkey: operator_funds_addresses[0].script_pubkey(),
            },
            TxOut {
                value: OPERATOR_FUNDS,
                script_pubkey: operator_funds_addresses[1].script_pubkey(),
            },
            TxOut {
                value: coinbase_amount - stake_amount - fees - OPERATOR_FUNDS - OPERATOR_FUNDS,
                script_pubkey: change_address.script_pubkey(),
            },
        ];
        let funding_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs_funding.clone(),
        };
        // Sign the funding tx
        let signed_funding_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&&funding_tx))],
            )
            .expect("must be able to sign transaction");

        assert!(signed_funding_tx.complete);
        let signed_funding_tx: Transaction =
            consensus::encode::deserialize_hex(&signed_funding_tx.hex).expect("must deserialize");

        // Broadcast the funding tx
        let funding_txid = btc_client
            .send_raw_transaction(&signed_funding_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%funding_txid, "funding tx broadcasted");

        // Mine the funding tx
        let _ = btc_client
            .generate_to_address(1, &funded_address)
            .expect("must be able to generate blocks");

        // Create PreStakeTx
        let stake_0_address = btc_client
            .new_address_with_type(AddressType::Bech32m)
            .unwrap();
        let prevout = TxOut {
            value: stake_amount,
            script_pubkey: pre_stake_address.script_pubkey(),
        };
        let inputs = vec![TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            ..Default::default()
        }];
        let outputs = vec![TxOut {
            value: stake_amount,
            script_pubkey: stake_0_address.script_pubkey(),
        }];
        let pre_stake = PreStakeTx::new(inputs, outputs.clone(), &prevout);
        let pre_stake_txid = pre_stake.compute_txid();
        let pre_stake_tx = pre_stake.psbt.extract_tx().unwrap();
        // Sign the transaction
        let signed_pre_stake_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&&pre_stake_tx))],
            )
            .expect("must be able to sign transaction");

        assert!(signed_pre_stake_tx.complete);
        let signed_pre_stake_tx = consensus::encode::deserialize_hex(&signed_pre_stake_tx.hex)
            .expect(
                "must
        deserialize",
            );
        // Broadcast the PreStakeTx
        let prestake_txid = btc_client
            .send_raw_transaction(&signed_pre_stake_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%prestake_txid, "PreStakeTx broadcasted");

        // Mine the PreStakeTx
        let _ = btc_client
            .generate_to_address(1, &funded_address)
            .expect("must be able to generate blocks");

        // Create a StakeChain with 3 inputs
        let wots_master_sk = "test-stake-chain";
        let stake_preimages = [[0u8; 32], [1u8; 32]];
        trace!(?stake_preimages, "stake preimages");
        let stake_hashes = [
            sha256::Hash::hash(&stake_preimages[0]),
            sha256::Hash::hash(&stake_preimages[1]),
        ];
        trace!(?stake_hashes, "stake hashes");
        let operator_funds = [
            TxIn {
                previous_output: OutPoint {
                    txid: funding_txid,
                    vout: 1,
                },
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: funding_txid,
                    vout: 2,
                },
                ..Default::default()
            },
        ];
        trace!(?operator_funds, "operator funds");
        let original_stake = TxIn {
            previous_output: OutPoint {
                txid: pre_stake_txid,
                vout: 0,
            },
            ..Default::default()
        };
        trace!(?original_stake, "original stake");
        let stake_inputs = StakeInputs::new(
            stake_amount,
            operator_pubkey,
            n_of_n_pubkey,
            wots_master_sk.to_string(),
            stake_hashes,
            operator_funds,
            original_stake,
            pre_stake_txid,
            delta,
            network,
        );
        let stake_chain = StakeChain::<2>::new(&stake_inputs);

        // Sign and broadcast the first StakeTx
        let stake_chain_0_tx = stake_chain[0].psbt.unsigned_tx.clone();
        let stake_chain_0_txid = stake_chain_0_tx.compute_txid();
        info!(%stake_chain_0_txid, "StakeTx 0 txid created (unsigned");
        // Sign the transaction
        let signed_stake_chain_0_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&&stake_chain_0_tx))],
            )
            .expect("must be able to sign transaction");

        assert!(signed_stake_chain_0_tx.complete);
        let signed_stake_chain_0_tx: Transaction =
            consensus::encode::deserialize_hex(&signed_stake_chain_0_tx.hex)
                .expect("must deserialize");

        // Broadcast the StakeTx
        let stake_chain_0_txid = btc_client
            .send_raw_transaction(&signed_stake_chain_0_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%stake_chain_0_txid, "StakeTx 0 broadcasted");

        // Mine the StakeTx but for only 1 block
        // This will make the stake chain advancement to fail and we need to test it
        let _ = btc_client
            .generate_to_address(1, &funded_address)
            .expect("must be able to generate blocks");
        info!(%stake_chain_0_txid, "StakeTx 0 mined");

        // Sign and broadcast the second StakeTx
        // FIXME: I give up using the Psbt API.
        // Sign the connector s from the StakeTx (under the hood changes the PSBT)
        // let mut stake_tx = stake_chain[1].clone();
        // stake_tx.finalize_connector_s(
        //     outputs_funding[1].clone(),
        //     &stake_preimages[0],
        //     &operator_keypair,
        //     n_of_n_pubkey,
        //     delta,
        //     network,
        // );
        // let stake_chain_1_tx = stake_tx.psbt.extract_tx().unwrap();
        // trace!(?stake_chain_1_tx, "StakeTx 1");
        // let stake_chain_1_txid = stake_chain_1_tx.compute_txid();
        // info!(%stake_chain_1_txid, "StakeTx 1 txid created (signed)");

        // Sign and broadcast the second StakeTx NOT using the Psbt API
        let stake_chain_1 = stake_chain[1].clone();
        let mut stake_chain_1_tx = stake_chain_1.psbt.unsigned_tx.clone();
        // Recreate the connector s.
        let connector_s = ConnectorStake::new(
            n_of_n_pubkey,
            operator_pubkey,
            stake_hashes[0],
            delta,
            network,
        );
        // Create sighash for the spending transaction
        let taproot_script = connector_s.generate_address().script_pubkey();
        let sighash_type = sighash::TapSighashType::Default;
        // Create the prevouts
        let prevouts = [
            outputs_funding[2].clone(),
            TxOut {
                value: stake_amount,
                script_pubkey: taproot_script,
            },
        ];
        let prevouts = Prevouts::All(&prevouts);
        // OPERATOR_FUNDS witness (key path spend)
        let mut sighash_cache = SighashCache::new(&mut stake_chain_1_tx);
        let tweaked = operator_fund_1_keypair.tap_tweak(SECP256K1, None);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
            .expect("must create sighash");
        let message = Message::from(sighash);
        let signature = SECP256K1.sign_schnorr(&message, &tweaked.to_inner());
        trace!(%signature, "Signature stake_tx 1 operator funds");
        // Update the witness stack.
        let signature = taproot::Signature {
            signature,
            sighash_type,
        };
        *sighash_cache.witness_mut(0).unwrap() = Witness::p2tr_key_spend(&signature);
        let mut stake_chain_1_tx = sighash_cache.into_transaction().to_owned();
        // Connector S witness (script path spend)
        // Create the locking script
        let mut sighash_cache = SighashCache::new(&mut stake_chain_1_tx);
        let locking_script = connector_s.generate_script();
        // Get taproot spend info
        let (_, control_block) = connector_s.generate_spend_info();
        let leaf_hash =
            TapLeafHash::from_script(locking_script.as_script(), LeafVersion::TapScript);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(1, &prevouts, leaf_hash, sighash_type)
            .expect("must create sighash");
        let message =
            Message::from_digest_slice(sighash.as_byte_array()).expect("must create a message");
        // Sign the transaction with operator key
        let signature = SECP256K1.sign_schnorr(&message, &operator_keypair);
        trace!(%signature, "Signature stake_tx 1 connector s");
        // Construct the witness stack
        let mut witness = Witness::new();
        witness.push(stake_preimages[0]);
        witness.push(signature.as_ref());
        witness.push(locking_script.to_bytes());
        witness.push(control_block.serialize());
        *sighash_cache.witness_mut(1).unwrap() = witness;
        let signed_stake_chain_1_tx = sighash_cache.into_transaction().to_owned();

        // Broadcast the StakeTx which will error because of the delta relative timelock
        let stake_chain_1_txid = btc_client.send_raw_transaction(&signed_stake_chain_1_tx);
        assert!(stake_chain_1_txid.is_err());

        // Mine the blockchain delta-1 blocks
        info!(%delta, %stake_chain_0_txid, "StakeTx 0 mined and blockchain advanced to spendable delta relative timelock");

        let _ = btc_client
            .generate_to_address((delta.to_consensus_u32() as usize) - 1, &funded_address)
            .expect("must be able to generate blocks");
        let stake_chain_1_txid = btc_client
            .send_raw_transaction(&signed_stake_chain_1_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%stake_chain_1_txid, "StakeTx 1 broadcasted");
    }
}
