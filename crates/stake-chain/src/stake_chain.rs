//! The stake chain is a series of transactions that move the stake from one transaction to the
//! next.

use std::ops::{Deref, DerefMut};

use bitcoin::{hashes::sha256, relative, Amount, Network, OutPoint, TxIn, Txid, XOnlyPublicKey};
use strata_bridge_primitives::wots;
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
///
/// # Construction
///
/// [`StakeChain`]s can be constructed by first creating a [`StakeInputs`] of length `N` and then
/// calling [`StakeInputs::<M>::to_stake_chain`](StakeInputs::to_stake_chain), where `M < N`
/// (compile-time check).
///
/// The user can also coerce a [`Vec<StakeTx>`] into a `[StakeChain; N]`, but it does not offer the
/// same compile-time guarantees as the previous method.
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
        stake_inputs.to_stake_chain::<M>()
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

    /// Converts a [`StakeInputs`] into a [`StakeChain`].
    ///
    /// # Note
    ///
    /// The [`StakeChain`] can be of length less than or equal to the [`StakeInputs`].
    ///
    /// It is impossible to create a [`StakeChain`] with a length greater than the [`StakeInputs`].
    /// This is done by compile-time checks.
    pub fn to_stake_chain<const M: usize>(&self) -> StakeChain<M>
    where
        [(); N - M]:,
    {
        let wots_pubkeys = wots::PublicKeys::new(&self.wots_master_sk, self.pre_stake_txid);
        let connector_k = ConnectorK::new(self.n_of_n_agg_pubkey, self.network, wots_pubkeys);
        let connector_p =
            ConnectorP::new(self.n_of_n_agg_pubkey, self.stake_hashes[0], self.network);
        let connector_s = ConnectorStake::new(
            self.n_of_n_agg_pubkey,
            self.operator_pubkey,
            self.stake_hashes[0],
            self.delta,
            self.network,
        );
        let first_stake_tx = StakeTx::new(
            0,
            self.original_stake.clone(),
            self.amount,
            self.operator_funds[0].clone(),
            self.operator_pubkey,
            connector_k,
            connector_p,
            connector_s,
            self.network,
        );

        // Instantiate a vector with the length `M`.
        let mut stake_chain = Vec::with_capacity(M);
        stake_chain.push(first_stake_tx);

        // for-loop to generate the rest of the `StakeTx`s from the second
        for index in 1..M {
            let previous_stake_tx = stake_chain.get(index -1).expect("always valid since we are starting from 1 (we always have 0) and the length is checked at compile time");
            let previous_stake_txid = previous_stake_tx.compute_txid();
            let wots_pubkeys = wots::PublicKeys::new(&self.wots_master_sk, previous_stake_txid);
            let new_stake_tx = generate_new_stake_tx(
                previous_stake_tx,
                self.amount,
                self.delta,
                self.operator_funds[index].clone(),
                self.operator_pubkey,
                self.n_of_n_agg_pubkey,
                wots_pubkeys,
                self.stake_hashes[index],
                self.network,
            );
            stake_chain.push(new_stake_tx);
        }

        let arr: [StakeTx; M] = stake_chain
            .try_into()
            .expect("stake inputs did not contain exactly M transactions");
        StakeChain(arr)
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
    wots_public_keys: wots::PublicKeys,
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
    let connector_k = ConnectorK::new(n_of_n_agg_pubkey, network, wots_public_keys);
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
        absolute, consensus,
        hashes::Hash,
        sighash::{self, Prevouts, SighashCache},
        taproot::LeafVersion,
        transaction, Amount, BlockHash, OutPoint, TapLeafHash, Transaction, TxIn, TxOut, Witness,
    };
    use corepc_node::{serde_json::json, AddressType, Conf, Node};
    use secp256k1::{Message, SECP256K1};
    use strata_bridge_test_utils::prelude::generate_keypair;
    use strata_btcio::rpc::types::{
        CreateRawTransaction, CreateRawTransactionInput, PreviousTransactionOutput,
        SignRawTransactionWithWallet,
    };
    use strata_common::logging::{self, LoggerConfig};
    use tracing::{info, trace};

    use super::*;
    use crate::prelude::{PreStakeTx, DUST_AMOUNT, OPERATOR_FUNDS};

    #[test]
    fn stake_chain_advancement() {
        logging::init(LoggerConfig::new("stake_chain_advancement".to_string()));

        // Setup Bitcoin node
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::from_downloaded_with_conf(&conf).unwrap();
        let btc_client = &bitcoind.client;

        // Get network
        let network = btc_client
            .get_blockchain_info()
            .expect("must get blockchain info")
            .chain;
        let network = network.parse::<Network>().expect("network must be valid");

        // Mine until maturity
        let funded_address = btc_client.new_address().unwrap();
        let change_address = btc_client.new_address().unwrap();
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
        let operator_keypair = generate_keypair();
        let n_of_n_pubkey = n_of_n_keypair.x_only_public_key().0;
        let operator_pubkey = operator_keypair.x_only_public_key().0;

        // Generate stake preimage
        let stake_preimage = [1; 32];
        let stake_hash = sha256::Hash::hash(&stake_preimage);

        // Create relative timelock (e.g., 6 blocks)
        let delta = relative::LockTime::from_height(6);

        // Create PreStakeTx
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
        // 3 OPERATOR_FUNDS outputs
        let operator_funds_addresses = [
            btc_client
                .new_address_with_type(AddressType::Bech32m)
                .unwrap(),
            btc_client
                .new_address_with_type(AddressType::Bech32m)
                .unwrap(),
            btc_client
                .new_address_with_type(AddressType::Bech32m)
                .unwrap(),
        ];
        let outputs = vec![
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
                value: OPERATOR_FUNDS,
                script_pubkey: operator_funds_addresses[2].script_pubkey(),
            },
            TxOut {
                value: coinbase_amount
                    - stake_amount
                    - fees
                    - OPERATOR_FUNDS
                    - OPERATOR_FUNDS
                    - OPERATOR_FUNDS,
                script_pubkey: change_address.script_pubkey(),
            },
        ];
        let pre_stake_tx = PreStakeTx::new(inputs, outputs).psbt.unsigned_tx;
        let pre_stake_txid = pre_stake_tx.compute_txid();
        // Sign the transaction
        let signed_pre_stake_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&&pre_stake_tx))],
            )
            .expect("must be able to sign transaction");

        assert!(signed_pre_stake_tx.complete);
        let signed_funding_tx =
            consensus::encode::deserialize_hex(&signed_pre_stake_tx.hex).expect("must deserialize");

        // Broadcast the PreStakeTx
        let funding_txid = btc_client
            .send_raw_transaction(&signed_funding_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%funding_txid, "PreStakeTx broadcasted");

        // Mine the PreStakeTx
        let _ = btc_client
            .generate_to_address(1, &funded_address)
            .expect("must be able to generate blocks");

        // Create a StakeChain with 3 inputs
        let wots_master_sk = "test-stake-chain";
        let stake_preimages = [[0u8; 32], [1u8; 32], [2u8; 32]];
        let stake_hashes = [
            sha256::Hash::hash(&stake_preimages[0]),
            sha256::Hash::hash(&stake_preimages[1]),
            sha256::Hash::hash(&stake_preimages[2]),
        ];
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
            TxIn {
                previous_output: OutPoint {
                    txid: funding_txid,
                    vout: 3,
                },
                ..Default::default()
            },
        ];
        let original_stake = TxIn {
            previous_output: OutPoint {
                txid: pre_stake_txid,
                vout: 0,
            },
            ..Default::default()
        };
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
        let stake_chain = StakeChain::<3>::new(&stake_inputs);

        // Sign and broadcast the first StakeTx
        let stake_chain_0_tx = stake_chain[0].psbt.unsigned_tx.clone();
        let stake_chain_0_txid = stake_chain_0_tx.compute_txid();
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

        // Get the CPFP for StakeTx 0
        let cpfp_vout = 3; // 4th output in StakeTx
        let cpfp_txid = stake_chain_0_txid;
        let cpfp_spk = stake_chain_0_tx.output[cpfp_vout].script_pubkey.clone();

        // Needed for 1P1C TRUC relay
        let prev_outputs_1p1c = PreviousTransactionOutput {
            txid: cpfp_txid,
            vout: cpfp_vout as u32,
            script_pubkey: cpfp_spk.to_string(),
            redeem_script: None,
            witness_script: None,
            amount: Some(DUST_AMOUNT.to_btc()),
        };

        // Broadcast the PreStakeTx
        let stake_chain_0_txid = btc_client
            .send_raw_transaction(&signed_funding_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%stake_chain_0_txid, "StakeTx 0 broadcasted");

        // Mine the StakeTx
        let _ = btc_client
            .generate_to_address((delta.to_consensus_u32() as usize) + 1, &funded_address)
            .expect("must be able to generate blocks");
    }
}
