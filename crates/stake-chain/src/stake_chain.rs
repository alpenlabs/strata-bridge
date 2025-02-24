//! The stake chain is a series of transactions that move the stake from one transaction to the
//! next.

use std::ops::{Deref, DerefMut};

use bitcoin::{hashes::sha256, relative, Amount, OutPoint, XOnlyPublicKey};
use strata_bridge_connectors::prelude::ConnectorCpfp;
use strata_bridge_primitives::{
    build_context::BuildContext, params::stake_chain::StakeChainParams,
};

use crate::{
    prelude::{StakeTx, STAKE_VOUT},
    transactions::stake::StakeTxData,
};

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
    pub fn new<const N: usize>(
        context: &impl BuildContext,
        stake_chain_inputs: &StakeChainInputs<N>,
        connector_cpfp: ConnectorCpfp,
    ) -> Self
    where
        [(); N - M]:,
    {
        let first_stake_inputs = stake_chain_inputs.stake_inputs[0];

        let first_stake_tx = StakeTx::create_initial(
            context,
            stake_chain_inputs.params,
            first_stake_inputs.hash,
            first_stake_inputs.withdrawal_fulfillment_pk,
            stake_chain_inputs.pre_stake_outpoint,
            first_stake_inputs.operator_funds,
            stake_chain_inputs.operator_pubkey,
            connector_cpfp,
        );
        let first_stake_txid = first_stake_tx.compute_txid();

        // Instantiate a vector with the length `M`.
        let mut stake_chain = Vec::with_capacity(M);
        stake_chain.push(first_stake_tx);

        // for-loop to generate the rest of the `StakeTx`s from the second
        for index in 1..M {
            let stake_inputs = stake_chain_inputs.stake_inputs;
            let prev_stake = OutPoint {
                txid: first_stake_txid,
                vout: STAKE_VOUT,
            };
            let prev_hash = stake_chain_inputs.stake_hash_at_index(index - 1);

            let stake_input = StakeTxData {
                operator_funds: stake_inputs[index].operator_funds,
                hash: stake_chain_inputs.stake_hash_at_index(index),
                withdrawal_fulfillment_pk: stake_inputs[index].withdrawal_fulfillment_pk,
            };

            let new_stake_tx = StakeTx::advance(
                context,
                stake_chain_inputs.params,
                stake_input,
                prev_hash,
                prev_stake,
                stake_chain_inputs.operator_pubkey,
                connector_cpfp,
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
/// 1. Operator's public key.
/// 2. `N`-length WOTS public keys.
/// 3. `N`-length array of stake hashes.
/// 4. `N`-length array of operator fund prevouts.
/// 5. `N`-length array of operator fund previous UTXOs.
/// 6. Pre-stake prevout.
/// 7. Pre-stake utxo.
/// 8. Stake Chain protocol parameters:
///    1. Stake amount.
///    2. N-of-N aggregated bridge public key.
///    3. `ΔS` relative timelock interval.
///    4. Network.
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
/// The staking amount, N-of-N aggregated bridge public key, `ΔS` relative timelock interval, and
/// network are configurable parameters which can be set at compile time to a contracted value.
///
/// The network is the bitcoin network on which the stake chain operates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeChainInputs<const N: usize> {
    /// Operator's public key.
    pub operator_pubkey: XOnlyPublicKey,

    /// Inputs required for individual stake transactions.
    pub stake_inputs: [StakeTxData; N],

    /// [`OutPoint`] from the [`PreStakeTx`](crate::transactions::PreStakeTx) that carries the
    /// stake.
    pub pre_stake_outpoint: OutPoint,

    /// Stake Chain protocol parameters.
    pub params: StakeChainParams,
}

impl<const N: usize> StakeChainInputs<N> {
    /// Stake amount.
    ///
    /// The staking amount is the amount that is staked in the transaction graph for a single stake.
    pub fn amount(&self) -> Amount {
        self.params.stake_amount
    }

    /// Stake hashes for all the [`StakeInputs`]s.
    ///
    /// The stake hashes are used to derive the locking script and must be shared with between
    /// operators so that each operator can compute the transactions deterministically.
    ///
    /// If you only need the stake hash for a single stake, use
    /// [`StakeInputs::stake_hash_at_index`].
    pub fn stake_hashes(&self) -> [sha256::Hash; N] {
        self.stake_inputs.map(|input| input.hash)
    }

    /// Stake hash for the [`StakeInputs`] at the given index.
    ///
    /// The stake hashes are used to derive the locking script and must be shared with between
    /// operators so that each operator can compute the transactions deterministically.
    ///
    /// If you need the stake hash for all the stakes, use [`StakeInputs::stake_hashes`].
    ///
    /// # Panics
    ///
    /// If the index is out of bounds.
    pub fn stake_hash_at_index(&self, index: usize) -> sha256::Hash {
        self.stake_inputs[index].hash
    }

    /// Operator funds for all the [`StakeInputs`]s.
    ///
    /// The operator funds are the inputs to cover the dust outputs for the entirety of the
    /// [`StakeInputs`]s.
    ///
    /// If you only need the operator funds for a single stake, use
    /// [`StakeInputs::operator_funds_at_index`] since it vastly reduces the allocations.
    ///
    /// # Panics
    ///
    /// If the index is out of bounds.
    pub fn operator_funds(&self) -> [OutPoint; N] {
        self.stake_inputs.map(|input| input.operator_funds)
    }

    /// Operator funds for the [`StakeInputs`] at the given index.
    ///
    /// The operator funds are the inputs to cover the dust outputs for the entirety of the
    /// [`StakeInputs`]s.
    ///
    /// If you need the operator funds for all the stakes, use [`StakeInputs::operator_funds`].
    ///
    /// # Panics
    ///
    /// If the index is out of bounds.
    pub fn operator_funds_at_index(&self, index: usize) -> OutPoint {
        self.stake_inputs[index].operator_funds
    }

    /// Prevout of the first stake transaction.
    pub fn pre_stake_prevout(&self) -> OutPoint {
        self.pre_stake_outpoint
    }

    /// Relative timelock interval to advance the stake chain.
    ///
    /// The stake chain can be advanced forward by revealing a preimage to a locking script that is
    /// also relative timelocked to a certain `ΔS` interval.
    pub fn delta(&self) -> relative::LockTime {
        self.params.delta
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::{
        absolute,
        bip32::{ChildNumber, Xpriv},
        hashes::Hash,
        key::{Keypair, TapTweak},
        sighash::{self, Prevouts, SighashCache},
        taproot::{self, LeafVersion},
        transaction, Address, Amount, BlockHash, Network, OutPoint, TapLeafHash, Transaction, TxIn,
        TxOut, Witness,
    };
    use corepc_node::{Conf, Node};
    use secp256k1::{Message, SECP256K1};
    use strata_bridge_connectors::prelude::ConnectorStake;
    use strata_bridge_primitives::{build_context::TxBuildContext, wots};
    use strata_common::logging::{self, LoggerConfig};
    use tracing::{info, trace};

    use super::*;
    use crate::prelude::{PreStakeTx, OPERATOR_FUNDS};

    /// Signs a [`Transaction`] with the given [`Keypair`].
    ///
    /// It must be a P2TR key path spend transaction with a single input.
    fn sign_tx(transaction: &Transaction, keypair: &Keypair, prevout: TxOut) -> Transaction {
        let mut sighasher = SighashCache::new(transaction);
        let sighash_type = sighash::TapSighashType::Default;
        let taproot_key_spend_signature_hash = sighasher
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), sighash_type)
            .expect("must create sighash");
        let message = Message::from_digest_slice(taproot_key_spend_signature_hash.as_byte_array())
            .expect("must create a message");
        let tweaked = keypair.tap_tweak(SECP256K1, None);
        let signature = SECP256K1.sign_schnorr(&message, &tweaked.to_inner());
        let mut transaction = transaction.clone();
        transaction.input[0].witness.push(signature.as_ref());
        transaction
    }

    /// Signs the first [`StakeTx`] in a `StakeChain`.
    ///
    /// The prevouts must be the following:
    ///
    /// 1. An operator fund prevout that has value [`OPERATOR_FUNDS`] and is a simple P2TR key path
    ///    spend.
    /// 2. The [`PreStakeTx`] first output.
    fn sign_first_stake_tx<const M: usize>(
        stake_chain: &StakeChain<M>,
        keypair_operator_funds: &Keypair,
        keypair_pre_stake: &Keypair,
        prevouts: [TxOut; 2],
    ) -> Transaction {
        let sighash_type = sighash::TapSighashType::Default;
        // The key path spend for the first input
        let stake = stake_chain[0].clone();
        let mut stake_tx = stake.psbt.unsigned_tx.clone();
        // Create the prevouts
        let prevouts = Prevouts::All(&prevouts);

        // OPERATOR_FUNDS witness (key path spend)
        let mut sighash_cache = SighashCache::new(&mut stake_tx);
        let tweaked = keypair_operator_funds.tap_tweak(SECP256K1, None);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
            .expect("must create sighash");
        let message = Message::from(sighash);
        let signature = SECP256K1.sign_schnorr(&message, &tweaked.to_inner());
        trace!(%M, %signature, "Signature stake_tx operator funds");
        // Update the witness stack.
        let signature = taproot::Signature {
            signature,
            sighash_type,
        };
        *sighash_cache.witness_mut(0).unwrap() = Witness::p2tr_key_spend(&signature);
        let mut stake_tx = sighash_cache.into_transaction().to_owned();

        let mut sighash_cache = SighashCache::new(&mut stake_tx);
        let tweaked = keypair_pre_stake.tap_tweak(SECP256K1, None);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(1, &prevouts, sighash_type)
            .expect("must create sighash");
        let message = Message::from(sighash);
        let signature = SECP256K1.sign_schnorr(&message, &tweaked.to_inner());
        trace!(%M, %signature, "Signature stake_tx operator funds");
        // Update the witness stack.
        let signature = taproot::Signature {
            signature,
            sighash_type,
        };
        *sighash_cache.witness_mut(1).unwrap() = Witness::p2tr_key_spend(&signature);
        sighash_cache.into_transaction().to_owned()
    }

    /// Signs a [`StakeTx`], i.e. `StakeChain::[x]` given an index `0 < x <= M`.
    ///
    /// The prevouts must be the following:
    ///
    /// 1. An operator fund prevout that has value [`OPERATOR_FUNDS`] and is a simple P2TR key path
    ///    spend.
    /// 2. A connector `s` that is a P2TR script path spend.
    #[expect(clippy::too_many_arguments)]
    fn sign_stake_tx<const M: usize>(
        index: usize,
        stake_chain: &StakeChain<M>,
        keypair_operator_funds: &Keypair,
        keypair_connector_s: &Keypair,
        prevouts: [TxOut; 2],
        stake_preimage: &[u8; 32],
        n_of_n_pubkey: XOnlyPublicKey,
        operator_pubkey: XOnlyPublicKey,
        delta: relative::LockTime,
        network: Network,
    ) -> Transaction {
        let sighash_type = sighash::TapSighashType::Default;
        let stake_hash = sha256::Hash::hash(stake_preimage);
        // The key path spend for the first input
        let stake = stake_chain[index].clone();
        let mut stake_tx = stake.psbt.unsigned_tx.clone();
        // Recreate the connector s.
        let connector_s =
            ConnectorStake::new(n_of_n_pubkey, operator_pubkey, stake_hash, delta, network);
        // Create the prevouts
        let prevouts = Prevouts::All(&prevouts);

        // OPERATOR_FUNDS witness (key path spend)
        // CATCH: if is the first stake, then we panic!
        if index == 0 {
            panic!("The first stake must be signed using another function");
        }
        let mut sighash_cache = SighashCache::new(&mut stake_tx);
        let tweaked = keypair_operator_funds.tap_tweak(SECP256K1, None);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
            .expect("must create sighash");
        let message = Message::from(sighash);
        let signature = SECP256K1.sign_schnorr(&message, &tweaked.to_inner());
        trace!(%index, %M, %signature, "Signature stake_tx operator funds");
        // Update the witness stack.
        let signature = taproot::Signature {
            signature,
            sighash_type,
        };
        *sighash_cache.witness_mut(0).unwrap() = Witness::p2tr_key_spend(&signature);
        let mut stake_tx = sighash_cache.into_transaction().to_owned();

        // Connector S witness (script path spend)
        // Create the locking script
        let mut sighash_cache = SighashCache::new(&mut stake_tx);
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
        let signature = SECP256K1.sign_schnorr(&message, keypair_connector_s);
        trace!(%index, %M, %signature, "Signature stake_tx connector s");
        // Construct the witness stack
        let mut witness = Witness::new();
        witness.push(stake_preimage);
        witness.push(signature.as_ref());
        witness.push(locking_script.to_bytes());
        witness.push(control_block.serialize());
        *sighash_cache.witness_mut(1).unwrap() = witness;
        sighash_cache.into_transaction().to_owned()
    }

    /// Creates an [`Address`] from a [`ConnectorStake`].
    fn create_connector_stake(
        n_of_n_pubkey: XOnlyPublicKey,
        operator_pubkey: XOnlyPublicKey,
        stake_hash: sha256::Hash,
        delta: relative::LockTime,
        network: Network,
    ) -> Address {
        let connect_s =
            ConnectorStake::new(n_of_n_pubkey, operator_pubkey, stake_hash, delta, network);
        connect_s.generate_address()
    }

    #[test]
    fn stake_chain_advancement() {
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

        // Get network
        let network = btc_client
            .get_blockchain_info()
            .expect("must get blockchain info")
            .chain;
        let network = network.parse::<Network>().expect("network must be valid");

        // Generate a random xpriv
        let secret_bytes = [0; 32];
        let xpriv = Xpriv::new_master(network, &secret_bytes).unwrap();
        trace!(%xpriv, "xpriv");
        let operator_keypair = xpriv.to_keypair(SECP256K1);

        // Mine until maturity
        let funded_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(0).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let funded_address = Address::p2tr(
            SECP256K1,
            funded_keypair.x_only_public_key().0,
            None,
            network,
        );
        let change_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(1).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let change_address = Address::p2tr(
            SECP256K1,
            change_keypair.x_only_public_key().0,
            None,
            network,
        );
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

        let operator_pubkey = operator_keypair.x_only_public_key().0;
        let pubkey_table = BTreeMap::from([(0, operator_keypair.public_key())]);
        let tx_build_context = TxBuildContext::new(network, pubkey_table.into(), 0);
        let n_of_n_agg_pubkey = tx_build_context.aggregated_pubkey();

        // Create relative timelock (e.g., 6 blocks)
        let delta = relative::LockTime::from_height(6);
        let slash_stake_count: usize = 24;

        // Create the StakeParams
        let stake_amount = Amount::from_btc(25.0).expect("must be a valid amount");
        let params = StakeChainParams {
            stake_amount,
            delta,
            slash_stake_count,
        };

        // Create funding transaction
        let pre_stake_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(2).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let pre_stake_address = Address::p2tr(
            SECP256K1,
            pre_stake_keypair.x_only_public_key().0,
            None,
            network,
        );
        let funding_input = OutPoint {
            txid: coinbase_txid,
            vout: 0,
        };
        let coinbase_amount = Amount::from_btc(50.0).expect("must be valid amount");
        let fees = Amount::from_sat(1_000);

        let inputs = vec![TxIn {
            previous_output: funding_input,
            ..Default::default()
        }];
        // 2 OPERATOR_FUNDS outputs:
        let operator_fund_1_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(3).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let operator_fund_1_address = Address::p2tr(
            SECP256K1,
            operator_fund_1_keypair.x_only_public_key().0,
            None,
            network,
        );
        let operator_fund_2_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(4).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let operator_fund_2_address = Address::p2tr(
            SECP256K1,
            operator_fund_2_keypair.x_only_public_key().0,
            None,
            network,
        );
        let operator_funds_addresses = [operator_fund_1_address, operator_fund_2_address];
        let operator_funds_previous_utxos = [
            TxOut {
                value: OPERATOR_FUNDS,
                script_pubkey: operator_funds_addresses[0].script_pubkey(),
            },
            TxOut {
                value: OPERATOR_FUNDS,
                script_pubkey: operator_funds_addresses[1].script_pubkey(),
            },
        ];
        let outputs_funding = vec![
            TxOut {
                value: stake_amount,
                script_pubkey: pre_stake_address.script_pubkey(),
            },
            operator_funds_previous_utxos[0].clone(),
            operator_funds_previous_utxos[1].clone(),
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
        let prevout_funding = TxOut {
            value: coinbase_amount,
            script_pubkey: funded_address.script_pubkey(),
        };
        let signed_funding_tx = sign_tx(&funding_tx, &funded_keypair, prevout_funding.clone());

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
        let stake_0_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(4).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let stake_0_address = Address::p2tr(
            SECP256K1,
            stake_0_keypair.x_only_public_key().0,
            None,
            network,
        );
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
        let pre_stake_output = vec![TxOut {
            value: stake_amount,
            script_pubkey: stake_0_address.script_pubkey(),
        }];
        let pre_stake = PreStakeTx::new(inputs, pre_stake_output.clone(), &prevout);
        let pre_stake_txid = pre_stake.compute_txid();
        let pre_stake_tx = pre_stake.psbt.extract_tx().unwrap();
        // Sign the transaction
        let signed_pre_stake_tx = sign_tx(&pre_stake_tx, &pre_stake_keypair, prevout);

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
        let pre_stake_prevout = TxIn {
            previous_output: OutPoint {
                txid: pre_stake_txid,
                vout: 0,
            },
            ..Default::default()
        };
        trace!(?pre_stake_prevout, "pre-stake prevout");
        let wots_public_keys = [
            wots::Wots256PublicKey::new("0"),
            wots::Wots256PublicKey::new("1"),
        ];
        trace!(?wots_public_keys, "wots public keys");

        let stake_inputs: [StakeTxData; 2] = (0..stake_hashes.len())
            .map(|i| StakeTxData {
                operator_funds: operator_funds[i].previous_output,
                hash: stake_hashes[i],
                withdrawal_fulfillment_pk: wots_public_keys[i],
            })
            .collect::<Vec<StakeTxData>>()
            .try_into()
            .expect("sizes must match");

        let stake_chain_inputs = StakeChainInputs {
            operator_pubkey,
            stake_inputs,
            pre_stake_outpoint: pre_stake_prevout.previous_output,
            params,
        };

        let connector_cpfp = ConnectorCpfp::new(operator_pubkey, network);
        let stake_chain =
            StakeChain::<2>::new(&tx_build_context, &stake_chain_inputs, connector_cpfp);

        // Sign the StakeTx 0
        let prevouts = [
            TxOut {
                value: OPERATOR_FUNDS,
                script_pubkey: operator_funds_addresses[0].script_pubkey(),
            },
            TxOut {
                value: stake_amount,
                script_pubkey: stake_0_address.script_pubkey(),
            },
        ];
        let stake_chain_0_tx = sign_first_stake_tx::<2>(
            &stake_chain,
            &operator_fund_1_keypair,
            &stake_0_keypair,
            prevouts,
        );
        let stake_chain_0_txid = stake_chain_0_tx.compute_txid();
        info!(%stake_chain_0_txid, "StakeTx 0 txid created and signed");

        // Broadcast the StakeTx 0
        let stake_chain_0_txid = btc_client
            .send_raw_transaction(&stake_chain_0_tx)
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

        // Sign the StakeTx 1
        let connector_s = create_connector_stake(
            n_of_n_agg_pubkey,
            operator_pubkey,
            stake_hashes[0],
            delta,
            network,
        );
        let prevouts = [
            outputs_funding[2].clone(),
            TxOut {
                value: stake_amount,
                script_pubkey: connector_s.script_pubkey(),
            },
        ];
        let stake_chain_1_tx = sign_stake_tx::<2>(
            1,
            &stake_chain,
            &operator_fund_2_keypair,
            &operator_keypair,
            prevouts,
            &stake_preimages[0],
            n_of_n_agg_pubkey,
            operator_pubkey,
            delta,
            network,
        );
        let stake_chain_1_txid = stake_chain_1_tx.compute_txid();
        info!(%stake_chain_1_txid, "StakeTx 1 txid created and signed");

        // Broadcast the StakeTx 1 which will error because of the delta relative timelock
        let stake_chain_1_txid = btc_client.send_raw_transaction(&stake_chain_1_tx);
        assert!(stake_chain_1_txid.is_err());

        // Mine the blockchain delta-1 blocks
        info!(%delta, %stake_chain_0_txid, "StakeTx 0 mined and blockchain advanced to spendable delta relative timelock");

        let _ = btc_client
            .generate_to_address((delta.to_consensus_u32() as usize) - 1, &funded_address)
            .expect("must be able to generate blocks");
        let stake_chain_1_txid = btc_client
            .send_raw_transaction(&stake_chain_1_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%stake_chain_1_txid, "StakeTx 1 broadcasted");
    }
}
