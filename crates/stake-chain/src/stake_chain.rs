//! The stake chain is a series of transactions that move the stake from one transaction to the
//! next.

use alpen_bridge_params::stake_chain::StakeChainParams;
use bitcoin::{hashes::sha256, OutPoint, XOnlyPublicKey};
use indexmap::IndexSet;
use strata_bridge_connectors::prelude::ConnectorCpfp;
use strata_bridge_primitives::build_context::BuildContext;

use crate::{
    prelude::StakeTx,
    transactions::stake::{Head, StakeTxData, Tail},
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
/// The stake chain can be advanced forward by revealing a preimage to a locking script and
/// providing the operator's signature, that is also relative timelocked to a certain `ΔS` interval.
///
/// Note that the number of stake transactions in the chain cannot be known at compile-time for all
/// use cases. Therefore for maximum flexibility, this type holds a heap-allocated [`Vec`] of
/// [`StakeTx`] where each successive transaction spends the stake output from the previous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeChain {
    head: Option<StakeTx<Head>>,

    tail: Vec<StakeTx<Tail>>,
}

impl StakeChain {
    /// Creates a new [`StakeChain`] from the provided [`StakeChainInputs`].
    ///
    /// This can be used to recreate a stake chain if the initial set of inputs are known.
    ///
    /// # Parameters
    ///
    /// - `context`: The context to use for building the transactions.
    /// - `stake_chain_inputs`: The inputs to use for creating the stake chain.
    /// - `stake_chain_params`: The parameters to used for creating the stake chain dictated by the
    ///   protocol.
    /// - `connector_cpfp`: The connector to use for CPFP.
    pub fn new(
        context: &impl BuildContext,
        stake_chain_inputs: &StakeChainInputs,
        stake_chain_params: &StakeChainParams,
        connector_cpfp: ConnectorCpfp,
    ) -> Self {
        // Instantiate a vector with the length `M`.
        let stake_inputs = &stake_chain_inputs.stake_inputs;
        let num_inputs = stake_inputs.len();

        if num_inputs == 0 {
            return Self {
                head: None,
                tail: vec![],
            };
        }

        let first_stake_inputs = stake_chain_inputs.stake_inputs[0];

        let first_stake_tx = StakeTx::<Head>::new(
            context,
            stake_chain_params,
            first_stake_inputs.hash,
            first_stake_inputs.withdrawal_fulfillment_pk,
            stake_chain_inputs.pre_stake_outpoint,
            first_stake_inputs.operator_funds,
            stake_chain_inputs.operator_pubkey,
            connector_cpfp,
        );

        if num_inputs == 1 {
            return Self {
                head: Some(first_stake_tx),
                tail: vec![],
            };
        }

        let new_stake_tx = first_stake_tx.advance(
            context,
            stake_chain_params,
            stake_inputs[1],
            stake_chain_inputs.operator_pubkey,
            connector_cpfp,
        );

        let tail = stake_inputs
            .iter()
            .skip(2) // first and the second created above
            .fold(vec![new_stake_tx], |mut tail, stake_input| {
                let new_stake_tx = tail
                    .last()
                    .expect("must have at least one element in every loop because it is initialized with one element")
                    .advance(
                        context,
                        stake_chain_params,
                        *stake_input,
                        stake_chain_inputs.operator_pubkey,
                        connector_cpfp,
                    );

                tail.push(new_stake_tx);

                tail
            });

        Self {
            head: Some(first_stake_tx),
            tail,
        }
    }

    /// Gets the first stake transaction in the chain.
    pub fn head(&self) -> Option<&StakeTx<Head>> {
        self.head.as_ref()
    }

    /// Gets the all the stake transactions in the chain except the first.
    pub fn tail(&self) -> &[StakeTx<Tail>] {
        &self.tail
    }

    /// Gets the length of the stake chain.
    pub fn len(&self) -> usize {
        self.head.as_ref().map(|_| 1 + self.tail.len()).unwrap_or(0)
    }

    /// Checks if the stake chain is empty.
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }
}

/// [`StakeChainInputs`] holds all the necessary data to construct a
/// [`StakeChain`] whose length equals the length of the inputs.
///
/// The data that it needs are:
///
/// 1. Operator's public key.
/// 2. WOTS public keys.
/// 3. Stake hashes.
/// 4. Operator funds to fund the dust values in the tx graph.
/// 5. Pre-stake prevout.
/// 6. Pre-stake utxo.
/// 7. Stake Chain protocol parameters:
///    1. Stake amount.
///    2. `ΔS` relative timelock interval.
///
///
/// The WOTS public keys, stake hashes, and operator funds are needed to
/// construct the transaction graph for the corresponding deposit to be claimed while using and
/// advancing the [`StakeChain`].
///
/// The staking amount and `ΔS` relative timelock interval are consensus parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeChainInputs {
    /// Operator's public key.
    pub operator_pubkey: XOnlyPublicKey,

    /// Inputs required for individual stake transactions.
    pub stake_inputs: IndexSet<StakeTxData>,

    /// [`OutPoint`] from the [`PreStakeTx`](crate::transactions::PreStakeTx) that carries the
    /// stake.
    pub pre_stake_outpoint: OutPoint,
}

impl StakeChainInputs {
    /// Stake hashes for all the [`StakeChainInputs`]s.
    ///
    /// The stake hashes are used to derive the locking script and must be shared with between
    /// operators so that each operator can compute the transactions deterministically.
    ///
    /// If you only need the stake hash for a single stake, use
    /// [`StakeChainInputs::stake_hash_at_index`].
    pub fn stake_hashes(&self) -> impl IntoIterator<Item = sha256::Hash> + use<'_> {
        self.stake_inputs.iter().map(|input| input.hash)
    }

    /// Stake hash for the [`StakeChainInputs`] at the given index.
    ///
    /// The stake hashes are used to derive the locking script and must be shared with between
    /// operators so that each operator can compute the transactions deterministically.
    ///
    /// If you need the stake hash for all the stakes, use [`StakeChainInputs::stake_hashes`].
    pub fn stake_hash_at_index(&self, index: usize) -> Option<sha256::Hash> {
        self.stake_inputs.iter().nth(index).map(|v| v.hash)
    }

    /// Operator funds for all the [`StakeChainInputs`]s.
    ///
    /// The operator funds are the inputs to cover the dust outputs for the entirety of the
    /// [`StakeChainInputs`]s.
    ///
    /// If you only need the operator funds for a single stake, use
    /// [`StakeChainInputs::operator_funds_at_index`] since it vastly reduces the allocations.
    ///
    /// # Panics
    ///
    /// If the index is out of bounds.
    pub fn operator_funds(&self) -> impl IntoIterator<Item = OutPoint> + use<'_> {
        self.stake_inputs.iter().map(|input| input.operator_funds)
    }

    /// Operator funds for the [`StakeChainInputs`] at the given index.
    ///
    /// The operator funds are the inputs to cover the dust outputs for the entirety of the
    /// [`StakeChainInputs`]s.
    ///
    /// If you need the operator funds for all the stakes, use [`StakeChainInputs::operator_funds`].
    pub fn operator_funds_at_index(&self, index: usize) -> Option<OutPoint> {
        self.stake_inputs
            .iter()
            .nth(index)
            .map(|v| v.operator_funds)
    }

    /// Prevout of the first stake transaction.
    pub fn pre_stake_prevout(&self) -> OutPoint {
        self.pre_stake_outpoint
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use bitcoin::{
        absolute,
        bip32::{ChildNumber, Xpriv},
        hashes::{sha256d, Hash},
        key::{Keypair, TapTweak},
        relative,
        sighash::{self, Prevouts, SighashCache},
        transaction, Address, Amount, BlockHash, Network, OutPoint, Transaction, TxIn, TxOut, Txid,
    };
    use corepc_node::{Conf, Node};
    use secp256k1::{generate_keypair, rand::rngs::OsRng, Message, SECP256K1};
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_connectors::prelude::ConnectorStake;
    use strata_bridge_primitives::{build_context::TxBuildContext, wots};
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
        let signature = SECP256K1.sign_schnorr(&message, keypair);
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
    fn sign_first_stake_tx(
        stake_chain: &StakeChain,
        keypair_operator_funds: &Keypair,
        keypair_pre_stake: &Keypair,
        stake_amount: Amount,
        prevouts: [TxOut; 2],
    ) -> Transaction {
        let messages = stake_chain.head().unwrap().sighashes(
            stake_amount,
            prevouts.clone().map(|prevout| prevout.script_pubkey),
        );

        let funds_signature = SECP256K1.sign_schnorr(&messages[0], keypair_operator_funds);
        trace!(%funds_signature, "Signature stake_tx operator funds");

        let pre_stake_signature = SECP256K1.sign_schnorr(&messages[1], keypair_pre_stake);
        trace!(%pre_stake_signature, "Signature stake_tx operator funds");

        stake_chain
            .head()
            .unwrap()
            .clone()
            .finalize_unchecked(funds_signature, pre_stake_signature)
    }

    /// Signs a [`StakeTx`], i.e. `StakeChain::[x]` given an index.
    ///
    /// The prevouts must be the following:
    ///
    /// 1. An operator fund prevout that has value [`OPERATOR_FUNDS`] and is a simple P2TR key path
    ///    spend.
    /// 2. A connector `s` that is a P2TR script path spend.
    ///
    /// # Panics
    ///
    /// If the index is out of bounds.
    #[expect(clippy::too_many_arguments)]
    fn sign_stake_tx(
        index: usize,
        stake_chain: &StakeChain,
        keypair_operator_funds: &Keypair,
        keypair_connector_s: &Keypair,
        prevouts: [TxOut; 2],
        stake_preimage: &[u8; 32],
        n_of_n_pubkey: XOnlyPublicKey,
        operator_pubkey: XOnlyPublicKey,
        delta: relative::LockTime,
        network: Network,
    ) -> Transaction {
        // OPERATOR_FUNDS witness (key path spend)
        // CATCH: if is the first stake, then we panic!
        if index == 0 {
            panic!("The first stake must be signed using another function");
        }

        let stake_hash = sha256::Hash::hash(stake_preimage);
        // The key path spend for the first input
        let stake_tx = stake_chain.tail()[index - 1].clone();
        // Recreate the connector s.
        let connector_s =
            ConnectorStake::new(n_of_n_pubkey, operator_pubkey, stake_hash, delta, network);
        // Create the prevouts

        let messages = stake_tx.sighashes(prevouts[0].script_pubkey.clone());

        let funds_signature = SECP256K1.sign_schnorr(&messages[0], keypair_operator_funds);

        trace!(%index, %funds_signature, "Signature stake_tx operator funds");

        // Sign the transaction with operator key
        let stake_signature = SECP256K1.sign_schnorr(&messages[1], keypair_connector_s);
        trace!(%index, %stake_signature, "Signature stake_tx connector s");
        // Construct the witness stack

        stake_tx.finalize_unchecked(
            stake_preimage,
            funds_signature,
            stake_signature,
            connector_s,
        )
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
        let funded_address = Address::p2tr_tweaked(
            funded_keypair
                .x_only_public_key()
                .0
                .dangerous_assume_tweaked(),
            network,
        );
        let change_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(1).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let change_address = Address::p2tr_tweaked(
            change_keypair
                .x_only_public_key()
                .0
                .dangerous_assume_tweaked(),
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

        // Create the StakeParams
        let params = StakeChainParams::default();
        let delta = params.delta;
        let stake_amount = params.stake_amount;

        // Create funding transaction
        let pre_stake_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(2).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let pre_stake_address = Address::p2tr_tweaked(
            pre_stake_keypair
                .x_only_public_key()
                .0
                .dangerous_assume_tweaked(),
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
        // 3 OPERATOR_FUNDS outputs:
        let operator_fund_1_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(3).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let operator_fund_1_address = Address::p2tr_tweaked(
            operator_fund_1_keypair
                .x_only_public_key()
                .0
                .dangerous_assume_tweaked(),
            network,
        );
        let operator_fund_2_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(4).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let operator_fund_2_address = Address::p2tr_tweaked(
            operator_fund_2_keypair
                .x_only_public_key()
                .0
                .dangerous_assume_tweaked(),
            network,
        );
        let operator_fund_3_keypair = xpriv
            .derive_priv(SECP256K1, &[ChildNumber::from_hardened_idx(5).unwrap()])
            .unwrap()
            .to_keypair(SECP256K1);
        let operator_fund_3_address = Address::p2tr_tweaked(
            operator_fund_3_keypair
                .x_only_public_key()
                .0
                .dangerous_assume_tweaked(),
            network,
        );
        let operator_funds_addresses = [
            operator_fund_1_address,
            operator_fund_2_address,
            operator_fund_3_address,
        ];
        let operator_funds_previous_utxos = [
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
        ];
        let outputs_funding = vec![
            TxOut {
                value: stake_amount,
                script_pubkey: pre_stake_address.script_pubkey(),
            },
            operator_funds_previous_utxos[0].clone(),
            operator_funds_previous_utxos[1].clone(),
            operator_funds_previous_utxos[2].clone(),
            TxOut {
                value: coinbase_amount
                    - stake_amount
                    - fees
                    - OPERATOR_FUNDS * operator_funds_previous_utxos.len() as u64,
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
        let stake_0_address = Address::p2tr_tweaked(
            stake_0_keypair
                .x_only_public_key()
                .0
                .dangerous_assume_tweaked(),
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
        let stake_preimages = [[0u8; 32], [1u8; 32], [2u8; 32]];
        trace!(?stake_preimages, "stake preimages");
        let stake_hashes = [
            sha256::Hash::hash(&stake_preimages[0]),
            sha256::Hash::hash(&stake_preimages[1]),
            sha256::Hash::hash(&stake_preimages[2]),
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
            TxIn {
                previous_output: OutPoint {
                    txid: funding_txid,
                    vout: 3,
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
            wots::Wots256PublicKey::new("0", pre_stake_txid),
            wots::Wots256PublicKey::new("1", pre_stake_txid),
            wots::Wots256PublicKey::new("2", pre_stake_txid),
        ];
        trace!(?wots_public_keys, "wots public keys");

        let stake_inputs = (0..stake_hashes.len())
            .map(|i| StakeTxData {
                operator_funds: operator_funds[i].previous_output,
                hash: stake_hashes[i],
                withdrawal_fulfillment_pk: wots_public_keys[i],
            })
            .collect();

        let stake_chain_inputs = StakeChainInputs {
            operator_pubkey,
            stake_inputs,
            pre_stake_outpoint: pre_stake_prevout.previous_output,
        };

        let connector_cpfp = ConnectorCpfp::new(operator_pubkey, network);
        let stake_chain = StakeChain::new(
            &tx_build_context,
            &stake_chain_inputs,
            &params,
            connector_cpfp,
        );

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
        let stake_chain_0_tx = sign_first_stake_tx(
            &stake_chain,
            &operator_fund_1_keypair,
            &stake_0_keypair,
            stake_amount,
            prevouts,
        );
        let stake_chain_0_txid = stake_chain_0_tx.compute_txid();
        info!(%stake_chain_0_txid, ?stake_chain_0_tx, "StakeTx 0 txid created and signed");

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
        let stake_chain_1_tx = sign_stake_tx(
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
        info!(%delta, %stake_chain_0_txid, "mine some blocks before broadcasting stake 1 tx");

        let _ = btc_client
            .generate_to_address(delta.to_consensus_u32() as usize, &funded_address)
            .expect("must be able to generate blocks");
        let stake_chain_1_txid = btc_client
            .send_raw_transaction(&stake_chain_1_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%stake_chain_1_txid, "StakeTx 1 broadcasted");

        let connector_s = create_connector_stake(
            n_of_n_agg_pubkey,
            operator_pubkey,
            stake_hashes[1],
            delta,
            network,
        );
        let prevouts = [
            outputs_funding[3].clone(),
            TxOut {
                value: stake_amount,
                script_pubkey: connector_s.script_pubkey(),
            },
        ];
        let stake_chain_2_tx = sign_stake_tx(
            2,
            &stake_chain,
            &operator_fund_3_keypair,
            &operator_keypair,
            prevouts,
            &stake_preimages[1],
            n_of_n_agg_pubkey,
            operator_pubkey,
            delta,
            network,
        );

        let stake_chain_2_txid = stake_chain_2_tx.compute_txid();
        info!(%stake_chain_2_txid, "StakeTx 2 txid created and signed");

        // Broadcast the StakeTx 1 which will error because of the delta relative timelock
        let stake_chain_2_txid = btc_client.send_raw_transaction(&stake_chain_2_tx);
        assert!(
            stake_chain_2_txid.is_err(),
            "must not be able to send raw transaction due to timelock",
        );

        // Mine the blockchain delta-1 blocks
        info!(%delta, %stake_chain_0_txid, "StakeTx 1 mined and blockchain advanced to spendable delta relative timelock");

        btc_client
            .generate_to_address(delta.to_consensus_u32() as usize, &funded_address)
            .expect("must be able to generate blocks");

        let stake_chain_2_txid = btc_client
            .send_raw_transaction(&stake_chain_2_tx)
            .expect("must be able to broadcast stake tx 2 after timelock")
            .txid()
            .expect("must have txid");

        info!(%stake_chain_2_txid, "StakeTx 2 broadcasted");
    }

    #[test]
    fn bench_stake_chain_generation() {
        logging::init(LoggerConfig::new(
            "bench_stake_chain_generation".to_string(),
        ));

        const STAKE_CHAIN_SIZE: usize = 100;
        const ITER: usize = 10;

        let mut total_time = Duration::from_secs(0);

        for i in 0..ITER {
            info!(iteration = i, "generating stake chain");
            let (_sk, pk) = generate_keypair(&mut OsRng);
            let pubkeys = BTreeMap::from([(0, pk)]);

            let build_context = TxBuildContext::new(Network::Regtest, pubkeys.into(), 0);
            let connector_cpfp = ConnectorCpfp::new(pk.x_only_public_key().0, Network::Regtest);
            let stake_chain_inputs = StakeChainInputs {
                operator_pubkey: pk.x_only_public_key().0,
                stake_inputs: [StakeTxData {
                    operator_funds: OutPoint::null(),
                    hash: sha256::Hash::hash(&[0; 32]),
                    withdrawal_fulfillment_pk: wots::Wots256PublicKey::new(
                        "0",
                        Txid::from_raw_hash(sha256d::Hash::hash(&[0; 32])),
                    ),
                }; STAKE_CHAIN_SIZE]
                    .into_iter()
                    .collect(),
                pre_stake_outpoint: OutPoint::null(),
            };
            info!(size = %stake_chain_inputs.stake_inputs.len(), "generated stake chain inputs");

            info!("generating stake chain");
            let start_time = std::time::Instant::now();
            let stake_chain = StakeChain::new(
                &build_context,
                &stake_chain_inputs,
                &StakeChainParams::default(),
                connector_cpfp,
            );
            let stop_time = std::time::Instant::now();

            let elapsed_time = stop_time.duration_since(start_time);
            info!(?elapsed_time, size=%stake_chain.len(), "StakeChain generated");

            total_time += elapsed_time;
        }

        let average_time = total_time.checked_div(ITER as u32).unwrap();
        info!(
            ?average_time,
            size = STAKE_CHAIN_SIZE,
            "average time to generate stake chain"
        );
    }
}
