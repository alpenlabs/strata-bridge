//! Constructs the slash stake transaction.

use alpen_bridge_params::prelude::StakeChainParams;
use bitcoin::{
    psbt::PsbtSighashType, sighash::Prevouts, taproot, Amount, Network, OutPoint, Psbt,
    TapSighashType, Transaction, TxOut,
};
use secp256k1::schnorr;
use strata_bridge_connectors::prelude::{ConnectorNOfN, ConnectorStake, StakeSpendPath};
use strata_bridge_primitives::{
    constants::SEGWIT_MIN_AMOUNT,
    scripts::{
        prelude::{create_tx, create_tx_ins},
        taproot::{create_taproot_addr, SpendPath, TaprootWitness},
    },
};
use strata_primitives::constants::UNSPENDABLE_PUBLIC_KEY;

use super::prelude::CovenantTx;

/// The metadata required to construct a slash stake transaction.
#[derive(Debug, Clone)]
pub struct SlashStakeData {
    /// The outpoint of the stake transaction to be slashed.
    pub stake_outpoint: OutPoint,

    /// The outpoint of the claim transaction.
    pub claim_outpoint: OutPoint,

    /// The bitcoin network on which the transaction is to be constructed.
    pub network: Network,
}

/// The number of inputs that require an $N$-of-$N$ signature in the [`SlashStakeTx`].
pub const NUM_SLASH_STAKE_INPUTS: usize = 2;

/// The transaction used to slash an operator's stake.
///
/// The purpose of this transaction is to penalize advancing the stake chain without having fully
/// executed any previous claims.
#[derive(Debug, Clone)]
pub struct SlashStakeTx {
    psbt: Psbt,

    prevouts: [TxOut; NUM_SLASH_STAKE_INPUTS],

    witnesses: [TaprootWitness; NUM_SLASH_STAKE_INPUTS],
}

impl SlashStakeTx {
    /// Creates a new instance of the slash stake transaction.
    ///
    /// The transaction has two inputs: one from the claim transaction (via [``]) and one from the
    /// stake transaction (via [`ConnectorStake`]).
    pub fn new(
        data: SlashStakeData,
        stake_chain_params: StakeChainParams,
        claim_out_conn: ConnectorNOfN,
        stake_conn: ConnectorStake,
    ) -> Self {
        let utxos = [data.claim_outpoint, data.stake_outpoint];

        let tx_ins = create_tx_ins(utxos);

        let (burn_address, _) = create_taproot_addr(
            &data.network,
            SpendPath::KeySpend {
                internal_key: *UNSPENDABLE_PUBLIC_KEY,
            },
        )
        .expect("must be able to create taproot address");

        // Two outputs are required because we need two `SIGHASH_SINGLE` inputs.
        let tx_outs = vec![
            TxOut {
                value: SEGWIT_MIN_AMOUNT,
                script_pubkey: burn_address.script_pubkey(),
            },
            TxOut {
                value: stake_chain_params.burn_amount - SEGWIT_MIN_AMOUNT,
                script_pubkey: burn_address.script_pubkey(),
            },
        ];

        let unsigned_tx = create_tx(tx_ins, tx_outs);
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("transaction must be unsigned");

        let claim_out_script = claim_out_conn.create_taproot_address().script_pubkey();
        let claim_out_amount = claim_out_script.minimal_non_dust();
        let prevouts = [
            TxOut {
                value: claim_out_amount,
                script_pubkey: claim_out_script,
            },
            TxOut {
                value: stake_chain_params.stake_amount,
                script_pubkey: stake_conn.generate_address().script_pubkey(),
            },
        ];

        let tweak = stake_conn.generate_merkle_root();
        let witnesses = [TaprootWitness::Key, TaprootWitness::Tweaked { tweak }];

        psbt.inputs
            .iter_mut()
            .zip(prevouts.iter())
            .for_each(|(input, prevout)| {
                input.witness_utxo = Some(prevout.clone());
                input.sighash_type = Some(PsbtSighashType::from(TapSighashType::Single));
            });

        Self {
            psbt,
            prevouts,
            witnesses,
        }
    }

    /// Finalizes the transaction.
    pub fn finalize(
        mut self,
        claim_sig: schnorr::Signature,
        stake_sig: schnorr::Signature,
        claim_out_conn: ConnectorNOfN,
        stake_conn: ConnectorStake,
    ) -> Transaction {
        let claim_sig = taproot::Signature {
            signature: claim_sig,
            sighash_type: TapSighashType::Single,
        };

        let stake_sig = taproot::Signature {
            signature: stake_sig,
            sighash_type: TapSighashType::Single,
        };

        claim_out_conn.finalize_input(self.psbt_mut().inputs.first_mut().unwrap(), claim_sig);

        let stake_spend_witness = StakeSpendPath::SlashStake(stake_sig);
        stake_conn.finalize_input(
            self.psbt_mut().inputs.get_mut(1).unwrap(),
            stake_spend_witness,
        );

        // don't check for fees because this SIGHASH_SINGLE transaction where the final output will
        // be added later.
        self.psbt.extract_tx_unchecked_fee_rate()
    }
}

impl CovenantTx<NUM_SLASH_STAKE_INPUTS> for SlashStakeTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness; 2] {
        &self.witnesses
    }

    fn input_amount(&self) -> Amount {
        self.psbt
            .inputs
            .iter()
            .map(|input| input.witness_utxo.as_ref().unwrap().value)
            .sum()
    }

    fn compute_txid(&self) -> bitcoin::Txid {
        self.psbt.unsigned_tx.compute_txid()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use alpen_bridge_params::prelude::StakeChainParams;
    use bitcoin::{
        hashes::{self, Hash},
        sighash::SighashCache,
        Amount, Network, OutPoint, TxOut,
    };
    use corepc_node::{Conf, Node};
    use secp256k1::rand::{rngs::OsRng, Rng};
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_connectors::prelude::{ConnectorNOfN, ConnectorStake};
    use strata_bridge_primitives::{
        build_context::{BuildContext, TxBuildContext},
        scripts::{
            prelude::{create_tx, create_tx_ins, create_tx_outs},
            taproot::create_message_hash,
        },
    };
    use strata_bridge_test_utils::{
        bitcoin_rpc::fund_and_sign_raw_tx,
        musig2::generate_agg_signature,
        prelude::{generate_keypair, get_funding_utxo_exact},
    };
    use tracing::info;

    use super::{SlashStakeData, SlashStakeTx};
    use crate::transactions::prelude::CovenantTx;

    #[test]
    fn test_slash_stake() {
        logging::init(LoggerConfig::new("test-slash-stake".to_string()));

        let keypair = generate_keypair();
        let operator_pubkey = keypair.x_only_public_key().0;
        let operator_pubkeys = BTreeMap::from([(0, keypair.public_key().into())]);

        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::with_conf("bitcoind", &conf).unwrap();
        let btc_client = &bitcoind.client;

        let wallet_addr = btc_client.new_address().unwrap();
        btc_client.generate_to_address(101, &wallet_addr).unwrap();

        let network = btc_client.get_blockchain_info().unwrap().chain;
        let network = Network::from_str(&network).unwrap();

        let build_context = TxBuildContext::new(network, operator_pubkeys.into(), 0);
        let n_of_n_agg_pubkey = build_context.aggregated_pubkey();

        let n_of_n_connector = ConnectorNOfN::new(n_of_n_agg_pubkey, network);
        let stake_preimage: [u8; 32] = OsRng.gen();
        let stake_hash = hashes::sha256::Hash::hash(&stake_preimage);
        let stake_chain_params = StakeChainParams::default();
        let delta = stake_chain_params.delta;

        let stake_connector = ConnectorStake::new(
            n_of_n_agg_pubkey,
            operator_pubkey,
            stake_hash,
            delta,
            network,
        );

        // create a transaction with some output that can be used in the slash stake transaction.
        let n_of_n_addr_script = n_of_n_connector.create_taproot_address().script_pubkey();
        let n_of_n_addr_amt = n_of_n_addr_script.minimal_non_dust();
        let scripts_and_amounts = [
            (n_of_n_addr_script, n_of_n_addr_amt),
            (
                stake_connector.generate_address().script_pubkey(),
                stake_chain_params.stake_amount,
            ),
        ];
        let tx_outs = create_tx_outs(scripts_and_amounts);

        let total_amount = tx_outs.iter().map(|tx_out| tx_out.value).sum();
        let (_funding_utxo, funding_outpoint) = get_funding_utxo_exact(btc_client, total_amount);
        let tx_ins = create_tx_ins([funding_outpoint]);

        let claim_stake_mock = create_tx(tx_ins, tx_outs);

        let signed_claim_stake_mock =
            fund_and_sign_raw_tx(btc_client, &claim_stake_mock, None, Some(true));

        info!(action = "broadcasting transaction with claim and stake outputs", ?signed_claim_stake_mock, txid = %signed_claim_stake_mock.compute_txid());
        btc_client
            .send_raw_transaction(&signed_claim_stake_mock)
            .unwrap();

        btc_client.generate_to_address(6, &wallet_addr).unwrap();
        let claim_stake_mock_txid = signed_claim_stake_mock.compute_txid();

        let slash_stake_data = SlashStakeData {
            claim_outpoint: OutPoint {
                txid: claim_stake_mock_txid,
                vout: 0,
            },
            stake_outpoint: OutPoint {
                txid: claim_stake_mock_txid,
                vout: 1,
            },
            network,
        };
        let slash_stake_tx = SlashStakeTx::new(
            slash_stake_data,
            stake_chain_params,
            n_of_n_connector,
            stake_connector.clone(),
        );

        let raw_slash_stake_tx = slash_stake_tx.psbt().unsigned_tx.clone();
        let mut sighash_cache = SighashCache::new(&raw_slash_stake_tx);
        let prevouts = slash_stake_tx.prevouts();

        let claim_input_index = 0;
        let claim_witness = &slash_stake_tx.witnesses()[claim_input_index];

        let stake_input_index = 1;
        let stake_witness = &slash_stake_tx.witnesses()[stake_input_index];

        let claim_input_hash = create_message_hash(
            &mut sighash_cache,
            prevouts.clone(),
            claim_witness,
            slash_stake_tx.psbt().inputs[claim_input_index]
                .sighash_type
                .expect("SIGHASH type must be set")
                .taproot_hash_ty()
                .unwrap(),
            claim_input_index,
        )
        .unwrap();

        let stake_input_hash = create_message_hash(
            &mut sighash_cache,
            prevouts,
            stake_witness,
            slash_stake_tx.psbt().inputs[stake_input_index]
                .sighash_type
                .expect("SIGHASH type must be set")
                .taproot_hash_ty()
                .unwrap(),
            stake_input_index,
        )
        .unwrap();

        let claim_input_sig = generate_agg_signature(&claim_input_hash, &keypair, claim_witness);
        let stake_input_sig = generate_agg_signature(&stake_input_hash, &keypair, stake_witness);

        let mut signed_slash_stake_tx = slash_stake_tx.finalize(
            claim_input_sig,
            stake_input_sig,
            n_of_n_connector,
            stake_connector,
        );

        info!(
            event = "created signed slash stake transaction",
            ?signed_slash_stake_tx
        );

        info!(action = "adding output to signed slash stake transaction");
        let slash_stake_reward = Amount::from_sat(199_999_000); // 2 BTC - 1000 sats
        signed_slash_stake_tx.output.push(TxOut {
            value: slash_stake_reward,
            script_pubkey: wallet_addr.script_pubkey(),
        });

        info!(
            action = "broadcasting signed slash stake transaction with reward output",
            ?signed_slash_stake_tx
        );
        btc_client
            .send_raw_transaction(&signed_slash_stake_tx)
            .expect("must be able to broadcast signed slash stake transaction after adding output");
    }
}
