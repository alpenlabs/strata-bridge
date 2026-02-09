//! This module contains the staking graph.

use std::num::NonZero;

use bitcoin::{hashes::sha256, relative, Amount, Network, OutPoint, Txid, XOnlyPublicKey};
use strata_bridge_connectors2::{
    n_of_n::NOfNConnector,
    prelude::{UnstakingIntentOutput, UnstakingOutput},
    SigningInfo,
};
use strata_l1_txfmt::MagicBytes;
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::{
    musig_functor::StakeFunctor,
    transactions::{
        prelude::{StakeTx, UnstakingData, UnstakingIntentData, UnstakingIntentTx, UnstakingTx},
        PresignedTx,
    },
};

/// Data that is needed to construct a [`StakeGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeData {
    /// Parameters that are inherent from the protocol.
    pub protocol: ProtocolParams,
    /// Parameters that are known at setup time.
    pub setup: SetupParams,
}

/// Parameters that are known at setup time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupParams {
    /// Used bitcoin network.
    pub network: Network,
    /// Magic bytes that identify the bridge.
    pub magic_bytes: MagicBytes,
    /// Game index.
    pub game_index: NonZero<u32>,
    /// Operator index.
    pub operator_index: u32,
    /// N/N key.
    pub n_of_n_pubkey: XOnlyPublicKey,
    /// Unstaking hash image.
    pub unstaking_image: sha256::Hash,
    /// Descriptor where the operator wants to receive the unstaked funds.
    pub unstaking_operator_descriptor: Descriptor,
    /// UTXO that funds the stake transaction.
    pub stake_funds: OutPoint,
}

/// Parameters that are inherent from the protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolParams {
    /// Timelock for the entire game.
    pub game_timelock: relative::LockTime,
    /// Stake amount.
    pub stake_amount: Amount,
}

/// Collection of the transactions that handle the stake of a given operator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StakeGraph {
    /// Stake transaction.
    stake: StakeTx,
    /// Unstaking intent transaction.
    unstaking_intent: UnstakingIntentTx,
    /// Unstaking transaction.
    unstaking: UnstakingTx,
}

/// Collection of the IDs of all transactions of a [`StakeGraph`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct StakeGraphSummary {
    /// ID of the stake transaction.
    pub stake: Txid,
    /// ID of the unstaking intent transaction.
    pub unstaking_intent: Txid,
    /// ID of the unstaking transaction.
    pub unstaking: Txid,
}

impl StakeGraph {
    /// Creates a new stake graph.
    pub fn new(data: StakeData) -> Self {
        let protocol = data.protocol;
        let setup = data.setup;

        let stake_connector =
            NOfNConnector::new(setup.network, setup.n_of_n_pubkey, protocol.stake_amount);
        let unstaking_intent_output =
            UnstakingIntentOutput::new(setup.network, setup.n_of_n_pubkey, setup.unstaking_image);
        let unstaking_output =
            UnstakingOutput::new(setup.network, setup.n_of_n_pubkey, protocol.game_timelock);

        let stake_data = crate::transactions::stake::StakeData {
            stake_funds: setup.stake_funds,
        };
        let stake = StakeTx::new(stake_data, unstaking_intent_output, stake_connector);

        let unstaking_intent_data = UnstakingIntentData {
            operator_idx: setup.operator_index,
            stake_txid: stake.as_ref().compute_txid(),
            magic_bytes: setup.magic_bytes,
        };
        let unstaking_intent = UnstakingIntentTx::new(
            unstaking_intent_data,
            unstaking_intent_output,
            unstaking_output,
        );

        let unstaking_data = UnstakingData {
            stake_txid: stake.as_ref().compute_txid(),
            unstaking_intent_txid: unstaking_intent.as_ref().compute_txid(),
        };
        let unstaking = UnstakingTx::new(
            unstaking_data,
            unstaking_output,
            stake_connector,
            &setup.unstaking_operator_descriptor,
        );

        Self {
            stake,
            unstaking_intent,
            unstaking,
        }
    }

    /// Summarizes the stake graph.
    pub fn summarize(&self) -> StakeGraphSummary {
        StakeGraphSummary {
            stake: self.stake.as_ref().compute_txid(),
            unstaking_intent: self.unstaking_intent.as_ref().compute_txid(),
            unstaking: self.unstaking.as_ref().compute_txid(),
        }
    }

    /// Generates a functor of the signing infos of each presigned transaction.
    pub fn musig_signing_info(&self) -> StakeFunctor<SigningInfo> {
        StakeFunctor {
            unstaking_intent: self.unstaking_intent.signing_info(),
            unstaking: self.unstaking.signing_info(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::{sha256, Hash},
        relative, Amount, Network, OutPoint, TxOut,
    };
    use secp256k1::{rand::random, Keypair};
    use strata_bridge_connectors2::{
        prelude::{UnstakingIntentOutput, UnstakingIntentWitness},
        test_utils::BitcoinNode,
        Connector,
    };
    use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins};
    use strata_bridge_test_utils::prelude::generate_keypair;
    use strata_primitives::bitcoin_bosd::Descriptor;

    use super::*;

    const GAME_TIMELOCK: relative::LockTime = relative::LockTime::from_height(10);
    const FEE_AMOUNT: Amount = Amount::from_sat(1_000);

    #[derive(Debug)]
    struct Signer {
        pub n_of_n_keypair: Keypair,
        pub unstaking_preimage: [u8; 32],
    }

    impl Signer {
        fn generate() -> Self {
            Signer {
                n_of_n_keypair: generate_keypair(),
                unstaking_preimage: random(),
            }
        }
    }

    fn get_stake_data(node: &mut BitcoinNode, signer: &Signer) -> StakeData {
        let protocol = ProtocolParams {
            game_timelock: GAME_TIMELOCK,
            stake_amount: Amount::from_int_btc(1),
        };
        let wallet_descriptor = Descriptor::try_from(node.wallet_address().clone()).unwrap();
        let mut setup = SetupParams {
            network: Network::Regtest,
            magic_bytes: (*b"ALPN").into(),
            game_index: NonZero::new(1).unwrap(),
            operator_index: 0,
            n_of_n_pubkey: signer.n_of_n_keypair.x_only_public_key().0,
            unstaking_image: sha256::Hash::hash(&signer.unstaking_preimage),
            unstaking_operator_descriptor: wallet_descriptor,
            stake_funds: OutPoint::default(),
        };

        // FIXME: (@uncomputable) Prevent having to recreate the connectors
        let unstaking_intent_output =
            UnstakingIntentOutput::new(setup.network, setup.n_of_n_pubkey, setup.unstaking_image);

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                       Funding Transaction                         │
        // └───────────────────────────────────────────────────────────────────┘
        //
        // inputs         | outputs
        // ---------------+-----------------------------------
        // 50 btc: wallet | 1 btc + ε sat: stake UTXO (wallet)
        //                +-----------------------------------
        //                | 49 btc - ε sat - fee: wallet
        let input = create_tx_ins([node.next_coinbase_outpoint()]);
        let output = vec![
            TxOut {
                value: protocol.stake_amount + unstaking_intent_output.value(),
                script_pubkey: node.wallet_address().script_pubkey(),
            },
            TxOut {
                value: node.coinbase_amount()
                    - protocol.stake_amount
                    - unstaking_intent_output.value()
                    - FEE_AMOUNT,
                script_pubkey: node.wallet_address().script_pubkey(),
            },
        ];
        let funding_tx = create_tx(input, output);
        let funding_txid = node.sign_and_broadcast(&funding_tx);
        node.mine_blocks(1);

        setup.stake_funds = OutPoint {
            txid: funding_txid,
            vout: 0,
        };

        StakeData { protocol, setup }
    }

    #[test]
    fn unstake() {
        let mut node = BitcoinNode::new();
        let signer = Signer::generate();
        let stake_data = get_stake_data(&mut node, &signer);
        let graph = StakeGraph::new(stake_data);
        let presigned = graph
            .musig_signing_info()
            .map(|x| x.sign(&signer.n_of_n_keypair));

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                       Stake Transaction                           │
        // └───────────────────────────────────────────────────────────────────┘
        let child = node.create_cpfp_child(&graph.stake, FEE_AMOUNT * 2);
        let stake = node.sign(graph.stake.as_ref());
        node.submit_package(&[stake, child]);
        node.mine_blocks(1);

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                   Unstaking Intent Transaction                    │
        // └───────────────────────────────────────────────────────────────────┘
        let child = node.create_cpfp_child(&graph.unstaking_intent, FEE_AMOUNT * 2);

        let witness = UnstakingIntentWitness {
            n_of_n_signature: presigned.unstaking_intent[0],
            unstaking_preimage: signer.unstaking_preimage,
        };
        let unstaking_intent = graph.unstaking_intent.finalize(&witness);

        node.submit_package(&[unstaking_intent, child]);
        node.mine_blocks(GAME_TIMELOCK.to_consensus_u32() as usize - 1);

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                      Unstaking Transaction                        │
        // └───────────────────────────────────────────────────────────────────┘
        let child = node.create_cpfp_child(&graph.unstaking, FEE_AMOUNT * 2);
        let unstaking = graph.unstaking.finalize(presigned.unstaking);

        let package = [unstaking, child];
        node.submit_package_invalid(&package);
        node.mine_blocks(1);
        node.submit_package(&package);
    }
}
