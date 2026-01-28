//! This module contains the game graph,
//! which is the collection of the transactions of a game.

use std::{array, num::NonZero};

use bitcoin::{hashes::sha256, relative, Amount, Network, OutPoint, Txid, XOnlyPublicKey};
use strata_bridge_connectors2::{
    prelude::{
        ClaimContestConnector, ClaimPayoutConnector, ContestCounterproofOutput,
        ContestPayoutConnector, ContestProofConnector, ContestSlashConnector,
        CounterproofConnector, NOfNConnector,
    },
    SigningInfo,
};
use strata_l1_txfmt::MagicBytes;
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::{
    musig_functor::{GameFunctor, WatchtowerFunctor},
    transactions::{
        prelude::{
            BridgeProofTimeoutData, BridgeProofTimeoutTx, ClaimData, ClaimTx, ContestData,
            ContestTx, ContestedPayoutData, ContestedPayoutTx, CounterproofAckData,
            CounterproofAckTx, CounterproofData, CounterproofTx, SlashData, SlashTx,
            UncontestedPayoutData, UncontestedPayoutTx,
        },
        PresignedTx,
    },
};

/// Data that is needed to construct a [`GameGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameData {
    /// Parameters that are inherent from the protocol.
    pub protocol: ProtocolParams,
    /// Parameters that are known at setup time.
    pub setup: SetupParams,
    /// Parameters that are known at deposit time.
    pub deposit: DepositParams,
}

/// Parameters that are known at deposit time.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DepositParams {
    /// UTXO that funds the claim transaction.
    pub claim_funds: OutPoint,
    /// UTXO that holds the deposit.
    pub deposit_outpoint: OutPoint,
    /// UTXO that holds the stake.
    pub stake_outpoint: OutPoint,
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
    /// Collection of public keys and hash images.
    pub keys: KeyData,
}

/// Collection of all public keys and hash images that are used in the game graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyData {
    /// N/N key.
    pub n_of_n_pubkey: XOnlyPublicKey,
    /// Operator key.
    pub operator_pubkey: XOnlyPublicKey,
    /// For each watchtower, a key to authorize the contest.
    pub watchtower_pubkeys: Vec<XOnlyPublicKey>,
    /// Admin key.
    pub admin_pubkey: XOnlyPublicKey,
    /// Unstaking hash image.
    pub unstaking_image: sha256::Hash,
    /// For each watchtower, a fault key from Mosaic.
    pub wt_fault_pubkeys: Vec<XOnlyPublicKey>,
    /// Descriptor where the operator wants to receive the payout.
    pub payout_operator_descriptor: Descriptor,
    /// For each watchtower, a descriptor where to receive the slashed stake.
    pub slash_watchtower_descriptors: Vec<Descriptor>,
}

/// Parameters that are inherent from the protocol.
///
/// These parameters don't need to be actively shared.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolParams {
    /// Timelock for contesting a claim.
    pub contest_timelock: relative::LockTime,
    /// Timelock for submitting a bridge proof.
    pub proof_timelock: relative::LockTime,
    /// Timelock for ACK-ing a counterproof.
    pub ack_timelock: relative::LockTime,
    /// Timelock for NACK-ing a counterproof.
    pub nack_timelock: relative::LockTime,
    /// Timelock for submitting a contested payout.
    pub contested_payout_timelock: relative::LockTime,
    /// Number of bytes for the serialized counterproof (including public values).
    pub counterproof_n_bytes: NonZero<usize>,
    /// Deposit amount.
    pub deposit_amount: Amount,
    /// Stake amount.
    pub stake_amount: Amount,
}

/// Collection of the transactions of a game.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GameGraph {
    /// Claim transaction.
    pub claim: ClaimTx,
    /// Uncontested payout transaction.
    pub uncontested_payout: UncontestedPayoutTx,
    /// Contest transaction.
    pub contest: ContestTx,
    /// Bridge proof timeout transaction.
    pub bridge_proof_timeout: BridgeProofTimeoutTx,
    /// Counterproof graph of each watchtower.
    pub counterproofs: Vec<CounterproofGraph>,
    /// Contested payout transaction.
    pub contested_payout: ContestedPayoutTx,
    /// Slash transaction.
    pub slash: SlashTx,
}

/// Collection of presigned transactions for the counterproof of a single watchtower.
///
/// The graph is replicated for each watchtower.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CounterproofGraph {
    /// Counterproof transaction.
    pub counterproof: CounterproofTx,
    /// Counterproof ACK transaction.
    pub counterproof_ack: CounterproofAckTx,
}

/// Collection of the IDs of all transactions of a [`GameGraph`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GameGraphSummary {
    /// ID of the claim transaction.
    pub claim: Txid,
    /// ID of the contest transaction.
    pub contest: Txid,
    /// ID of the bridge proof timeout transaction.
    pub bridge_proof_timeout: Txid,
    /// Summary of the counterproof graph of each watchtower.
    pub counterproofs: Vec<CounterproofGraphSummary>,
    /// ID of the slash transaction.
    pub slash: Txid,
}

/// Collection of the IDs of all transactions of a [`CounterproofGraph`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CounterproofGraphSummary {
    /// ID of the counterproof transaction.
    pub counterproof: Txid,
    /// ID of the counterproof ACK transaction.
    pub counterproof_ack: Txid,
}

/// Collection of all connectors that exist in a game.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GameConnectors {
    /// Claim contest connector.
    pub claim_contest: ClaimContestConnector,
    /// Claim payout connector.
    pub claim_payout: ClaimPayoutConnector,
    /// Deposit connector.
    pub deposit: NOfNConnector,
    /// Contest proof connector.
    pub contest_proof: ContestProofConnector,
    /// Contest payout connector.
    pub contest_payout: ContestPayoutConnector,
    /// Contest slash connector.
    pub contest_slash: ContestSlashConnector,
    /// Contest counterproof output.
    pub contest_counterproof: ContestCounterproofOutput,
    /// Counterproof connectors for each watchtower.
    pub counterproof: Vec<CounterproofConnector>,
    /// Stake connector.
    pub stake: NOfNConnector,
}

impl GameGraph {
    /// Creates a new game graph.
    ///
    /// # Panics
    ///
    /// This method panics if the number of watchtowers is inconsistent.
    /// The following need to be equal:
    /// - The number of watchtower public keys.
    /// - The number of watchtower fault keys.
    /// - The number of watchtower slash descriptors.
    ///
    /// This method also panics if the number of watchtowers is greater than [`u32::MAX`].
    pub fn new(data: GameData) -> (Self, GameConnectors) {
        let protocol = data.protocol;
        let setup = data.setup;
        let keys = &setup.keys;
        let deposit = data.deposit;

        assert_eq!(
            keys.watchtower_pubkeys.len(),
            keys.wt_fault_pubkeys.len(),
            "inconsistent number of watchtowers"
        );
        assert_eq!(
            keys.watchtower_pubkeys.len(),
            keys.slash_watchtower_descriptors.len(),
            "inconsistent number of watchtowers"
        );
        // cast safety: 32-bit arch or higher
        assert!(
            keys.watchtower_pubkeys.len() <= u32::MAX as usize,
            "too many watchtowers"
        );

        let connectors = GameConnectors::new(&protocol, &setup);

        let claim_data = ClaimData {
            claim_funds: deposit.claim_funds,
        };
        let claim = ClaimTx::new(
            claim_data,
            connectors.claim_contest.clone(),
            connectors.claim_payout,
        );

        let uncontested_payout_data = UncontestedPayoutData {
            claim_txid: claim.as_ref().compute_txid(),
            deposit_outpoint: deposit.deposit_outpoint,
        };
        let uncontested_payout = UncontestedPayoutTx::new(
            uncontested_payout_data,
            connectors.deposit,
            connectors.claim_contest.clone(),
            connectors.claim_payout,
            &keys.payout_operator_descriptor,
        );

        let contest_data = ContestData {
            claim_txid: claim.as_ref().compute_txid(),
        };
        let contest = ContestTx::new(
            contest_data,
            connectors.claim_contest.clone(),
            connectors.contest_proof,
            connectors.contest_payout,
            connectors.contest_slash,
            connectors.contest_counterproof,
        );

        let bridge_proof_timeout_data = BridgeProofTimeoutData {
            contest_txid: contest.as_ref().compute_txid(),
        };
        let bridge_proof_timeout = BridgeProofTimeoutTx::new(
            bridge_proof_timeout_data,
            connectors.contest_proof,
            connectors.contest_payout,
        );

        let counterproofs: Vec<_> = connectors
            .counterproof
            .iter()
            .copied()
            .enumerate()
            .map(|(watchtower_index, counterproof_connector)| {
                // cast safety: asserted above that len(watchtowers) <= u32::MAX
                let counterproof_data = CounterproofData {
                    contest_txid: contest.as_ref().compute_txid(),
                    watchtower_index: watchtower_index as u32,
                };
                let counterproof = CounterproofTx::new(
                    counterproof_data,
                    connectors.contest_counterproof,
                    counterproof_connector,
                );

                let counterproof_ack_data = CounterproofAckData {
                    counterproof_txid: counterproof.as_ref().compute_txid(),
                    contest_txid: contest.as_ref().compute_txid(),
                };
                let counterproof_ack = CounterproofAckTx::new(
                    counterproof_ack_data,
                    counterproof_connector,
                    connectors.contest_payout,
                );

                CounterproofGraph {
                    counterproof,
                    counterproof_ack,
                }
            })
            .collect();

        let contested_payout_data = ContestedPayoutData {
            deposit_outpoint: deposit.deposit_outpoint,
            claim_txid: claim.as_ref().compute_txid(),
            contest_txid: contest.as_ref().compute_txid(),
        };
        let contested_payout = ContestedPayoutTx::new(
            contested_payout_data,
            connectors.deposit,
            connectors.claim_payout,
            connectors.contest_payout,
            connectors.contest_slash,
            &keys.payout_operator_descriptor,
        );

        let slash_data = SlashData {
            operator_idx: setup.operator_index,
            contest_txid: contest.as_ref().compute_txid(),
            stake_outpoint: deposit.stake_outpoint,
            magic_bytes: setup.magic_bytes,
        };
        let slash = SlashTx::new(
            slash_data,
            connectors.contest_slash,
            connectors.stake,
            &keys.slash_watchtower_descriptors,
        );

        let game_graph = Self {
            claim,
            uncontested_payout,
            contest,
            bridge_proof_timeout,
            counterproofs,
            contested_payout,
            slash,
        };

        (game_graph, connectors)
    }

    /// Summarizes the game graph.
    pub fn summarize(&self) -> GameGraphSummary {
        GameGraphSummary {
            claim: self.claim.as_ref().compute_txid(),
            contest: self.contest.as_ref().compute_txid(),
            bridge_proof_timeout: self.bridge_proof_timeout.as_ref().compute_txid(),
            counterproofs: self
                .counterproofs
                .iter()
                .map(CounterproofGraph::summarize)
                .collect(),
            slash: self.slash.as_ref().compute_txid(),
        }
    }

    /// Generates a functor of the signing infos of each presigned transaction.
    ///
    /// # Contest transaction
    ///
    /// The contest transaction has multiple spending paths leading to it,
    /// one for each watchtower. This method returns a (distinct) signing info
    /// for each contesting watchtower.
    ///
    /// # Counterproof transaction
    ///
    /// The counterproof transaction has multiple sighashes because it uses OP_CODESEPARATOR.
    /// For Musig2, only the first sighash is relevant, which is returned by this method.
    pub fn musig_signing_info(&self) -> GameFunctor<SigningInfo> {
        GameFunctor {
            uncontested_payout: self.uncontested_payout.signing_info(),
            bridge_proof_timeout: self.bridge_proof_timeout.signing_info(),
            contested_payout: self.contested_payout.signing_info(),
            slash: self.slash.signing_info(),
            watchtowers: (0..self.contest.n_watchtowers())
                .map(|watchtower_index| WatchtowerFunctor {
                    contest: [self.contest.signing_info(watchtower_index)],
                    counterproof: self.counterproofs[watchtower_index as usize]
                        .counterproof
                        .signing_info(),
                    counterproof_ack: self.counterproofs[watchtower_index as usize]
                        .counterproof_ack
                        .signing_info(),
                })
                .collect(),
        }
    }

    /// Generates a functor of the inpoints of each presigned transaction.
    ///
    /// An inpoint has the following structure:
    ///
    /// ```ignore
    /// OutPoint {
    ///     txid: todo!("ID of the spending transaction"), // not the prevout
    ///     vout: todo!("Index of the input (vin)"),       // not the vout
    /// }
    /// ```
    ///
    /// In any game graph, every inpoint is guaranteed to be unique.
    ///
    /// # Contest transaction
    ///
    /// The contest transaction has multiple spending paths leading to it,
    /// one for each watchtower. This method returns a vector of equal inpoints
    /// for the contest transaction.
    pub fn musig_inpoints(&self) -> GameFunctor<OutPoint> {
        let uncontested_payout_txid = self.uncontested_payout.as_ref().compute_txid();
        let contest_txid = self.contest.as_ref().compute_txid();
        let bridge_proof_timeout_txid = self.bridge_proof_timeout.as_ref().compute_txid();
        let contested_payout_txid = self.contested_payout.as_ref().compute_txid();
        let slash_txid = self.slash.as_ref().compute_txid();

        // cast safety: the number of inputs of each transaction
        // is bounded and strictly less than u32::MAX
        GameFunctor {
            uncontested_payout: array::from_fn(|i| {
                OutPoint::new(uncontested_payout_txid, i as u32)
            }),
            bridge_proof_timeout: array::from_fn(|i| {
                OutPoint::new(bridge_proof_timeout_txid, i as u32)
            }),
            contested_payout: array::from_fn(|i| OutPoint::new(contested_payout_txid, i as u32)),
            slash: array::from_fn(|i| OutPoint::new(slash_txid, i as u32)),
            watchtowers: self
                .counterproofs
                .iter()
                .map(|subgraph| {
                    let counterproof_txid = subgraph.counterproof.as_ref().compute_txid();
                    let counterproof_ack_txid = subgraph.counterproof_ack.as_ref().compute_txid();
                    WatchtowerFunctor {
                        contest: [OutPoint::new(contest_txid, 0)],
                        counterproof: [OutPoint::new(counterproof_txid, 0)],
                        counterproof_ack: array::from_fn(|i| {
                            OutPoint::new(counterproof_ack_txid, i as u32)
                        }),
                    }
                })
                .collect(),
        }
    }
}

impl CounterproofGraph {
    /// Summarizes the counterproof graph.
    pub fn summarize(&self) -> CounterproofGraphSummary {
        CounterproofGraphSummary {
            counterproof: self.counterproof.as_ref().compute_txid(),
            counterproof_ack: self.counterproof_ack.as_ref().compute_txid(),
        }
    }
}

impl GameConnectors {
    /// Creates the collection of all connectors of a game.
    ///
    /// # Panics
    ///
    /// This method panics if the number of watchtowers is inconsistent.
    /// The following need to be equal:
    /// - The number of watchtower public keys.
    /// - The number of watchtower fault keys.
    /// - The number of watchtower slash descriptors.
    ///
    /// This method also panics if the number of watchtowers is greater than [`u32::MAX`].
    pub fn new(protocol: &ProtocolParams, setup: &SetupParams) -> Self {
        let keys = &setup.keys;

        assert_eq!(
            keys.watchtower_pubkeys.len(),
            keys.wt_fault_pubkeys.len(),
            "inconsistent number of watchtowers"
        );
        assert_eq!(
            keys.watchtower_pubkeys.len(),
            keys.slash_watchtower_descriptors.len(),
            "inconsistent number of watchtowers"
        );
        // cast safety: 32-bit arch or higher
        assert!(
            keys.watchtower_pubkeys.len() <= u32::MAX as usize,
            "too many watchtowers"
        );

        let claim_contest = ClaimContestConnector::new(
            setup.network,
            keys.n_of_n_pubkey,
            keys.watchtower_pubkeys.clone(),
            protocol.contest_timelock,
        );
        let claim_payout = ClaimPayoutConnector::new(
            setup.network,
            keys.n_of_n_pubkey,
            keys.admin_pubkey,
            keys.unstaking_image,
        );
        let deposit =
            NOfNConnector::new(setup.network, keys.n_of_n_pubkey, protocol.deposit_amount);
        let contest_proof = ContestProofConnector::new(
            setup.network,
            keys.n_of_n_pubkey,
            keys.operator_pubkey,
            setup.game_index,
            protocol.proof_timelock,
        );
        let contest_payout =
            ContestPayoutConnector::new(setup.network, keys.n_of_n_pubkey, protocol.ack_timelock);
        let contest_slash = ContestSlashConnector::new(
            setup.network,
            keys.n_of_n_pubkey,
            protocol.contested_payout_timelock,
        );
        let contest_counterproof = ContestCounterproofOutput::new(
            setup.network,
            keys.n_of_n_pubkey,
            keys.operator_pubkey,
            protocol.counterproof_n_bytes,
        );
        let counterproof: Vec<_> = keys
            .wt_fault_pubkeys
            .iter()
            .copied()
            .map(|wt_fault_pubkey| {
                CounterproofConnector::new(
                    setup.network,
                    keys.n_of_n_pubkey,
                    wt_fault_pubkey,
                    protocol.nack_timelock,
                )
            })
            .collect();
        let stake = NOfNConnector::new(setup.network, keys.n_of_n_pubkey, protocol.stake_amount);

        Self {
            claim_contest,
            claim_payout,
            deposit,
            contest_proof,
            contest_payout,
            contest_slash,
            contest_counterproof,
            counterproof,
            stake,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, transaction::Version, TxOut};
    use secp256k1::{rand::random, Keypair, SECP256K1};
    use strata_bridge_connectors2::{
        prelude::ContestCounterproofWitness, test_utils::BitcoinNode, Connector,
    };
    use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::transactions::prelude::{
        AdminBurnData, AdminBurnTx, BridgeProofData, BridgeProofTx, CounterproofNackData,
        CounterproofNackTx, UnstakingBurnData, UnstakingBurnTx,
    };

    const N_WATCHTOWERS: usize = 10;
    const CONTESTING_WATCHTOWER_IDX: u32 = 0;
    // From claim tx
    const CONTEST_TIMELOCK: relative::LockTime = relative::LockTime::from_height(10);
    // From contest tx
    const PROOF_TIMELOCK: relative::LockTime = relative::LockTime::from_height(5);
    const ACK_TIMELOCK: relative::LockTime = relative::LockTime::from_height(10);
    const CONTESTED_PAYOUT_TIMELOCK: relative::LockTime = relative::LockTime::from_height(15);
    // From counterproof tx
    const NACK_TIMELOCK: relative::LockTime = relative::LockTime::from_height(5);
    const DEPOSIT_AMOUNT: Amount = Amount::from_sat(100_000_000);
    const STAKE_AMOUNT: Amount = Amount::from_sat(100_000_000);
    const FEE: Amount = Amount::from_sat(1_000);

    #[derive(Debug)]
    struct Signer {
        pub n_of_n_keypair: Keypair,
        pub operator_keypair: Keypair,
        pub watchtower_keypairs: Vec<Keypair>,
        pub admin_keypair: Keypair,
        pub unstaking_preimage: [u8; 32],
        pub wt_fault_keypairs: Vec<Keypair>,
    }

    impl Signer {
        fn generate() -> Self {
            Signer {
                n_of_n_keypair: generate_keypair(),
                operator_keypair: generate_keypair(),
                watchtower_keypairs: (0..N_WATCHTOWERS).map(|_| generate_keypair()).collect(),
                admin_keypair: generate_keypair(),
                unstaking_preimage: random(),
                wt_fault_keypairs: (0..N_WATCHTOWERS).map(|_| generate_keypair()).collect(),
            }
        }
    }

    fn get_game_data(node: &mut BitcoinNode, signer: &Signer) -> GameData {
        let protocol = ProtocolParams {
            contest_timelock: CONTEST_TIMELOCK,
            proof_timelock: PROOF_TIMELOCK,
            ack_timelock: ACK_TIMELOCK,
            nack_timelock: NACK_TIMELOCK,
            contested_payout_timelock: CONTESTED_PAYOUT_TIMELOCK,
            counterproof_n_bytes: NonZero::new(128).unwrap(),
            deposit_amount: DEPOSIT_AMOUNT,
            stake_amount: STAKE_AMOUNT,
        };
        let wallet_descriptor = Descriptor::from(node.wallet_address().clone());
        let keys = KeyData {
            n_of_n_pubkey: signer.n_of_n_keypair.x_only_public_key().0,
            operator_pubkey: signer.operator_keypair.x_only_public_key().0,
            watchtower_pubkeys: signer
                .watchtower_keypairs
                .iter()
                .map(|k| k.x_only_public_key().0)
                .collect(),
            admin_pubkey: signer.admin_keypair.x_only_public_key().0,
            unstaking_image: sha256::Hash::hash(&signer.unstaking_preimage),
            wt_fault_pubkeys: signer
                .wt_fault_keypairs
                .iter()
                .map(|k| k.x_only_public_key().0)
                .collect(),
            payout_operator_descriptor: wallet_descriptor.clone(),
            slash_watchtower_descriptors: vec![wallet_descriptor; N_WATCHTOWERS],
        };
        let setup = SetupParams {
            network: Network::Regtest,
            magic_bytes: (*b"ALPN").into(),
            game_index: NonZero::new(1).unwrap(),
            operator_index: 0,
            keys,
        };
        let keys = &setup.keys;

        // FIXME: (@uncomputable) Prevent having to recreate the connectors
        let deposit_connector =
            NOfNConnector::new(setup.network, keys.n_of_n_pubkey, DEPOSIT_AMOUNT);
        let stake_connector = NOfNConnector::new(setup.network, keys.n_of_n_pubkey, STAKE_AMOUNT);
        let claim_contest_connector = ClaimContestConnector::new(
            setup.network,
            keys.n_of_n_pubkey,
            keys.watchtower_pubkeys.clone(),
            protocol.contest_timelock,
        );
        let claim_payout_connector = ClaimPayoutConnector::new(
            setup.network,
            keys.n_of_n_pubkey,
            keys.admin_pubkey,
            keys.unstaking_image,
        );
        let claim_funds_amount = claim_contest_connector.value() + claim_payout_connector.value();

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                       Funding Transaction                         │
        // └───────────────────────────────────────────────────────────────────┘
        //
        // inputs         | outputs
        // ---------------+------------------------------------
        // 50 btc: wallet | (4 + ω)ε sat: claim UTXO (wallet)
        //                +------------------------------------
        //                | 1 btc: deposit UTXO (N/N)
        //                +------------------------------------
        //                | 1 btc: stake UTXO (N/N)
        //                +------------------------------------
        //                | 48 btc - (4 + ω)ε sat - fee: wallet
        let input = create_tx_ins([node.next_coinbase_outpoint()]);
        let output = vec![
            TxOut {
                value: claim_funds_amount,
                script_pubkey: node.wallet_address().script_pubkey(),
            },
            deposit_connector.tx_out(),
            stake_connector.tx_out(),
            TxOut {
                value: node.coinbase_amount()
                    - claim_funds_amount
                    - DEPOSIT_AMOUNT
                    - STAKE_AMOUNT
                    - FEE,
                script_pubkey: node.wallet_address().script_pubkey(),
            },
        ];
        let funding_tx = create_tx(input, output);
        let funding_txid = node.sign_and_broadcast(&funding_tx);
        node.mine_blocks(1);

        GameData {
            protocol,
            setup,
            deposit: DepositParams {
                claim_funds: OutPoint {
                    txid: funding_txid,
                    vout: 0,
                },
                deposit_outpoint: OutPoint {
                    txid: funding_txid,
                    vout: 1,
                },
                stake_outpoint: OutPoint {
                    txid: funding_txid,
                    vout: 2,
                },
            },
        }
    }

    /// Test scenario for an entire game.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    enum Scenario {
        /// The contest transaction is posted.
        Contested(ProofScenario),
        /// The uncontested payout transaction is posted.
        Uncontested,
        /// The admin burn transaction is posted.
        AdminBurn,
        /// The unstaking burn transaction is posted.
        UnstakingBurn,
    }

    /// Test scenario for the operator bridge proof.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    enum ProofScenario {
        /// The bridge proof timeout and slash transactions are posted.
        Timeout,
        /// The bridge proof transaction is posted.
        Proof(CounterproofScenario),
    }

    /// Test scenario for the watchtower counterproof.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    enum CounterproofScenario {
        /// No counterproof transaction is posted; the contested payout transaction is posted.
        Timeout,
        /// The counterproof, counterproof nack and contested payout transactions are posted.
        Nack,
        /// The counterproof, counterproof ack and slash transactions are posted.
        Ack,
    }

    fn test_scenario(scenario: Scenario) {
        let mut node = BitcoinNode::new();
        let signer = Signer::generate();
        let game_data = get_game_data(&mut node, &signer);
        let game_index = game_data.setup.game_index;
        let (game, connectors) = GameGraph::new(game_data);
        let presigned = game
            .musig_signing_info()
            .map(|x| x.sign(&signer.n_of_n_keypair));

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                              Claim                                │
        // └───────────────────────────────────────────────────────────────────┘
        let claim = node.sign(game.claim.as_ref());
        assert_eq!(claim.version, Version(3));
        let child = node.create_cpfp_child(&game.claim, FEE * 2);
        assert_eq!(child.version, Version(3));

        node.submit_package(&[claim, child]);
        match scenario {
            Scenario::Uncontested => {
                node.mine_blocks(CONTEST_TIMELOCK.to_consensus_u32() as usize - 1);
            }
            _ => {
                node.mine_blocks(1);
            }
        }

        // ┌───────────────────────────────────────────────────────────────────┐
        // │              Uncontested Payout (test terminates here)            │
        // └───────────────────────────────────────────────────────────────────┘
        if let Scenario::Uncontested = scenario {
            let child = node.create_cpfp_child(&game.uncontested_payout, FEE * 2);
            assert_eq!(child.version, Version(3));
            let uncontested_payout = game
                .uncontested_payout
                .finalize(presigned.uncontested_payout);
            assert_eq!(uncontested_payout.version, Version(3));
            let package = [uncontested_payout, child];

            node.submit_package_invalid(&package);
            node.mine_blocks(1);
            node.submit_package(&package);
            return;
        }

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                Admin burn (test terminates here)                  │
        // └───────────────────────────────────────────────────────────────────┘
        if let Scenario::AdminBurn = scenario {
            let data = AdminBurnData {
                claim_txid: game.claim.as_ref().compute_txid(),
            };
            let mut admin_burn = AdminBurnTx::new(data, connectors.claim_payout);
            admin_burn.push_input(node.next_coinbase_txin(), node.coinbase_tx_out());
            admin_burn.push_output(TxOut {
                value: node.coinbase_amount() - FEE,
                script_pubkey: node.wallet_address().script_pubkey(),
            });

            let admin_signature = admin_burn
                .signing_info_partial()
                .sign(&signer.admin_keypair);
            let admin_burn = admin_burn.finalize_partial(admin_signature);
            assert_eq!(admin_burn.version, Version(3));

            node.sign_and_broadcast(&admin_burn);
            return;
        }

        // ┌───────────────────────────────────────────────────────────────────┐
        // │              Unstaking burn (test terminates here)                │
        // └───────────────────────────────────────────────────────────────────┘
        if let Scenario::UnstakingBurn = scenario {
            let data = UnstakingBurnData {
                claim_txid: game.claim.as_ref().compute_txid(),
            };
            let mut unstaking_burn = UnstakingBurnTx::new(data, connectors.claim_payout);
            unstaking_burn.push_input(node.next_coinbase_txin(), node.coinbase_tx_out());
            unstaking_burn.push_output(TxOut {
                value: node.coinbase_amount() - FEE,
                script_pubkey: node.wallet_address().script_pubkey(),
            });

            let unstaking_burn = unstaking_burn.finalize_partial(signer.unstaking_preimage);
            assert_eq!(unstaking_burn.version, Version(3));

            node.sign_and_broadcast(&unstaking_burn);
            return;
        }

        let Scenario::Contested(scenario) = scenario else {
            unreachable!("Other scenarios are caught above")
        };

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                             Contest                               │
        // └───────────────────────────────────────────────────────────────────┘
        // Cache contest_txid before game.contest is moved
        let contest_txid = game.contest.as_ref().compute_txid();

        let signing_info = game.contest.signing_info(CONTESTING_WATCHTOWER_IDX);
        let watchtower_signature =
            signing_info.sign(&signer.watchtower_keypairs[CONTESTING_WATCHTOWER_IDX as usize]);

        let child = node.create_cpfp_child(&game.contest, FEE * 2);
        assert_eq!(child.version, Version(3));
        let contest = game.contest.finalize(
            presigned.watchtowers[CONTESTING_WATCHTOWER_IDX as usize].contest[0],
            CONTESTING_WATCHTOWER_IDX,
            watchtower_signature,
        );
        assert_eq!(contest.version, Version(3));

        node.submit_package(&[contest, child]);
        let mut since_contest = 0;

        // ┌───────────────────────────────────────────────────────────────────┐
        // │          Bridge Proof Timeout + Slash (test terminates here)      │
        // └───────────────────────────────────────────────────────────────────┘
        if let ProofScenario::Timeout = scenario {
            // ┌───────────────────────────────────────────────────────────────┐
            // │                     Bridge Proof Timeout                      │
            // └───────────────────────────────────────────────────────────────┘
            let n_blocks = PROOF_TIMELOCK.to_consensus_u32() as usize - 1;
            node.mine_blocks(n_blocks);
            since_contest += n_blocks;

            let child = node.create_cpfp_child(&game.bridge_proof_timeout, FEE * 2);
            assert_eq!(child.version, Version(3));
            let bridge_proof_timeout = game
                .bridge_proof_timeout
                .finalize(presigned.bridge_proof_timeout);
            assert_eq!(bridge_proof_timeout.version, Version(3));
            let package = [bridge_proof_timeout, child];

            node.submit_package_invalid(&package);
            node.mine_blocks(1);
            since_contest += 1;
            node.submit_package(&package);

            // ┌───────────────────────────────────────────────────────────────┐
            // │                            Slash                              │
            // └───────────────────────────────────────────────────────────────┘
            node.mine_blocks(
                CONTESTED_PAYOUT_TIMELOCK.to_consensus_u32() as usize - since_contest - 1,
            );

            let child = node.create_cpfp_child(&game.slash, FEE * 2);
            assert_eq!(child.version, Version(3));
            let slash = game.slash.finalize(presigned.slash);
            assert_eq!(slash.version, Version(3));
            let package = [slash, child];

            node.submit_package_invalid(&package);
            node.mine_blocks(1);
            node.submit_package(&package);

            return;
        };

        let ProofScenario::Proof(scenario) = scenario else {
            unreachable!("ProofScenario::Timeout is caught above")
        };

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                          Bridge Proof                             │
        // └───────────────────────────────────────────────────────────────────┘
        node.mine_blocks(1);
        since_contest += 1;

        let data = BridgeProofData {
            contest_txid,
            proof_bytes: vec![0x00; 128],
            game_index,
        };
        let mut bridge_proof = BridgeProofTx::new(data, connectors.contest_proof);
        bridge_proof.push_input(node.next_coinbase_txin(), node.coinbase_tx_out());
        bridge_proof.push_output(TxOut {
            value: node.coinbase_amount() - FEE,
            script_pubkey: node.wallet_address().script_pubkey(),
        });

        let tweaked_operator_keypair = signer
            .operator_keypair
            .add_xonly_tweak(SECP256K1, &bridge_proof.operator_key_tweak())
            .expect("valid tweak");
        let operator_signature = bridge_proof
            .signing_info_partial()
            .sign(&tweaked_operator_keypair);
        let bridge_proof = bridge_proof.finalize_partial(operator_signature);
        assert_eq!(bridge_proof.version, Version(3));

        node.sign_and_broadcast(&bridge_proof);
        node.mine_blocks(1);
        since_contest += 1;

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                         Counterproof                              │
        // └───────────────────────────────────────────────────────────────────┘
        if scenario != CounterproofScenario::Timeout {
            let operator_signatures = game.counterproofs[0]
                .counterproof
                .sighashes()
                .into_iter()
                .map(|msg| signer.operator_keypair.sign_schnorr(msg))
                .collect();
            let witness = ContestCounterproofWitness {
                n_of_n_signature: presigned.watchtowers[0].counterproof[0],
                operator_signatures,
            };
            let counterproof = game.counterproofs[0]
                .counterproof
                .clone()
                .finalize(&witness);
            assert_eq!(counterproof.version, Version(3));
            let child = node.create_cpfp_child(&game.counterproofs[0].counterproof, FEE * 2);
            assert_eq!(child.version, Version(3));
            let package = [counterproof, child];

            node.submit_package(&package);
        }

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                       Counterproof NACK                           │
        // └───────────────────────────────────────────────────────────────────┘
        if scenario == CounterproofScenario::Nack {
            node.mine_blocks(1);
            since_contest += 1;

            let data = CounterproofNackData {
                counterproof_txid: game.counterproofs[0].counterproof.as_ref().compute_txid(),
            };
            let mut counterproof_nack = CounterproofNackTx::new(data, connectors.counterproof[0]);
            counterproof_nack.push_input(node.next_coinbase_txin(), node.coinbase_tx_out());
            counterproof_nack.push_output(TxOut {
                value: node.coinbase_amount() - FEE,
                script_pubkey: node.wallet_address().script_pubkey(),
            });
            let wt_fault_signature = counterproof_nack
                .signing_info_partial()
                .sign(&signer.wt_fault_keypairs[0]);
            let counterproof_nack = counterproof_nack.finalize_partial(wt_fault_signature);
            assert_eq!(counterproof_nack.version, Version(3));

            node.sign_and_broadcast(&counterproof_nack);
            node.mine_blocks(1);
            since_contest += 1;
        }

        // ┌───────────────────────────────────────────────────────────────────┐
        // │          Counterproof ACK + Slash (test terminates here)          │
        // └───────────────────────────────────────────────────────────────────┘
        if scenario == CounterproofScenario::Ack {
            // ┌───────────────────────────────────────────────────────────────┐
            // │                       Counterproof ACK                        │
            // └───────────────────────────────────────────────────────────────┘
            let n_blocks = NACK_TIMELOCK.to_consensus_u32() as usize - 1;
            node.mine_blocks(n_blocks);
            since_contest += n_blocks;

            let counterproof_ack = game.counterproofs[0]
                .counterproof_ack
                .clone()
                .finalize(presigned.watchtowers[0].counterproof_ack);
            assert_eq!(counterproof_ack.version, Version(3));
            let child = node.create_cpfp_child(&game.counterproofs[0].counterproof_ack, FEE * 2);
            assert_eq!(child.version, Version(3));
            let package = [counterproof_ack, child];

            node.submit_package_invalid(&package);
            node.mine_blocks(1);
            since_contest += 1;
            node.submit_package(&package);

            // ┌───────────────────────────────────────────────────────────────┐
            // │                            Slash                              │
            // └───────────────────────────────────────────────────────────────┘
            node.mine_blocks(
                CONTESTED_PAYOUT_TIMELOCK.to_consensus_u32() as usize - since_contest - 1,
            );

            let child = node.create_cpfp_child(&game.slash, FEE * 2);
            assert_eq!(child.version, Version(3));
            let slash = game.slash.finalize(presigned.slash);
            assert_eq!(slash.version, Version(3));
            let package = [slash, child];

            node.submit_package_invalid(&package);
            node.mine_blocks(1);
            node.submit_package(&package);
            return;
        }

        // ┌───────────────────────────────────────────────────────────────────┐
        // │                        Contested Payout                           │
        // └───────────────────────────────────────────────────────────────────┘
        node.mine_blocks(ACK_TIMELOCK.to_consensus_u32() as usize - since_contest - 1);

        let child = node.create_cpfp_child(&game.contested_payout, FEE * 2);
        assert_eq!(child.version, Version(3));
        let contested_payout = game.contested_payout.finalize(presigned.contested_payout);
        assert_eq!(contested_payout.version, Version(3));
        let package = [contested_payout, child];

        node.submit_package_invalid(&package);
        node.mine_blocks(1);
        node.submit_package(&package);
    }

    #[test]
    fn uncontested_payout() {
        test_scenario(Scenario::Uncontested);
    }

    #[test]
    fn admin_burn_payout() {
        test_scenario(Scenario::AdminBurn);
    }

    #[test]
    fn unstaking_burn_payout() {
        test_scenario(Scenario::UnstakingBurn);
    }

    #[test]
    fn proof_timeout_slash() {
        test_scenario(Scenario::Contested(ProofScenario::Timeout));
    }

    #[test]
    fn no_counterproof_contested_payout() {
        test_scenario(Scenario::Contested(ProofScenario::Proof(
            CounterproofScenario::Timeout,
        )));
    }

    #[test]
    fn counterproof_nack_contested_payout() {
        test_scenario(Scenario::Contested(ProofScenario::Proof(
            CounterproofScenario::Nack,
        )));
    }

    #[test]
    fn counterproof_ack_slash() {
        test_scenario(Scenario::Contested(ProofScenario::Proof(
            CounterproofScenario::Ack,
        )));
    }
}
