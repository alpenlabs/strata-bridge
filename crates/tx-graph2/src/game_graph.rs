//! This module contains the game graph,
//! which is the collection of the transactions of a game.

use std::num::NonZero;

use bitcoin::{hashes::sha256, relative, Amount, Network, OutPoint, XOnlyPublicKey};
use strata_l1_txfmt::MagicBytes;
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::{
    connectors::prelude::{
        ClaimContestConnector, ClaimPayoutConnector, ContestCounterproofOutput,
        ContestPayoutConnector, ContestProofConnector, ContestSlashConnector,
        CounterproofConnector, NOfNConnector,
    },
    transactions::{
        prelude::{
            AdminBurnData, AdminBurnTx, BridgeProofData, BridgeProofTimeoutData,
            BridgeProofTimeoutTx, BridgeProofTx, ClaimData, ClaimTx, ContestData, ContestTx,
            ContestedPayoutData, ContestedPayoutTx, CounterproofAckData, CounterproofAckTx,
            CounterproofData, CounterproofNackData, CounterproofNackTx, CounterproofTx, SlashData,
            SlashTx, UncontestedPayoutData, UncontestedPayoutTx, UnstakingBurnData,
            UnstakingBurnTx,
        },
        AsTransaction,
    },
};

/// Data that is needed to construct a [`GameGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameData {
    /// Data that is inherent from the protocol.
    pub constant: ConstantData,
    /// Data that varies per game instance.
    pub runtime: RuntimeData,
}

/// Parameters that instantiate a specific game graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeData {
    /// Game index.
    pub game_index: NonZero<u32>,
    /// Operator index.
    pub operator_index: u32,
    /// UTXO that funds the claim transaction.
    pub claim_funds: OutPoint,
    /// UTXO that holds the deposit.
    pub deposit_outpoint: OutPoint,
    /// UTXO that holds the stake.
    pub stake_outpoint: OutPoint,
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
pub struct ConstantData {
    /// Used bitcoin network.
    pub network: Network,
    /// Magic bytes that identify the bridge.
    pub magic_bytes: MagicBytes,
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
    /// Number of bytes for the serialized bridge proof (including public values).
    pub proof_n_bytes: usize,
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
    /// Bridge proof transaction.
    pub bridge_proof: BridgeProofTx,
    /// Bridge proof timeout transaction.
    pub bridge_proof_timeout: BridgeProofTimeoutTx,
    /// One counterproof graph for each watchtower.
    pub counterproofs: Vec<CounterproofGraph>,
    /// Contested payout transaction.
    pub contested_payout: ContestedPayoutTx,
    /// Slash transaction.
    pub slash: SlashTx,
    /// Admin burn transaction.
    pub admin_burn: AdminBurnTx,
    /// Unstaking burn transaction.
    pub unstaking_burn: UnstakingBurnTx,
}

/// Collection of presigned transactions for the counterproof of a single watchtower.
///
/// The graph is replicated for each watchtower.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CounterproofGraph {
    /// Counterproof transaction.
    pub counterproof: CounterproofTx,
    /// Counterproof NACK transaction.
    pub counterproof_nack: CounterproofNackTx,
    /// Counterproof ACK transaction.
    pub counterproof_ack: CounterproofAckTx,
}

impl GameGraph {
    /// Creates a new game graph.
    pub fn new(data: GameData) -> Self {
        let runtime = &data.runtime;
        let keys = &runtime.keys;
        let constant = &data.constant;

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

        let claim_contest_connector = ClaimContestConnector::new(
            constant.network,
            keys.n_of_n_pubkey,
            keys.watchtower_pubkeys.clone(),
            constant.contest_timelock,
        );
        let claim_payout_connector = ClaimPayoutConnector::new(
            constant.network,
            keys.n_of_n_pubkey,
            keys.admin_pubkey,
            keys.unstaking_image,
        );
        let deposit_connector = NOfNConnector::new(
            constant.network,
            keys.n_of_n_pubkey,
            constant.deposit_amount,
        );
        let contest_proof_connector = ContestProofConnector::new(
            constant.network,
            keys.n_of_n_pubkey,
            keys.operator_pubkey,
            runtime.game_index,
            constant.proof_timelock,
        );
        let contest_payout_connector = ContestPayoutConnector::new(
            constant.network,
            keys.n_of_n_pubkey,
            constant.ack_timelock,
        );
        let contest_slash_connector = ContestSlashConnector::new(
            constant.network,
            keys.n_of_n_pubkey,
            constant.contested_payout_timelock,
        );
        let contest_counterproof_output = ContestCounterproofOutput::new(
            constant.network,
            keys.n_of_n_pubkey,
            keys.operator_pubkey,
            constant.counterproof_n_bytes,
        );
        let counterproof_connectors: Vec<_> = keys
            .wt_fault_pubkeys
            .iter()
            .copied()
            .map(|wt_fault_pubkey| {
                CounterproofConnector::new(
                    constant.network,
                    keys.n_of_n_pubkey,
                    wt_fault_pubkey,
                    constant.nack_timelock,
                )
            })
            .collect();
        let stake_connector =
            NOfNConnector::new(constant.network, keys.n_of_n_pubkey, constant.stake_amount);

        let claim_data = ClaimData {
            claim_funds: runtime.claim_funds,
        };
        let claim = ClaimTx::new(
            claim_data,
            claim_contest_connector.clone(),
            claim_payout_connector,
        );

        let uncontested_payout_data = UncontestedPayoutData {
            claim_txid: claim.as_unsigned_tx().compute_txid(),
            deposit_outpoint: runtime.deposit_outpoint,
        };
        let uncontested_payout = UncontestedPayoutTx::new(
            uncontested_payout_data,
            deposit_connector,
            claim_contest_connector.clone(),
            claim_payout_connector,
            keys.payout_operator_descriptor.clone(),
        );

        let contest_data = ContestData {
            claim_txid: claim.as_unsigned_tx().compute_txid(),
        };
        let contest = ContestTx::new(
            contest_data,
            claim_contest_connector,
            contest_proof_connector,
            contest_payout_connector,
            contest_slash_connector,
            contest_counterproof_output,
        );

        let bridge_proof_data = BridgeProofData {
            contest_txid: contest.as_unsigned_tx().compute_txid(),
            proof_n_bytes: constant.proof_n_bytes,
            game_index: runtime.game_index,
        };
        let bridge_proof = BridgeProofTx::new(bridge_proof_data, contest_proof_connector);

        let bridge_proof_timeout_data = BridgeProofTimeoutData {
            contest_txid: contest.as_unsigned_tx().compute_txid(),
        };
        let bridge_proof_timeout = BridgeProofTimeoutTx::new(
            bridge_proof_timeout_data,
            contest_proof_connector,
            contest_payout_connector,
        );

        let counterproofs: Vec<_> = counterproof_connectors
            .into_iter()
            .enumerate()
            .map(|(watchtower_index, counterproof_connector)| {
                // cast safety: asserted above that len(watchtowers) <= u32::MAX
                let counterproof_data = CounterproofData {
                    contest_txid: contest.as_unsigned_tx().compute_txid(),
                    watchtower_index: watchtower_index as u32,
                };
                let counterproof = CounterproofTx::new(
                    counterproof_data,
                    contest_counterproof_output,
                    counterproof_connector,
                );

                let counterproof_nack_data = CounterproofNackData {
                    counterproof_txid: counterproof.as_unsigned_tx().compute_txid(),
                };
                let counterproof_nack =
                    CounterproofNackTx::new(counterproof_nack_data, counterproof_connector);

                let counterproof_ack_data = CounterproofAckData {
                    counterproof_txid: counterproof.as_unsigned_tx().compute_txid(),
                    contest_txid: contest.as_unsigned_tx().compute_txid(),
                };
                let counterproof_ack = CounterproofAckTx::new(
                    counterproof_ack_data,
                    counterproof_connector,
                    contest_payout_connector,
                );

                CounterproofGraph {
                    counterproof,
                    counterproof_nack,
                    counterproof_ack,
                }
            })
            .collect();

        let contested_payout_data = ContestedPayoutData {
            deposit_outpoint: runtime.deposit_outpoint,
            claim_txid: claim.as_unsigned_tx().compute_txid(),
            contest_txid: contest.as_unsigned_tx().compute_txid(),
        };
        let contested_payout = ContestedPayoutTx::new(
            contested_payout_data,
            deposit_connector,
            claim_payout_connector,
            contest_payout_connector,
            contest_slash_connector,
            keys.payout_operator_descriptor.clone(),
        );

        let slash_data = SlashData {
            operator_idx: runtime.operator_index,
            contest_txid: contest.as_unsigned_tx().compute_txid(),
            stake_outpoint: runtime.stake_outpoint,
            magic_bytes: constant.magic_bytes,
        };
        let slash = SlashTx::new(
            slash_data,
            contest_slash_connector,
            stake_connector,
            &keys.slash_watchtower_descriptors,
        );

        let admin_burn_data = AdminBurnData {
            claim_txid: claim.as_unsigned_tx().compute_txid(),
        };
        let admin_burn = AdminBurnTx::new(admin_burn_data, claim_payout_connector);

        let unstaking_burn_data = UnstakingBurnData {
            claim_txid: claim.as_unsigned_tx().compute_txid(),
        };
        let unstaking_burn = UnstakingBurnTx::new(unstaking_burn_data, claim_payout_connector);

        Self {
            claim,
            uncontested_payout,
            contest,
            bridge_proof,
            bridge_proof_timeout,
            counterproofs,
            contested_payout,
            slash,
            admin_burn,
            unstaking_burn,
        }
    }
}
