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
    transactions::prelude::{
        BridgeProofTimeoutData, BridgeProofTimeoutTx, ClaimData, ClaimTx, ContestData, ContestTx,
        ContestedPayoutData, ContestedPayoutTx, CounterproofAckData, CounterproofAckTx,
        CounterproofData, CounterproofTx, SlashData, SlashTx, UncontestedPayoutData,
        UncontestedPayoutTx,
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
    /// One counterproof graph for each watchtower.
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
    pub fn new(data: GameData) -> Self {
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
        let deposit_connector =
            NOfNConnector::new(setup.network, keys.n_of_n_pubkey, protocol.deposit_amount);
        let contest_proof_connector = ContestProofConnector::new(
            setup.network,
            keys.n_of_n_pubkey,
            keys.operator_pubkey,
            setup.game_index,
            protocol.proof_timelock,
        );
        let contest_payout_connector =
            ContestPayoutConnector::new(setup.network, keys.n_of_n_pubkey, protocol.ack_timelock);
        let contest_slash_connector = ContestSlashConnector::new(
            setup.network,
            keys.n_of_n_pubkey,
            protocol.contested_payout_timelock,
        );
        let contest_counterproof_output = ContestCounterproofOutput::new(
            setup.network,
            keys.n_of_n_pubkey,
            keys.operator_pubkey,
            protocol.counterproof_n_bytes,
        );
        let counterproof_connectors: Vec<_> = keys
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
        let stake_connector =
            NOfNConnector::new(setup.network, keys.n_of_n_pubkey, protocol.stake_amount);

        let claim_data = ClaimData {
            claim_funds: deposit.claim_funds,
        };
        let claim = ClaimTx::new(
            claim_data,
            claim_contest_connector.clone(),
            claim_payout_connector,
        );

        let uncontested_payout_data = UncontestedPayoutData {
            claim_txid: claim.as_ref().compute_txid(),
            deposit_outpoint: deposit.deposit_outpoint,
        };
        let uncontested_payout = UncontestedPayoutTx::new(
            uncontested_payout_data,
            deposit_connector,
            claim_contest_connector.clone(),
            claim_payout_connector,
            keys.payout_operator_descriptor.clone(),
        );

        let contest_data = ContestData {
            claim_txid: claim.as_ref().compute_txid(),
        };
        let contest = ContestTx::new(
            contest_data,
            claim_contest_connector,
            contest_proof_connector,
            contest_payout_connector,
            contest_slash_connector,
            contest_counterproof_output,
        );

        let bridge_proof_timeout_data = BridgeProofTimeoutData {
            contest_txid: contest.as_ref().compute_txid(),
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
                    contest_txid: contest.as_ref().compute_txid(),
                    watchtower_index: watchtower_index as u32,
                };
                let counterproof = CounterproofTx::new(
                    counterproof_data,
                    contest_counterproof_output,
                    counterproof_connector,
                );

                let counterproof_ack_data = CounterproofAckData {
                    counterproof_txid: counterproof.as_ref().compute_txid(),
                    contest_txid: contest.as_ref().compute_txid(),
                };
                let counterproof_ack = CounterproofAckTx::new(
                    counterproof_ack_data,
                    counterproof_connector,
                    contest_payout_connector,
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
            deposit_connector,
            claim_payout_connector,
            contest_payout_connector,
            contest_slash_connector,
            keys.payout_operator_descriptor.clone(),
        );

        let slash_data = SlashData {
            operator_idx: setup.operator_index,
            contest_txid: contest.as_ref().compute_txid(),
            stake_outpoint: deposit.stake_outpoint,
            magic_bytes: setup.magic_bytes,
        };
        let slash = SlashTx::new(
            slash_data,
            contest_slash_connector,
            stake_connector,
            &keys.slash_watchtower_descriptors,
        );

        Self {
            claim,
            uncontested_payout,
            contest,
            bridge_proof_timeout,
            counterproofs,
            contested_payout,
            slash,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, transaction::Version, TxOut};
    use secp256k1::{rand::random, Keypair};
    use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{
        connectors::{test_utils::BitcoinNode, Connector},
        transactions::PresignedTx,
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
            magic_bytes: *b"alpn",
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

        // Create a transaction that funds the claim, deposit and stake.
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

    #[test]
    fn uncontested_payout() {
        let mut node = BitcoinNode::new();
        let signer = Signer::generate();
        let game_data = get_game_data(&mut node, &signer);
        let game = GameGraph::new(game_data);

        // Create the claim transaction + its CPFP child.
        //
        // inputs               | outputs
        // ---------------------+---------------------------------------
        // (4 + ω)ε sat: wallet | (3 + ω)ε sat: claim contest connector
        //                      |---------------------------------------
        //                      | ε sat: claim payout connector
        //                      |---------------------------------------
        //                      | 0 sat: cpfp connector (CPFP)
        let signed_claim_tx = node.sign(game.claim.as_ref());
        assert_eq!(signed_claim_tx.version, Version(3));
        let signed_claim_child_tx = node.create_cpfp_child(&game.claim, FEE * 2);
        assert_eq!(signed_claim_child_tx.version, Version(3));

        node.submit_package(&[signed_claim_tx, signed_claim_child_tx]);
        node.mine_blocks(CONTEST_TIMELOCK.to_consensus_u32() as usize - 1);

        // Create the uncontested payout transaction + its CPFP child.
        //
        // inputs                                | outputs
        // --------------------------------------+----------------------------------
        // 1 btc: deposit connector              | 1 btc + (4 + ω)ε: operator (CPFP)
        // --------------------------------------|
        // (3 + ω)ε sat: claim contest connector |
        // --------------------------------------|
        // ε sat: claim payout connector         |
        let signing_info = game.uncontested_payout.signing_info();
        let n_of_n_signatures =
            std::array::from_fn(|i| signing_info[i].sign(&signer.n_of_n_keypair));

        let signed_payout_child_tx = node.create_cpfp_child(&game.uncontested_payout, FEE * 2);
        assert_eq!(signed_payout_child_tx.version, Version(3));
        let signed_uncontested_payout_tx = game.uncontested_payout.finalize(n_of_n_signatures);
        assert_eq!(signed_uncontested_payout_tx.version, Version(3));
        let package = [signed_uncontested_payout_tx, signed_payout_child_tx];

        node.submit_package_invalid(&package);
        node.mine_blocks(1);
        node.submit_package(&package);
    }

    #[test]
    fn contested_payout() {
        let mut node = BitcoinNode::new();
        let signer = Signer::generate();
        let game_data = get_game_data(&mut node, &signer);
        let game = GameGraph::new(game_data);

        // Create the claim transaction + its CPFP child.
        //
        // inputs               | outputs
        // ---------------------+---------------------------------------
        // (4 + ω)ε sat: wallet | (3 + ω)ε sat: claim contest connector
        //                      |---------------------------------------
        //                      | ε sat: claim payout connector
        //                      |---------------------------------------
        //                      | 0 sat: cpfp connector (CPFP)
        let signed_claim_tx = node.sign(game.claim.as_ref());
        assert_eq!(signed_claim_tx.version, Version(3));
        let signed_claim_child_tx = node.create_cpfp_child(&game.claim, FEE * 2);
        assert_eq!(signed_claim_child_tx.version, Version(3));

        node.submit_package(&[signed_claim_tx, signed_claim_child_tx]);
        node.mine_blocks(1);

        // Create the contest transaction + its CPFP child.
        //
        // inputs                                | outputs
        // --------------------------------------+-----------------------------------
        // (3 + ω)ε sat: claim contest connector | ε sat: contest proof connector
        // --------------------------------------+-----------------------------------
        //                                       | ε sat: contest payout connector
        //                                       |-----------------------------------
        //                                       | ε sat: contest slash connector
        //                                       |-----------------------------------
        //                                       | ε sat: contest counterproof output
        //                                       |-----------------------------------
        //                                       | ...
        //                                       |-----------------------------------
        //                                       | ε sat: contest counterproof output
        //                                       |-----------------------------------
        //                                       | 0 sat: cpfp connector
        let signing_info = game.contest.signing_info(CONTESTING_WATCHTOWER_IDX);
        let n_of_n_signature = signing_info.sign(&signer.n_of_n_keypair);
        let watchtower_signature =
            signing_info.sign(&signer.watchtower_keypairs[CONTESTING_WATCHTOWER_IDX as usize]);

        let signed_contest_child_tx = node.create_cpfp_child(&game.contest, FEE * 2);
        assert_eq!(signed_contest_child_tx.version, Version(3));
        let signed_contest_tx = game.contest.finalize(
            n_of_n_signature,
            CONTESTING_WATCHTOWER_IDX,
            watchtower_signature,
        );
        assert_eq!(signed_contest_tx.version, Version(3));

        node.submit_package(&[signed_contest_tx, signed_contest_child_tx]);
        node.mine_blocks(ACK_TIMELOCK.to_consensus_u32() as usize - 1);

        // Create the contested payout transaction + its CPFP child.
        //
        // inputs                          | outputs
        // --------------------------------+--------------------------------
        // 1 btc: deposit connector        | 1 btc + 3ε sat: operator (CPFP)
        // --------------------------------|
        // ε sat: claim payout connector   |
        // --------------------------------|
        // ε sat: contest payout connector |
        // --------------------------------|
        // ε sat: contest slash connector  |
        let signing_info = game.contested_payout.signing_info();
        let n_of_n_signatures =
            std::array::from_fn(|i| signing_info[i].sign(&signer.n_of_n_keypair));

        let signed_payout_child_tx = node.create_cpfp_child(&game.contested_payout, FEE * 2);
        assert_eq!(signed_payout_child_tx.version, Version(3));
        let signed_contested_payout_tx = game.contested_payout.finalize(n_of_n_signatures);
        assert_eq!(signed_contested_payout_tx.version, Version(3));
        let package = [signed_contested_payout_tx, signed_payout_child_tx];

        node.submit_package_invalid(&package);
        node.mine_blocks(1);
        node.submit_package(&package);
    }
}
