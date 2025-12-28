//! This module contains the contested payout transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    OutPoint, Psbt, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_bridge_primitives::scripts::prelude::create_tx_outs;
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::{
    connectors::{
        n_of_n::NOfNSpend,
        prelude::{
            ClaimPayoutConnector, ClaimPayoutSpendPath, ClaimPayoutWitness, ContestPayoutConnector,
            ContestSlashConnector, NOfNConnector, TimelockedSpendPath, TimelockedWitness,
        },
        Connector,
    },
    transactions::{
        prelude::{ClaimTx, ContestTx, DepositTx},
        ParentTx, PresignedTx, SigningInfo,
    },
};

/// Data that is needed to construct a [`ContestedPayoutTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ContestedPayoutData {
    /// ID of the deposit transaction.
    pub deposit_txid: Txid,
    /// ID of the claim transaction.
    pub claim_txid: Txid,
    /// Id of the contest transaction.
    pub contest_txid: Txid,
}

/// The contested payout transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContestedPayoutTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    deposit_connector: NOfNConnector,
    claim_payout_connector: ClaimPayoutConnector,
    contest_payout_connector: ContestPayoutConnector,
    contest_slash_connector: ContestSlashConnector,
}

impl ContestedPayoutTx {
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 0;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 4;

    /// Creates an contested payout transaction.
    pub fn new(
        data: ContestedPayoutData,
        deposit_connector: NOfNConnector,
        claim_payout_connector: ClaimPayoutConnector,
        contest_payout_connector: ContestPayoutConnector,
        contest_slash_connector: ContestSlashConnector,
        operator_descriptor: Descriptor,
    ) -> Self {
        debug_assert!(deposit_connector.network() == claim_payout_connector.network());
        debug_assert!(deposit_connector.network() == contest_payout_connector.network());
        debug_assert!(deposit_connector.network() == contest_slash_connector.network());

        let prevouts = [
            deposit_connector.tx_out(),
            claim_payout_connector.tx_out(),
            contest_payout_connector.tx_out(),
            contest_slash_connector.tx_out(),
        ];
        let input = vec![
            TxIn {
                previous_output: OutPoint {
                    txid: data.deposit_txid,
                    vout: DepositTx::DEPOSIT_VOUT,
                },
                sequence: deposit_connector.sequence(NOfNSpend),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: data.claim_txid,
                    vout: ClaimTx::PAYOUT_VOUT,
                },
                sequence: claim_payout_connector.sequence(ClaimPayoutSpendPath::Payout),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: data.contest_txid,
                    vout: ContestTx::PAYOUT_VOUT,
                },
                sequence: contest_payout_connector.sequence(TimelockedSpendPath::Timeout),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: data.contest_txid,
                    vout: ContestTx::SLASH_VOUT,
                },
                sequence: contest_slash_connector.sequence(TimelockedSpendPath::Normal),
                ..Default::default()
            },
        ];
        let output = create_tx_outs([(
            operator_descriptor.to_script(),
            deposit_connector.value()
                + claim_payout_connector.value()
                + contest_payout_connector.value()
                + contest_slash_connector.value(),
        )]);
        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        Self {
            psbt,
            prevouts,
            deposit_connector,
            claim_payout_connector,
            contest_payout_connector,
            contest_slash_connector,
        }
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, n_of_n_signatures: [schnorr::Signature; Self::N_INPUTS]) -> Transaction {
        let mut psbt = self.psbt;

        let deposit_witness = n_of_n_signatures[0];
        let claim_payout_witness = ClaimPayoutWitness::Payout {
            output_key_signature: n_of_n_signatures[1],
        };
        let contest_payout_witnes = TimelockedWitness::Timeout {
            timelocked_key_signature: n_of_n_signatures[2],
        };
        let contest_slash_witness = TimelockedWitness::Normal {
            output_key_signature: n_of_n_signatures[3],
        };

        self.deposit_connector
            .finalize_input(&mut psbt.inputs[0], &deposit_witness);
        self.claim_payout_connector
            .finalize_input(&mut psbt.inputs[1], &claim_payout_witness);
        self.contest_payout_connector
            .finalize_input(&mut psbt.inputs[2], &contest_payout_witnes);
        self.contest_slash_connector
            .finalize_input(&mut psbt.inputs[3], &contest_slash_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for ContestedPayoutTx {
    fn cpfp_tx_out(&self) -> TxOut {
        self.psbt.unsigned_tx.output[0].clone()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.psbt.unsigned_tx.compute_txid(),
            vout: Self::CPFP_VOUT,
        }
    }
}

impl PresignedTx<{ Self::N_INPUTS }> for ContestedPayoutTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        [
            self.deposit_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                NOfNSpend,
                0,
            ),
            self.claim_payout_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                ClaimPayoutSpendPath::Payout,
                1,
            ),
            self.contest_payout_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                TimelockedSpendPath::Timeout,
                2,
            ),
            self.contest_slash_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                TimelockedSpendPath::Normal,
                3,
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use bitcoin::{
        hashes::{sha256, Hash},
        relative, Amount, Network, TxOut,
    };
    use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins};
    use strata_bridge_test_utils::prelude::generate_keypair;
    use strata_l1_txfmt::MagicBytes;

    use super::*;
    use crate::{
        connectors::{
            prelude::{
                ClaimContestConnector, ClaimPayoutConnector, ContestCounterproofOutput,
                ContestProofConnector, DepositRequestConnector, NOfNConnector,
            },
            test_utils::BitcoinNode,
        },
        transactions::prelude::{
            ClaimData, ClaimTx, ContestData, ContestTx, DepositData, DepositTx,
        },
    };

    const NETWORK: Network = Network::Regtest;
    const N_WATCHTOWERS: usize = 10;
    const N_DATA: NonZero<usize> = NonZero::new(10).unwrap();
    const CONTESTING_WATCHTOWER_IDX: u32 = 0;
    const CONTEST_TIMELOCK: relative::LockTime = relative::LockTime::from_height(10);
    const REFUND_TIMELOCK: relative::LockTime = CONTEST_TIMELOCK;
    const PROOF_TIMELOCK: relative::LockTime = CONTEST_TIMELOCK;
    const ACK_TIMELOCK: relative::LockTime = CONTEST_TIMELOCK;
    const CONTESTED_PAYOUT_TIMELOCK: relative::LockTime = CONTEST_TIMELOCK;
    const UNSTAKING_PREIMAGE: [u8; 32] = [0; 32];
    const DEPOSIT: Amount = Amount::from_sat(100_000_000);
    const FEE: Amount = Amount::from_sat(1_000);
    const DEPOSIT_IDX: u32 = 0;
    const GAME_IDX: NonZero<u32> = NonZero::new(1).unwrap();
    const MAGIC_BYTES: MagicBytes = *b"alpn";

    #[test]
    fn contested_payout() {
        let mut node = BitcoinNode::new();

        let n_of_n_keypair = generate_keypair();
        let watchtower_keypairs: Vec<_> = (0..N_WATCHTOWERS).map(|_| generate_keypair()).collect();
        let operator_keypair = generate_keypair();
        let admin_keypair = generate_keypair();
        let depositor_keypair = generate_keypair();

        let n_of_n_pubkey = n_of_n_keypair.x_only_public_key().0;
        let watchtower_pubkeys: Vec<_> = watchtower_keypairs
            .iter()
            .map(|k| k.x_only_public_key().0)
            .collect();
        let operator_pubkey = operator_keypair.x_only_public_key().0;
        let admin_pubkey = admin_keypair.x_only_public_key().0;
        let unstaking_image = sha256::Hash::hash(&UNSTAKING_PREIMAGE);
        let depositor_pubkey = depositor_keypair.x_only_public_key().0;

        let deposit_request_connector = DepositRequestConnector::new(
            NETWORK,
            n_of_n_pubkey,
            depositor_pubkey,
            REFUND_TIMELOCK,
            DEPOSIT + FEE,
        );
        let deposit_connector = NOfNConnector::new(NETWORK, n_of_n_pubkey, DEPOSIT);
        let claim_contest_connector = ClaimContestConnector::new(
            NETWORK,
            n_of_n_pubkey,
            watchtower_pubkeys.clone(),
            CONTEST_TIMELOCK,
        );
        let claim_payout_connector =
            ClaimPayoutConnector::new(NETWORK, n_of_n_pubkey, admin_pubkey, unstaking_image);
        let contest_proof_connector = ContestProofConnector::new(
            NETWORK,
            n_of_n_pubkey,
            operator_pubkey,
            GAME_IDX,
            PROOF_TIMELOCK,
        );
        let contest_payout_connector =
            ContestPayoutConnector::new(NETWORK, n_of_n_pubkey, ACK_TIMELOCK);
        let contest_slash_connector =
            ContestSlashConnector::new(NETWORK, n_of_n_pubkey, CONTESTED_PAYOUT_TIMELOCK);
        let contest_counterproof_output =
            ContestCounterproofOutput::new(NETWORK, n_of_n_pubkey, operator_pubkey, N_DATA);

        // Create a transaction that funds the deposit and claim inputs.
        //
        // inputs         | outputs
        // ---------------+--------------------------------------------------
        // 50 btc: wallet | 1 btc + fee: deposit request connector
        //                +--------------------------------------------------
        //                | (4 + ω)ε sat: wallet
        //                |--------------------------------------------------
        //                | 50 btc - 1 btc - fee - (4 + ω)ε sat - fee: wallet
        let input = create_tx_ins([node.next_coinbase_outpoint()]);
        let output = vec![
            deposit_request_connector.tx_out(),
            TxOut {
                value: claim_contest_connector.value() + claim_payout_connector.value(),
                script_pubkey: node.wallet_address().script_pubkey(),
            },
            TxOut {
                value: node.coinbase_amount()
                    - deposit_request_connector.value()
                    - FEE
                    - claim_contest_connector.value()
                    - claim_payout_connector.value()
                    - FEE,
                script_pubkey: node.wallet_address().script_pubkey(),
            },
        ];
        let funding_tx = create_tx(input, output);
        let funding_txid = node.sign_and_broadcast(&funding_tx);
        node.mine_blocks(1);

        // Create the deposit transaction.
        //
        // inputs                                 | outputs
        // ---------------------------------------+-------------------------
        // 1 btc + fee: deposit request connector | 0 sat: OP_RETURN
        //                                        |-------------------------
        //                                        | 1 btc: deposit connector
        let deposit_data = DepositData {
            deposit_idx: DEPOSIT_IDX,
            deposit_request_outpoint: OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            magic_bytes: MAGIC_BYTES,
        };
        let deposit_tx = DepositTx::new(deposit_data, deposit_connector, deposit_request_connector);
        let signing_info = deposit_tx.signing_info();
        let n_of_n_signature = signing_info[0].sign(&n_of_n_keypair);
        let signed_deposit_tx = deposit_tx.finalize(n_of_n_signature);
        let deposit_txid = node.sign_and_broadcast(&signed_deposit_tx);
        node.mine_blocks(1);

        // Create the claim transaction + its CPFP child.
        //
        // inputs               | outputs
        // ---------------------+---------------------------------------
        // (4 + ω)ε sat: wallet | (3 + ω)ε sat: claim contest connector
        //                      |---------------------------------------
        //                      | ε sat: claim payout connector
        //                      |---------------------------------------
        //                      | 0 sat: cpfp connector (CPFP)
        let claim_data = ClaimData {
            claim_funds: OutPoint {
                txid: funding_txid,
                vout: 1,
            },
        };
        let claim_tx = ClaimTx::new(
            claim_data,
            claim_contest_connector.clone(),
            claim_payout_connector,
        );
        let signed_claim_child_tx = node.create_cpfp_child(&claim_tx, FEE * 2);
        let signed_claim_tx = node.sign(claim_tx.tx());
        let claim_txid = signed_claim_tx.compute_txid();
        node.submit_package([signed_claim_tx, signed_claim_child_tx]);
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
        let data = ContestData { claim_txid };
        let contest_tx = ContestTx::new(
            data,
            claim_contest_connector,
            contest_proof_connector,
            contest_payout_connector,
            contest_slash_connector,
            contest_counterproof_output,
        );

        let signing_info = contest_tx.signing_info(CONTESTING_WATCHTOWER_IDX);
        let n_of_n_signature = signing_info.sign(&n_of_n_keypair);
        let watchtower_signature =
            signing_info.sign(&watchtower_keypairs[CONTESTING_WATCHTOWER_IDX as usize]);
        let signed_contest_child_tx = node.create_cpfp_child(&contest_tx, FEE * 2);
        let signed_contest_tx = contest_tx.finalize(
            n_of_n_signature,
            CONTESTING_WATCHTOWER_IDX,
            watchtower_signature,
        );
        let contest_txid = signed_contest_tx.compute_txid();
        node.submit_package([signed_contest_tx, signed_contest_child_tx]);
        node.mine_blocks(ACK_TIMELOCK.to_consensus_u32() as usize);

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
        let operator_descriptor = Descriptor::from(node.wallet_address().clone());
        let data = ContestedPayoutData {
            deposit_txid,
            claim_txid,
            contest_txid,
        };
        let contested_payout_tx = ContestedPayoutTx::new(
            data,
            deposit_connector,
            claim_payout_connector,
            contest_payout_connector,
            contest_slash_connector,
            operator_descriptor,
        );

        let signing_info = contested_payout_tx.signing_info();
        let n_of_n_signatures = std::array::from_fn(|i| signing_info[i].sign(&n_of_n_keypair));
        let signed_payout_child_tx = node.create_cpfp_child(&contested_payout_tx, FEE * 2);
        let signed_contested_payout_tx = contested_payout_tx.finalize(n_of_n_signatures);

        node.submit_package([signed_contested_payout_tx, signed_payout_child_tx]);
        node.mine_blocks(1);
    }
}
