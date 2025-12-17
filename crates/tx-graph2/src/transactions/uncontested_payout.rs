//! This module contains the claim transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    OutPoint, Psbt, Transaction, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_bridge_primitives::scripts::prelude::{create_tx_ins, create_tx_outs};
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::{
    connectors::{
        prelude::{
            ClaimContestConnector, ClaimContestSpendPath, ClaimContestWitness,
            ClaimPayoutConnector, ClaimPayoutWitness, NOfNConnector,
        },
        Connector,
    },
    transactions::{deposit::DepositTx, prelude::ClaimTx, ParentTx, PresignedTx, SigningInfo},
};

/// Data that is needed to construct a [`UncontestedPayoutTx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncontestedPayoutData {
    /// ID of the claim transaction.
    pub claim_txid: Txid,
    /// ID of the deposit transaction.
    pub deposit_txid: Txid,
    /// Descriptor where the operator receives the payout.
    pub operator_descriptor: Descriptor,
}

/// The uncontested payout transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UncontestedPayoutTx {
    psbt: Psbt,
    prevouts: [TxOut; 3],
    deposit_connector: NOfNConnector,
    claim_contest_connector: ClaimContestConnector,
    claim_payout_connector: ClaimPayoutConnector,
}

impl UncontestedPayoutTx {
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 0;

    /// Creates an uncontested payout transaction.
    pub fn new(
        data: UncontestedPayoutData,
        deposit_connector: NOfNConnector,
        claim_contest_connector: ClaimContestConnector,
        claim_payout_connector: ClaimPayoutConnector,
    ) -> Self {
        let utxos = [
            OutPoint {
                txid: data.deposit_txid,
                vout: DepositTx::DEPOSIT_VOUT,
            },
            OutPoint {
                txid: data.claim_txid,
                vout: ClaimTx::CONTEST_VOUT,
            },
            OutPoint {
                txid: data.claim_txid,
                vout: ClaimTx::PAYOUT_VOUT,
            },
        ];
        let prevouts = [
            deposit_connector.tx_out(),
            claim_contest_connector.tx_out(),
            claim_payout_connector.tx_out(),
        ];

        let mut input = create_tx_ins(utxos);
        input[1].sequence = claim_contest_connector.contest_timelock().to_sequence();

        let output = create_tx_outs([(
            data.operator_descriptor.to_script(),
            deposit_connector.value()
                + claim_contest_connector.value()
                + claim_payout_connector.value(),
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
            claim_contest_connector,
            claim_payout_connector,
        }
    }
}

impl ParentTx for UncontestedPayoutTx {
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

impl PresignedTx<3> for UncontestedPayoutTx {
    type ExtraWitness = ();

    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn get_signing_info(
        &self,
        cache: &mut SighashCache<&Transaction>,
        input_index: usize,
    ) -> SigningInfo {
        match input_index {
            0 => self.deposit_connector.signing_info(
                cache,
                Prevouts::All(&self.prevouts),
                input_index,
            ),
            1 => self.claim_contest_connector.uncontested_signing_info(
                cache,
                Prevouts::All(&self.prevouts),
                input_index,
            ),
            2 => self.claim_payout_connector.payout_signing_info(
                cache,
                Prevouts::All(&self.prevouts),
                input_index,
            ),
            _ => panic!("Input index is out of bounds"),
        }
    }

    fn finalize(
        self,
        n_of_n_signatures: [schnorr::Signature; 3],
        _extra: &Self::ExtraWitness,
    ) -> Transaction {
        let mut psbt = self.psbt;

        let deposit_witness = n_of_n_signatures[0];
        let claim_contest_witness = ClaimContestWitness {
            n_of_n_signature: n_of_n_signatures[1],
            spend_path: ClaimContestSpendPath::Uncontested,
        };
        let claim_payout_witness = ClaimPayoutWitness::Payout {
            output_key_signature: n_of_n_signatures[2],
        };

        self.deposit_connector
            .finalize_input(&mut psbt.inputs[0], &deposit_witness);
        self.claim_contest_connector
            .finalize_input(&mut psbt.inputs[1], &claim_contest_witness);
        self.claim_payout_connector
            .finalize_input(&mut psbt.inputs[2], &claim_payout_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::{sha256, Hash},
        relative, Amount, Network, TxOut,
    };
    use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{
        connectors::{
            prelude::{
                ClaimContestConnector, ClaimPayoutConnector, CpfpConnector,
                DepositRequestConnector, NOfNConnector,
            },
            test_utils::BitcoinNode,
        },
        transactions::prelude::{ClaimData, ClaimTx, DepositData, DepositTx},
    };

    const NETWORK: Network = Network::Regtest;
    const N_WATCHTOWERS: usize = 10;
    const CONTEST_TIMELOCK: relative::LockTime = relative::LockTime::from_height(10);
    const REFUND_TIMELOCK: relative::LockTime = CONTEST_TIMELOCK;
    const UNSTAKING_PREIMAGE: [u8; 32] = [0; 32];
    const DEPOSIT: Amount = Amount::from_sat(100_000_000);
    const FEE: Amount = Amount::from_sat(1_000);

    #[test]
    fn uncontested_payout() {
        let mut node = BitcoinNode::new();

        let n_of_n_keypair = generate_keypair();
        let watchtower_keypairs: Vec<_> = (0..N_WATCHTOWERS).map(|_| generate_keypair()).collect();
        let admin_keypair = generate_keypair();
        let depositor_keypair = generate_keypair();

        let n_of_n_pubkey = n_of_n_keypair.x_only_public_key().0;
        let watchtower_pubkeys: Vec<_> = watchtower_keypairs
            .iter()
            .map(|k| k.x_only_public_key().0)
            .collect();
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
        let cpfp_connector = CpfpConnector::new(NETWORK);

        // Create a deposit request transaction dummy.
        // Crucially, the deposit request connector is vout 1.
        //
        // inputs         | outputs
        // ---------------+---------------------------------------
        // 50 btc: wallet | 50 btc - 1 btc - fee * 2: wallet
        //                |---------------------------------------
        //                | 1 btc + fee: deposit request connector
        let input = create_tx_ins([node.next_coinbase_outpoint()]);
        let output = vec![
            TxOut {
                value: node.coinbase_amount() - deposit_request_connector.value() - FEE,
                script_pubkey: node.wallet_address().script_pubkey(),
            },
            deposit_request_connector.tx_out(),
        ];
        let deposit_request_tx = create_tx(input, output);
        let deposit_request_txid = node.sign_and_broadcast(&deposit_request_tx);
        node.mine_blocks(1);

        // Create the deposit transaction.
        //
        // inputs                                 | outputs
        // ---------------------------------------+-------------------------
        // 1 btc + fee: deposit request connector | 0 sat: OP_RETURN
        //                                        |-------------------------
        //                                        | 1 btc: deposit connector
        let deposit_data = DepositData {
            deposit_idx: u32::default(),
            deposit_request_txid,
        };
        let deposit_tx = DepositTx::new(deposit_data, deposit_connector, deposit_request_connector);
        let signing_info = deposit_tx.signing_info();
        let n_of_n_signatures = std::array::from_fn(|i| signing_info[i].sign(&n_of_n_keypair));
        let signed_deposit_tx = deposit_tx.finalize(n_of_n_signatures, &());
        let deposit_txid = node.sign_and_broadcast(&signed_deposit_tx);
        node.mine_blocks(1);

        // Create a transaction that funds the claim input.
        //
        // inputs         | outputs
        // ---------------+------------------------------------
        // 50 btc: wallet | (4 + ω)ε sat: wallet
        //                |------------------------------------
        //                | 50 btc - (4 + ω)ε sat - fee: wallet
        let input = create_tx_ins([node.next_coinbase_outpoint()]);
        let output = vec![
            TxOut {
                value: claim_contest_connector.value() + claim_payout_connector.value(),
                script_pubkey: node.wallet_address().script_pubkey(),
            },
            TxOut {
                value: node.coinbase_amount()
                    - claim_contest_connector.value()
                    - claim_payout_connector.value()
                    - FEE,
                script_pubkey: node.wallet_address().script_pubkey(),
            },
        ];
        let funding_tx = create_tx(input, output);
        let funding_txid = node.sign_and_broadcast(&funding_tx);
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
                vout: 0,
            },
        };
        let claim_tx = ClaimTx::new(
            claim_data,
            claim_contest_connector.clone(),
            claim_payout_connector,
            cpfp_connector,
        );
        let signed_claim_tx = node.sign(claim_tx.tx());
        let signed_claim_child_tx = node.create_cpfp_child(&claim_tx, FEE * 2);
        node.submit_package([signed_claim_tx, signed_claim_child_tx]);
        node.mine_blocks(CONTEST_TIMELOCK.to_consensus_u32() as usize);
        let claim_txid = claim_tx.tx().compute_txid();

        // Create the uncontested payout transaction + its CPFP child.
        //
        // inputs                                | outputs
        // --------------------------------------+----------------------------------
        // 1 btc: deposit connector              | 1 btc + (4 + ω)ε: operator (CPFP)
        // --------------------------------------|
        // (3 + ω)ε sat: claim contest connector |
        // --------------------------------------|
        // ε sat: claim payout connector         |
        let descriptor = Descriptor::from(node.wallet_address().clone());
        let data = UncontestedPayoutData {
            claim_txid,
            deposit_txid,
            operator_descriptor: descriptor.clone(),
        };
        let uncontested_payout_tx = UncontestedPayoutTx::new(
            data,
            deposit_connector,
            claim_contest_connector,
            claim_payout_connector,
        );

        let signing_info = uncontested_payout_tx.signing_info();
        let n_of_n_signatures = std::array::from_fn(|i| signing_info[i].sign(&n_of_n_keypair));
        let signed_payout_child_tx = node.create_cpfp_child(&uncontested_payout_tx, FEE * 2);
        let signed_uncontested_payout_tx = uncontested_payout_tx.finalize(n_of_n_signatures, &());

        node.submit_package([signed_uncontested_payout_tx, signed_payout_child_tx]);
        node.mine_blocks(1);
    }
}
