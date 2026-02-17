//! Universal test fixtures usable by any state machine.
//!
//! This module provides helpers for creating common test data structures
//! like blocks and transactions that are used across multiple state machines.

use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxMerkleNode, Witness, XOnlyPublicKey, block, blockdata, hashes::Hash, relative,
    script::Builder, transaction,
};
use secp256k1::{Keypair, SECP256K1, SecretKey};
use strata_bridge_p2p_types::P2POperatorPubKey;
use strata_bridge_primitives::{
    operator_table::OperatorTable, secp::EvenSecretKey, types::OperatorIdx,
};
use strata_bridge_test_utils::bitcoin::generate_spending_tx;
use strata_bridge_tx_graph2::transactions::deposit::{DepositData, DepositTx};
use strata_l1_txfmt::MagicBytes;

/// Creates a takeback transaction (script-spend with multiple witness elements).
///
/// Takeback transactions are identified by having multiple witness elements,
/// as they use script-path spending (as opposed to key-path spending).
pub fn test_takeback_tx(outpoint: OutPoint) -> Transaction {
    generate_spending_tx(outpoint, &[vec![0u8; 64], vec![1u8; 32]])
}

/// Creates a payout transaction (key-spend with empty/single witness element).
///
/// Payout transactions use key-path spending and have minimal witness data.
pub fn test_payout_tx(outpoint: OutPoint) -> Transaction {
    generate_spending_tx(outpoint, &[])
}

/// Creates a deterministic test operator table with `n` operators,
/// and marks `pov_idx` as the POV operator.
pub fn test_operator_table(n: usize, pov_idx: OperatorIdx) -> OperatorTable {
    let operators = (0..n as OperatorIdx)
        .map(|idx| {
            let byte =
                u8::try_from(idx + 1).expect("operator index too large for test key derivation");
            let sk = EvenSecretKey::from(SecretKey::from_slice(&[byte; 32]).unwrap());
            let pk = sk.public_key(SECP256K1);
            let p2p = P2POperatorPubKey::from(pk.serialize().to_vec());

            (idx, p2p, pk)
        })
        .collect();

    OperatorTable::new(operators, move |entry| entry.0 == pov_idx)
        .expect("Failed to create test operator table")
}
