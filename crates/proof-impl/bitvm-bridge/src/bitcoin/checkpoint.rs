use bitcoin::Block;
use strata_primitives::{
    bridge::OperatorIdx,
    buf::Buf32,
    l1::{BitcoinAmount, OutputRef, XOnlyPk},
};
use strata_proofimpl_btc_blockspace::block::{check_merkle_root, check_witness_commitment};
use strata_state::{
    batch::{BatchCheckpoint, BatchInfo},
    bridge_state::DepositState,
    chain_state::ChainState,
    tx::ProtocolOperation,
};
use strata_tx_parser::filter::{filter_relevant_txs, TxFilterRule};

use crate::{
    bitcoin::primitives::WithdrawalInfo,
    ckp_verifier::{verify_groth16, STRATA_CKP_VERIFICATION_KEY},
};

/// Verifies the checkpoint proof and extracts withdrawal and batch information from the chain
/// state.
pub fn verify_checkpoint_and_extract_info(
    check_point_block: &Block,
    chain_state: &ChainState,
    output_ref: &OutputRef,
) -> (WithdrawalInfo, BatchInfo) {
    let ckp = extract_batch_checkpoint(check_point_block);
    let (operator_pk, user_withdrawl_info, ckp_state_root) =
        extract_chain_state_info(chain_state, output_ref);

    assert_eq!(*ckp.batch_info().final_l2_state_hash(), ckp_state_root);

    let withdrwal_info: WithdrawalInfo = (operator_pk, user_withdrawl_info);
    let batch_info = ckp.batch_info();

    (withdrwal_info, batch_info.clone())
}

/// Extracts the `BatchCheckpoint` from the given block, ensuring its validity.
fn extract_batch_checkpoint(block: &Block) -> BatchCheckpoint {
    assert!(check_merkle_root(block));
    assert!(check_witness_commitment(block));

    let tx_filters = [TxFilterRule::RollupInscription("alpenstrata".to_string())];
    let batch_checkpoint = retrieve_batch_checkpoint(block, tx_filters.to_vec())
        .expect("Batch info not found in the block");

    let proof = batch_checkpoint.proof();

    // TODO: assert proof is not empty
    // Only use this for dev mode
    if proof.is_empty() {
        println!("Accepting with the emptry proof")
    } else {
        // TODO: Verify the checkpoint proof
        let public_params_raw = borsh::to_vec(&batch_checkpoint.proof_output()).unwrap();
        assert!(
            verify_groth16(
                proof,
                STRATA_CKP_VERIFICATION_KEY.as_ref(),
                &public_params_raw
            ),
            "Checkpoint proof verification fiiled"
        )
    }

    batch_checkpoint
}

/// Retrieves the `BatchCheckpoint` from a block using specified transaction filter rules.
fn retrieve_batch_checkpoint(
    block: &Block,
    tx_filters: Vec<TxFilterRule>,
) -> Option<BatchCheckpoint> {
    let relevant_txs = filter_relevant_txs(block, &tx_filters);
    for tx in relevant_txs {
        if let ProtocolOperation::RollupInscription(signed_batch) = tx.proto_op() {
            // TODO: Apply cred rule
            let batch: BatchCheckpoint = signed_batch.clone().into();
            return Some(batch);
        }
    }
    None
}

/// Parses the chain state to extract the operator's public key, withdrawal information, and the
/// chain state root.
fn extract_chain_state_info(
    chain_state: &ChainState,
    output_ref: &OutputRef,
) -> (OperatorIdx, (XOnlyPk, BitcoinAmount), Buf32) {
    let deposit_entry = chain_state
        .deposits_table()
        .deposits()
        .find(|el| *el.output() == *output_ref)
        .expect("Deposit entry not found for the given output_ref");

    // We need the deposit state in `DepositState::Dispatched`
    if let DepositState::Dispatched(deposit_state) = deposit_entry.deposit_state() {
        // Operator
        let operator_idx = deposit_state.assignee();

        // Destination info
        let withdraw_output = deposit_state.cmd().withdraw_outputs().first().unwrap();
        let dest_address = withdraw_output.dest_addr();
        // TODO: BitcoinAmt is always fixed right ???
        let amt = BitcoinAmount::from_sat(1000000000);

        // Chain state root
        let chain_root = chain_state.compute_state_root();

        return (operator_idx, (*dest_address, amt), chain_root);
    }
    panic!("deposit state not in `DepositState::Dispatched`")
}

#[cfg(test)]
mod test {
    use prover_test_utils::{get_bitcoin_client, get_chain_state};
    use strata_btcio::rpc::traits::Reader;
    use strata_state::bridge_state::DepositEntry;

    use crate::bitcoin::checkpoint::{
        extract_batch_checkpoint, extract_chain_state_info, verify_checkpoint_and_extract_info,
    };

    #[tokio::test]
    async fn test_verify_checkpoint_and_extract_info() {
        let (chain_state, output_ref) = get_chain_state();
        let block_num: u64 = 787;
        let btc_client = get_bitcoin_client();
        let block = btc_client.get_block_at(block_num).await.unwrap();

        verify_checkpoint_and_extract_info(&block, &chain_state, &output_ref);
    }

    #[tokio::test]
    async fn test_retrieve_batch_checkpoint() {
        let block_num: u64 = 787;
        let btc_client = get_bitcoin_client();
        let block = btc_client.get_block_at(block_num).await.unwrap();

        let _batch_checkpoint = extract_batch_checkpoint(&block);
        println!("{:?}", _batch_checkpoint);
    }

    #[test]
    fn test_extract_chain_state_info() {
        let (chain_state, output_ref) = get_chain_state();

        // Output ref
        let deposit_entry: Option<&DepositEntry> = chain_state
            .deposits_table()
            .deposits()
            .find(|el| *el.output() == output_ref);

        assert!(deposit_entry.is_some());

        let _infos = extract_chain_state_info(&chain_state, &output_ref);
    }
}
