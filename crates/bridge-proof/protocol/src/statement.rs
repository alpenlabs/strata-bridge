use bitcoin::hashes::Hash;
use borsh::BorshDeserialize;
use strata_l1tx::envelope::parser::parse_envelope_data;
use strata_primitives::l1::{BitcoinAmount, XOnlyPk};
use strata_state::{
    batch::{BatchCheckpoint, SignedBatchCheckpoint},
    bridge_state::DepositState,
    l1::get_btc_params,
};

use crate::{
    primitives::{BridgeProofPublicParams, StrataBridgeState},
    BridgeProofInput,
};

pub const STRATA_CKP_VERIFICATION_KEY: &str =
    "0x005027dda93318eb6bb85acd3a924f9d6d63006672ed2ff14c87352acf538993";

pub const ROLLUP_NAME: &str = "alpenstrata";

pub fn process_bridge_proof(
    input: BridgeProofInput,
    state: StrataBridgeState,
) -> Result<BridgeProofPublicParams, Box<dyn std::error::Error>> {
    let BridgeProofInput {
        headers,
        deposit_txid,
        checkpoint: (checkpoint_height, checkpoint),
        bridge_out: (bridge_out_height, bridge_out),
    } = input;

    let params = &get_btc_params();

    if bridge_out_height <= checkpoint_height {
        return Err("bridge_out before checkpoint".into());
    }
    let checkpoint_header_index =
        (checkpoint_height - state.initial_header_state.last_verified_block_num - 1) as usize;
    let bridge_out_header_index =
        (bridge_out_height - state.initial_header_state.last_verified_block_num - 1) as usize;

    // verify header chain
    let mut hvs = state.initial_header_state.clone();
    headers.iter().for_each(|header| {
        hvs.check_and_update_full(header, params);
    });

    // verify checkpoint inclusion proof
    checkpoint
        .verify(&headers[checkpoint_header_index])
        .map_err(|_err| "invalid checkpoint tx: non-inclusion")?;

    // verify bridge_out inclusion proof
    bridge_out
        .verify(&headers[bridge_out_header_index])
        .map_err(|_err| "invalid bridge_out tx: non-inclusion")?;

    // TODO: parse and validate bridge out tx
    let (operator_id, withdrawal_address, withdrawal_amount) = {
        let operator_id = u32::from_be_bytes(
            bridge_out.tx.0.output[0].script_pubkey.as_bytes()[2..6]
                .try_into()
                .map_err(|_| "bridge_out: invalid operator id")?,
        );
        let withdrawal_amount = BitcoinAmount::from_sat(bridge_out.tx.0.output[1].value.to_sat());
        let withdrawal_address =
            XOnlyPk::try_from_slice(&bridge_out.tx.0.output[1].script_pubkey.as_bytes()[2..])
                .map_err(|_| "bridge_out: invalid withdrawal address")?;
        (operator_id, withdrawal_address, withdrawal_amount)
    };

    // verify checkpoint proof and withdrawal state
    {
        // extract batch checkpoint from checkpoint tx
        let script = checkpoint.tx.0.input[0].witness.tapscript().unwrap();
        let inscription = parse_envelope_data(&script.into(), ROLLUP_NAME).unwrap();
        let batch_checkpoint: BatchCheckpoint =
            borsh::from_slice::<SignedBatchCheckpoint>(inscription.data())
                .unwrap()
                .into();

        let batch_checkpoint_proof = batch_checkpoint.proof();
        // TODO: Fix this
        if !batch_checkpoint_proof.is_empty() {
            let public_params = borsh::to_vec(&batch_checkpoint.proof_output()).unwrap();

            // TODO: optimization
            sp1_verifier::Groth16Verifier::verify(
                batch_checkpoint_proof.as_bytes(),
                &public_params,
                STRATA_CKP_VERIFICATION_KEY,
                &sp1_verifier::GROTH16_VK_BYTES,
            )
            .map_err(|_| "checkpoint: internal proof verification failed")?;
        }

        let batch_info = batch_checkpoint.batch_info();
        if state.compute_state_root() != *batch_info.final_l2_state_hash() {
            return Err("checkpoint: strata state root mismatch".into());
        }

        let entry = state
            .deposits_table()
            .deposits()
            .find(|&el| el.output().outpoint().txid.to_byte_array() == deposit_txid)
            .ok_or("checkpoint: deposit_txid does not exist in deposits_table")?;

        let dispatched_state = match entry.deposit_state() {
            DepositState::Dispatched(dispatched_state) => dispatched_state,
            _ => return Err("checkpoint: withdrawal not dispatched for given deposit".into()),
        };

        let withdrawal = dispatched_state.cmd().withdraw_outputs().first().unwrap();

        if operator_id != dispatched_state.assignee()
            || withdrawal_address != *withdrawal.dest_addr()
            || withdrawal_amount != BitcoinAmount::from_sat(800000000)
        {
            return Err("checkpoint: invalid operator or withdrawal address or amount".into());
        }

        if batch_info.l1_transition.1 != state.initial_header_state.compute_hash().unwrap() {
            return Err("checkpoint: invalid initial_header_state".into());
        }
    }

    Ok(BridgeProofPublicParams {
        deposit_txid,
        withdrawal_fulfillment_txid: bridge_out.tx.0.compute_txid().to_byte_array(),
    })
}

/// Wrapper to be called by the bridge operator
pub fn run_process_bridge_proof(
    serialized_input: &[u8],
    state: StrataBridgeState,
) -> Result<BridgeProofPublicParams, Box<dyn std::error::Error>> {
    process_bridge_proof(bincode::deserialize(serialized_input).unwrap(), state)
}
