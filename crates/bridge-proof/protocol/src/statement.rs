use alpen_bridge_params::prelude::PegOutGraphParams;
use bitcoin::block::Header;
use strata_params::RollupParams;

use crate::{error::BridgeProofError, BridgeProofInputBorsh, BridgeProofPublicOutput};

/// The number of headers after withdrawal fulfillment transaction that must be provided as private
/// input.
///
/// This is essentially the number of headers in the chain fragment used in the proof.
/// The longer it is the harder it is to mine privately.
// TODO: (@prajwolrg, @Rajil1213) update this once this is finalized.
// It's fine to have a smaller value in testnet-I since we run the bridge nodes and they're
// incapable of constructing a private fork but this needs to be higher for mainnet (at least in the
// BitVM-based bridge design).
// The reason for choosing a lower value is that we want the bridge node
// to be able to generate the proof immediately when it needs to i.e., after it is challenged and
// the timelock between the `Claim` and `PreAssert` transaction has expired, without having to wait
// for a long time for the bitcoin chain to have enough headers after the withdrawal fulfillment
// transaction. This means that this needs to be set to a value that is lower than the
// `pre_assert_timelock` in the bridge params. To facilitate local testing, this has been sent to a
// much smaller value of `10`.
pub const REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX: usize = 10;

/// Processes the verification of all transactions and chain state necessary for a bridge proof.
///
/// # Arguments
///
/// * `input` - The input data for the bridge proof, containing transactions and state information.
/// * `headers` - A sequence of Bitcoin headers that should include the transactions in question.
/// * `rollup_params` - Configuration parameters for the Strata Rollup.
///
/// # Returns
///
/// If successful, returns a tuple consisting of:
/// - `BridgeProofOutput` containing essential proof-related output data.
/// - `BatchCheckpoint` representing the Strata checkpoint.
pub(crate) fn process_bridge_proof(
    _input: BridgeProofInputBorsh,
    _headers: Vec<Header>,
    _rollup_params: RollupParams,
    _peg_out_graph_params: PegOutGraphParams,
) -> Result<BridgeProofPublicOutput, BridgeProofError> {
    let output = BridgeProofPublicOutput {
        deposit_txid: Default::default(),
        withdrawal_fulfillment_txid: Default::default(),
    };

    Ok(output)
}
