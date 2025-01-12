mod tx_inclusion_proof;

use bitcoin::block::Header;
use strata_state::chain_state::Chainstate;
pub struct BridgeProofInput {
    headers: Vec<Header>,
    chain_state: Chainstate,
}
