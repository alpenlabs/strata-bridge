//! Common functionalities across different modules in the stake state machine duty execution
//! context.

use bitcoin::OutPoint;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SecretService, StakeChainPreimages};

use crate::errors::ExecutorError;

/// Fetches the preimage from the secret service given an [`OutPoint`] as the seed.
pub(super) async fn get_preimage(
    s2_client: &SecretServiceClient,
    outpoint: OutPoint,
) -> Result<[u8; 32], ExecutorError> {
    const STAKE_TX_INDEX: u32 = 0; // there is only one stake tx.

    let preimage_client = s2_client.stake_chain_preimages();

    preimage_client
        .get_preimg(outpoint.txid, outpoint.vout, STAKE_TX_INDEX)
        .await
        .map_err(ExecutorError::SecretServiceErr)
}
