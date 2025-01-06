use bitcoin::Txid;
use strata_bridge_primitives::{
    params::connectors::{
        NUM_PKS_A160, NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A256, NUM_PKS_A256_PER_CONNECTOR,
    },
    types::OperatorIdx,
};
use tracing::trace;

use super::prelude::*;
use crate::connectors::prelude::*;

#[derive(Debug, Clone)]
pub struct AssertChainData {
    pub pre_assert_data: PreAssertData,
    pub deposit_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct AssertChain {
    pub pre_assert: PreAssertTx,
    pub assert_data: AssertDataTxBatch,
    pub post_assert: PostAssertTx,
}

impl AssertChain {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        data: AssertChainData,
        operator_idx: OperatorIdx,
        connector_c0: ConnectorC0,
        connector_s: ConnectorS,
        connector_a30: ConnectorA30,
        connector_a31: ConnectorA31,
        connector_a160_factory: ConnectorA160Factory<NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160>,
        connector_a256_factory: ConnectorA256Factory<NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256>,
    ) -> Self {
        let pre_assert = PreAssertTx::new(
            data.pre_assert_data,
            connector_c0,
            connector_s,
            connector_a256_factory,
            connector_a160_factory,
        );
        let pre_assert_txid = pre_assert.compute_txid();
        trace!(event = "created pre-assert tx", %pre_assert_txid, %operator_idx);

        let pre_assert_net_output_stake = pre_assert.remaining_stake();

        let assert_data_input = AssertDataTxInput {
            pre_assert_txid,
            pre_assert_txouts: pre_assert.tx_outs(),
        };

        trace!(event = "constructed assert data input", ?assert_data_input);
        let assert_data = AssertDataTxBatch::new(assert_data_input, connector_s);

        let assert_data_txids = assert_data.compute_txids().to_vec();
        trace!(event = "created assert_data tx batch", ?assert_data_txids, %operator_idx);

        let post_assert_data = PostAssertTxData {
            assert_data_txids,
            pre_assert_txid,
            input_amount: pre_assert_net_output_stake,
            deposit_txid: data.deposit_txid,
        };

        let post_assert = PostAssertTx::new(
            post_assert_data,
            operator_idx,
            connector_s,
            connector_a30,
            connector_a31,
        );

        trace!(event = "created post_assert tx", post_assert_txid = ?post_assert.compute_txid(), %operator_idx);

        Self {
            pre_assert,
            assert_data,
            post_assert,
        }
    }
}
