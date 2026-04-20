use musig2::AggNonce;
use strata_bridge_p2p_types::NagRequestPayload;
use strata_bridge_tx_graph::{musig_functor::StakeFunctor, stake_graph::StakeGraph};

use crate::{
    stake::{
        config::StakeSMCfg,
        context::MinimumStakeData,
        duties::StakeDuty,
        errors::{SSMError, SSMResult},
        events::{NagReceivedEvent, StakeEvent},
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes an incoming nag from another operator.
    ///
    /// # Note
    ///
    /// Sender validation, recipient check, and operator_idx routing are done upstream.
    pub(crate) fn process_nag_received(
        &self,
        cfg: &StakeSMCfg,
        event: NagReceivedEvent,
    ) -> SSMResult<SSMOutput> {
        let duties = match &event.payload {
            NagRequestPayload::UnstakingData { .. } => self.process_unstaking_data_nag(&event),
            NagRequestPayload::UnstakingNonces { .. } => {
                self.process_unstaking_nonces_nag(cfg, &event)
            }
            NagRequestPayload::UnstakingPartials { .. } => {
                self.process_unstaking_partials_nag(cfg, &event)
            }
            NagRequestPayload::GraphData { .. }
            | NagRequestPayload::GraphNonces { .. }
            | NagRequestPayload::GraphPartials { .. } => {
                Err(self.reject_nag(&event, "Graph-domain nag is not applicable to StakeSM"))
            }
            NagRequestPayload::DepositNonce { .. }
            | NagRequestPayload::DepositPartial { .. }
            | NagRequestPayload::PayoutNonce { .. }
            | NagRequestPayload::PayoutPartial { .. } => {
                Err(self.reject_nag(&event, "Deposit-domain nag is not applicable to StakeSM"))
            }
        }?;

        Ok(SMOutput::with_duties(duties))
    }

    fn reject_nag(&self, event: &NagReceivedEvent, detail: impl Into<String>) -> SSMError {
        let reason = format!(
            "{}; payload={:?}; sender_operator_idx={}; current_state={}",
            detail.into(),
            event.payload,
            event.sender_operator_idx,
            self.state()
        );

        SSMError::rejected(
            self.state().clone(),
            StakeEvent::NagReceived(event.clone()),
            reason,
        )
    }

    fn process_unstaking_data_nag(&self, event: &NagReceivedEvent) -> SSMResult<Vec<StakeDuty>> {
        match self.state() {
            StakeState::Created { .. }
            | StakeState::StakeGraphGenerated { .. }
            | StakeState::UnstakingNoncesCollected { .. }
            | StakeState::UnstakingSigned { .. } => Ok(vec![StakeDuty::PublishStakeData {
                operator_idx: self.context().operator_idx(),
            }]),
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag UnstakingData in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable UnstakingData nag; expected state(s): Created | StakeGraphGenerated | UnstakingNoncesCollected | UnstakingSigned",
                ))
            }
        }
    }

    fn process_unstaking_nonces_nag(
        &self,
        cfg: &StakeSMCfg,
        event: &NagReceivedEvent,
    ) -> SSMResult<Vec<StakeDuty>> {
        match self.state() {
            StakeState::StakeGraphGenerated { stake_data, .. }
            | StakeState::UnstakingNoncesCollected { stake_data, .. }
            | StakeState::UnstakingSigned { stake_data, .. } => Ok(vec![
                self.build_publish_unstaking_nonces_duty(cfg, stake_data),
            ]),
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag UnstakingNonces in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable UnstakingNonces nag; expected state(s): StakeGraphGenerated | UnstakingNoncesCollected | UnstakingSigned",
                ))
            }
        }
    }

    fn process_unstaking_partials_nag(
        &self,
        cfg: &StakeSMCfg,
        event: &NagReceivedEvent,
    ) -> SSMResult<Vec<StakeDuty>> {
        match self.state() {
            StakeState::UnstakingNoncesCollected {
                stake_data,
                agg_nonces,
                ..
            } => Ok(vec![self.build_publish_unstaking_partials_duty(
                cfg,
                stake_data,
                agg_nonces.clone(),
            )]),
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag UnstakingPartials in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable UnstakingPartials nag; expected state(s): UnstakingNoncesCollected",
                ))
            }
        }
    }

    fn build_publish_unstaking_nonces_duty(
        &self,
        cfg: &StakeSMCfg,
        stake_data: &MinimumStakeData,
    ) -> StakeDuty {
        let stake_graph = StakeGraph::new(stake_data.expand(*cfg, self.context()));
        let graph_inpoints = stake_graph.musig_inpoints().boxed();
        let graph_tweaks = stake_graph
            .musig_signing_info()
            .map(|info| info.tweak)
            .boxed();
        let ordered_pubkeys = self
            .context()
            .operator_table()
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        StakeDuty::PublishUnstakingNonces {
            operator_idx: self.context().operator_idx(),
            graph_inpoints,
            graph_tweaks,
            ordered_pubkeys,
        }
    }

    fn build_publish_unstaking_partials_duty(
        &self,
        cfg: &StakeSMCfg,
        stake_data: &MinimumStakeData,
        agg_nonces: Box<StakeFunctor<AggNonce>>,
    ) -> StakeDuty {
        let stake_graph = StakeGraph::new(stake_data.expand(*cfg, self.context()));
        let graph_inpoints = stake_graph.musig_inpoints().boxed();
        let (graph_tweaks, sighashes) = stake_graph
            .musig_signing_info()
            .map(|info| (info.tweak, info.sighash))
            .unzip();
        let ordered_pubkeys = self
            .context()
            .operator_table()
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        StakeDuty::PublishUnstakingPartials {
            operator_idx: self.context().operator_idx(),
            graph_inpoints,
            graph_tweaks: graph_tweaks.boxed(),
            sighashes: sighashes.boxed(),
            ordered_pubkeys,
            agg_nonces,
        }
    }
}
