//! Implementation of the Stake State Machine.

use std::sync::Arc;

use crate::{
    signals::Signal,
    stake::{
        config::StakeSMCfg,
        context::StakeSMCtx,
        duties::StakeDuty,
        errors::{SSMError, SSMResult},
        events::{NagTickEvent, RetryTickEvent, StakeEvent},
        state::StakeState,
    },
    state_machine::{SMOutput, StateMachine},
};

/// The Stake State Machine tracks the lifecycle of the stake of a given operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeSM {
    /// The context of the state machine.
    pub context: StakeSMCtx,
    /// The current state.
    pub state: StakeState,
}

impl StateMachine for StakeSM {
    type Config = Arc<StakeSMCfg>;
    type Duty = StakeDuty;
    type OutgoingSignal = Signal;
    type Event = StakeEvent;
    type Error = SSMError;

    fn process_event(
        &mut self,
        cfg: Self::Config,
        event: Self::Event,
    ) -> Result<SMOutput<Self::Duty, Self::OutgoingSignal>, Self::Error> {
        match event {
            StakeEvent::StakeDataReceived(event) => self.process_stake_data(event),
            StakeEvent::UnstakingNoncesReceived(event) => {
                self.process_unstaking_nonces_received(event)
            }
            StakeEvent::UnstakingPartialsReceived(event) => {
                self.process_unstaking_partials_received(event)
            }
            StakeEvent::StakeConfirmed(event) => self.process_stake_confirmed(event),
            StakeEvent::PreimageRevealed(event) => self.process_preimage_revealed(event),
            StakeEvent::UnstakingConfirmed(event) => self.process_unstaking_confirmed(event),
            StakeEvent::NewBlock(event) => self.process_new_block(cfg, event),
            StakeEvent::NagTick(NagTickEvent) => self.process_nag_tick(),
            StakeEvent::RetryTick(RetryTickEvent) => self.process_retry_tick(),
        }
    }
}

/// The output type of the Stake State Machine.
pub type SSMOutput = SMOutput<StakeDuty, Signal>;

impl StakeSM {
    /// Creates a new [`StakeSM`] at [`StakeState::Created`].
    ///
    /// Returns an optional initial duty. If this node tracks its own stake instance,
    /// then it should publish stake data.
    pub fn new(context: StakeSMCtx, block_height: u64) -> (Self, Option<StakeDuty>) {
        let sm = Self {
            context,
            state: StakeState::new(block_height),
        };

        let initial_duty = (sm.context().operator_table().pov_idx() == sm.context().operator_idx())
            .then_some(StakeDuty::PublishStakeData {
                operator_idx: sm.context().operator_idx(),
            });

        (sm, initial_duty)
    }

    /// Returns a reference to the context of the state machine.
    pub const fn context(&self) -> &StakeSMCtx {
        &self.context
    }

    /// Returns a reference to the current state.
    pub const fn state(&self) -> &StakeState {
        &self.state
    }

    /// Returns a mutable reference to the current state.
    pub const fn state_mut(&mut self) -> &mut StakeState {
        &mut self.state
    }

    /// Checks that the operator index exists, otherwise returns `SSMError::Rejected`.
    pub(super) fn check_operator_idx<E>(&self, operator_idx: u32, inner_event: &E) -> SSMResult<()>
    where
        E: Clone + Into<StakeEvent>,
    {
        if self.context().operator_table().contains_idx(&operator_idx) {
            Ok(())
        } else {
            Err(SSMError::rejected(
                self.state().clone(),
                inner_event.clone().into(),
                format!("Operator index {} not in operator table", operator_idx),
            ))
        }
    }
}
