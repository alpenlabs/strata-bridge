//! Implementation of the Stake State Machine.

use std::sync::Arc;

use crate::{
    signals::Signal,
    stake::{
        config::StakeSMCfg, context::StakeSMCtx, duties::StakeDuty, errors::SSMError,
        events::StakeEvent, state::StakeState,
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
        let _ = cfg;
        match event {
            StakeEvent::StakeDataReceived(event) => self.process_stake_data(event),
            StakeEvent::UnstakingNoncesReceived(_) => todo!(),
            StakeEvent::UnstakingPartialsReceived(_) => todo!(),
            StakeEvent::StakeConfirmed(_) => todo!(),
            StakeEvent::PreimageRevealed(_) => todo!(),
            StakeEvent::UnstakingConfirmed(_) => todo!(),
            StakeEvent::NewBlock(_) => todo!(),
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
}
