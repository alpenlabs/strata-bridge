use crate::{
    deposit::{
        errors::{DSMError, DSMResult},
        events::NewBlockEvent,
        machine::{DSMOutput, DepositSM},
        state::DepositState,
    },
    signals::{DepositSignal, DepositToGraph},
    state_machine::SMOutput,
};

impl DepositSM {
    /// Processes information about new blocks and applies any updates related to block height
    /// timeouts
    pub(crate) fn process_new_block(&mut self, new_block: NewBlockEvent) -> DSMResult<DSMOutput> {
        let last_processed_block_height = self.state().last_processed_block_height();
        if last_processed_block_height.is_some_and(|height| *height >= new_block.block_height) {
            return Err(DSMError::duplicate(self.state().clone(), new_block.into()));
        }

        match self.state_mut() {
            DepositState::Created {
                last_block_height, ..
            }
            | DepositState::GraphGenerated {
                last_block_height, ..
            }
            | DepositState::DepositNoncesCollected {
                last_block_height, ..
            }
            | DepositState::DepositPartialsCollected {
                last_block_height, ..
            }
            | DepositState::Deposited {
                last_block_height, ..
            }
            | DepositState::Assigned {
                last_block_height, ..
            }
            | DepositState::CooperativePathFailed {
                last_block_height, ..
            } => {
                *last_block_height = new_block.block_height;

                Ok(SMOutput {
                    duties: vec![],
                    signals: vec![],
                })
            }

            DepositState::Fulfilled {
                last_block_height,
                assignee,
                cooperative_payout_deadline: cooperative_payment_deadline,
                ..
            }
            | DepositState::PayoutDescriptorReceived {
                last_block_height,
                assignee,
                cooperative_payment_deadline,
                ..
            }
            | DepositState::PayoutNoncesCollected {
                last_block_height,
                assignee,
                cooperative_payment_deadline,
                ..
            } => {
                let assignee = *assignee; // reassign to get past the borrow-checker

                // Check for `>=` instead of just `>` to allow disabling cooperative payout by
                // setting this param to zero. This will come into effect after a 1-block delay
                // (when the next block is observed).
                let has_cooperative_payout_timed_out =
                    new_block.block_height >= *cooperative_payment_deadline;

                if has_cooperative_payout_timed_out {
                    // Transition to CooperativePathFailed state
                    self.state = DepositState::CooperativePathFailed {
                        last_block_height: new_block.block_height,
                    };

                    // activate the graph if the cooperative payout path has failed
                    return Ok(SMOutput {
                        duties: vec![],
                        signals: vec![DepositSignal::ToGraph(
                            DepositToGraph::CooperativePayoutFailed {
                                assignee,
                                deposit_idx: self.context().deposit_idx(),
                            },
                        )],
                    });
                }

                *last_block_height = new_block.block_height;

                Ok(SMOutput {
                    duties: vec![],
                    signals: vec![],
                })
            }

            DepositState::Spent | DepositState::Aborted => Err(DSMError::rejected(
                self.state().clone(),
                new_block.into(),
                "New blocks irrelevant in terminal state",
            )),
        }
    }
}
