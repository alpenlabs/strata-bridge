use crate::types::{DepositIdx, OperatorIdx};

/// Events emitted by the mosaic client's background pollers.
#[derive(Debug, Clone, Copy)]
pub enum MosaicEvent {
    /// Garbler side: adaptor signatures have been received and verified by mosaic.
    /// Deposit is ready to be processed by bridge.
    AdaptorsVerified {
        /// The operator this event is for.
        operator_idx: OperatorIdx,
        /// The deposit this event is for.
        deposit_idx: DepositIdx,
    },
}
