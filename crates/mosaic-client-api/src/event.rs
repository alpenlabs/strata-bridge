use strata_bridge_primitives::types::GraphIdx;

/// Events emitted by the mosaic client's background pollers.
#[derive(Debug, Clone, Copy)]
pub enum MosaicEvent {
    /// Garbler side: adaptor signatures have been received and verified by mosaic.
    /// Deposit is ready to be processed by bridge.
    AdaptorsVerified(GraphIdx),
}
