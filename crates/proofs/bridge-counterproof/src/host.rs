//! Host construction for [`crate::CounterproofProgram`].

#[cfg(not(feature = "sp1"))]
mod backend {
    use zkaleido_native_adapter::NativeHost;

    use crate::statements::process_counterproof;

    /// The host used to generate bridge counterproofs.
    ///
    /// Resolves to `NativeHost` in the default build, `SP1Host` under the
    /// `sp1` feature.
    pub type BridgeCounterproofHost = NativeHost;

    /// Constructs the [`BridgeCounterproofHost`] for the active backend.
    pub fn build_bridge_counterproof_host() -> BridgeCounterproofHost {
        NativeHost::new(process_counterproof)
    }
}

#[cfg(feature = "sp1")]
mod backend {
    use zkaleido_sp1_host::SP1Host;

    /// The host used to generate bridge counterproofs.
    ///
    /// Resolves to `NativeHost` in the default build, `SP1Host` under the
    /// `sp1` feature.
    pub type BridgeCounterproofHost = SP1Host;

    /// Constructs the [`BridgeCounterproofHost`] for the active backend.
    pub fn build_bridge_counterproof_host() -> BridgeCounterproofHost {
        todo!("SP1 bridge-counterproof host not yet wired")
    }
}

pub use backend::{BridgeCounterproofHost, build_bridge_counterproof_host};
