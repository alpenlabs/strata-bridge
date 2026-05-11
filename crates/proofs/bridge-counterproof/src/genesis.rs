//! Trust anchors for the bridge counterproof

/// Trust anchors used by the counterproof.
#[derive(Debug, Default)]
pub struct BridgeCounterproofGenesis {}

/// Builds the bridge-counterproof genesis.
pub const fn load_genesis() -> BridgeCounterproofGenesis {
    BridgeCounterproofGenesis {}
}
