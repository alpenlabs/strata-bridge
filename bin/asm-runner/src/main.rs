//! ASM Runner Binary
//!
//! Standalone binary that runs the ASM (Anchor State Machine) STF and exposes an RPC API
//! for querying ASM state.

use strata_bridge_common::logging::{self, LoggerConfig};

fn main() {
    // 1. Initialize logging
    logging::init(LoggerConfig::with_base_name("asm-runner"));
}
