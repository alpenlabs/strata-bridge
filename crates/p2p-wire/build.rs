//! Compile-time `.proto` files to Rust code and types.
use std::io::Result;

/// Compiles the `.proto` files as Rust types.
fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "proto/strata/bitvm2/p2p/v1/getmessage.proto",
            "proto/strata/bitvm2/p2p/v1/gossipsub.proto",
        ],
        &["proto/"],
    )?;
    Ok(())
}
