[package]
edition = "2021"
name = "strata-bridge-tx-graph"
version = "0.1.0"

[lints]
rust.missing_debug_implementations = "warn"
rust.rust_2018_idioms = { level = "deny", priority = -1 }
rust.unreachable_pub = "warn"
// rust.unused_crate_dependencies = "deny"
rust.unused_must_use = "deny"

[dependencies]
strata-bridge-contexts.workspace = true

bitcoin = { workspace = true, features = ["rand-std"] }
bitcoin-script = { workspace = true }
bitcoin-scriptexec = { workspace = true }
esplora-client.workspace = true
lazy_static.workspace = true
musig2 = { workspace = true, features = ["serde"] }
rand.workspace = true
serde.workspace = true
serde_json.workspace = true
sha2.workspace = true

[dev-dependencies]
hex.workspace = true
