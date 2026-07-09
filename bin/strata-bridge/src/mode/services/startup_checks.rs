//! Startup consistency checks between the bridge and its external components
use anyhow::Result;
use strata_bridge_common::params::Params;
use strata_bridge_counterproof::BridgeCounterproofHost;
use strata_bridge_proof::BridgeProofHost;
use strata_predicate::PredicateKey;

/// Runs every startup consistency check; the failure aborts node startup.
pub(in crate::mode) fn verify(
    params: &Params,
    bridge_proof_host: &BridgeProofHost,
    counterproof_host: &BridgeCounterproofHost,
) -> Result<()> {
    verify_predicates(params, bridge_proof_host, counterproof_host)?;
    Ok(())
}

/// Each proof host's loaded guest ELF matches its corresponding verification predicate.
fn verify_predicates(
    params: &Params,
    bridge_proof_host: &BridgeProofHost,
    counterproof_host: &BridgeCounterproofHost,
) -> Result<()> {
    ensure_predicate_match(
        "bridge-proof",
        bridge_proof_host.sp1_predicate()?,
        &params.protocol.bridge_proof_predicate,
    )?;
    ensure_predicate_match(
        "bridge-counterproof",
        counterproof_host.sp1_predicate()?,
        &params.protocol.counterproof_predicate,
    )
}

/// Errors unless the ELF's `derived` predicate matches the `expected` params one. `None` (native
/// host or non-`sp1` build) pins no ELF — nothing to check.
fn ensure_predicate_match(
    label: &str,
    derived: Option<PredicateKey>,
    expected: &PredicateKey,
) -> Result<()> {
    let Some(derived) = derived else {
        return Ok(());
    };
    if derived.id() != expected.id() || derived.condition() != expected.condition() {
        anyhow::bail!(
            "{label}: loaded SP1 guest ELF does not match the configured predicate; regenerate it \
             with `proof-datatool sp1-predicate <elf>` or point at the matching ELF"
        );
    }
    Ok(())
}
