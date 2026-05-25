//! Hardcoded fees for presigned transactions.
//!
//! Until CPFP is implemented, every presigned transaction must pay its own fee.
//! Setting [`FEE_RATE_SAT_PER_VB`] to `0` disables fees entirely (matches the original
//! zero-fee behaviour) without removing any code.
//!
//! Vsizes are closed-form functions of the two graph parameters (`n_watchtowers` and
//! `n_data`). Numbers are pinned by `tests::pin_*` unit tests that build the actual finalized
//! transactions and assert that `vsize × FEE_RATE_SAT_PER_VB == fee`.
//!
//! Each fee corresponds to a specific presigned transaction; see the comments below for
//! which transaction each constant belongs to.
//!
//! Output sizes are taken from real outputs:
//! - P2TR script_pubkey is 34 bytes.
//! - SPS-50 OP_RETURN script_pubkey is variable but small (taken from the actual data).
//! - Operator/watchtower descriptors are P2TR in tests; production uses BOSD which resolves to
//!   bech32 / P2TR scripts of similar size.

use std::{num::NonZero, sync::LazyLock};

use bitcoin::{
    blockdata::constants::WITNESS_SCALE_FACTOR,
    consensus::encode::VarInt,
    key::TweakedPublicKey,
    relative,
    secp256k1::{Keypair, SecretKey, SECP256K1},
    taproot::LeafVersion,
    Amount, FeeRate, Network, ScriptBuf, TxOut, XOnlyPublicKey,
};
use strata_bridge_connectors::{
    prelude::{ClaimContestConnector, ContestCounterproofOutput},
    Connector,
};

/// Fee rate (sat/vb) that every presigned transaction pays.
///
/// Set to `0` to disable fees entirely — every helper in this module then returns
/// `Amount::ZERO`, every connector surcharge collapses to zero, and every per-tx
/// `value_in - value_out` becomes zero again, matching the original behaviour.
///
/// Set back to `2` (or any positive value) to re-enable fees once CPFP needs them
/// disabled again.
pub(crate) const FEE_RATE_SAT_PER_VB: u64 = 2;

/// [`FEE_RATE_SAT_PER_VB`] as a [`FeeRate`].
pub const FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(FEE_RATE_SAT_PER_VB);

/// Multiplies a vsize (in vbytes) by [`FEE_RATE_SAT_PER_VB`] to produce a fee.
const fn fee_for_vsize(vsize: u64) -> Amount {
    Amount::from_sat(vsize.saturating_mul(FEE_RATE_SAT_PER_VB))
}

/// P2TR `script_pubkey` for use as a synthetic placeholder when querying rust-bitcoin for
/// output-shape data (vbyte size, dust threshold). Tweaking the placeholder pubkey is
/// unnecessary for shape-only queries, so [`TweakedPublicKey::dangerous_assume_tweaked`] is
/// used directly.
static PLACEHOLDER_P2TR_SCRIPT_PUBKEY: LazyLock<ScriptBuf> = LazyLock::new(|| {
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
        placeholder_xonly(0),
    ))
});

/// Value to put on every cpfp anchor output (`KeyedAnchor`/`MultiAnchor`).
///
/// When [`FEE_RATE_SAT_PER_VB`] is `0`, returns `Amount::ZERO` — anchors stay at zero, matching
/// the original zero-fee TRUC behaviour where bitcoin core's relay policy permits dust outputs
/// only when the parent pays no fee.
///
/// When [`FEE_RATE_SAT_PER_VB`] is non-zero, returns rust-bitcoin's `Script::minimal_non_dust`
/// for a P2TR script_pubkey, the smallest amount bitcoin core's relay policy accepts on a tx
/// that pays a fee.
pub fn anchor_dust_value() -> Amount {
    if FEE_RATE_SAT_PER_VB == 0 {
        Amount::ZERO
    } else {
        PLACEHOLDER_P2TR_SCRIPT_PUBKEY.minimal_non_dust()
    }
}

/// Vbytes contributed by a single P2TR output, from rust-bitcoin's `TxOut::size`.
static P2TR_OUTPUT_VBYTES: LazyLock<u64> = LazyLock::new(|| {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: PLACEHOLDER_P2TR_SCRIPT_PUBKEY.clone(),
    }
    .size() as u64
});

/// Witness vbytes added per counterproof `n_data` byte (three extra script bytes
/// weighing 3 wu + one extra schnorr signature in the witness weighing 65 wu = 68 wu /
/// [`WITNESS_SCALE_FACTOR`] after amortising the steady-state varint encoding).
const COUNTERPROOF_PER_DATA_BYTE_VBYTES: u64 = 17;

// -------------------------------------------------------------------------------------------------
// Per-tx vsize formulas. Hardcoded and pinned by unit tests below.
//
// These are the predicted finalized vsizes (vbytes, ceil-rounded). Vsize = ceil(weight / 4).
// Each value was determined by constructing the actual finalized transaction in a unit test
// and reading `tx.weight().to_vbytes_ceil()`.
// -------------------------------------------------------------------------------------------------

/// Predicted vsize of [`crate::transactions::claim::ClaimTx`] in vbytes.
///
/// Structure: 1 wallet input (P2TR key path) + 3 P2TR outputs (claim_contest, claim_payout,
/// anchor).
const CLAIM_VSIZE: u64 = 197;

/// Predicted vsize of [`crate::transactions::uncontested_payout::UncontestedPayoutTx`] in vbytes.
///
/// Structure: 3 inputs (NOfN key path, ClaimContest uncontested script path, ClaimPayout key path)
/// + 1 P2TR output.
const UNCONTESTED_PAYOUT_VSIZE: u64 = 268;

/// Vsize of [`crate::transactions::contest::ContestTx`] excluding per-watchtower outputs and
/// the variable taproot control block of the spent leaf. Empirically measured: header + 1
/// input non-witness + 3 fixed P2TR dust outputs (proof, payout, slash) + 1 P2TR cpfp anchor
/// + 2 schnorr signatures + leaf script in the witness.
const CONTEST_FIXED_VBYTES: u64 = 273;

/// Predicted vsize of [`crate::transactions::contest::ContestTx`] in vbytes.
///
/// Non-linear in `n_watchtowers` because the spent `ClaimContestConnector` leaf carries a
/// taproot control block whose size depends on the leaf's position in the tap tree built by
/// rust-bitcoin's `TaprootBuilder`. The control-block contribution is queried from the
/// connector's `TaprootSpendInfo` rather than computed by hand.
fn contest_vsize(n_watchtowers: u32) -> u64 {
    let n = n_watchtowers as u64;
    CONTEST_FIXED_VBYTES
        + *P2TR_OUTPUT_VBYTES * n
        + contest_input_control_block_vsize(n_watchtowers)
}

/// Predicted vsize of [`crate::transactions::bridge_proof_timeout::BridgeProofTimeoutTx`].
///
/// Structure: 2 script-path inputs (ContestProof timeout, ContestPayout normal) + 1 P2TR
/// output. MultiAnchor output's tap-tree depth scales with watchtower count, but its
/// script_pubkey is always 34 bytes.
const BRIDGE_PROOF_TIMEOUT_VSIZE: u64 = 187;

/// Vsize of [`crate::transactions::counterproof::CounterproofTx`] with `n_data = 0` and the
/// 1-byte short witness-item length-prefix in effect. Empirically measured: header + 1 input
/// non-witness + 1 counterproof-connector P2TR output + 1 cpfp anchor + the witness's n-of-n
/// signature + script header + control block.
const COUNTERPROOF_FIXED_VBYTES: u64 = 179;

/// Predicted vsize of [`crate::transactions::counterproof::CounterproofTx`] in vbytes.
///
/// Each `n_data` byte adds one `OP_TUCK + OP_CHECKSIGVERIFY + OP_CODESEPARATOR` triple to the
/// counterproof leaf script and one 64-byte schnorr operator signature to the witness, for a
/// measured [`COUNTERPROOF_PER_DATA_BYTE_VBYTES`] vbytes per byte. [`COUNTERPROOF_FIXED_VBYTES`]
/// assumes the witness-item varint length-prefix for the leaf script is one byte; once the
/// script crosses the boundary where rust-bitcoin's [`VarInt::size`] grows, the extra prefix
/// bytes are added back in.
fn counterproof_vsize(n_data: NonZero<usize>) -> u64 {
    let n = n_data.get() as u64;
    let connector = ContestCounterproofOutput::new(
        Network::Regtest,
        placeholder_xonly(0),
        placeholder_xonly(1),
        n_data,
        Amount::ZERO,
    );
    let leaf_script = connector
        .leaf_scripts()
        .into_iter()
        .next()
        .expect("ContestCounterproofOutput has a single leaf script");
    let script_prefix_bytes = VarInt::from(leaf_script.len()).size() as u64;
    let prefix_extra_wu = script_prefix_bytes - 1;
    COUNTERPROOF_FIXED_VBYTES
        + COUNTERPROOF_PER_DATA_BYTE_VBYTES * n
        + prefix_extra_wu.div_ceil(WITNESS_SCALE_FACTOR as u64)
}

/// Predicted vsize of [`crate::transactions::counterproof_ack::CounterproofAckTx`].
///
/// Structure: 2 inputs (Counterproof timeout script path, ContestPayout normal key path)
/// + 1 P2TR output (cpfp anchor).
const COUNTERPROOF_ACK_VSIZE: u64 = 187;

/// Predicted vsize of [`crate::transactions::contested_payout::ContestedPayoutTx`].
///
/// Structure: 4 inputs (deposit NOfN key, claim_payout key, contest_payout timeout script,
/// contest_slash normal key) + 1 P2TR output.
const CONTESTED_PAYOUT_VSIZE: u64 = 302;

/// Vsize of [`crate::transactions::slash::SlashTx`] excluding per-watchtower outputs.
/// Empirically measured: header + 2 inputs (contest_slash timeout script-path + stake N/N
/// key-path) + 1 SPS-50 OP_RETURN header output + the witness's signature + script + control
/// block for the timeout-spend leaf.
const SLASH_FIXED_VBYTES: u64 = 165;

/// Predicted vsize of [`crate::transactions::slash::SlashTx`] in vbytes.
///
/// Linear in `n_watchtowers`: the spent `ContestSlashConnector` has a single-leaf tap tree
/// (no control-block growth), and each watchtower adds one P2TR output.
fn slash_vsize(n_watchtowers: u32) -> u64 {
    SLASH_FIXED_VBYTES + *P2TR_OUTPUT_VBYTES * n_watchtowers as u64
}

/// Predicted vsize of [`crate::transactions::stake::StakeTx`].
///
/// Structure: 1 wallet input (P2TR key path) + 3 P2TR outputs.
const STAKE_VSIZE: u64 = 197;

/// Predicted vsize of [`crate::transactions::unstaking_intent::UnstakingIntentTx`].
///
/// Structure: 1 script-path input (UnstakingIntentOutput) + 3 outputs (header + unstaking +
/// anchor).
const UNSTAKING_INTENT_VSIZE: u64 = 211;

/// Predicted vsize of [`crate::transactions::unstaking::UnstakingTx`].
///
/// Structure: 2 inputs (UnstakingOutput timeout script, stake NOfN key) + 1 P2TR output.
const UNSTAKING_VSIZE: u64 = 187;

/// Predicted vsize of [`crate::transactions::deposit::DepositTx`].
///
/// Structure: 1 input (DepositRequestConnector key path) + 2 outputs (SPS-50 OP_RETURN + N/N
/// P2TR).
const DEPOSIT_VSIZE: u64 = 132;

/// Predicted vsize of [`crate::transactions::cooperative_payout::CooperativePayoutTx`].
///
/// Structure: 1 input (deposit NOfN key path) + 1 P2TR operator output.
const COOPERATIVE_PAYOUT_VSIZE: u64 = 111;

/// Predicted vsize of [`crate::transactions::not_presigned::CounterproofNackTx`].
///
/// Structure: 1 input (CounterproofConnector script-path) + 1 P2TR output.
const COUNTERPROOF_NACK_VSIZE: u64 = 111;

/// Deterministic x-only pubkey for the given seed. The tap tree's merkle structure is
/// determined by the leaves' `TapLeafHash`es, so distinct watchtower pubkeys are required to
/// reproduce the production tree shape — duplicate scripts would coalesce in the lookup.
fn placeholder_xonly(seed: u32) -> XOnlyPublicKey {
    let mut bytes = [1u8; 32];
    bytes[0..4].copy_from_slice(&seed.wrapping_add(1).to_le_bytes());
    let sk = SecretKey::from_slice(&bytes).expect("non-zero 32-byte slice is a valid secret key");
    Keypair::from_secret_key(SECP256K1, &sk)
        .x_only_public_key()
        .0
}

/// Witness vsize contribution of the largest contested-leaf control block of a
/// `ClaimContestConnector` with the given watchtower count.
///
/// For non-power-of-two leaf counts, rust-bitcoin's `TaprootBuilder` places some leaves at a
/// shallower depth than others. Since `ContestTx` is built once with a single fee but
/// `ContestTx::finalize` accepts any watchtower index, the watchtower with the deepest leaf
/// drives the tx's largest possible vsize — picking that leaf here keeps the tx at or above
/// 2 sat/vb regardless of which watchtower contests (shallower-leaf contests will overpay
/// slightly, which is conservative for relay).
///
/// # Panics
///
/// Panics if `n_watchtowers == 0`, since `ContestTx` is only constructed for graphs with at
/// least one watchtower.
fn contest_input_control_block_vsize(n_watchtowers: u32) -> u64 {
    assert!(
        n_watchtowers >= 1,
        "contest tx requires at least one watchtower"
    );
    let watchtower_pubkeys = (0..n_watchtowers).map(placeholder_xonly).collect();
    let connector = ClaimContestConnector::new(
        Network::Regtest,
        placeholder_xonly(u32::MAX),
        watchtower_pubkeys,
        relative::Height::from_height(1),
        Amount::ZERO,
    );
    let spend_info = connector.spend_info();
    let mut leaf_scripts = connector.leaf_scripts();
    // Drop the trailing uncontested-payout leaf — `ContestTx` only spends contested leaves.
    leaf_scripts.truncate(n_watchtowers as usize);
    let max_control_block_bytes = leaf_scripts
        .into_iter()
        .map(|leaf| {
            spend_info
                .control_block(&(leaf, LeafVersion::TapScript))
                .expect("contested leaf was just included in the tap tree")
                .serialize()
                .len() as u64
        })
        .max()
        .expect("n_watchtowers >= 1 so at least one contested leaf exists");
    let prefix_bytes = VarInt::from(max_control_block_bytes).size() as u64;
    (prefix_bytes + max_control_block_bytes).div_ceil(WITNESS_SCALE_FACTOR as u64)
}

// -------------------------------------------------------------------------------------------------
// Per-tx fees. Each is `vsize × FEE_RATE_SAT_PER_VB`.
// -------------------------------------------------------------------------------------------------

/// Fee for [`crate::transactions::claim::ClaimTx`].
pub(crate) const fn claim_fee() -> Amount {
    fee_for_vsize(CLAIM_VSIZE)
}

/// Fee for [`crate::transactions::uncontested_payout::UncontestedPayoutTx`].
pub(crate) const fn uncontested_payout_fee() -> Amount {
    fee_for_vsize(UNCONTESTED_PAYOUT_VSIZE)
}

/// Fee for [`crate::transactions::contest::ContestTx`].
pub(crate) fn contest_fee(n_watchtowers: u32) -> Amount {
    fee_for_vsize(contest_vsize(n_watchtowers))
}

/// Fee for [`crate::transactions::bridge_proof_timeout::BridgeProofTimeoutTx`].
pub(crate) const fn bridge_proof_timeout_fee() -> Amount {
    fee_for_vsize(BRIDGE_PROOF_TIMEOUT_VSIZE)
}

/// Fee for [`crate::transactions::counterproof::CounterproofTx`].
pub(crate) fn counterproof_fee(n_data: NonZero<usize>) -> Amount {
    fee_for_vsize(counterproof_vsize(n_data))
}

/// Fee for [`crate::transactions::counterproof_ack::CounterproofAckTx`].
pub(crate) const fn counterproof_ack_fee() -> Amount {
    fee_for_vsize(COUNTERPROOF_ACK_VSIZE)
}

/// Fee for [`crate::transactions::contested_payout::ContestedPayoutTx`].
pub(crate) const fn contested_payout_fee() -> Amount {
    fee_for_vsize(CONTESTED_PAYOUT_VSIZE)
}

/// Fee for [`crate::transactions::slash::SlashTx`].
pub(crate) fn slash_fee(n_watchtowers: u32) -> Amount {
    fee_for_vsize(slash_vsize(n_watchtowers))
}

/// Fee for [`crate::transactions::stake::StakeTx`].
pub(crate) const fn stake_fee() -> Amount {
    fee_for_vsize(STAKE_VSIZE)
}

/// Fee for [`crate::transactions::unstaking_intent::UnstakingIntentTx`].
pub(crate) const fn unstaking_intent_fee() -> Amount {
    fee_for_vsize(UNSTAKING_INTENT_VSIZE)
}

/// Fee for [`crate::transactions::unstaking::UnstakingTx`].
pub(crate) const fn unstaking_fee() -> Amount {
    fee_for_vsize(UNSTAKING_VSIZE)
}

/// Fee for [`crate::transactions::deposit::DepositTx`].
pub(crate) const fn deposit_fee() -> Amount {
    fee_for_vsize(DEPOSIT_VSIZE)
}

/// Fee for [`crate::transactions::cooperative_payout::CooperativePayoutTx`].
pub(crate) const fn cooperative_payout_fee() -> Amount {
    fee_for_vsize(COOPERATIVE_PAYOUT_VSIZE)
}

/// Fee for [`crate::transactions::not_presigned::CounterproofNackTx`].
pub const fn counterproof_nack_fee() -> Amount {
    fee_for_vsize(COUNTERPROOF_NACK_VSIZE)
}

// -------------------------------------------------------------------------------------------------
// Connector surcharges. These are added to a connector's base value so the downstream
// transaction's input arrives with the fee already included. Used for transactions whose
// outputs are all dust connectors / cpfp anchors and cannot absorb a fee without underflowing.
// -------------------------------------------------------------------------------------------------

/// Surcharge for `CounterproofConnector`. Funds the [`counterproof_ack_fee`] of
/// [`crate::transactions::counterproof_ack::CounterproofAckTx`].
pub(crate) const fn counterproof_surcharge() -> Amount {
    counterproof_ack_fee()
}

/// Surcharge for `ContestProofConnector`. Funds the [`bridge_proof_timeout_fee`] of
/// [`crate::transactions::bridge_proof_timeout::BridgeProofTimeoutTx`].
pub(crate) const fn contest_proof_surcharge() -> Amount {
    bridge_proof_timeout_fee()
}

/// Surcharge for `ContestCounterproofOutput`. Funds the [`counterproof_fee`] of
/// [`crate::transactions::counterproof::CounterproofTx`], the cpfp anchor dust on that tx,
/// plus the inflation that `CounterproofConnector` carries (= [`counterproof_ack_fee`]).
pub(crate) fn contest_counterproof_surcharge(n_data: NonZero<usize>) -> Amount {
    counterproof_fee(n_data) + counterproof_ack_fee() + anchor_dust_value()
}

/// Surcharge for `ClaimContestConnector`. Funds the [`contest_fee`], the contest tx's cpfp
/// anchor dust, plus the inflation that all of [`crate::transactions::contest::ContestTx`]'s
/// outputs carry: `ContestProofConnector` (`bridge_proof_timeout_fee`) and the per-watchtower
/// `ContestCounterproofOutput` (`contest_counterproof_surcharge(n_data)`).
pub fn claim_contest_surcharge(n_watchtowers: u32, n_data: NonZero<usize>) -> Amount {
    contest_fee(n_watchtowers)
        + bridge_proof_timeout_fee()
        + anchor_dust_value()
        + contest_counterproof_surcharge(n_data) * u64::from(n_watchtowers)
}

/// Surcharge for `UnstakingIntentOutput`. Funds the [`unstaking_intent_fee`] of
/// [`crate::transactions::unstaking_intent::UnstakingIntentTx`] plus that tx's cpfp anchor dust.
pub fn unstaking_intent_surcharge() -> Amount {
    unstaking_intent_fee() + anchor_dust_value()
}

#[cfg(test)]
mod tests {
    //! Pinning tests that build each presigned transaction with dummy signatures of the
    //! correct size, measure the actual finalized `vsize`, and assert it matches the
    //! hardcoded `*_VSIZE` constants above. If any connector's witness composition drifts
    //! (e.g., a leaf script gains an opcode), one of these tests will fail loudly rather
    //! than the bridge silently broadcasting an underpaying transaction in production.
    use std::num::NonZero;

    use bitcoin::{
        hashes::{sha256, Hash},
        relative,
        secp256k1::{rand::random, schnorr, Keypair},
        Amount, Network, OutPoint, Transaction, TxOut, Witness,
    };
    use bitcoin_bosd::Descriptor;
    use strata_bridge_connectors::prelude::{
        ContestCounterproofWitness, DepositRequestConnector, NOfNConnector, UnstakingIntentWitness,
    };
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{
        game_graph::{DepositParams, GameData, GameGraph, KeyData, ProtocolParams, SetupParams},
        stake_graph::{
            ProtocolParams as StakeProtocolParams, SetupParams as StakeSetupParams, StakeData,
            StakeGraph,
        },
        transactions::prelude::{
            CooperativePayoutData, CooperativePayoutTx, CounterproofNackData, CounterproofNackTx,
            DepositData, DepositTx,
        },
    };

    const N_WATCHTOWERS: usize = 10;
    const N_DATA: NonZero<usize> = NonZero::new(132).unwrap();
    const DEPOSIT_AMOUNT: Amount = Amount::from_int_btc(10);
    /// Picked so the per-watchtower stake (`STAKE_AMOUNT / n_watchtowers`) is an integer for
    /// every `n_watchtowers` exercised by the per-`n` `pin_slash_vsize_at_*` tests, since
    /// `SlashTx::new` asserts `STAKE_AMOUNT.to_sat() % n_watchtowers == 0`.
    /// `2520` = LCM(1..=10).
    const STAKE_AMOUNT: Amount = Amount::from_sat(2_520_000_000);

    /// Returns a 64-byte schnorr signature of the right size. The bytes are arbitrary —
    /// signature verification isn't performed; only the on-the-wire size matters for
    /// vsize measurement.
    fn dummy_sig() -> schnorr::Signature {
        schnorr::Signature::from_slice(&[0xAA; 64]).expect("64 bytes is a valid sig length")
    }

    /// P2TR-keyspend witness (single 64-byte schnorr signature) for wallet-funded inputs.
    fn dummy_p2tr_keyspend_witness() -> Witness {
        let mut w = Witness::new();
        w.push(dummy_sig().serialize());
        w
    }

    /// A bag of dummy keys and a preimage covering every signing role in the graph.
    struct TestSigner {
        n_of_n: Keypair,
        operator: Keypair,
        admin: Keypair,
        unstaking_preimage: [u8; 32],
        watchtowers: Vec<Keypair>,
        wt_faults: Vec<Keypair>,
    }

    impl TestSigner {
        fn generate(n_watchtowers: usize) -> Self {
            Self {
                n_of_n: generate_keypair(),
                operator: generate_keypair(),
                admin: generate_keypair(),
                unstaking_preimage: random(),
                watchtowers: (0..n_watchtowers).map(|_| generate_keypair()).collect(),
                wt_faults: (0..n_watchtowers).map(|_| generate_keypair()).collect(),
            }
        }
    }

    /// Builds a `GameData` for a graph with `n_watchtowers` watchtowers and `n_data`-byte
    /// counterproofs, with arbitrary (non-on-chain) outpoints.
    fn test_game_data(signer: &TestSigner, n_watchtowers: u32, n_data: NonZero<usize>) -> GameData {
        let operator_xonly = signer.operator.x_only_public_key().0;
        let payout_descriptor = Descriptor::new_p2tr(&operator_xonly.serialize())
            .expect("32-byte x-only key is a valid p2tr payload");

        let protocol = ProtocolParams {
            network: Network::Regtest,
            magic_bytes: (*b"ALPN").into(),
            contest_timelock: relative::Height::from_height(10),
            proof_timelock: relative::Height::from_height(5),
            ack_timelock: relative::Height::from_height(10),
            nack_timelock: relative::Height::from_height(5),
            contested_payout_timelock: relative::Height::from_height(15),
            counterproof_n_data: n_data,
            deposit_amount: DEPOSIT_AMOUNT,
            stake_amount: STAKE_AMOUNT,
        };
        let n_wt = n_watchtowers as usize;
        let keys = KeyData {
            n_of_n_pubkey: signer.n_of_n.x_only_public_key().0,
            operator_pubkey: operator_xonly,
            operator_adaptor_pubkeys: vec![operator_xonly; n_wt],
            watchtower_pubkeys: signer
                .watchtowers
                .iter()
                .take(n_wt)
                .map(|k| k.x_only_public_key().0)
                .collect(),
            admin_pubkey: signer.admin.x_only_public_key().0,
            unstaking_image: sha256::Hash::hash(&signer.unstaking_preimage),
            wt_fault_pubkeys: signer
                .wt_faults
                .iter()
                .take(n_wt)
                .map(|k| k.x_only_public_key().0)
                .collect(),
            operator_descriptor: payout_descriptor.clone(),
            slash_watchtower_descriptors: vec![payout_descriptor; n_wt],
        };
        let setup = SetupParams {
            operator_index: 0,
            stake_outpoint: OutPoint::null(),
            keys,
        };
        GameData {
            protocol,
            setup: setup.clone(),
            deposit: DepositParams {
                game_index: NonZero::new(1).unwrap(),
                claim_funds: OutPoint::null(),
                deposit_outpoint: OutPoint::null(),
                adaptor_pubkeys: setup.keys.operator_adaptor_pubkeys.clone(),
                fault_pubkeys: setup.keys.wt_fault_pubkeys.clone(),
            },
        }
    }

    fn test_stake_data(signer: &TestSigner) -> StakeData {
        let operator_xonly = signer.operator.x_only_public_key().0;
        StakeData {
            protocol: StakeProtocolParams {
                network: Network::Regtest,
                magic_bytes: (*b"ALPN").into(),
                unstaking_timelock: relative::Height::from_height(10),
                stake_amount: STAKE_AMOUNT,
            },
            setup: StakeSetupParams {
                operator_index: 0,
                operator_pubkey: operator_xonly,
                n_of_n_pubkey: signer.n_of_n.x_only_public_key().0,
                unstaking_image: sha256::Hash::hash(&signer.unstaking_preimage),
                unstaking_operator_descriptor: Descriptor::new_p2tr(&operator_xonly.serialize())
                    .unwrap(),
                stake_funds: OutPoint::null(),
            },
        }
    }

    /// Replaces every input's witness with a P2TR key-path schnorr signature and returns
    /// the finalized-vsize of the tx.
    fn vsize_with_keyspend_witnesses(mut tx: Transaction) -> u64 {
        for input in &mut tx.input {
            input.witness = dummy_p2tr_keyspend_witness();
        }
        tx.weight().to_vbytes_ceil()
    }

    fn pin(actual_vsize: u64, predicted_vsize: u64, label: &str) {
        assert_eq!(
            actual_vsize, predicted_vsize,
            "{label}: actual vsize {actual_vsize} differs from predicted {predicted_vsize}; \
             update the constant in fee.rs to match the new connector witness shape"
        );
    }

    #[test]
    fn pin_claim_vsize() {
        // ClaimTx is funded by an external wallet (P2TR key-path). Attach a 64-byte
        // schnorr witness to the single input and measure.
        let signer = TestSigner::generate(N_WATCHTOWERS);
        let game = test_game_data(&signer, N_WATCHTOWERS as u32, N_DATA);
        let (graph, _) = GameGraph::new(game);
        let tx = graph.claim.as_ref().clone();
        pin(vsize_with_keyspend_witnesses(tx), CLAIM_VSIZE, "claim");
    }

    #[test]
    fn pin_uncontested_payout_vsize() {
        let signer = TestSigner::generate(N_WATCHTOWERS);
        let (graph, _) = GameGraph::new(test_game_data(&signer, N_WATCHTOWERS as u32, N_DATA));
        let signed = graph
            .uncontested_payout
            .finalize([dummy_sig(), dummy_sig(), dummy_sig()]);
        pin(
            signed.weight().to_vbytes_ceil(),
            UNCONTESTED_PAYOUT_VSIZE,
            "uncontested_payout",
        );
    }

    // Includes the boundary points where rust-bitcoin's `TaprootBuilder` shifts the contested
    // leaf to a deeper merkle path (n=1→2, n=3→4, n=5→8) so a drift at any depth step is caught.
    // Iterates every watchtower index because for non-power-of-two leaf counts some leaves are
    // shallower than others; `contest_vsize` is conservative (sized for the deepest leaf) so the
    // measured vsize for any index must be ≤ predicted.
    #[test]
    fn pin_contest_vsize() {
        for n_watchtowers in [1u32, 2, 3, 4, 5, 8, 10] {
            let signer = TestSigner::generate(n_watchtowers as usize);
            let (graph, _) = GameGraph::new(test_game_data(&signer, n_watchtowers, N_DATA));
            let predicted = contest_vsize(n_watchtowers);
            for watchtower_index in 0..n_watchtowers {
                let signed =
                    graph
                        .contest
                        .clone()
                        .finalize(dummy_sig(), watchtower_index, dummy_sig());
                let actual = signed.weight().to_vbytes_ceil();
                assert!(
                    actual <= predicted,
                    "contest(n_watchtowers={n_watchtowers}, watchtower_index={watchtower_index}): \
                     actual vsize {actual} exceeds predicted {predicted}"
                );
            }
            // The deepest leaf should match exactly — at least one watchtower must hit it.
            let deepest = (0..n_watchtowers)
                .map(|i| {
                    graph
                        .contest
                        .clone()
                        .finalize(dummy_sig(), i, dummy_sig())
                        .weight()
                        .to_vbytes_ceil()
                })
                .max()
                .expect("at least one watchtower");
            pin(
                deepest,
                predicted,
                &format!("contest(n_watchtowers={n_watchtowers}, deepest)"),
            );
        }
    }

    #[test]
    fn pin_bridge_proof_timeout_vsize() {
        let signer = TestSigner::generate(N_WATCHTOWERS);
        let (graph, _) = GameGraph::new(test_game_data(&signer, N_WATCHTOWERS as u32, N_DATA));
        let signed = graph
            .bridge_proof_timeout
            .finalize([dummy_sig(), dummy_sig()]);
        pin(
            signed.weight().to_vbytes_ceil(),
            BRIDGE_PROOF_TIMEOUT_VSIZE,
            "bridge_proof_timeout",
        );
    }

    // Includes the boundary point where the counterproof leaf script crosses 252 bytes (at
    // `n_data = 63`) and the witness-item length-prefix grows from 1 byte to 3 bytes, so
    // drifts at the boundary are caught separately from drifts in the per-byte slope. The
    // last value is the production size (groth16 proof bytes + 4-byte deposit_idx).
    #[test]
    fn pin_counterproof_vsize() {
        for n_data in [1, 62, 63, 64, N_DATA.get()] {
            let n_data = NonZero::new(n_data).unwrap();
            let signer = TestSigner::generate(N_WATCHTOWERS);
            let (graph, _) = GameGraph::new(test_game_data(&signer, N_WATCHTOWERS as u32, n_data));
            let cf = graph.counterproofs[0].counterproof.clone();
            let witness = ContestCounterproofWitness {
                n_of_n_signature: dummy_sig(),
                operator_signatures: vec![dummy_sig(); n_data.get()],
            };
            let signed = cf.finalize(&witness);
            pin(
                signed.weight().to_vbytes_ceil(),
                counterproof_vsize(n_data),
                &format!("counterproof(n_data={})", n_data.get()),
            );
        }
    }

    #[test]
    fn pin_counterproof_ack_vsize() {
        let signer = TestSigner::generate(N_WATCHTOWERS);
        let (graph, _) = GameGraph::new(test_game_data(&signer, N_WATCHTOWERS as u32, N_DATA));
        let signed = graph.counterproofs[0]
            .counterproof_ack
            .clone()
            .finalize([dummy_sig(), dummy_sig()]);
        pin(
            signed.weight().to_vbytes_ceil(),
            COUNTERPROOF_ACK_VSIZE,
            "counterproof_ack",
        );
    }

    #[test]
    fn pin_contested_payout_vsize() {
        let signer = TestSigner::generate(N_WATCHTOWERS);
        let (graph, _) = GameGraph::new(test_game_data(&signer, N_WATCHTOWERS as u32, N_DATA));
        let signed =
            graph
                .contested_payout
                .finalize([dummy_sig(), dummy_sig(), dummy_sig(), dummy_sig()]);
        pin(
            signed.weight().to_vbytes_ceil(),
            CONTESTED_PAYOUT_VSIZE,
            "contested_payout",
        );
    }

    // Slash is linear in watchtower count (no taproot tree growth in the spent leaf), so a
    // few representative values are sufficient.
    #[test]
    fn pin_slash_vsize() {
        for n_watchtowers in [1u32, 5, 10] {
            let signer = TestSigner::generate(n_watchtowers as usize);
            let (graph, _) = GameGraph::new(test_game_data(&signer, n_watchtowers, N_DATA));
            let signed = graph.slash.finalize([dummy_sig(), dummy_sig()]);
            pin(
                signed.weight().to_vbytes_ceil(),
                slash_vsize(n_watchtowers),
                &format!("slash(n_watchtowers={n_watchtowers})"),
            );
        }
    }

    #[test]
    fn pin_stake_vsize() {
        let signer = TestSigner::generate(0);
        let graph = StakeGraph::new(test_stake_data(&signer));
        let tx = graph.stake.as_ref().clone();
        pin(vsize_with_keyspend_witnesses(tx), STAKE_VSIZE, "stake");
    }

    #[test]
    fn pin_unstaking_intent_vsize() {
        let signer = TestSigner::generate(0);
        let graph = StakeGraph::new(test_stake_data(&signer));
        let signed = graph.unstaking_intent.finalize(&UnstakingIntentWitness {
            n_of_n_signature: dummy_sig(),
            unstaking_preimage: signer.unstaking_preimage,
        });
        pin(
            signed.weight().to_vbytes_ceil(),
            UNSTAKING_INTENT_VSIZE,
            "unstaking_intent",
        );
    }

    #[test]
    fn pin_unstaking_vsize() {
        let signer = TestSigner::generate(0);
        let graph = StakeGraph::new(test_stake_data(&signer));
        let signed = graph.unstaking.finalize([dummy_sig(), dummy_sig()]);
        pin(
            signed.weight().to_vbytes_ceil(),
            UNSTAKING_VSIZE,
            "unstaking",
        );
    }

    #[test]
    fn pin_deposit_vsize() {
        // The DepositTx has 1 timelocked-key-path input and an OP_RETURN + N/N P2TR output.
        let signer = TestSigner::generate(0);
        let n_of_n = signer.n_of_n.x_only_public_key().0;
        let depositor = signer.operator.x_only_public_key().0;
        let deposit_request = DepositRequestConnector::new(
            Network::Regtest,
            n_of_n,
            depositor,
            relative::Height::from_height(1_008),
            DepositTx::drt_required(DEPOSIT_AMOUNT),
        );
        let deposit_connector = NOfNConnector::new(Network::Regtest, n_of_n, DEPOSIT_AMOUNT);
        let data = DepositData {
            deposit_idx: 0,
            deposit_request_outpoint: OutPoint::null(),
            magic_bytes: (*b"ALPN").into(),
        };
        let signed = DepositTx::new(data, deposit_connector, deposit_request).finalize(dummy_sig());
        pin(signed.weight().to_vbytes_ceil(), DEPOSIT_VSIZE, "deposit");
    }

    #[test]
    fn pin_cooperative_payout_vsize() {
        let signer = TestSigner::generate(0);
        let n_of_n = signer.n_of_n.x_only_public_key().0;
        let operator_xonly = signer.operator.x_only_public_key().0;
        let descriptor = Descriptor::new_p2tr(&operator_xonly.serialize()).unwrap();
        let deposit_connector = NOfNConnector::new(Network::Regtest, n_of_n, DEPOSIT_AMOUNT);
        let signed = CooperativePayoutTx::new(
            CooperativePayoutData {
                deposit_outpoint: OutPoint::null(),
            },
            deposit_connector,
            descriptor,
        )
        .finalize(dummy_sig());
        pin(
            signed.weight().to_vbytes_ceil(),
            COOPERATIVE_PAYOUT_VSIZE,
            "cooperative_payout",
        );
    }

    #[test]
    fn pin_counterproof_nack_vsize() {
        // In production, CounterproofNackTx has just the connector input and a single
        // P2TR operator-wallet output (no wallet-funded extra input). Build that shape.
        let signer = TestSigner::generate(N_WATCHTOWERS);
        let (graph, connectors) =
            GameGraph::new(test_game_data(&signer, N_WATCHTOWERS as u32, N_DATA));
        let mut nack = CounterproofNackTx::new(
            CounterproofNackData {
                counterproof_txid: graph.counterproofs[0].counterproof.as_ref().compute_txid(),
            },
            connectors.counterproof[0],
        );
        let operator_descriptor =
            Descriptor::new_p2tr(&signer.operator.x_only_public_key().0.serialize()).unwrap();
        nack.push_output(TxOut {
            value: nack.prevouts()[0].value - counterproof_nack_fee(),
            script_pubkey: operator_descriptor.to_script(),
        });
        let signed = nack.finalize_partial(dummy_sig());
        pin(
            signed.weight().to_vbytes_ceil(),
            COUNTERPROOF_NACK_VSIZE,
            "counterproof_nack",
        );
    }
}
