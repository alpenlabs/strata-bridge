//! Pure validation of deposit request transactions against a bridge configuration and active
//! operator set.

use bitcoin::{Amount, Transaction, hex::DisplayHex, secp256k1::XOnlyPublicKey};
use strata_asm_proto_bridge_v1_txs::{
    BRIDGE_V1_SUBPROTOCOL_ID,
    constants::BridgeTxType,
    deposit_request::{DRT_OUTPUT_INDEX, create_deposit_request_locking_script, parse_drt},
    errors::TxStructureError,
};
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_sm::deposit::config::DepositSMCfg;
use strata_bridge_tx_graph::transactions::deposit::DepositTx;
use strata_l1_txfmt::extract_tx_magic_and_tag;
use thiserror::Error;

/// Successfully validated DRT data needed to construct a `DepositSM`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Valid {
    /// Depositor's x-only recovery pubkey parsed from the SPS-50 aux data.
    pub(super) depositor_pubkey: XOnlyPublicKey,
    /// Amount on the deposit-request output (output index 1).
    pub(super) drt_output_amount: Amount,
}

/// Reason [`validate_candidate`] rejected a transaction.
#[derive(Debug, Error)]
pub(super) enum ValidationError {
    /// SPS-50 envelope identified the tx as our DRT, but the structural parse failed.
    #[error("DRT is structurally invalid: {0}")]
    Structure(#[source] TxStructureError),
    /// The 32-byte recovery pubkey in the SPS-50 aux data is not a valid x-only point.
    #[error("DRT aux carries invalid recovery pubkey: {0}")]
    InvalidRecoveryPubkey(String),
    /// Output-1 carries less than `deposit_amount + deposit-tx fee` and so cannot fund a
    /// relayable deposit transaction.
    #[error("DRT output value {actual} is below required {required}")]
    OutputValueBelowRequired { actual: Amount, required: Amount },
    /// Output-1's P2TR script does not match the script reconstructed from the depositor's
    /// recovery pubkey, the active N-of-N aggregated key, and the bridge's recovery delay.
    /// The DRT is therefore not cooperatively spendable by the bridge.
    #[error("DRT output script does not match expected P2TR locking script")]
    LockingScriptMismatch,
}

/// Returns `true` iff `tx`'s SPS-50 envelope identifies it as a Bridge-v1 deposit request for
/// the bridge configured by `cfg`.
pub(super) fn is_our_drt_envelope(tx: &Transaction, cfg: &DepositSMCfg) -> bool {
    let Ok((magic, tag)) = extract_tx_magic_and_tag(tx) else {
        return false;
    };
    magic == cfg.magic_bytes
        && tag.subproto_id() == BRIDGE_V1_SUBPROTOCOL_ID
        && tag.tx_type() == BridgeTxType::DepositRequest as u8
}

/// Validates a candidate DRT against the bridge configuration and active operator set, and
/// returns the parts a `DepositSM` needs.
///
/// The caller must have already verified the SPS-50 envelope via [`is_our_drt_envelope`];
/// passing a tx that fails the envelope check yields [`ValidationError::Structure`].
pub(super) fn validate_candidate(
    tx: &Transaction,
    cfg: &DepositSMCfg,
    active_operator_table: &OperatorTable,
) -> Result<Valid, ValidationError> {
    let drt_info = parse_drt(tx).map_err(ValidationError::Structure)?;

    let recovery_pk_bytes = drt_info.header_aux().recovery_pk();
    let depositor_pubkey = XOnlyPublicKey::from_slice(recovery_pk_bytes).map_err(|_| {
        ValidationError::InvalidRecoveryPubkey(recovery_pk_bytes.to_lower_hex_string())
    })?;

    // `parse_drt` already ensures output at index 1 exists.
    let drt_output = tx
        .output
        .get(DRT_OUTPUT_INDEX)
        .expect("parse_drt guarantees output index 1 exists");

    let required = DepositTx::drt_required(cfg.deposit_amount);
    if drt_output.value < required {
        return Err(ValidationError::OutputValueBelowRequired {
            actual: drt_output.value,
            required,
        });
    }

    let n_of_n = active_operator_table
        .aggregated_btc_key()
        .x_only_public_key()
        .0;
    let expected_script =
        create_deposit_request_locking_script(recovery_pk_bytes, n_of_n, cfg.recovery_delay);
    if drt_output.script_pubkey != expected_script {
        return Err(ValidationError::LockingScriptMismatch);
    }

    Ok(Valid {
        depositor_pubkey,
        drt_output_amount: drt_output.value,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::{ScriptBuf, TxIn, TxOut, absolute, secp256k1::SECP256K1, transaction};
    use strata_bridge_test_utils::bitcoin::generate_xonly_pubkey;
    use strata_l1_txfmt::{MagicBytes, ParseConfig, TagData};

    use super::*;
    use crate::testing::{
        DrtBuilder, N_TEST_OPERATORS, TEST_POV_IDX, test_deposit_sm_cfg, test_operator_table,
    };

    // ===== is_our_drt_envelope tests =====

    #[test]
    fn envelope_accepts_aligned_drt() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let tx = DrtBuilder::aligned(&operator_table, &cfg).build();

        assert!(
            is_our_drt_envelope(&tx, &cfg),
            "aligned DRT envelope must classify as ours",
        );
    }

    #[test]
    fn envelope_rejects_tx_without_sps50() {
        let cfg = test_deposit_sm_cfg();
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        assert!(
            !is_our_drt_envelope(&tx, &cfg),
            "tx without an OP_RETURN must not classify as ours",
        );
    }

    #[test]
    fn envelope_rejects_non_op_return_first_output() {
        let cfg = test_deposit_sm_cfg();
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2tr(SECP256K1, generate_xonly_pubkey(), None),
            }],
        };

        assert!(
            !is_our_drt_envelope(&tx, &cfg),
            "tx whose output 0 is not OP_RETURN must not classify as ours",
        );
    }

    #[test]
    fn envelope_rejects_wrong_magic() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.magic = MagicBytes::new(*b"XXXX");

        assert!(
            !is_our_drt_envelope(&builder.build(), &cfg),
            "tx with mismatched magic bytes must not classify as ours",
        );
    }

    #[test]
    fn envelope_rejects_wrong_subproto() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.subproto_id = BRIDGE_V1_SUBPROTOCOL_ID.wrapping_add(1);

        assert!(
            !is_our_drt_envelope(&builder.build(), &cfg),
            "tx with a non-Bridge-v1 subprotocol id must not classify as ours",
        );
    }

    #[test]
    fn envelope_rejects_wrong_tx_type() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.tx_type = BridgeTxType::Deposit as u8;

        assert!(
            !is_our_drt_envelope(&builder.build(), &cfg),
            "non-DepositRequest Bridge-v1 tx type must not classify as our DRT",
        );
    }

    // ===== validate_candidate tests =====

    #[test]
    fn candidate_accepts_aligned_drt() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let builder = DrtBuilder::aligned(&operator_table, &cfg);
        let expected_pk = XOnlyPublicKey::from_slice(&builder.recovery_pk_in_aux).unwrap();
        let expected_value = builder.output_value;

        let valid = validate_candidate(&builder.build(), &cfg, &operator_table)
            .expect("aligned DRT must validate");

        assert_eq!(
            valid.depositor_pubkey, expected_pk,
            "validator must return the recovery pubkey from aux",
        );
        assert_eq!(
            valid.drt_output_amount, expected_value,
            "validator must return the output-1 amount",
        );
    }

    #[test]
    fn candidate_rejects_malformed_aux() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        // Aux below 32 bytes makes `parse_drt` fail with InvalidAuxiliaryData; envelope is
        // otherwise aligned for our bridge.
        let tag = TagData::new(
            BRIDGE_V1_SUBPROTOCOL_ID,
            BridgeTxType::DepositRequest as u8,
            vec![0u8; 31],
        )
        .expect("aux must fit SPS-50 size limits");
        let op_return = ParseConfig::new(cfg.magic_bytes)
            .encode_script_buf(&tag.as_ref())
            .expect("SPS-50 tag must encode");
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return,
            }],
        };

        assert!(
            matches!(
                validate_candidate(&tx, &cfg, &operator_table),
                Err(ValidationError::Structure(_)),
            ),
            "under-32-byte aux must surface as Structure error",
        );
    }

    #[test]
    fn candidate_rejects_invalid_recovery_pubkey() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        // 32 zero bytes are not a valid x-only point.
        builder.recovery_pk_in_aux = [0u8; 32];
        builder.recovery_pk_in_script = [0u8; 32];

        assert!(
            matches!(
                validate_candidate(&builder.build(), &cfg, &operator_table),
                Err(ValidationError::InvalidRecoveryPubkey(_)),
            ),
            "32 zero bytes must surface as InvalidRecoveryPubkey",
        );
    }

    #[test]
    fn candidate_rejects_output_value_below_required() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let required = DepositTx::drt_required(cfg.deposit_amount);
        let actual = required - Amount::from_sat(1);
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.output_value = actual;

        let err = validate_candidate(&builder.build(), &cfg, &operator_table).unwrap_err();
        match err {
            ValidationError::OutputValueBelowRequired {
                actual: got_actual,
                required: got_required,
            } => {
                assert_eq!(
                    got_actual, actual,
                    "error must echo the actual DRT output value",
                );
                assert_eq!(
                    got_required, required,
                    "error must echo the required (deposit_amount + deposit_fee) value",
                );
            }
            other => panic!("expected OutputValueBelowRequired, got {other:?}"),
        }
    }

    #[test]
    fn candidate_rejects_mismatched_recovery_pk_in_script() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.recovery_pk_in_script = generate_xonly_pubkey().serialize();
        assert_ne!(
            builder.recovery_pk_in_aux, builder.recovery_pk_in_script,
            "test must mutate the script's recovery pk away from the aux's",
        );

        assert!(
            matches!(
                validate_candidate(&builder.build(), &cfg, &operator_table),
                Err(ValidationError::LockingScriptMismatch),
            ),
            "recovery pk encoded in the takeback tapscript must match aux",
        );
    }

    #[test]
    fn candidate_rejects_mismatched_internal_key() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.n_of_n_in_script = generate_xonly_pubkey();

        assert!(
            matches!(
                validate_candidate(&builder.build(), &cfg, &operator_table),
                Err(ValidationError::LockingScriptMismatch),
            ),
            "P2TR internal key must match the active N-of-N aggregated key",
        );
    }

    #[test]
    fn candidate_rejects_mismatched_recovery_delay() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.recovery_delay_in_script = cfg.recovery_delay.wrapping_add(1);

        assert!(
            matches!(
                validate_candidate(&builder.build(), &cfg, &operator_table),
                Err(ValidationError::LockingScriptMismatch),
            ),
            "tapscript CSV delay must match the bridge's configured recovery_delay",
        );
    }
}
