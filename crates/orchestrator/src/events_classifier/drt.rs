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

/// Reason [`validate`] rejected a transaction.
#[derive(Debug, Error)]
pub(super) enum ValidationError {
    /// Transaction is not addressed to this bridge: missing SPS-50 OP_RETURN, or the magic /
    /// subprotocol id / tx type do not identify it as a Bridge-v1 DRT for `cfg.magic_bytes`.
    /// Expected for the vast majority of block transactions and not worth surfacing as an
    /// error to the operator.
    #[error("transaction is not a DRT for this bridge")]
    NotOurEnvelope,
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

/// Validates that `tx` is a well-formed DRT for the bridge with the given `cfg` and active
/// operator set, and returns the parts a `DepositSM` needs.
///
/// Pure: no registry or applicator access.
pub(super) fn validate(
    tx: &Transaction,
    cfg: &DepositSMCfg,
    active_operator_table: &OperatorTable,
) -> Result<Valid, ValidationError> {
    let Ok((magic, tag)) = extract_tx_magic_and_tag(tx) else {
        return Err(ValidationError::NotOurEnvelope);
    };
    if magic != cfg.magic_bytes
        || tag.subproto_id() != BRIDGE_V1_SUBPROTOCOL_ID
        || tag.tx_type() != BridgeTxType::DepositRequest as u8
    {
        return Err(ValidationError::NotOurEnvelope);
    }

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

    #[test]
    fn accepts_aligned_drt() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let builder = DrtBuilder::aligned(&operator_table, &cfg);
        let expected_pk = XOnlyPublicKey::from_slice(&builder.recovery_pk_in_aux).unwrap();
        let expected_value = builder.output_value;

        let valid =
            validate(&builder.build(), &cfg, &operator_table).expect("aligned DRT must validate");

        assert_eq!(valid.depositor_pubkey, expected_pk);
        assert_eq!(valid.drt_output_amount, expected_value);
    }

    #[test]
    fn rejects_tx_without_sps50_envelope() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        assert!(matches!(
            validate(&tx, &cfg, &operator_table),
            Err(ValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn rejects_non_op_return_first_output() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
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

        assert!(matches!(
            validate(&tx, &cfg, &operator_table),
            Err(ValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn rejects_wrong_magic() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.magic = MagicBytes::new(*b"XXXX");

        assert!(matches!(
            validate(&builder.build(), &cfg, &operator_table),
            Err(ValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn rejects_wrong_subproto() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.subproto_id = BRIDGE_V1_SUBPROTOCOL_ID.wrapping_add(1);

        assert!(matches!(
            validate(&builder.build(), &cfg, &operator_table),
            Err(ValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn rejects_wrong_tx_type() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.tx_type = BridgeTxType::Deposit as u8;

        assert!(matches!(
            validate(&builder.build(), &cfg, &operator_table),
            Err(ValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn rejects_malformed_aux() {
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

        assert!(matches!(
            validate(&tx, &cfg, &operator_table),
            Err(ValidationError::Structure(_))
        ));
    }

    #[test]
    fn rejects_invalid_recovery_pubkey() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        // 32 zero bytes are not a valid x-only point.
        builder.recovery_pk_in_aux = [0u8; 32];
        builder.recovery_pk_in_script = [0u8; 32];

        assert!(matches!(
            validate(&builder.build(), &cfg, &operator_table),
            Err(ValidationError::InvalidRecoveryPubkey(_))
        ));
    }

    #[test]
    fn rejects_output_value_below_required() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let required = DepositTx::drt_required(cfg.deposit_amount);
        let actual = required - Amount::from_sat(1);
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.output_value = actual;

        let err = validate(&builder.build(), &cfg, &operator_table).unwrap_err();
        match err {
            ValidationError::OutputValueBelowRequired {
                actual: got_actual,
                required: got_required,
            } => {
                assert_eq!(got_actual, actual);
                assert_eq!(got_required, required);
            }
            other => panic!("expected OutputValueBelowRequired, got {other:?}"),
        }
    }

    #[test]
    fn rejects_mismatched_recovery_pk_in_script() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.recovery_pk_in_script = generate_xonly_pubkey().serialize();
        assert_ne!(builder.recovery_pk_in_aux, builder.recovery_pk_in_script);

        assert!(matches!(
            validate(&builder.build(), &cfg, &operator_table),
            Err(ValidationError::LockingScriptMismatch)
        ));
    }

    #[test]
    fn rejects_mismatched_internal_key() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.n_of_n_in_script = generate_xonly_pubkey();

        assert!(matches!(
            validate(&builder.build(), &cfg, &operator_table),
            Err(ValidationError::LockingScriptMismatch)
        ));
    }

    #[test]
    fn rejects_mismatched_recovery_delay() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.recovery_delay_in_script = cfg.recovery_delay.wrapping_add(1);

        assert!(matches!(
            validate(&builder.build(), &cfg, &operator_table),
            Err(ValidationError::LockingScriptMismatch)
        ));
    }
}
