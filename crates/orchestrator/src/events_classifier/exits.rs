//! Parsing operator exits from Bitcoin transactions.

use bitcoin::Transaction;
use strata_asm_common::TxInputRef;
use strata_asm_proto_bridge_txs::{
    BRIDGE_SUBPROTOCOL_ID, constants::BridgeTxType, slash::parse_slash_tx,
    unstake::parse_unstake_tx,
};
pub use strata_bridge_sm::operator_set::ParsedExit;
use strata_l1_txfmt::{MagicBytes, ParseConfig};

/// Extracts an operator exit from a transaction with the supplied magic bytes.
///
/// Returns `None` for unrecognized or malformed exit transactions.
/// Successful parsing does not establish protocol validity.
pub fn parse_exit(magic: MagicBytes, tx: &Transaction) -> Option<ParsedExit> {
    let tag = ParseConfig::new(magic).try_parse_tx(tx).ok()?;
    if tag.subproto_id() != BRIDGE_SUBPROTOCOL_ID {
        return None;
    }
    let input = TxInputRef::new(tx, tag);
    match input.tag().tx_type() {
        kind if kind == BridgeTxType::Slash as u8 => {
            parse_slash_tx(&input).ok().map(ParsedExit::Slash)
        }
        kind if kind == BridgeTxType::Unstake as u8 => {
            parse_unstake_tx(&input).ok().map(ParsedExit::Unstake)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, TxIn, TxOut, Witness, absolute, transaction};
    use strata_asm_proto_bridge_txs::unstake::stake_connector_script;
    use strata_bridge_sm::operator_set::ExitKind;
    use strata_bridge_test_utils::bitcoin::generate_xonly_pubkey;
    use strata_l1_txfmt::TagData;

    use super::*;

    fn transaction(kind: BridgeTxType) -> Transaction {
        let tag = TagData::new(
            BRIDGE_SUBPROTOCOL_ID,
            kind as u8,
            7u32.to_be_bytes().to_vec(),
        )
        .unwrap();
        let script = ParseConfig::new(MagicBytes::new(*b"test"))
            .encode_script_buf(&tag.as_ref())
            .unwrap();
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default(), TxIn::default()],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: script,
            }],
        }
    }

    #[test]
    fn slash_parsing_needs_no_local_stake() {
        let mut tx = transaction(BridgeTxType::Slash);
        tx.input[1].previous_output.vout = 42;
        let parsed = parse_exit(MagicBytes::new(*b"test"), &tx).unwrap();
        assert_eq!(parsed.operator(), 7);
        assert_eq!(parsed.source(), tx.input[1].previous_output);
        assert_eq!(parsed.kind(), ExitKind::Slash);
    }

    #[test]
    fn unstaking_intent_uses_asm_witness_checks() {
        let mut tx = transaction(BridgeTxType::Unstake);
        let magic = MagicBytes::new(*b"test");
        assert!(parse_exit(magic, &tx).is_none());
        let script = stake_connector_script([1; 32], generate_xonly_pubkey());
        tx.input[0].witness =
            Witness::from_slice(&[vec![1; 32], vec![2; 64], script.into_bytes(), vec![3; 33]]);
        let parsed = parse_exit(magic, &tx).unwrap();
        assert_eq!(parsed.operator(), 7);
        assert_eq!(parsed.source(), tx.input[0].previous_output);
        assert_eq!(parsed.kind(), ExitKind::UnstakingIntent);
        tx.input[0].witness =
            Witness::from_slice(&[vec![1; 32], vec![2; 64], vec![0], vec![3; 33]]);
        assert!(parse_exit(magic, &tx).is_none());
    }

    #[test]
    fn unrelated_namespace_and_malformed_slash_are_ignored() {
        let mut tx = transaction(BridgeTxType::Slash);
        assert!(parse_exit(MagicBytes::new(*b"else"), &tx).is_none());
        tx.input.pop();
        assert!(parse_exit(MagicBytes::new(*b"test"), &tx).is_none());
        let tx = transaction(BridgeTxType::DepositRequest);
        assert!(parse_exit(MagicBytes::new(*b"test"), &tx).is_none());
    }
}
