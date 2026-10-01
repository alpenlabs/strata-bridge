//! Parsing operator exits from Bitcoin transactions.

use bitcoin::Transaction;
use bitcoind_async_client::{Client as BitcoinClient, error::ClientError, traits::Reader};
use strata_asm_common::TxInputRef;
use strata_asm_proto_bridge_txs::{
    BRIDGE_SUBPROTOCOL_ID, constants::BridgeTxType, slash::parse_slash_tx,
    unstake::parse_unstake_tx,
};
use strata_bridge_sm::operator_set::ExitObservation;
pub use strata_bridge_sm::operator_set::ParsedExit;
use strata_l1_txfmt::{MagicBytes, ParseConfig};

use crate::errors::PipelineError;

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

pub(crate) async fn resolve_exit_observation(
    client: &BitcoinClient,
    magic: MagicBytes,
    tx: &Transaction,
    tx_index: usize,
) -> Result<Option<ExitObservation>, PipelineError> {
    let Some(parsed) = parse_exit(magic, tx) else {
        return Ok(None);
    };
    let outpoint = parsed.source();

    // NOTE: (@Rajil1213) Local membership avoids a hard per-block dependency on
    // asm-runner: making ASM the membership source of truth would require a query
    // for every block. These bitcoind fetches are conditional on a parsed slash or
    // unstaking intent at a height not yet processed by membership. The bridge
    // already relies on this node for chain data. An unavailable input must stop
    // membership advancement; replaying processed membership needs no lookup.
    let parent = client
        .get_raw_transaction_verbosity_zero(&outpoint.txid)
        .await
        .map_err(|source| PipelineError::ExitInput { outpoint, source })?
        .0;

    if parent.compute_txid() != outpoint.txid {
        return Err(PipelineError::ExitInput {
            outpoint,
            source: ClientError::MalformedResponse("exit input transaction ID mismatch".into()),
        });
    }

    let output =
        parent
            .output
            .get(outpoint.vout as usize)
            .ok_or_else(|| PipelineError::ExitInput {
                outpoint,
                source: ClientError::MalformedResponse(
                    "exit input output index out of bounds".into(),
                ),
            })?;

    Ok(Some(ExitObservation {
        parsed,
        txid: tx.compute_txid(),
        tx_index: u32::try_from(tx_index).expect("Bitcoin block transaction count fits u32"),
        spent_output_script: output.script_pubkey.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness, absolute,
        consensus::encode::serialize_hex, transaction,
    };
    use strata_asm_proto_bridge_txs::unstake::stake_connector_script;
    use strata_bridge_sm::operator_set::ExitKind;
    use strata_bridge_test_utils::bitcoin::generate_xonly_pubkey;
    use strata_l1_txfmt::TagData;

    use super::*;
    use crate::testing::{mock_bitcoin_rpc, unavailable_bitcoin_client};

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

    #[tokio::test]
    async fn exit_inputs_resolve_the_referenced_output_from_bitcoin_rpc() {
        let mut parent = transaction(BridgeTxType::DepositRequest);
        parent.output.push(TxOut {
            value: Amount::ONE_SAT,
            script_pubkey: ScriptBuf::new(),
        });
        let mut tx = transaction(BridgeTxType::Slash);
        tx.input[1].previous_output = OutPoint::new(parent.compute_txid(), 1);
        let (client, server) = mock_bitcoin_rpc(vec![format!(
            r#"{{"result":"{}","error":null,"id":0}}"#,
            serialize_hex(&parent)
        )])
        .await;
        let observation = resolve_exit_observation(&client, MagicBytes::new(*b"test"), &tx, 3)
            .await
            .unwrap()
            .unwrap();
        let request = server.await.unwrap().remove(0);
        assert!(request.contains("getrawtransaction"));
        assert!(request.contains(&parent.compute_txid().to_string()));
        assert_eq!(observation.parsed.source(), tx.input[1].previous_output);
        assert_eq!(
            observation.spent_output_script,
            parent.output[1].script_pubkey
        );
        assert_eq!(observation.tx_index, 3);
    }

    #[tokio::test]
    async fn exit_input_failure_is_an_error_instead_of_an_unvalidated_observation() {
        let parent = transaction(BridgeTxType::DepositRequest);
        for (response, vout) in [
            (
                r#"{"result":null,"error":{"code":-5,"message":"missing input"},"id":0}"#
                    .to_string(),
                0,
            ),
            (
                format!(
                    r#"{{"result":"{}","error":null,"id":0}}"#,
                    serialize_hex(&transaction(BridgeTxType::Slash))
                ),
                0,
            ),
            (
                format!(
                    r#"{{"result":"{}","error":null,"id":0}}"#,
                    serialize_hex(&parent)
                ),
                42,
            ),
        ] {
            let mut tx = transaction(BridgeTxType::Slash);
            let outpoint = OutPoint::new(parent.compute_txid(), vout);
            tx.input[1].previous_output = outpoint;
            let (client, server) = mock_bitcoin_rpc(vec![response]).await;
            let error = resolve_exit_observation(&client, MagicBytes::new(*b"test"), &tx, 3)
                .await
                .unwrap_err();
            server.await.unwrap();
            assert!(
                matches!(error, PipelineError::ExitInput { outpoint: source, .. } if source == outpoint)
            );
        }
    }

    #[tokio::test]
    async fn transactions_without_exits_need_no_rpc() {
        let tx = transaction(BridgeTxType::DepositRequest);
        let client = unavailable_bitcoin_client();
        let observation = resolve_exit_observation(&client, MagicBytes::new(*b"test"), &tx, 3)
            .await
            .unwrap();
        assert!(observation.is_none());
    }
}
