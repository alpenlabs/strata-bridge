//! Serde DTOs mirroring the Fireblocks REST API schemas this backend touches.
//!
//! Field names use `rename_all = "camelCase"` to match the wire format. Only the fields the
//! backend actually consumes are modelled; unknown fields are ignored on deserialization.

use serde::{Deserialize, Serialize};

/// One unspent input reference (`UnspentInput` in the Fireblocks schema).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnspentInput {
    /// Funding transaction id (hex).
    pub tx_hash: String,
    /// Output index within `tx_hash`.
    pub index: u32,
}

/// One element of the `GET …/unspent_inputs` response (`UnspentInputsResponse`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnspentInputsResponse {
    /// The outpoint (`txHash` + `index`).
    pub input: UnspentInput,
    /// Address holding the UTXO; the source for its `script_pubkey`.
    pub address: String,
    /// Value as a decimal BTC string (e.g. `"0.5"`).
    pub amount: String,
    /// Confirmation count as of the query.
    pub confirmations: u64,
}

/// Response body of `GET /v1/vault/accounts/{id}/{asset}/unspent_inputs`.
pub(super) type GetUnspentInputsResponse = Vec<UnspentInputsResponse>;

// ── RAW signing: request ─────────────────────────────────────────────────────

/// Body of `POST /v1/transactions` for a `RAW` signing operation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RawSignRequest {
    /// Always `"RAW"`.
    pub operation: &'static str,
    /// Asset id (`BTC` / `BTC_TEST`) — selects the signing key family.
    pub asset_id: String,
    /// Vault account the signing key lives in.
    pub source: TransferPeer,
    /// Carries the raw messages to sign.
    pub extra_parameters: ExtraParameters,
}

/// A transfer peer reference (here, the signing vault account).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TransferPeer {
    /// Always `"VAULT_ACCOUNT"` for this backend.
    #[serde(rename = "type")]
    pub peer_type: &'static str,
    /// Vault account id.
    pub id: String,
}

/// `extraParameters` wrapper carrying the raw message data.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExtraParameters {
    pub raw_message_data: RawMessageData,
}

/// The set of messages (sighashes) to sign and the algorithm to use.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RawMessageData {
    pub messages: Vec<UnsignedRawMessage>,
    /// `MPC_ECDSA_SECP256K1` for Bitcoin.
    pub algorithm: &'static str,
}

/// One message to sign: a hex-encoded 32-byte sighash that Fireblocks signs **as-is**, plus the
/// BIP44 derivation indices telling Fireblocks which derived key under the vault to sign with.
///
/// Without `bip44AddressIndex`/`bip44change` Fireblocks signs with the vault's default key, which
/// only matches the configured `deposit_address` for the default vault address — operators using
/// a non-default address would get back a pubkey that doesn't control the prevout and
/// `assemble_p2wpkh_witness` would (correctly) reject it. Sending the indices explicitly lets
/// the backend spend any vault address.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnsignedRawMessage {
    pub content: String,
    pub bip44_address_index: u32,
    /// Fireblocks names this field with a lowercase `c` (`bip44change`); the explicit rename
    /// overrides the struct-level `camelCase` so we don't end up sending `bip44Change`.
    #[serde(rename = "bip44change")]
    pub bip44_change: u32,
}

// ── RAW signing: response ────────────────────────────────────────────────────

/// Response of `POST /v1/transactions` — the created transaction's id (its initial `status`
/// is ignored; we poll the transaction detail endpoint for the signed result).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateTransactionResponse {
    pub id: String,
}

/// A `GET /v1/transactions/{id}` detail response (subset).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TransactionDetails {
    pub status: String,
    /// Per-message signatures, populated once the transaction reaches a signed state. Matched
    /// back to inputs by each message's echoed `content`, not by position — do not rely on
    /// ordering here.
    #[serde(default)]
    pub signed_messages: Vec<SignedMessage>,
}

/// One signed message: the echoed content, the signing public key, and the signature.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SignedMessage {
    /// The signed message echoed back — the hex sighash we submitted. Used to match each
    /// signature to the input that requested it (rather than trusting positional order).
    pub content: String,
    /// Compressed public key (hex) the message was signed with.
    pub public_key: String,
    pub signature: SignatureData,
}

/// The ECDSA signature returned for a signed message.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SignatureData {
    /// `r || s`, 64 bytes hex.
    pub full_sig: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unspent_inputs_response() {
        // Shape per the Fireblocks swagger `UnspentInputsResponse` schema, with an extra
        // unknown field to confirm forward-compatibility.
        let json = r#"[
            {
                "input": { "txHash": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", "index": 2 },
                "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                "amount": "0.12345678",
                "confirmations": 6,
                "status": "CONFIRMED",
                "someFutureField": true
            }
        ]"#;

        let parsed: GetUnspentInputsResponse = serde_json::from_str(json).expect("parses");
        assert_eq!(parsed.len(), 1);
        let u = &parsed[0];
        assert_eq!(
            u.input.tx_hash,
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
        assert_eq!(u.input.index, 2);
        assert_eq!(u.address, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        assert_eq!(u.amount, "0.12345678");
        assert_eq!(u.confirmations, 6);
    }

    #[test]
    fn unsigned_raw_message_serializes_with_fireblocks_field_names() {
        // Pin the exact wire names: Fireblocks expects `bip44AddressIndex` (camelCase) and
        // `bip44change` (all lowercase) — `rename_all = "camelCase"` would otherwise emit
        // `bip44Change`, which Fireblocks would silently ignore and fall back to the default key.
        let msg = UnsignedRawMessage {
            content: "deadbeef".to_string(),
            bip44_address_index: 5,
            bip44_change: 1,
        };
        let v: serde_json::Value = serde_json::to_value(&msg).expect("serializes");
        assert_eq!(v["content"], "deadbeef");
        assert_eq!(v["bip44AddressIndex"], 5);
        assert_eq!(v["bip44change"], 1);
        assert!(
            v.get("bip44Change").is_none(),
            "must not emit `bip44Change` (camelCase) — Fireblocks would ignore it"
        );
    }
}
