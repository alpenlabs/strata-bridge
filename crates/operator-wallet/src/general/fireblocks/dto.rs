//! Serde DTOs mirroring the Fireblocks REST API schemas this module touches.
//!
//! Field names use `rename_all = "camelCase"` to match the wire format. Only the fields the
//! module actually consumes are modelled; unknown fields are ignored on deserialization.

use serde::{Deserialize, Serialize};

// ── RAW signing: request ─────────────────────────────────────────────────────

/// Body of `POST /v1/transactions` for a `RAW` signing operation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RawSignRequest {
    /// Always `"RAW"`.
    pub operation: &'static str,
    /// Asset id: `BTC` on mainnet, and on a test network the id that the vault shows. It selects
    /// the signing key family.
    pub asset_id: String,
    /// Vault account the signing key lives in.
    pub source: TransferPeer,
    /// The identity of this request. Fireblocks rejects a later request that reuses it, with
    /// HTTP 400, and returns the request through `GET /v1/transactions/external_tx_id/{id}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_tx_id: Option<String>,
    /// Text for the vendor audit log.
    pub note: String,
    /// Carries the raw messages to sign.
    pub extra_parameters: ExtraParameters,
}

/// A transfer peer reference (here, the signing vault account).
#[derive(Debug, Serialize)]
pub(super) struct TransferPeer {
    /// Always `"VAULT_ACCOUNT"` for this module.
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

/// One message to sign: a hex-encoded 32-byte sighash that Fireblocks signs **as-is**. It names
/// no derivation path, so it selects the default key of the vault account.
#[derive(Debug, Serialize)]
pub(super) struct UnsignedRawMessage {
    pub content: String,
}

// ── RAW signing: response ────────────────────────────────────────────────────

/// Response of `POST /v1/transactions` — the created transaction's id (its initial `status`
/// is ignored; we poll the transaction detail endpoint for the signed result).
#[derive(Debug, Deserialize)]
pub(super) struct CreateTransactionResponse {
    pub id: String,
}

/// A `GET /v1/transactions/{id}` or `GET /v1/transactions/external_tx_id/{id}` detail response
/// (subset).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TransactionDetails {
    pub id: String,
    pub status: String,
    /// The reason for `status`, for example `BLOCKED_BY_POLICY`. Absent on most statuses.
    pub sub_status: Option<String>,
    /// Per-message signatures, populated once the transaction reaches a signed state. Matched
    /// back to inputs by each message's echoed `content`, not by position — do not rely on
    /// ordering here.
    #[serde(default)]
    pub signed_messages: Vec<SignedMessage>,
}

/// One signed message: the echoed content, the signing public key, and the signature.
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SignatureData {
    /// `r || s`, 64 bytes hex.
    pub full_sig: String,
}

/// Response of `POST /v1/transactions/{id}/cancel`.
#[derive(Debug, Deserialize)]
pub(super) struct CancelTransactionResponse {
    pub success: bool,
}

/// A `GET /v1/vault/accounts/{id}/{asset}/{change}/{index}/public_key_info` response (subset).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PublicKeyInformation {
    /// The public key of the vault address, as hex.
    pub public_key: String,
}
