//! Serde DTOs mirroring the Fireblocks REST API schemas this backend touches.
//!
//! Field names use `rename_all = "camelCase"` to match the wire format. Only the fields the
//! backend actually consumes are modelled; unknown fields are ignored on deserialization.

use serde::Deserialize;

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
}
