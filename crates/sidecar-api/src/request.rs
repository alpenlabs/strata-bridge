//! The question the bridge asks: one [`Action`], wrapped in an [`AssessmentRequest`].

use serde::{Deserialize, Serialize};

/// Current wire-protocol version. A sidecar must refuse a request with any other version.
pub const PROTOCOL_VERSION: u16 = 1;

/// What the node is about to act on, which waits for the sidecar's decision.
///
/// Every field is fixed for the request: if any changes, it is a different request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// A deposit request this node may take part in: build the deposit's graphs and sign. Asked
    /// once the request is registered, before anything is signed.
    DepositRequest {
        /// The deposit request transaction (DRT), as a hex txid.
        drt_txid: String,
        /// The DRT output the deposit spends.
        drt_vout: u32,
        /// The bridge denomination, in satoshis.
        amount_sats: u64,
    },
    /// A withdrawal request that ASM assigned to this node to pay: fund, sign and publish the
    /// payment to the user.
    WithdrawalRequest {
        /// The deposit whose withdrawal is being paid; the key of ASM's assignment entry.
        deposit_idx: u32,
        /// The operator index ASM assigned the withdrawal to: this node.
        assignee: u32,
        /// The Bitcoin height by which the assignee must pay.
        deadline: u64,
        /// The bridge denomination, in satoshis, before the operator fee.
        amount_sats: u64,
        /// The operator fee, in satoshis; the user receives `amount_sats - operator_fee_sats`.
        operator_fee_sats: u64,
        /// Where the payment goes: a hex-encoded BOSD descriptor.
        destination: String,
    },
}

/// One question to the sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentRequest {
    /// The wire-protocol version; [`PROTOCOL_VERSION`] for requests built with [`Self::new`].
    pub version: u16,
    /// What the node is about to do.
    pub action: Action,
}

impl AssessmentRequest {
    /// Builds a request with the current [`PROTOCOL_VERSION`].
    pub const fn new(action: Action) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            action,
        }
    }

    /// The request's identity: the blake3 hash of its JSON encoding, as hex.
    ///
    /// Every field takes part, so no two different requests share an ID. Changing a field name,
    /// order or encoding changes every ID, and is a protocol change.
    pub fn id(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("a request holds only JSON-safe fields");
        blake3::hash(&bytes).to_hex().to_string()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::Value;

    use super::*;

    pub(crate) fn deposit() -> AssessmentRequest {
        AssessmentRequest::new(Action::DepositRequest {
            drt_txid: "11".repeat(32),
            drt_vout: 0,
            amount_sats: 1_000_000_000,
        })
    }

    pub(crate) fn withdrawal() -> AssessmentRequest {
        AssessmentRequest::new(Action::WithdrawalRequest {
            deposit_idx: 7,
            assignee: 1,
            deadline: 900,
            amount_sats: 1_000_000_000,
            operator_fee_sats: 10_000,
            destination: "0014".to_owned() + &"33".repeat(20),
        })
    }

    /// The exact JSON both sides exchange. A change here is a protocol change.
    #[test]
    fn the_wire_format_is_stable() {
        assert_eq!(
            serde_json::to_string(&deposit()).unwrap(),
            format!(
                r#"{{"version":1,"action":{{"kind":"deposit_request","drt_txid":"{}","drt_vout":0,"amount_sats":1000000000}}}}"#,
                "11".repeat(32)
            )
        );
        assert_eq!(
            serde_json::to_string(&withdrawal()).unwrap(),
            format!(
                r#"{{"version":1,"action":{{"kind":"withdrawal_request","deposit_idx":7,"assignee":1,"deadline":900,"amount_sats":1000000000,"operator_fee_sats":10000,"destination":"0014{}"}}}}"#,
                "33".repeat(20)
            )
        );
    }

    /// Both sides must compute the same ID from the same request. A change here is a protocol
    /// change.
    #[test]
    fn request_ids_are_fixed_vectors() {
        assert_eq!(
            deposit().id(),
            "12fb639232693941fefe23b51bae106b54bf228045ba37abc0b11f4fbeed5700"
        );
        assert_eq!(
            withdrawal().id(),
            "e0eca0a48c02e8966dd3262e97503ee1259f640c11efbcb7c29a9c00f3a5ed13"
        );
    }

    /// Changing any single field, at the top level or inside the action, changes the ID.
    #[test]
    fn every_field_takes_part_in_the_id() {
        for request in [deposit(), withdrawal()] {
            let original = serde_json::to_value(&request).unwrap();
            let mut paths: Vec<Vec<&str>> = Vec::new();
            for key in original.as_object().unwrap().keys() {
                if key == "action" {
                    for inner in original["action"].as_object().unwrap().keys() {
                        if inner != "kind" {
                            paths.push(vec!["action", inner]);
                        }
                    }
                } else {
                    paths.push(vec![key]);
                }
            }

            for path in paths {
                let mut changed = original.clone();
                let field = path
                    .iter()
                    .fold(&mut changed, |value, key| &mut value[*key]);
                *field = match field {
                    Value::Number(n) => (n.as_u64().unwrap() + 1).into(),
                    Value::String(s) => format!("{s}x").into(),
                    other => panic!("unexpected field type at {path:?}: {other}"),
                };
                let changed: AssessmentRequest = serde_json::from_value(changed).unwrap();
                assert_ne!(changed.id(), request.id(), "{path:?} is not in the ID");
            }
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut request = serde_json::to_value(deposit()).unwrap();
        request["action"]["extra"] = 1.into();
        assert!(serde_json::from_value::<AssessmentRequest>(request.clone()).is_err());

        request["action"].as_object_mut().unwrap().remove("extra");
        request["extra"] = 1.into();
        assert!(serde_json::from_value::<AssessmentRequest>(request).is_err());
    }
}
