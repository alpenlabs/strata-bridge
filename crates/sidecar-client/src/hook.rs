//! [`SidecarHook`] for [`SidecarClient`]: maps the bridge's two questions onto the wire.

use strata_bridge_orchestrator::sidecar_hook::{
    DepositParticipationRequest, FulfillmentDecision, ParticipationDecision, SidecarHook,
    WithdrawalFulfillmentRequest,
};
use strata_bridge_sidecar_api::{Action, AssessmentRequest, Decision};

use crate::SidecarClient;

/// The wire action for a deposit request this node may take part in.
fn deposit_action(request: &DepositParticipationRequest) -> Action {
    Action::DepositRequest {
        drt_txid: request.deposit_request_outpoint.txid.to_string(),
        drt_vout: request.deposit_request_outpoint.vout,
        amount_sats: request.amount.to_sat(),
    }
}

/// The wire action for a withdrawal this node is assigned to pay.
fn withdrawal_action(request: &WithdrawalFulfillmentRequest) -> Action {
    Action::WithdrawalRequest {
        deposit_idx: request.deposit_idx,
        assignee: request.assignee,
        deadline: request.deadline,
        amount_sats: request.amount.to_sat(),
        operator_fee_sats: request.operator_fee.to_sat(),
        destination: request.destination.to_string(),
    }
}

impl SidecarHook for SidecarClient {
    fn deposit_participation(
        &self,
        request: &DepositParticipationRequest,
    ) -> Option<ParticipationDecision> {
        match self.poll(AssessmentRequest::new(deposit_action(request))) {
            Decision::Proceed => Some(ParticipationDecision::Participate),
            Decision::Decline => Some(ParticipationDecision::Decline),
            Decision::Defer => None,
        }
    }

    fn withdrawal_fulfillment(
        &self,
        request: &WithdrawalFulfillmentRequest,
    ) -> Option<FulfillmentDecision> {
        match self.poll(AssessmentRequest::new(withdrawal_action(request))) {
            Decision::Proceed => Some(FulfillmentDecision::Fulfill),
            Decision::Decline => Some(FulfillmentDecision::Decline),
            Decision::Defer => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bitcoin::{Amount, OutPoint, Txid, XOnlyPublicKey, hashes::Hash};
    use bitcoin_bosd::Descriptor;
    use strata_bridge_primitives::covenant::CovenantId;

    use super::*;
    use crate::client::tests::{answering_server, open, test_config};

    /// The x-only key of the secp256k1 generator, a valid key for test covenants.
    const GENERATOR_X: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    #[tokio::test]
    async fn both_questions_are_asked_and_answered_through_the_sidecar() {
        let (endpoint, server) = answering_server(Decision::Proceed).await;
        let client = open(test_config(&endpoint)).unwrap();
        let mut wakeups = client.take_wakeups().unwrap();
        let covenant = CovenantId {
            aggregate_pubkey: XOnlyPublicKey::from_slice(&GENERATOR_X).unwrap(),
            activation_height: 100,
        };
        let deposit = DepositParticipationRequest {
            deposit_idx: 0,
            covenant,
            deposit_request_outpoint: OutPoint::default(),
            amount: Amount::from_sat(100_000),
        };
        let withdrawal = WithdrawalFulfillmentRequest {
            deposit_idx: 1,
            covenant,
            deadline: 1_000,
            destination: Descriptor::new_p2tr(&GENERATOR_X).unwrap(),
            amount: Amount::from_sat(100_000),
            assignee: 0,
            operator_fee: Amount::from_sat(1_000),
        };

        assert_eq!(
            client.deposit_participation(&deposit),
            None,
            "first ask schedules"
        );
        assert_eq!(client.withdrawal_fulfillment(&withdrawal), None);
        // Wake-ups coalesce (the channel holds one), so ask again after each until both answers
        // are in, as the pipeline does.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                wakeups.recv().await.expect("wake-up channel open");
                if client.deposit_participation(&deposit).is_some()
                    && client.withdrawal_fulfillment(&withdrawal).is_some()
                {
                    break;
                }
            }
        })
        .await
        .expect("each answer wakes the pipeline");
        assert_eq!(
            client.deposit_participation(&deposit),
            Some(ParticipationDecision::Participate)
        );
        assert_eq!(
            client.withdrawal_fulfillment(&withdrawal),
            Some(FulfillmentDecision::Fulfill)
        );
        server.abort();
    }

    /// The exact wire request the bridge's own types produce. The text fields come from
    /// `Txid`, `Descriptor` and `Amount` formatting in other crates; a change there would change
    /// every request ID, so it must fail here first.
    #[test]
    fn bridge_requests_map_to_pinned_wire_requests() {
        let covenant = CovenantId {
            aggregate_pubkey: XOnlyPublicKey::from_slice(&GENERATOR_X).unwrap(),
            activation_height: 100,
        };
        let deposit = AssessmentRequest::new(deposit_action(&DepositParticipationRequest {
            deposit_idx: 7,
            covenant,
            deposit_request_outpoint: OutPoint::new(Txid::from_byte_array([0x11; 32]), 0),
            amount: Amount::from_sat(1_000_000_000),
        }));
        let withdrawal = AssessmentRequest::new(withdrawal_action(&WithdrawalFulfillmentRequest {
            deposit_idx: 7,
            covenant,
            deadline: 900,
            destination: Descriptor::new_p2tr(&GENERATOR_X).unwrap(),
            amount: Amount::from_sat(1_000_000_000),
            assignee: 1,
            operator_fee: Amount::from_sat(10_000),
        }));

        assert_eq!(
            serde_json::to_string(&deposit).unwrap(),
            format!(
                r#"{{"version":1,"action":{{"kind":"deposit_request","drt_txid":"{}","drt_vout":0,"amount_sats":1000000000}}}}"#,
                "11".repeat(32)
            )
        );
        assert_eq!(
            serde_json::to_string(&withdrawal).unwrap(),
            format!(
                r#"{{"version":1,"action":{{"kind":"withdrawal_request","deposit_idx":7,"assignee":1,"deadline":900,"amount_sats":1000000000,"operator_fee_sats":10000,"destination":"{}"}}}}"#,
                "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            )
        );
    }
}
