//! The lifecycle of a RAW signing request: find or create the request of a sighash set under
//! its `externalTxId`, poll it for the signatures, and cancel it on a give-up.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use reqwest::Method;
use sha2::{Digest, Sha256};

use super::{dto, FireblocksError, FireblocksSigner};

/// The most messages that Fireblocks accepts in one RAW request. One message signs one input.
pub(super) const MAX_RAW_MESSAGES: usize = 127;
/// How often to poll a RAW-signing transaction for completion. Tests poll fast against a mock
/// server; the production value is not exercised by a test.
const SIGN_POLL_INTERVAL: Duration = if cfg!(test) {
    Duration::from_millis(5)
} else {
    Duration::from_secs(2)
};
/// The limit on one wait for signatures. It sits above the MPC latency of an auto-approved
/// request. Each wait polls at least once, and a poll error does not end it: the request exists on
/// the server, so an API blip must not cost its MPC run. The deadline is read after each poll, so a
/// stalled signer costs this limit plus one
/// [`HTTP_REQUEST_TIMEOUT`](super::client::HTTP_REQUEST_TIMEOUT) and one more for the cancel, and a
/// batch of bumps pays that per parent.
pub(super) const SIGN_MAX_DURATION: Duration = Duration::from_secs(180);

impl FireblocksSigner {
    /// Signs `sighashes` via a Fireblocks `RAW` transaction: finds or creates the request of this
    /// sighash set, then polls it until the signatures are available (or it fails / times out).
    /// Returns one signed message per sighash, in the order of `sighashes`. `sighashes` must be
    /// distinct, because the response binds a signature to its message by content alone.
    ///
    /// `note` goes to the vendor audit log, which otherwise sees only digests.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "used by the commit that signs vault inputs through Fireblocks"
        )
    )]
    async fn raw_sign(
        &self,
        sighashes: &[[u8; 32]],
        note: &str,
    ) -> Result<Vec<dto::SignedMessage>, FireblocksError> {
        if sighashes.len() > MAX_RAW_MESSAGES {
            return Err(FireblocksError::TooManyInputs {
                count: sighashes.len(),
            });
        }
        // Lowercase-hex of each sighash; also the `content` we expect echoed back per message.
        let expected: Vec<String> = sighashes.iter().map(hex::encode).collect();
        let deadline = Instant::now() + SIGN_MAX_DURATION;
        let tx_id = self
            .find_or_create(&external_tx_digest(sighashes), &expected, note, deadline)
            .await?;
        self.await_signatures(&tx_id, &expected, deadline).await
    }

    /// Returns the id of the live request of this sighash set, and creates one if none exists.
    ///
    /// This creates first and looks up on any failure. It rests only on the documented duplicate
    /// rejection and the lookup of an id that exists: the docs do not give the response for an
    /// unknown id, so a failed lookup cannot tell "no request" from an outage, and the create
    /// error stands. A create that failed in transit is found by the next attempt at the latest.
    ///
    /// A request that this finds already signed goes through the same poll as any other, so one
    /// path checks the response.
    async fn find_or_create(
        &self,
        digest: &str,
        messages: &[String],
        note: &str,
        deadline: Instant,
    ) -> Result<String, FireblocksError> {
        let first = {
            let known = self
                .generations
                .lock()
                .expect("no panic holds the generation map");
            known.get(digest).copied().unwrap_or(0)
        };
        for generation in first.. {
            if Instant::now() >= deadline {
                break;
            }
            self.generations
                .lock()
                .expect("no panic holds the generation map")
                .insert(digest.to_string(), generation);
            let external_tx_id = format!("{digest}-{generation}");
            let create_error = match self
                .create_raw_tx(messages, note, Some(&external_tx_id))
                .await
            {
                Ok(created) => return Ok(created.id),
                Err(e) => e,
            };
            let subpath = format!("/transactions/external_tx_id/{external_tx_id}");
            let existing = match self
                .signed_request::<dto::TransactionDetails>(Method::GET, &subpath, None)
                .await
            {
                Ok(existing) => existing,
                Err(lookup_error) => {
                    tracing::warn!(
                        %external_tx_id,
                        error = %lookup_error,
                        "no raw-sign transaction found after a failed create"
                    );
                    return Err(create_error);
                }
            };
            let tx_id = existing.id.clone();
            match RawProgress::of(existing, messages) {
                RawProgress::Refused(reason) | RawProgress::Dead(reason) => tracing::warn!(
                    %external_tx_id,
                    %tx_id,
                    %reason,
                    "raw-sign id is taken by an ended transaction; moving to the next generation"
                ),
                RawProgress::Signed(_) | RawProgress::Pending => return Ok(tx_id),
            }
        }
        Err(FireblocksError::SearchTimeout {
            digest: digest.to_string(),
        })
    }

    /// Creates a RAW transaction over `messages`. A request with no `external_tx_id` is a new
    /// request on each call.
    async fn create_raw_tx(
        &self,
        messages: &[String],
        note: &str,
        external_tx_id: Option<&str>,
    ) -> Result<dto::CreateTransactionResponse, FireblocksError> {
        let messages = messages
            .iter()
            .map(|content| dto::UnsignedRawMessage {
                content: content.clone(),
            })
            .collect();
        let request = dto::RawSignRequest {
            operation: "RAW",
            asset_id: self.config.asset_id.clone(),
            source: dto::TransferPeer {
                peer_type: "VAULT_ACCOUNT",
                id: self.config.vault_account_id.clone(),
            },
            note: note.to_string(),
            external_tx_id: external_tx_id.map(str::to_string),
            extra_parameters: dto::ExtraParameters {
                raw_message_data: dto::RawMessageData {
                    messages,
                    algorithm: "MPC_ECDSA_SECP256K1",
                },
            },
        };
        let body = serde_json::to_string(&request).map_err(|e| {
            FireblocksError::SignRequest(format!("serialize raw-sign request: {e}"))
        })?;
        self.signed_request(Method::POST, "/transactions", Some(&body))
            .await
    }

    /// Polls transaction `tx_id` until every message in `expected` has a signature. A wait that
    /// gives up cancels the transaction: the next attempt may sign other digests, and then
    /// nothing collects this result.
    async fn await_signatures(
        &self,
        tx_id: &str,
        expected: &[String],
        deadline: Instant,
    ) -> Result<Vec<dto::SignedMessage>, FireblocksError> {
        let subpath = format!("/transactions/{tx_id}");
        let give_up = loop {
            match self
                .signed_request::<dto::TransactionDetails>(Method::GET, &subpath, None)
                .await
            {
                Ok(details) => match RawProgress::of(details, expected) {
                    RawProgress::Signed(signed) => return Ok(signed),
                    RawProgress::Refused(reason) | RawProgress::Dead(reason) => {
                        return Err(FireblocksError::RequestFailed {
                            tx_id: tx_id.to_string(),
                            reason,
                        })
                    }
                    RawProgress::Pending => {}
                },
                Err(e) => {
                    tracing::warn!(%tx_id, error = %e, "error polling raw-sign transaction");
                }
            }
            if Instant::now() >= deadline {
                break FireblocksError::SigningTimeout(tx_id.to_string());
            }
            tokio::time::sleep(SIGN_POLL_INTERVAL).await;
        };
        self.cancel(tx_id).await;
        Err(give_up)
    }

    /// Asks Fireblocks to cancel `tx_id`. The give-up error is what the caller needs, so a failed
    /// cancel only logs: the next attempt finds the request through its `externalTxId`.
    async fn cancel(&self, tx_id: &str) {
        let subpath = format!("/transactions/{tx_id}/cancel");
        // Fireblocks' own clients post an empty JSON object to cancel.
        match self
            .signed_request::<dto::CancelTransactionResponse>(Method::POST, &subpath, Some("{}"))
            .await
        {
            Ok(response) if response.success => {
                tracing::info!(%tx_id, "cancelled raw-sign transaction");
            }
            Ok(_) => tracing::warn!(%tx_id, "Fireblocks declined to cancel raw-sign transaction"),
            Err(e) => {
                tracing::warn!(%tx_id, error = %e, "failed to cancel raw-sign transaction");
            }
        }
    }
}

/// The hash part of the `externalTxId` of a sighash set. The order of the inputs does not change
/// it. A sighash commits to the script of its input, so the set names one vault key too.
fn external_tx_digest(sighashes: &[[u8; 32]]) -> String {
    let mut sorted = sighashes.to_vec();
    sorted.sort_unstable();
    let mut hasher = Sha256::new();
    for sighash in &sorted {
        hasher.update(sighash);
    }
    hex::encode(hasher.finalize())
}

/// Where a RAW transaction stands.
enum RawProgress {
    /// Every expected message has a signature. They are in the order of the expected messages.
    Signed(Vec<dto::SignedMessage>),
    /// The transaction can still produce the signatures.
    Pending,
    /// Fireblocks or its policy turned the request down. It holds the reason.
    Refused(String),
    /// The transaction ended, and it can never produce the signatures. It holds the reason.
    Dead(String),
}

impl RawProgress {
    /// Reads `details`, the state of a RAW transaction, against the messages it must sign.
    fn of(details: dto::TransactionDetails, expected: &[String]) -> Self {
        let reason = match &details.sub_status {
            Some(sub_status) => format!("{} ({sub_status})", details.status),
            None => details.status.clone(),
        };
        // A failure status outranks any signature in the same response: the status is the
        // vendor's statement on the request, and the cost of the rule is one more MPC run.
        match details.status.as_str() {
            "REJECTED" | "BLOCKED" => return Self::Refused(reason),
            "FAILED" | "CANCELLED" | "CANCELLING" | "TIMEOUT" => return Self::Dead(reason),
            _ => {}
        }
        // Any other status, an unknown one too, is pending until the deadline of the poll.
        // Index the returned signatures by their echoed `content` so that each one binds to the
        // input that requested it, not to a position in the response. The case of the echoed hex
        // is the vendor's choice, and only its value matters.
        let mut by_content: HashMap<String, dto::SignedMessage> = details
            .signed_messages
            .into_iter()
            .map(|m| (m.content.to_lowercase(), m))
            .collect();
        // Only done once *every* requested sighash has a matching signature, which guards against
        // partial / incremental population mid-signing.
        let signed: Option<Vec<dto::SignedMessage>> = expected
            .iter()
            .map(|content| by_content.remove(content))
            .collect();
        match signed {
            Some(signed) => Self::Signed(signed),
            // A completed request, partly or not, signs nothing more.
            None if matches!(details.status.as_str(), "COMPLETED" | "PARTIALLY_COMPLETED") => {
                Self::Dead(format!("{reason} with missing signatures"))
            }
            None => Self::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        matchers::{body_partial_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::general::fireblocks::test_utils::{
        created, details, expect, mock_signer, ok, CREATE_PATH, TX_ID, TX_PATH, VAULT_SECRET,
    };

    const SIGHASH: [u8; 32] = [0x11; 32];

    /// The `externalTxId` of `[SIGHASH]` at `generation`.
    fn external_id(generation: u64) -> String {
        format!("{}-{generation}", external_tx_digest(&[SIGHASH]))
    }

    /// Finds or creates the request of `[SIGHASH]`, within `limit`.
    async fn find_in(
        signer: &FireblocksSigner,
        limit: Duration,
    ) -> Result<String, FireblocksError> {
        signer
            .find_or_create(
                &external_tx_digest(&[SIGHASH]),
                &[hex::encode(SIGHASH)],
                "note",
                Instant::now() + limit,
            )
            .await
    }

    /// What `raw_sign` does for `[SIGHASH]`.
    async fn sign_sighash(
        signer: &FireblocksSigner,
    ) -> Result<Vec<dto::SignedMessage>, FireblocksError> {
        let tx_id = find_in(signer, SIGN_MAX_DURATION).await?;
        signer
            .await_signatures(
                &tx_id,
                &[hex::encode(SIGHASH)],
                Instant::now() + SIGN_MAX_DURATION,
            )
            .await
    }

    fn lookup_path(generation: u64) -> String {
        format!(
            "/v1/transactions/external_tx_id/{}",
            external_id(generation)
        )
    }

    /// The HTTP 400 that Fireblocks returns for a repeated `externalTxId`.
    fn rejected() -> ResponseTemplate {
        ResponseTemplate::new(400).set_body_json(json!({ "message": "duplicate", "code": 1 }))
    }

    const CANCEL_PATH: &str = "/v1/transactions/tx-1/cancel";
    const SHORT: Duration = Duration::from_millis(50);

    #[test]
    fn a_request_id_does_not_depend_on_input_order() {
        let (a, b) = ([1; 32], [2; 32]);
        assert_eq!(external_tx_digest(&[a, b]), external_tx_digest(&[b, a]));
        assert_ne!(external_tx_digest(&[a]), external_tx_digest(&[a, b]));
    }

    #[tokio::test]
    async fn a_signing_request_carries_its_external_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CREATE_PATH))
            .and(body_partial_json(json!({
                "operation": "RAW",
                "assetId": "BTC_TEST",
                "source": { "type": "VAULT_ACCOUNT", "id": "0" },
                "externalTxId": external_id(0),
                "note": "note",
                "extraParameters": {
                    "rawMessageData": {
                        "algorithm": "MPC_ECDSA_SECP256K1",
                        "messages": [{ "content": hex::encode(SIGHASH) }],
                    },
                },
            })))
            .respond_with(created())
            .expect(1)
            .mount(&server)
            .await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
            1,
        )
        .await;

        let signed = sign_sighash(&mock_signer(&server)).await.expect("signed");
        assert_eq!(signed.len(), 1);
        assert_eq!(signed[0].content, hex::encode(SIGHASH));
    }

    /// A retry of an unchanged transaction joins the first request, so it starts no second MPC
    /// run and still collects the signature.
    #[tokio::test]
    async fn a_duplicate_rejection_resumes_the_existing_request() {
        let server = MockServer::start().await;
        expect(&server, "POST", CREATE_PATH, rejected(), 1).await;
        expect(
            &server,
            "GET",
            &lookup_path(0),
            ok(details("PENDING_SIGNATURE", &[], &VAULT_SECRET)),
            1,
        )
        .await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
            1,
        )
        .await;

        sign_sighash(&mock_signer(&server))
            .await
            .expect("signed through the existing request");
    }

    /// An id stays taken after its request ends, and the same sighashes must still be signable.
    #[tokio::test]
    async fn a_dead_request_moves_the_id_to_the_next_generation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CREATE_PATH))
            .and(body_partial_json(json!({ "externalTxId": external_id(0) })))
            .respond_with(rejected())
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CREATE_PATH))
            .and(body_partial_json(json!({ "externalTxId": external_id(1) })))
            .respond_with(created())
            .expect(1)
            .mount(&server)
            .await;
        expect(
            &server,
            "GET",
            &lookup_path(0),
            ok(details("CANCELLED", &[], &VAULT_SECRET)),
            1,
        )
        .await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
            1,
        )
        .await;

        sign_sighash(&mock_signer(&server))
            .await
            .expect("signed under the next generation");
    }

    /// A refused request ended, so the same sighashes move to the next generation, and a corrected
    /// policy applies there.
    #[tokio::test]
    async fn a_refused_request_moves_the_id_to_the_next_generation() {
        for status in ["REJECTED", "BLOCKED"] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(CREATE_PATH))
                .and(body_partial_json(json!({ "externalTxId": external_id(0) })))
                .respond_with(rejected())
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(CREATE_PATH))
                .and(body_partial_json(json!({ "externalTxId": external_id(1) })))
                .respond_with(created())
                .expect(1)
                .mount(&server)
                .await;
            expect(
                &server,
                "GET",
                &lookup_path(0),
                ok(details(status, &[], &VAULT_SECRET)),
                1,
            )
            .await;
            expect(
                &server,
                "GET",
                TX_PATH,
                ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
                1,
            )
            .await;

            sign_sighash(&mock_signer(&server))
                .await
                .unwrap_or_else(|e| panic!("{status}: signed under the next generation: {e:?}"));
        }
    }

    /// A broken server must not hold the signer in the walk.
    #[tokio::test]
    async fn a_walk_through_dead_requests_stops_at_its_deadline() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CREATE_PATH))
            .respond_with(rejected())
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ok(details("FAILED", &[], &VAULT_SECRET)))
            .mount(&server)
            .await;

        let err = find_in(&mock_signer(&server), SHORT)
            .await
            .expect_err("every generation is dead");
        assert!(
            matches!(err, FireblocksError::SearchTimeout { .. }),
            "got {err:?}"
        );
    }

    /// A request that completed without the signatures can never produce them.
    #[tokio::test]
    async fn a_completed_request_without_signatures_is_a_dead_request() {
        let server = MockServer::start().await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[], &VAULT_SECRET)),
            1,
        )
        .await;
        expect(&server, "POST", CANCEL_PATH, created(), 0).await;
        let err = mock_signer(&server)
            .await_signatures(
                TX_ID,
                &[hex::encode(SIGHASH)],
                Instant::now() + SIGN_MAX_DURATION,
            )
            .await
            .expect_err("no signature can arrive");
        assert!(
            matches!(err, FireblocksError::RequestFailed { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_create_with_no_request_behind_it_returns_the_create_error() {
        let server = MockServer::start().await;
        expect(&server, "POST", CREATE_PATH, rejected(), 1).await;
        expect(
            &server,
            "GET",
            &lookup_path(0),
            ResponseTemplate::new(404),
            1,
        )
        .await;

        let err = sign_sighash(&mock_signer(&server))
            .await
            .expect_err("the create failed");
        assert!(err.to_string().contains("duplicate"), "got {err}");
    }

    /// Polls the transaction of [`TX_ID`] for `[SIGHASH]` until [`SHORT`] runs out.
    async fn wait_briefly(server: &MockServer) -> FireblocksError {
        mock_signer(server)
            .await_signatures(TX_ID, &[hex::encode(SIGHASH)], Instant::now() + SHORT)
            .await
            .expect_err("nothing signs")
    }

    #[tokio::test]
    async fn a_wait_that_times_out_cancels_the_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(TX_PATH))
            .respond_with(ok(details("PENDING_AUTHORIZATION", &[], &VAULT_SECRET)))
            .mount(&server)
            .await;
        expect(
            &server,
            "POST",
            CANCEL_PATH,
            ok(json!({ "success": true })),
            1,
        )
        .await;

        let err = wait_briefly(&server).await;
        assert!(
            matches!(err, FireblocksError::SigningTimeout(ref id) if id == TX_ID),
            "got {err:?}"
        );
        let requests = server.received_requests().await.expect("recording is on");
        let cancel = requests
            .iter()
            .find(|request| request.url.path() == CANCEL_PATH)
            .expect("a cancel request");
        assert_eq!(
            cancel.body, b"{}",
            "the cancel posts an empty JSON object, as Fireblocks' clients do"
        );
    }

    /// A blip must not drop a request that can still sign.
    #[tokio::test]
    async fn a_poll_survives_errors_and_reads_the_signatures() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(TX_PATH))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(8)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(TX_PATH))
            .respond_with(ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)))
            .mount(&server)
            .await;
        expect(&server, "POST", CANCEL_PATH, created(), 0).await;

        mock_signer(&server)
            .await_signatures(
                TX_ID,
                &[hex::encode(SIGHASH)],
                Instant::now() + SIGN_MAX_DURATION,
            )
            .await
            .expect("the poll recovers");
    }

    /// A walk that uses the whole limit must not lose a request that is already signed.
    #[tokio::test]
    async fn a_wait_past_its_deadline_still_polls_once() {
        let server = MockServer::start().await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
            1,
        )
        .await;
        expect(&server, "POST", CANCEL_PATH, created(), 0).await;

        mock_signer(&server)
            .await_signatures(TX_ID, &[hex::encode(SIGHASH)], Instant::now())
            .await
            .expect("the signatures are there");
    }

    /// The caller needs the reason for the give-up, not the reason that the cancel failed.
    #[tokio::test]
    async fn a_failed_cancel_keeps_the_give_up_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(TX_PATH))
            .respond_with(ok(details("PENDING_SIGNATURE", &[], &VAULT_SECRET)))
            .mount(&server)
            .await;
        expect(&server, "POST", CANCEL_PATH, ResponseTemplate::new(500), 1).await;

        let err = wait_briefly(&server).await;
        assert!(
            matches!(err, FireblocksError::SigningTimeout(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_failed_request_reports_its_sub_status_and_is_not_cancelled() {
        let server = MockServer::start().await;
        expect(&server, "POST", CREATE_PATH, created(), 1).await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(json!({
                "id": TX_ID,
                "status": "BLOCKED",
                "subStatus": "BLOCKED_BY_POLICY",
            })),
            1,
        )
        .await;
        expect(&server, "POST", CANCEL_PATH, created(), 0).await;

        let err = sign_sighash(&mock_signer(&server))
            .await
            .expect_err("policy blocks it");
        assert!(
            err.to_string().contains("BLOCKED (BLOCKED_BY_POLICY)"),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn a_request_of_more_than_the_message_limit_never_reaches_the_api() {
        let server = MockServer::start().await;
        expect(&server, "POST", CREATE_PATH, created(), 0).await;
        let sighashes: Vec<[u8; 32]> = (0..=MAX_RAW_MESSAGES).map(distinct_digest).collect();

        let err = mock_signer(&server)
            .raw_sign(&sighashes, "note")
            .await
            .expect_err("over the limit");
        assert!(
            matches!(err, FireblocksError::TooManyInputs { count } if count == MAX_RAW_MESSAGES + 1),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_request_at_the_message_limit_is_signed() {
        let server = MockServer::start().await;
        let sighashes: Vec<[u8; 32]> = (0..MAX_RAW_MESSAGES).map(distinct_digest).collect();
        expect(&server, "POST", CREATE_PATH, created(), 1).await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &sighashes, &VAULT_SECRET)),
            1,
        )
        .await;

        let signed = mock_signer(&server)
            .raw_sign(&sighashes, "note")
            .await
            .expect("at the limit");
        assert_eq!(signed.len(), MAX_RAW_MESSAGES);
    }

    fn distinct_digest(i: usize) -> [u8; 32] {
        Sha256::digest(i.to_be_bytes()).into()
    }

    /// A redirect target would receive the API key and the JWT.
    #[tokio::test]
    async fn a_redirect_is_an_error_and_is_not_followed() {
        let server = MockServer::start().await;
        expect(
            &server,
            "POST",
            CREATE_PATH,
            ResponseTemplate::new(307).insert_header("Location", "/elsewhere"),
            1,
        )
        .await;
        expect(
            &server,
            "GET",
            &lookup_path(0),
            ResponseTemplate::new(302).insert_header("Location", "/elsewhere"),
            1,
        )
        .await;
        Mock::given(path("/elsewhere"))
            .respond_with(created())
            .expect(0)
            .mount(&server)
            .await;

        let err = sign_sighash(&mock_signer(&server))
            .await
            .expect_err("a redirect ends the request");
        assert!(matches!(err, FireblocksError::Api { .. }), "got {err:?}");
    }

    fn parsed(body: serde_json::Value) -> dto::TransactionDetails {
        serde_json::from_value(body).expect("a detail body")
    }

    #[test]
    fn partial_signatures_keep_a_request_pending() {
        let details = parsed(details("PENDING_SIGNATURE", &[[1; 32]], &VAULT_SECRET));
        let expected = [hex::encode([1; 32]), hex::encode([2; 32])];
        assert!(matches!(
            RawProgress::of(details, &expected),
            RawProgress::Pending
        ));
    }

    #[test]
    fn signatures_come_back_in_the_order_of_the_request() {
        let details = parsed(details("COMPLETED", &[[1; 32], [2; 32]], &VAULT_SECRET));
        let expected = [hex::encode([2; 32]), hex::encode([1; 32])];
        let RawProgress::Signed(signed) = RawProgress::of(details, &expected) else {
            panic!("every message is signed");
        };
        let contents: Vec<_> = signed.into_iter().map(|m| m.content).collect();
        assert_eq!(contents, expected);
    }

    #[test]
    fn a_failure_status_outranks_signatures() {
        let expected = [hex::encode([1; 32])];
        for status in ["REJECTED", "BLOCKED"] {
            let progress = RawProgress::of(
                parsed(details(status, &[[1; 32]], &VAULT_SECRET)),
                &expected,
            );
            assert!(matches!(progress, RawProgress::Refused(_)), "{status}");
        }
        for status in ["FAILED", "CANCELLED", "CANCELLING", "TIMEOUT"] {
            let progress = RawProgress::of(
                parsed(details(status, &[[1; 32]], &VAULT_SECRET)),
                &expected,
            );
            assert!(matches!(progress, RawProgress::Dead(_)), "{status}");
        }
    }

    /// The hex case of the echoed content is the vendor's choice.
    #[test]
    fn an_echoed_message_matches_in_any_hex_case() {
        let mut details = parsed(details("COMPLETED", &[[0xab; 32]], &VAULT_SECRET));
        details.signed_messages[0].content = details.signed_messages[0].content.to_uppercase();
        let expected = [hex::encode([0xab; 32])];
        assert!(matches!(
            RawProgress::of(details, &expected),
            RawProgress::Signed(_)
        ));
    }

    #[test]
    fn a_partially_completed_request_ends_like_a_completed_one() {
        let expected = [hex::encode([1; 32]), hex::encode([2; 32])];
        let partial = parsed(details("PARTIALLY_COMPLETED", &[[1; 32]], &VAULT_SECRET));
        assert!(
            matches!(RawProgress::of(partial, &expected), RawProgress::Dead(_)),
            "a partially completed request with a missing signature never completes"
        );
        let full = parsed(details(
            "PARTIALLY_COMPLETED",
            &[[1; 32], [2; 32]],
            &VAULT_SECRET,
        ));
        assert!(
            matches!(RawProgress::of(full, &expected), RawProgress::Signed(_)),
            "a partially completed request that holds every signature is signed"
        );
    }

    #[test]
    fn any_other_status_keeps_a_request_pending() {
        let expected = [hex::encode([1; 32])];
        for status in ["SUBMITTED", "PENDING_SIGNATURE", "BROADCASTING", ""] {
            let progress = RawProgress::of(parsed(details(status, &[], &VAULT_SECRET)), &expected);
            assert!(matches!(progress, RawProgress::Pending), "{status}");
        }
    }
}
