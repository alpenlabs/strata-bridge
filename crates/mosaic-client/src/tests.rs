use std::{
    array,
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use async_trait::async_trait;
use bitcoin::{XOnlyPublicKey, secp256k1::schnorr::Signature as SchnorrSignature};
use mosaic_rpc_types::{
    CacRole, DepositStatus, EvaluatorDepositConfig, EvaluatorWithdrawalConfig,
    GarblerDepositConfig, RpcByte32, RpcCompletedSignatures, RpcDepositId, RpcInstanceId,
    RpcPeerId, RpcSetupConfig, RpcTablesetId, RpcTablesetStatus, RpcWithdrawalInputs,
};
use strata_mosaic_client_api::{
    IMosaicClient, MosaicError, MosaicEvent, MosaicSetupError,
    types::{
        CompletedSignatures, DepositIdx, DepositSighashes, G16ProofRaw, N_DEPOSIT_INPUT_WIRES,
        N_WITHDRAWAL_INPUT_WIRES, OperatorIdx, Role,
    },
};
use tokio_stream::StreamExt;

use crate::{MosaicApi, MosaicClient, MosaicIdResolver};

// ---------------------------------------------------------------------------
// Test error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct MockRpcError(String);

impl fmt::Display for MockRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MockRpcError {}

// ---------------------------------------------------------------------------
// Mock MosaicApi
// ---------------------------------------------------------------------------

/// Queued responses for each RPC method.
/// Each call pops the front; panics if the queue is empty (test bug).
#[derive(Debug, Default)]
struct MockRpcQueues {
    get_tableset_id: VecDeque<Result<RpcTablesetId, MockRpcError>>,
    setup_tableset: VecDeque<Result<RpcTablesetId, MockRpcError>>,
    get_tableset_status: VecDeque<Result<RpcTablesetStatus, MockRpcError>>,
    get_fault_secret_pubkey: VecDeque<Result<Option<XOnlyPublicKey>, MockRpcError>>,
    evaluator_get_adaptor_pubkey: VecDeque<Result<Option<XOnlyPublicKey>, MockRpcError>>,
    init_garbler_deposit: VecDeque<Result<(), MockRpcError>>,
    init_evaluator_deposit: VecDeque<Result<(), MockRpcError>>,
    get_deposit_status: VecDeque<Result<DepositStatus, MockRpcError>>,
    mark_deposit_withdrawn: VecDeque<Result<(), MockRpcError>>,
    complete_adaptor_sigs: VecDeque<Result<(), MockRpcError>>,
    get_completed_adaptor_sigs: VecDeque<Result<RpcCompletedSignatures, MockRpcError>>,
    evaluate_tableset: VecDeque<Result<(), MockRpcError>>,
    sign_with_fault_secret: VecDeque<Result<Option<SchnorrSignature>, MockRpcError>>,
}

#[derive(Debug, Clone)]
struct MockRpc {
    queues: Arc<StdMutex<MockRpcQueues>>,
}

impl MockRpc {
    fn new() -> Self {
        Self {
            queues: Arc::new(StdMutex::new(MockRpcQueues::default())),
        }
    }

    fn queues(&self) -> std::sync::MutexGuard<'_, MockRpcQueues> {
        self.queues.lock().unwrap()
    }
}

macro_rules! mock_pop {
    ($self:expr, $field:ident) => {{
        $self
            .queues
            .lock()
            .unwrap()
            .$field
            .pop_front()
            .unwrap_or_else(|| panic!("MockRpc: {} queue exhausted", stringify!($field)))
    }};
}

#[async_trait]
impl MosaicApi for MockRpc {
    type Error = MockRpcError;

    async fn get_tableset_id(
        &self,
        _role: CacRole,
        _peer_id: RpcPeerId,
        _instance: RpcInstanceId,
    ) -> Result<RpcTablesetId, Self::Error> {
        mock_pop!(self, get_tableset_id)
    }

    async fn setup_tableset(&self, _config: RpcSetupConfig) -> Result<RpcTablesetId, Self::Error> {
        mock_pop!(self, setup_tableset)
    }

    async fn get_tableset_status(
        &self,
        _tsid: RpcTablesetId,
    ) -> Result<RpcTablesetStatus, Self::Error> {
        mock_pop!(self, get_tableset_status)
    }

    async fn get_fault_secret_pubkey(
        &self,
        _tsid: RpcTablesetId,
    ) -> Result<Option<XOnlyPublicKey>, Self::Error> {
        mock_pop!(self, get_fault_secret_pubkey)
    }

    async fn evaluator_get_adaptor_pubkey(
        &self,
        _tsid: RpcTablesetId,
        _deposit_id: RpcDepositId,
    ) -> Result<Option<XOnlyPublicKey>, Self::Error> {
        mock_pop!(self, evaluator_get_adaptor_pubkey)
    }

    async fn init_garbler_deposit(
        &self,
        _tsid: RpcTablesetId,
        _deposit_id: RpcDepositId,
        _deposit: GarblerDepositConfig,
    ) -> Result<(), Self::Error> {
        mock_pop!(self, init_garbler_deposit)
    }

    async fn init_evaluator_deposit(
        &self,
        _tsid: RpcTablesetId,
        _deposit_id: RpcDepositId,
        _deposit: EvaluatorDepositConfig,
    ) -> Result<(), Self::Error> {
        mock_pop!(self, init_evaluator_deposit)
    }

    async fn get_deposit_status(
        &self,
        _tsid: RpcTablesetId,
        _deposit_id: RpcDepositId,
    ) -> Result<DepositStatus, Self::Error> {
        mock_pop!(self, get_deposit_status)
    }

    async fn mark_deposit_withdrawn(
        &self,
        _tsid: RpcTablesetId,
        _deposit_id: RpcDepositId,
    ) -> Result<(), Self::Error> {
        mock_pop!(self, mark_deposit_withdrawn)
    }

    async fn complete_adaptor_sigs(
        &self,
        _tsid: RpcTablesetId,
        _deposit_id: RpcDepositId,
        _inputs: RpcWithdrawalInputs,
    ) -> Result<(), Self::Error> {
        mock_pop!(self, complete_adaptor_sigs)
    }

    async fn get_completed_adaptor_sigs(
        &self,
        _tsid: RpcTablesetId,
    ) -> Result<RpcCompletedSignatures, Self::Error> {
        mock_pop!(self, get_completed_adaptor_sigs)
    }

    async fn evaluate_tableset(
        &self,
        _tsid: RpcTablesetId,
        _deposit_id: RpcDepositId,
        _inputs: EvaluatorWithdrawalConfig,
    ) -> Result<(), Self::Error> {
        mock_pop!(self, evaluate_tableset)
    }

    async fn sign_with_fault_secret(
        &self,
        _tsid: RpcTablesetId,
        _digest: RpcByte32,
        _tweak: Option<RpcByte32>,
    ) -> Result<Option<SchnorrSignature>, Self::Error> {
        mock_pop!(self, sign_with_fault_secret)
    }
}

// ---------------------------------------------------------------------------
// Mock MosaicIdResolver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct MockIdResolver {
    peer_id: [u8; 32],
    operator_pubkey: [u8; 32],
    /// When set, `resolve_peer_id` returns `UnknownOperator` for this idx.
    fail_operator: Option<OperatorIdx>,
}

impl MockIdResolver {
    fn new() -> Self {
        Self {
            peer_id: [1u8; 32],
            operator_pubkey: [2u8; 32],
            fail_operator: None,
        }
    }

    fn failing(operator_idx: OperatorIdx) -> Self {
        Self {
            fail_operator: Some(operator_idx),
            ..Self::new()
        }
    }
}

#[async_trait]
impl MosaicIdResolver for MockIdResolver {
    async fn resolve_peer_id(&self, operator_idx: OperatorIdx) -> Result<[u8; 32], MosaicError> {
        if self.fail_operator == Some(operator_idx) {
            return Err(MosaicError::UnknownOperator(operator_idx));
        }
        Ok(self.peer_id)
    }

    async fn resolve_operator_pubkey(
        &self,
        operator_idx: OperatorIdx,
    ) -> Result<[u8; 32], MosaicError> {
        if self.fail_operator == Some(operator_idx) {
            return Err(MosaicError::UnknownOperator(operator_idx));
        }
        Ok(self.operator_pubkey)
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_OPERATOR: OperatorIdx = 0;
const TEST_DEPOSIT: DepositIdx = 42;

fn test_tableset_id() -> RpcTablesetId {
    [0xAA; 33].into()
}

fn test_deposit_id() -> RpcDepositId {
    // matches default resolve_deposit_id for TEST_DEPOSIT (42)
    let mut id = [0u8; 32];
    id[28..].copy_from_slice(&TEST_DEPOSIT.to_be_bytes());
    id.into()
}

fn test_pubkey() -> XOnlyPublicKey {
    // valid x-only pubkey (generator point x-coordinate)
    XOnlyPublicKey::from_slice(&[
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x98,
    ])
    .expect("valid x-only pubkey")
}

fn test_schnorr_sig() -> SchnorrSignature {
    SchnorrSignature::from_slice(&[0x01; 64]).expect("64 bytes")
}

fn test_sighashes() -> DepositSighashes {
    array::from_fn(|i| {
        let mut h = [0u8; 32];
        h[0] = i as u8;
        h
    })
}

fn test_completed_sigs() -> CompletedSignatures {
    array::from_fn(|_| test_schnorr_sig())
}

fn test_rpc_completed_sigs() -> RpcCompletedSignatures {
    test_completed_sigs().into()
}

fn test_counterproof() -> G16ProofRaw {
    G16ProofRaw([0xCC; 128])
}

fn test_client(rpc: MockRpc) -> MosaicClient<MockRpc, MockIdResolver> {
    MosaicClient::builder(Arc::new(rpc), MockIdResolver::new())
        .retry_delay(Duration::from_millis(1))
        .max_retries(2)
        .poll_interval(Duration::from_millis(10))
        .build()
}

/// Build a client and pre-populate the tableset cache so tests that
/// don't care about setup can skip the setup RPC calls.
fn test_client_with_cached_tableset(
    rpc: MockRpc,
    role: Role,
) -> MosaicClient<MockRpc, MockIdResolver> {
    let client = test_client(rpc);
    // Seed the cache directly.
    client
        .tablesets
        .try_write()
        .unwrap()
        .insert((role, TEST_OPERATOR), test_tableset_id());
    client
}

// ===========================================================================
// 1. Setup Phase
// ===========================================================================

#[tokio::test]
async fn test_ensure_setup_immediate_complete() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.setup_tableset.push_back(Ok(test_tableset_id()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::SetupComplete));
    }

    let client = test_client(rpc);
    client
        .ensure_mosaic_setup(TEST_OPERATOR, Role::Garbler)
        .await
        .expect("setup should succeed");

    // Verify tableset was cached.
    let cached = client.tablesets.read().await;
    assert!(cached.contains_key(&(Role::Garbler, TEST_OPERATOR)));
}

#[tokio::test]
async fn test_ensure_setup_polls_until_complete() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.setup_tableset.push_back(Ok(test_tableset_id()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Incomplete {
                details: "step 1".into(),
            }));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::SetupComplete));
    }

    let client = test_client(rpc);
    client
        .ensure_mosaic_setup(TEST_OPERATOR, Role::Evaluator)
        .await
        .expect("setup should eventually succeed");
}

#[tokio::test]
async fn test_ensure_setup_aborted() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.setup_tableset.push_back(Ok(test_tableset_id()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Aborted {
                reason: "protocol violation".into(),
            }));
    }

    let client = test_client(rpc);
    let err = client
        .ensure_mosaic_setup(TEST_OPERATOR, Role::Garbler)
        .await
        .unwrap_err();

    assert!(
        matches!(err, strata_mosaic_client_api::MosaicSetupError::Aborted(_)),
        "expected Aborted, got {err:?}"
    );
}

#[tokio::test]
async fn test_ensure_setup_succeeds_on_contest_state() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.setup_tableset.push_back(Ok(test_tableset_id()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Contest {
                deposit: test_deposit_id(),
            }));
    }

    let client = test_client(rpc);
    client
        .ensure_mosaic_setup(TEST_OPERATOR, Role::Garbler)
        .await
        .expect("contest implies setup completed");
}

#[tokio::test]
async fn test_ensure_setup_succeeds_on_consumed_state() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.setup_tableset.push_back(Ok(test_tableset_id()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Consumed {
                deposit: test_deposit_id(),
                success: true,
            }));
    }

    let client = test_client(rpc);
    client
        .ensure_mosaic_setup(TEST_OPERATOR, Role::Garbler)
        .await
        .expect("consumed implies setup completed");
}

// ===========================================================================
// 2. Deposit Phase — Evaluator Side
// ===========================================================================

#[tokio::test]
async fn test_get_fault_pubkey() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.get_fault_secret_pubkey.push_back(Ok(Some(test_pubkey())));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let result = client
        .get_fault_pubkey(TEST_OPERATOR, Role::Evaluator)
        .await
        .expect("should succeed");
    assert_eq!(result, Some(test_pubkey()));
}

#[tokio::test]
async fn test_get_adaptor_pubkey() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.evaluator_get_adaptor_pubkey
            .push_back(Ok(Some(test_pubkey())));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let result = client
        .get_adaptor_pubkey(TEST_OPERATOR, TEST_DEPOSIT)
        .await
        .expect("should succeed");
    assert_eq!(result, Some(test_pubkey()));
}

#[tokio::test]
async fn test_init_evaluator_deposit_success() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.init_evaluator_deposit.push_back(Ok(()));
        q.get_deposit_status.push_back(Ok(DepositStatus::Ready));
        q.evaluator_get_adaptor_pubkey
            .push_back(Ok(Some(test_pubkey())));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let pubkey = client
        .init_evaluator_deposit(TEST_OPERATOR, TEST_DEPOSIT, test_sighashes())
        .await
        .expect("should succeed");
    assert_eq!(pubkey, test_pubkey());
}

#[tokio::test]
async fn test_init_evaluator_deposit_missing_adaptor_pubkey() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.init_evaluator_deposit.push_back(Ok(()));
        q.get_deposit_status.push_back(Ok(DepositStatus::Ready));
        q.evaluator_get_adaptor_pubkey.push_back(Ok(None));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let err = client
        .init_evaluator_deposit(TEST_OPERATOR, TEST_DEPOSIT, test_sighashes())
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::UnexpectedMissingFinalSecret(_)),
        "expected UnexpectedMissingFinalSecret, got {err:?}"
    );
}

// ===========================================================================
// 3. Deposit Phase — Garbler Side
// ===========================================================================

#[tokio::test]
async fn test_init_garbler_deposit_ready() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.init_garbler_deposit.push_back(Ok(()));
        q.get_deposit_status.push_back(Ok(DepositStatus::Ready));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);
    let mut events = client.subscribe_events().await;

    client
        .init_garbler_deposit(TEST_OPERATOR, TEST_DEPOSIT, test_sighashes(), test_pubkey())
        .await
        .expect("should succeed");

    // Verify AdaptorsVerified event was emitted.
    let evt = events.next().await.expect("should receive event");
    assert!(matches!(
        evt,
        MosaicEvent::AdaptorsVerified {
            operator_idx: TEST_OPERATOR,
            deposit_idx: TEST_DEPOSIT,
        }
    ));
}

#[tokio::test]
async fn test_init_garbler_deposit_incomplete_adds_to_watched() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.init_garbler_deposit.push_back(Ok(()));
        q.get_deposit_status
            .push_back(Ok(DepositStatus::Incomplete {
                details: "pending".into(),
            }));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);
    client
        .init_garbler_deposit(TEST_OPERATOR, TEST_DEPOSIT, test_sighashes(), test_pubkey())
        .await
        .expect("should succeed");

    // Verify deposit was added to watched deposits.
    let watched = client.watched_deposits.lock().await;
    assert!(
        watched.contains_key(&(test_tableset_id(), TEST_OPERATOR, TEST_DEPOSIT)),
        "deposit should be in watched list"
    );
}

#[tokio::test]
async fn test_init_garbler_deposit_aborted() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.init_garbler_deposit.push_back(Ok(()));
        q.get_deposit_status.push_back(Ok(DepositStatus::Aborted {
            reason: "protocol error".into(),
        }));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);
    let err = client
        .init_garbler_deposit(TEST_OPERATOR, TEST_DEPOSIT, test_sighashes(), test_pubkey())
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::DepositAborted(_)),
        "expected DepositAborted, got {err:?}"
    );
}

#[tokio::test]
async fn test_init_garbler_deposit_already_withdrawn() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.init_garbler_deposit.push_back(Ok(()));
        q.get_deposit_status
            .push_back(Ok(DepositStatus::UncontestedWithdrawal));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);
    let err = client
        .init_garbler_deposit(TEST_OPERATOR, TEST_DEPOSIT, test_sighashes(), test_pubkey())
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::DepositWithdrawn(_)),
        "expected DepositWithdrawn, got {err:?}"
    );
}

// ===========================================================================
// 4. Withdrawal Phase
// ===========================================================================

#[tokio::test]
async fn test_mark_deposit_withdrawn() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.mark_deposit_withdrawn.push_back(Ok(()));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);
    client
        .mark_deposit_withdrawn(TEST_OPERATOR, Role::Garbler, TEST_DEPOSIT)
        .await
        .expect("should succeed");
}

#[tokio::test]
async fn test_complete_adaptor_sigs_success() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.complete_adaptor_sigs.push_back(Ok(()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Consumed {
                deposit: test_deposit_id(),
                success: true,
            }));
        q.get_completed_adaptor_sigs
            .push_back(Ok(test_rpc_completed_sigs()));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);
    let sigs = client
        .complete_adaptor_sigs(TEST_OPERATOR, TEST_DEPOSIT, test_counterproof())
        .await
        .expect("should succeed");

    assert_eq!(sigs.len(), N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES);
}

#[tokio::test]
async fn test_complete_adaptor_sigs_polls_through_states() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.complete_adaptor_sigs.push_back(Ok(()));
        // Polls: SetupComplete → Contest → Consumed
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::SetupComplete));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Contest {
                deposit: test_deposit_id(),
            }));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Consumed {
                deposit: test_deposit_id(),
                success: true,
            }));
        q.get_completed_adaptor_sigs
            .push_back(Ok(test_rpc_completed_sigs()));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);
    let sigs = client
        .complete_adaptor_sigs(TEST_OPERATOR, TEST_DEPOSIT, test_counterproof())
        .await
        .expect("should succeed after polling");

    assert_eq!(sigs.len(), N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES);
}

#[tokio::test]
async fn test_complete_adaptor_sigs_wrong_deposit_in_contest() {
    let wrong_deposit_id: RpcDepositId = [0xFF; 32].into();
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.complete_adaptor_sigs.push_back(Ok(()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Contest {
                deposit: wrong_deposit_id,
            }));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);
    let err = client
        .complete_adaptor_sigs(TEST_OPERATOR, TEST_DEPOSIT, test_counterproof())
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::UnexpectedDepositContest { .. }),
        "expected UnexpectedDepositContest, got {err:?}"
    );
}

#[tokio::test]
async fn test_complete_adaptor_sigs_aborted() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.complete_adaptor_sigs.push_back(Ok(()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Aborted {
                reason: "setup violation".into(),
            }));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);
    let err = client
        .complete_adaptor_sigs(TEST_OPERATOR, TEST_DEPOSIT, test_counterproof())
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::Aborted(_)),
        "expected Aborted, got {err:?}"
    );
}

#[tokio::test]
async fn test_evaluate_and_sign_success() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.evaluate_tableset.push_back(Ok(()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Consumed {
                deposit: test_deposit_id(),
                success: true,
            }));
        q.sign_with_fault_secret
            .push_back(Ok(Some(test_schnorr_sig())));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let sig = client
        .evaluate_and_sign(
            TEST_OPERATOR,
            TEST_DEPOSIT,
            test_counterproof(),
            test_completed_sigs(),
            [0xAA; 32],
            None,
        )
        .await
        .expect("should succeed");

    assert!(sig.is_some(), "should return a signature");
}

#[tokio::test]
async fn test_evaluate_and_sign_evaluation_failed() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.evaluate_tableset.push_back(Ok(()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Consumed {
                deposit: test_deposit_id(),
                success: false,
            }));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let sig = client
        .evaluate_and_sign(
            TEST_OPERATOR,
            TEST_DEPOSIT,
            test_counterproof(),
            test_completed_sigs(),
            [0xAA; 32],
            None,
        )
        .await
        .expect("should return Ok(None)");

    assert!(sig.is_none(), "should return None when evaluation fails");
}

#[tokio::test]
async fn test_evaluate_and_sign_polls_through_states() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.evaluate_tableset.push_back(Ok(()));
        // Polls: SetupComplete → Contest → Consumed
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::SetupComplete));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Contest {
                deposit: test_deposit_id(),
            }));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Consumed {
                deposit: test_deposit_id(),
                success: true,
            }));
        q.sign_with_fault_secret
            .push_back(Ok(Some(test_schnorr_sig())));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let sig = client
        .evaluate_and_sign(
            TEST_OPERATOR,
            TEST_DEPOSIT,
            test_counterproof(),
            test_completed_sigs(),
            [0xAA; 32],
            Some([0xBB; 32]),
        )
        .await
        .expect("should succeed after polling");

    assert!(sig.is_some());
}

// ===========================================================================
// 5. Poll Task (Background Watcher)
// ===========================================================================

#[tokio::test(start_paused = true)]
async fn test_poll_watched_deposits_ready() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.get_deposit_status.push_back(Ok(DepositStatus::Ready));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);

    // Seed a watched deposit.
    client
        .watched_deposits
        .lock()
        .await
        .insert((test_tableset_id(), TEST_OPERATOR, TEST_DEPOSIT), 0);

    let mut events = client.subscribe_events().await;

    // Spawn the poller and let it run one iteration.
    let poll_handle = tokio::spawn({
        let client = client.clone();
        async move { client.poll_watched_deposits().await }
    });

    // Advance past one poll interval.
    tokio::time::advance(Duration::from_millis(15)).await;
    tokio::task::yield_now().await;

    // Check event.
    let evt = tokio::time::timeout(Duration::from_millis(100), events.next())
        .await
        .expect("should not timeout")
        .expect("should receive event");

    assert!(matches!(
        evt,
        MosaicEvent::AdaptorsVerified {
            operator_idx: TEST_OPERATOR,
            deposit_idx: TEST_DEPOSIT,
        }
    ));

    // Deposit should be removed from watched list.
    assert!(client.watched_deposits.lock().await.is_empty());

    poll_handle.abort();
}

#[tokio::test(start_paused = true)]
async fn test_poll_watched_deposits_removed_after_max_retries() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        // max_retries = 2 in test_client, so 2 failures should remove the deposit.
        q.get_deposit_status
            .push_back(Err(MockRpcError("rpc fail 1".into())));
        q.get_deposit_status
            .push_back(Err(MockRpcError("rpc fail 2".into())));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);

    // Seed a watched deposit.
    client
        .watched_deposits
        .lock()
        .await
        .insert((test_tableset_id(), TEST_OPERATOR, TEST_DEPOSIT), 0);

    let poll_handle = tokio::spawn({
        let client = client.clone();
        async move { client.poll_watched_deposits().await }
    });

    // Advance past poll intervals, yielding after each to let the spawned task run.
    for _ in 0..3 {
        tokio::time::advance(Duration::from_millis(15)).await;
        tokio::task::yield_now().await;
    }

    // Deposit should be removed after max_retries consecutive failures.
    assert!(
        client.watched_deposits.lock().await.is_empty(),
        "deposit should be removed after max retries"
    );

    poll_handle.abort();
}

#[tokio::test(start_paused = true)]
async fn test_poll_watched_deposits_failure_counter_resets_on_incomplete() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        // Fail once, then incomplete (resets counter), then fail once, then ready.
        q.get_deposit_status
            .push_back(Err(MockRpcError("transient".into())));
        q.get_deposit_status
            .push_back(Ok(DepositStatus::Incomplete {
                details: "still going".into(),
            }));
        q.get_deposit_status
            .push_back(Err(MockRpcError("transient 2".into())));
        q.get_deposit_status.push_back(Ok(DepositStatus::Ready));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Garbler);

    let mut events = client.subscribe_events().await;

    client
        .watched_deposits
        .lock()
        .await
        .insert((test_tableset_id(), TEST_OPERATOR, TEST_DEPOSIT), 0);

    let poll_handle = tokio::spawn({
        let client = client.clone();
        async move { client.poll_watched_deposits().await }
    });

    // Advance through poll intervals, yielding after each.
    for _ in 0..5 {
        tokio::time::advance(Duration::from_millis(15)).await;
        tokio::task::yield_now().await;
    }

    // Should eventually get AdaptorsVerified despite transient failures.
    let evt = tokio::time::timeout(Duration::from_millis(100), events.next())
        .await
        .expect("should not timeout")
        .expect("should receive event");

    assert!(matches!(
        evt,
        MosaicEvent::AdaptorsVerified {
            operator_idx: TEST_OPERATOR,
            deposit_idx: TEST_DEPOSIT,
        }
    ));

    assert!(client.watched_deposits.lock().await.is_empty());

    poll_handle.abort();
}

// ===========================================================================
// 6. Tableset ID Caching
// ===========================================================================

#[tokio::test]
async fn test_tableset_id_cached_after_lookup() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        // Only one get_tableset_id response — second call should use cache.
        q.get_tableset_id.push_back(Ok(test_tableset_id()));
        // Two get_fault_secret_pubkey responses for two calls.
        q.get_fault_secret_pubkey.push_back(Ok(Some(test_pubkey())));
        q.get_fault_secret_pubkey.push_back(Ok(Some(test_pubkey())));
    }

    let client = test_client(rpc);

    // First call triggers get_tableset_id RPC.
    client
        .get_fault_pubkey(TEST_OPERATOR, Role::Evaluator)
        .await
        .expect("first call");

    // Second call should use cached tableset_id — no additional get_tableset_id RPC needed.
    client
        .get_fault_pubkey(TEST_OPERATOR, Role::Evaluator)
        .await
        .expect("second call (cached)");

    // If we got here without panic, the single get_tableset_id response was sufficient.
}

// ===========================================================================
// 7. evaluate_and_sign — Additional Error Paths
// ===========================================================================

#[tokio::test]
async fn test_evaluate_and_sign_wrong_deposit_in_contest() {
    let wrong_deposit_id: RpcDepositId = [0xFF; 32].into();
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.evaluate_tableset.push_back(Ok(()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Contest {
                deposit: wrong_deposit_id,
            }));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let err = client
        .evaluate_and_sign(
            TEST_OPERATOR,
            TEST_DEPOSIT,
            test_counterproof(),
            test_completed_sigs(),
            [0xAA; 32],
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::UnexpectedDepositContest { .. }),
        "expected UnexpectedDepositContest, got {err:?}"
    );
}

#[tokio::test]
async fn test_evaluate_and_sign_wrong_deposit_in_consumed() {
    let wrong_deposit_id: RpcDepositId = [0xFF; 32].into();
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.evaluate_tableset.push_back(Ok(()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Consumed {
                deposit: wrong_deposit_id,
                success: true,
            }));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let err = client
        .evaluate_and_sign(
            TEST_OPERATOR,
            TEST_DEPOSIT,
            test_counterproof(),
            test_completed_sigs(),
            [0xAA; 32],
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::UnexpectedDepositContest { .. }),
        "expected UnexpectedDepositContest, got {err:?}"
    );
}

#[tokio::test]
async fn test_evaluate_and_sign_aborted() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        q.evaluate_tableset.push_back(Ok(()));
        q.get_tableset_status
            .push_back(Ok(RpcTablesetStatus::Aborted {
                reason: "protocol violation".into(),
            }));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let err = client
        .evaluate_and_sign(
            TEST_OPERATOR,
            TEST_DEPOSIT,
            test_counterproof(),
            test_completed_sigs(),
            [0xAA; 32],
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::Aborted(_)),
        "expected Aborted, got {err:?}"
    );
}

// ===========================================================================
// 8. Retry Behavior
// ===========================================================================

#[tokio::test]
async fn test_rpc_retries_on_transient_failure() {
    let rpc = MockRpc::new();
    {
        let mut q = rpc.queues();
        // First call fails, retry succeeds.
        q.get_fault_secret_pubkey
            .push_back(Err(MockRpcError("transient".into())));
        q.get_fault_secret_pubkey.push_back(Ok(Some(test_pubkey())));
    }

    let client = test_client_with_cached_tableset(rpc, Role::Evaluator);
    let result = client
        .get_fault_pubkey(TEST_OPERATOR, Role::Evaluator)
        .await
        .expect("should succeed after retry");
    assert_eq!(result, Some(test_pubkey()));
}

// ===========================================================================
// 11. Unknown Operator (MockIdResolver Errors)
// ===========================================================================

fn test_client_with_failing_resolver(rpc: MockRpc) -> MosaicClient<MockRpc, MockIdResolver> {
    MosaicClient::builder(Arc::new(rpc), MockIdResolver::failing(TEST_OPERATOR))
        .retry_delay(Duration::from_millis(1))
        .max_retries(2)
        .poll_interval(Duration::from_millis(10))
        .build()
}

#[tokio::test]
async fn test_ensure_setup_unknown_operator() {
    let rpc = MockRpc::new();
    let client = test_client_with_failing_resolver(rpc);
    let err = client
        .ensure_mosaic_setup(TEST_OPERATOR, Role::Garbler)
        .await
        .unwrap_err();

    // resolve_peer_id fails → MosaicSetupError::RpcError wrapping UnknownOperator
    assert!(
        matches!(err, MosaicSetupError::RpcError(_)),
        "expected RpcError wrapping UnknownOperator, got {err:?}"
    );
}

#[tokio::test]
async fn test_get_fault_pubkey_unknown_operator() {
    let rpc = MockRpc::new();
    let client = test_client_with_failing_resolver(rpc);
    let err = client
        .get_fault_pubkey(TEST_OPERATOR, Role::Evaluator)
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::UnknownOperator(_)),
        "expected UnknownOperator, got {err:?}"
    );
}

#[tokio::test]
async fn test_init_garbler_deposit_unknown_operator() {
    let rpc = MockRpc::new();
    let client = test_client_with_failing_resolver(rpc);
    let err = client
        .init_garbler_deposit(TEST_OPERATOR, TEST_DEPOSIT, test_sighashes(), test_pubkey())
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::UnknownOperator(_)),
        "expected UnknownOperator, got {err:?}"
    );
}

#[tokio::test]
async fn test_complete_adaptor_sigs_unknown_operator() {
    let rpc = MockRpc::new();
    let client = test_client_with_failing_resolver(rpc);
    let err = client
        .complete_adaptor_sigs(TEST_OPERATOR, TEST_DEPOSIT, test_counterproof())
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::UnknownOperator(_)),
        "expected UnknownOperator, got {err:?}"
    );
}

#[tokio::test]
async fn test_evaluate_and_sign_unknown_operator() {
    let rpc = MockRpc::new();
    let client = test_client_with_failing_resolver(rpc);
    let err = client
        .evaluate_and_sign(
            TEST_OPERATOR,
            TEST_DEPOSIT,
            test_counterproof(),
            test_completed_sigs(),
            [0xAA; 32],
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, MosaicError::UnknownOperator(_)),
        "expected UnknownOperator, got {err:?}"
    );
}
