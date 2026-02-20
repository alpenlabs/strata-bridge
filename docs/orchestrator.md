# Orchestrator Crate Design Document

**Status:** Design
**Author:** Architecture Team
**Last Updated:** 2026-01-27

---

## Executive Summary

This document describes the design for replacing the monolithic `duty-tracker` crate with a new `orchestrator` crate. The new architecture uses `bridge-sm` patterns and provides clean separation between pipeline stages, improving maintainability, testability, and code organization.

---

## 1. Motivation

The current `duty-tracker` crate (`crates/duty-tracker/`) has grown into a monolithic component that:

1. **Mixes concerns**: Event handling, state machine logic, persistence, and execution are interleaved
2. **Has a large `ContractManager`**: The main struct handles too many responsibilities
3. **Contains duplicated patterns**: Similar routing and processing logic appears in multiple places
4. **Lacks clear boundaries**: Hard to test components in isolation

The new design separates these concerns into three distinct crates with clear responsibilities.

---

## 2. Crate Responsibilities

| Crate | Responsibility |
|-------|----------------|
| `bridge-sm` | State machine definitions (`StateMachine` trait, `SMOutput`, `Signal`, `DepositSM`) |
| `bridge-exec` | Duty execution implementations (port from `duty-tracker/executors/`) |
| `orchestrator` | Event loop, routing, SM coordination, persistence (NEW) |

---

## 3. Gap Analysis

### 3.1 bridge-sm: Current vs Required

| Component | Current State | Required for Orchestrator |
|-----------|---------------|---------------------------|
| `StateMachine` trait | ✅ Complete (`src/state_machine.rs`) | ✅ Ready |
| `TxClassifier` trait | ❌ Missing | **NEW**: Separate trait for tx→event classification |
| `SMOutput<D, S>` | ✅ Complete | ✅ Ready |
| `Signal` enum | ✅ Has `FromDeposit`, `FromGraph` | ✅ Ready |
| `DepositSM` | ⚠️ Partial (TODOs in `src/deposit/state.rs:278-374`) | Need to complete transitions |
| `DepositDuty` | ✅ 9 variants defined | ✅ Ready |
| `DepositEvent` | ✅ 12 variants defined | ✅ Ready |
| `GraphSM` | ❌ Missing | **NEW**: Add module |
| `GraphDuty` | ❌ Missing | **NEW**: `PublishNonces`, `PublishPartials` |
| `GraphEvent` | ❌ Missing | **NEW**: `NoncesReceived`, `PartialsReceived` |

### 3.2 bridge-exec: Current vs Required

| Component | Current State | Required for Orchestrator |
|-----------|---------------|---------------------------|
| `ExecutionConfig` | ⚠️ Minimal (2 fields in `src/config.rs`) | **EXPAND**: Add 10+ fields from duty-tracker |
| `OutputHandles` | ⚠️ Missing `db: SqliteDb` (`src/output_handles.rs`) | **EXPAND**: Add `db` field |
| `execute_deposit_duty` | ❌ All `todo!()` stubs in `src/deposit.rs` | **IMPLEMENT**: Port from duty-tracker |
| `graph.rs` | ❌ Missing | **NEW**: Nonces, partials executors |
| `withdrawal/` | ❌ Missing | **NEW**: Port `optimistic_withdrawal.rs`, `contested_withdrawal.rs` |
| `helpers/` | ❌ Missing | **NEW**: Port `proof_handler.rs`, `wots_handler.rs` |

---

## 4. Architecture Overview

### 4.1 Pipeline Design

The new `orchestrator` crate implements a staged pipeline:

```
                              ┌─────────────────────┐
   Event Streams ──────────▶  │   Mux (Stage 1)     │
   (blocks, p2p, etc.)        └──────────┬──────────┘
                                         │ UnifiedEvent
                                         │
                          ┌──────────────┴──────────────┐
                          │                             │
                   Block events                  P2P / Assignment
                          │                             │
                          ▼                             ▼
               ┌─────────────────────┐    ┌─────────────────────┐
               │   TxClassifier (2a) │    │  Event Router (2b)  │
               │  SM.classify_tx()   │    │  Predicate routing  │
               └──────────┬──────────┘    └──────────┬──────────┘
                          │ typed events             │ SM targets
                          └──────────┬───────────────┘
                                     │
                    ┌────────────────▼───────────────────────────┐
                    │         SIGNAL PROCESSING LOOP             │
                    │                                            │
                    │  SM.process_event() ──▶ Persist SM         │
                    │         (3)                 (6)            │
                    │          │                   │             │
                    │          ▼                   │             │
                    │   duties + signals           │             │
                    │          │                   │             │
                    │ signals ─┘ (loop back via 4) │             │
                    │                              │             │
                    └──────────────────────────────┘             │
                                     │                          │
                                     ▼ duties accumulated
                              ┌─────────────────────┐
                              │  Duty Dispatch (5)   │
                              │   (bridge-exec)      │
                              └─────────────────────┘
```

**Key Design Principles:**
- Events are multiplexed from multiple streams into a single `UnifiedEvent`
- **Block transactions** are classified by each SM via `TxClassifier::classify_tx()` — the SM owns the domain knowledge of which txids and structural patterns it cares about, and returns already-typed events in a single pass (no generic catch-all events, no double-filtering)
- **P2P / assignment events** are routed via predicate-based `event_router::route()` and converted to SM-specific events by the SM processor
- P2P message authentication is handled by libp2p gossipsub (not in orchestrator)
- Per-SM authorization (operator table checks) happens in the SM processor
- STF (State Transition Function) emits duties + signals
- Signals route to other SMs immediately (cascading)
- **Persistence is grouped by causal chain**: SMs linked by signals during a cascade are persisted together in a single DB transaction. The orchestrator tracks these groups; the persister is oblivious to signal routing.
- Duties execute at the very end (after all signal cascades complete)

### 4.2 Execution Model

```
External Event
    │
    ├─── Block ──────────────────────────────────┐
    │                                            │
    │  P2P / Assignment                          │  Block Transaction Processing
    │         │                                  │
    │         ▼                                  ▼
    │  event_router::route()              for tx in block.txdata:
    │  → Vec<SMId>                          for sm in registry:
    │         │                               sm.classify_tx(&tx, height)
    │         │                               → Option<SMEvent>
    │         │                                  │
    │         └──────────┬───────────────────────┘
    │                    │ typed events
    │                    ▼
    │  ┌─────────────────────────────────────────────────────────┐
    │  │  SIGNAL PROCESSING LOOP (cascading)                     │
    │  │                                                         │
    │  │  for each (sm_id, event):                               │
    │  │    1. sm.process_event(event) → SMOutput { duties, ... }│
    │  │    2. tracker.record(sm_id)   ← track causal group      │
    │  │    3. accumulated_duties.extend(duties)                 │
    │  │    4. signal_queue.extend(signals) ← route to more SMs  │
    │  │       tracker.link(source, target) for each signal      │
    │  │                                                         │
    │  │  Repeat until signal_queue is empty                     │
    │  └─────────────────────────────────────────────────────────┘
    │                    │
    │                    ▼
    │  ┌─────────────────────────────────────────────────────────┐
    │  │  BATCH PERSISTENCE (per causal group)                   │
    │  │                                                         │
    │  │  for group in tracker.into_batches():                   │
    │  │    persister.persist_batch(group)  ← one DB txn/group   │
    │  └─────────────────────────────────────────────────────────┘
    │                    │
    │                    ▼
    │  ┌─────────────────────────────────────────────────────────┐
    │  │  DUTY EXECUTION (at the very end)                       │
    │  │                                                         │
    │  │  for duty in accumulated_duties:                        │
    │  │    dispatcher.dispatch(duty).await                      │
    │  └─────────────────────────────────────────────────────────┘
```

---

## 5. Module Structure

### 5.1 orchestrator crate (NEW)

```
crates/orchestrator/
├── Cargo.toml                    # Depends on: bridge-sm, bridge-exec
└── src/
    ├── lib.rs                    # Public exports
    ├── orchestrator.rs           # Main Orchestrator struct (replaces ContractManager)
    │
    ├── pipeline/                 # Pipeline stage implementations
    │   ├── mod.rs
    │   ├── event_mux.rs          # Stage 1: Multiplexes event streams into UnifiedEvent
    │   ├── event_router.rs       # Stage 2: Predicate-based routing to SMs
    │   ├── sm_processor.rs       # Stage 3: State machine event processing
    │   ├── signal_router.rs      # Stage 4: Inter-SM signal routing
    │   ├── duty_dispatcher.rs    # Stage 5: Dispatch to bridge-exec
    │   └── persister.rs          # Stage 6: State persistence
    │
    ├── events/
    │   ├── mod.rs
    │   └── unified.rs            # UnifiedEvent enum (all event types)
    │
    ├── state_machines/
    │   ├── mod.rs
    │   ├── registry.rs           # SMRegistry for SM lookup/management
    │   └── graph.rs              # GraphSM for peg-out graph signing (new)
    │
    ├── persistence/
    │   ├── mod.rs
    │   └── coordinator.rs        # Unified persistence (port persisters)
    │
    ├── nag.rs                    # Nag mechanism for P2P consistency (cascading requests)
    ├── shutdown.rs               # Graceful shutdown handling
    ├── config.rs                 # OrchestratorConfig
    └── errors.rs                 # Error types
```

### 5.2 bridge-exec crate (EXPAND)

```
crates/bridge-exec/src/
├── lib.rs                        # Public exports
├── config.rs                     # ExecutionConfig (expand from duty-tracker)
├── output_handles.rs             # OutputHandles (expand from duty-tracker)
├── deposit.rs                    # Deposit duty executors (implement todo!()s)
├── graph.rs                      # Graph duty executors (NEW - nonces, partials)
├── withdrawal/
│   ├── mod.rs
│   ├── optimistic.rs             # Port from duty-tracker/executors/optimistic_withdrawal.rs
│   └── contested.rs              # Port from duty-tracker/executors/contested_withdrawal.rs
└── helpers/
    ├── mod.rs
    ├── proof_handler.rs          # Port from duty-tracker/executors/proof_handler.rs
    └── wots_handler.rs           # Port from duty-tracker/executors/wots_handler.rs
```

### 5.3 bridge-sm crate (EXPAND)

```
crates/bridge-sm/src/
├── lib.rs
├── state_machine.rs              # StateMachine trait, SMOutput (existing)
├── tx_classifier.rs              # TxClassifier trait for tx→event classification (NEW)
├── signals.rs                    # Signal, DepositSignal, GraphSignal (existing)
├── deposit/                      # Existing - complete TODOs
│   ├── mod.rs
│   ├── state.rs                  # DepositSM
│   ├── duties.rs                 # DepositDuty
│   ├── events.rs                 # DepositEvent
│   └── errors.rs                 # DSMError
└── graph/                        # NEW
    ├── mod.rs
    ├── state.rs                  # GraphSM implementing StateMachine trait
    ├── events.rs                 # GraphEvent enum
    ├── duties.rs                 # GraphDuty enum
    └── errors.rs                 # GraphError
```

---

## 6. Key Types

### 6.1 UnifiedEvent (events/unified.rs)

```rust
/// All possible events that the orchestrator can receive.
///
/// Priority ordering is enforced in the select! macro:
/// - Lower numbers = higher priority
pub enum UnifiedEvent {
    /// Priority 0: Self-published gossip messages for consistent state (ouroboros pattern)
    OuroborosMessage(UnsignedGossipsubMsg),

    /// Priority 1: Self-published nag requests (ouroboros pattern)
    OuroborosRequest(GetMessageRequest),

    /// Priority 2: Graceful shutdown request
    Shutdown(oneshot::Sender<ExecutionState>),

    /// Priority 3: Buried Bitcoin blocks from ZMQ
    Block(BlockEvent),

    /// Priority 4: ASM assignment state updates
    Assignment(AssignmentsState),

    /// Priority 5: Gossipsub messages from other operators (broadcast)
    GossipMessage(GossipsubMsg),

    /// Priority 5: Request-response messages from other operators (point-to-point)
    ReqRespRequest { request: GetMessageRequest, peer: PeerId },

    /// Priority 6: Periodic nag timer tick
    NagTick,
}
```

**P2P Message Types** (from `p2p-wire/src/p2p/v1.rs`):

| Variant | Purpose | Key Fields |
|---------|---------|------------|
| `StakeChainExchange` | Share pre-stake tx info | `stake_chain_id`, `operator_pk`, `pre_stake_txid`, `pre_stake_vout` |
| `DepositSetup` | Distribute WOTS PKs & funding info | `scope`, `index`, `hash`, `funding_txid`, `wots_pks` |
| `Musig2NoncesExchange` | Share public nonces for signing | `session_id`, `nonces: Vec<PubNonce>` |
| `Musig2SignaturesExchange` | Distribute partial signatures | `session_id`, `signatures: Vec<PartialSignature>` |

**Message Wrapper Structure**:
```rust
// Unsigned message (inner payload)
pub enum UnsignedGossipsubMsg {
    StakeChainExchange { ... },
    DepositSetup { ... },
    Musig2NoncesExchange { ... },
    Musig2SignaturesExchange { ... },
}

// Signed wrapper (what's sent over the wire)
pub struct GossipsubMsg {
    pub signature: Vec<u8>,           // ED25519 signature
    pub key: P2POperatorPubKey,       // Signer's P2P public key
    pub unsigned: UnsignedGossipsubMsg,
}

// Request-response (point-to-point, same 4 variants)
pub enum GetMessageRequest {
    StakeChainExchange { stake_chain_id, operator_pk },
    DepositSetup { scope, operator_pk },
    Musig2NoncesExchange { session_id, operator_pk },
    Musig2SignaturesExchange { session_id, operator_pk },
}
```

### 6.2 SMRegistry (state_machines/registry.rs)

```rust
/// Identifier for a state machine instance.
pub enum SMId {
    /// Per-deposit state machine
    Deposit(Txid),
    /// Per-deposit graph signing state machine
    Graph(Txid),
}

/// Registry holding all active state machines.
pub struct SMRegistry {
    /// Deposit state machines, keyed by deposit txid
    deposits: BTreeMap<Txid, DepositSM>,

    /// Graph state machines, keyed by deposit txid
    graphs: BTreeMap<Txid, GraphSM>,

    /// Reverse index: claim_txid → deposit_txid
    claim_to_deposit: BTreeMap<Txid, Txid>,
}

impl SMRegistry {
    /// Get a state machine by ID
    pub fn get(&self, id: &SMId) -> Option<&dyn StateMachine>;

    /// Get a mutable state machine by ID
    pub fn get_mut(&mut self, id: &SMId) -> Option<&mut dyn StateMachine>;

    /// Insert a new deposit and its associated graph SM
    pub fn insert_deposit(&mut self, txid: Txid, deposit: DepositSM, graph: GraphSM);

    /// Look up deposit by claim txid
    pub fn deposit_by_claim(&self, claim_txid: &Txid) -> Option<&DepositSM>;
}
```

### 6.3 UnifiedDuty (pipeline/duty_dispatcher.rs)

```rust
use bridge_sm::deposit::duties::DepositDuty;
use bridge_sm::graph::duties::GraphDuty;

/// Unified duty type for dispatch to bridge-exec.
pub enum UnifiedDuty {
    Deposit(DepositDuty),
    Graph(GraphDuty),
}

/// Dispatcher that routes duties to appropriate executors.
pub struct DutyDispatcher {
    cfg: Arc<ExecutionConfig>,
    handles: Arc<OutputHandles>,
}

impl DutyDispatcher {
    /// Dispatch a duty to the appropriate executor.
    pub async fn dispatch(&self, duty: UnifiedDuty) -> Result<(), Error> {
        match duty {
            UnifiedDuty::Deposit(d) => {
                bridge_exec::deposit::execute(&self.cfg, &self.handles, d).await
            }
            UnifiedDuty::Graph(d) => {
                bridge_exec::graph::execute(&self.cfg, &self.handles, d).await
            }
        }
    }
}
```

### 6.4 GraphSM (NEW - bridge-sm/graph/)

```rust
/// States for the peg-out graph signing state machine.
pub enum GraphState {
    /// Initial state, waiting for deposit to be confirmed
    Pending,

    /// Collecting nonces from all operators
    CollectingNonces {
        received: BTreeSet<OperatorIdx>,
        nonces: BTreeMap<OperatorIdx, Vec<PubNonce>>,
    },

    /// Collecting partial signatures from all operators
    CollectingPartials {
        aggnonces: Vec<AggNonce>,
        received: BTreeSet<OperatorIdx>,
        partials: BTreeMap<OperatorIdx, Vec<PartialSignature>>,
    },

    /// Graph is fully signed and ready
    Signed {
        signatures: Vec<Signature>,
    },

    /// Terminal: Graph was used for withdrawal
    Used,
}

/// Duties emitted by the Graph SM.
pub enum GraphDuty {
    /// Publish nonces for peg-out graph transactions
    PublishGraphNonces {
        claim_txid: Txid,
        pog_prevouts: Vec<TxOut>,
        pog_witnesses: Vec<Witness>,
        nonces: Vec<PubNonce>,
    },

    /// Publish partial signatures for peg-out graph
    PublishGraphSignatures {
        claim_txid: Txid,
        aggnonces: Vec<AggNonce>,
        pog_prevouts: Vec<TxOut>,
        pog_sighashes: Vec<TapSighash>,
        partials: Vec<PartialSignature>,
    },

    /// Publish root nonce for deposit transaction
    PublishRootNonce {
        deposit_request_txid: Txid,
        witness: Witness,
        nonce: PubNonce,
    },

    /// Publish root signature for deposit transaction
    PublishRootSignature {
        deposit_request_txid: Txid,
        aggnonce: AggNonce,
        sighash: TapSighash,
        witness: Witness,
        partial: PartialSignature,
    },
}

/// Events that the Graph SM can process.
pub enum GraphEvent {
    /// Deposit has been confirmed, start collecting nonces
    DepositConfirmed,

    /// Received nonces from another operator
    NoncesReceived {
        operator: OperatorIdx,
        nonces: Vec<PubNonce>,
    },

    /// Received partial signatures from another operator
    PartialsReceived {
        operator: OperatorIdx,
        partials: Vec<PartialSignature>,
    },

    /// Signal from DepositSM that cooperative payout failed
    CooperativePayoutFailed {
        assignee: OperatorIdx,
        deposit_idx: u32,
    },

    /// Graph was used for a withdrawal
    GraphUsed,

    /// Block cursor advanced (sent after all txs in a block are classified)
    BlockAdvanced(u64),
}
```

### 6.5 TxClassifier (bridge-sm/tx_classifier.rs)

The `TxClassifier` trait separates Bitcoin transaction classification from general state machine processing. Only SMs that need to react to on-chain transactions implement it. The trait collapses the filter + classify step into a single call: given a raw `Transaction`, the SM decides whether it cares and, if so, returns an already-typed event ready for `process_event`.

```rust
use bitcoin::Transaction;

/// Classifies raw Bitcoin transactions into typed SM events.
///
/// Implementers use their own internal state (known txids, graph summaries,
/// current state) to decide relevance and produce the correct event variant
/// in a single pass — no generic catch-all events, no double-filtering.
pub trait TxClassifier: StateMachine {
    /// Inspect a confirmed transaction and optionally produce a typed event.
    ///
    /// Returns `None` if the transaction is irrelevant to this SM.
    /// Returns `Some(event)` with an already-classified event variant that
    /// can be fed directly into `process_event`.
    fn classify_tx(&self, tx: &Transaction, height: u64) -> Option<Self::Event>;
}
```

**DepositSM implementation:**

```rust
impl TxClassifier for DepositSM {
    fn classify_tx(&self, tx: &Transaction, height: u64) -> Option<DepositEvent> {
        let txid = tx.compute_txid();

        // Deposit confirmation (direct txid match)
        if txid == self.deposit_txid {
            return Some(DepositEvent::DepositConfirmed {
                tx: tx.clone(),
                height,
            });
        }

        // State-dependent classification
        match &self.state {
            DepositState::Assigned { .. } => {
                if self.is_fulfillment(tx) {
                    Some(DepositEvent::FulfillmentConfirmed {
                        tx: tx.clone(),
                        height,
                    })
                } else {
                    None
                }
            }

            DepositState::Fulfilled { claim_txid, .. } => {
                if txid == *claim_txid {
                    Some(DepositEvent::ClaimConfirmed {
                        tx: tx.clone(),
                        height,
                    })
                } else {
                    None
                }
            }

            DepositState::Claimed { claim_txid, .. } => {
                if is_challenge(*claim_txid)(tx) {
                    Some(DepositEvent::ChallengeConfirmed { tx: tx.clone() })
                } else if txid == self.payout_optimistic_txid {
                    Some(DepositEvent::OptimisticPayoutConfirmed { tx: tx.clone() })
                } else if txid == self.pre_assert_txid {
                    Some(DepositEvent::PreAssertConfirmed { tx: tx.clone() })
                } else {
                    None
                }
            }

            DepositState::Challenged { .. } => {
                if txid == self.pre_assert_txid {
                    Some(DepositEvent::PreAssertConfirmed { tx: tx.clone() })
                } else {
                    None
                }
            }

            DepositState::PreAssertConfirmed { .. } => {
                if self.assert_data_txids.contains(&txid) {
                    Some(DepositEvent::AssertDataConfirmed { tx: tx.clone() })
                } else {
                    None
                }
            }

            DepositState::AssertDataConfirmed { post_assert_txid, .. } => {
                if txid == *post_assert_txid {
                    Some(DepositEvent::PostAssertConfirmed {
                        tx: tx.clone(),
                        height,
                    })
                } else {
                    None
                }
            }

            DepositState::Asserted { post_assert_txid, .. } => {
                if is_disprove(*post_assert_txid)(tx) {
                    Some(DepositEvent::DisproveConfirmed { tx: tx.clone() })
                } else if txid == self.payout_txid {
                    Some(DepositEvent::DefendedPayoutConfirmed { tx: tx.clone() })
                } else {
                    None
                }
            }

            // Terminal and initial states don't match transactions
            _ => None,
        }
    }
}
```

**GraphSM implementation:**

```rust
impl TxClassifier for GraphSM {
    fn classify_tx(&self, tx: &Transaction, height: u64) -> Option<GraphEvent> {
        // GraphSM currently does not react to on-chain transactions.
        // If graph-related on-chain events are needed in the future,
        // classification logic goes here.
        None
    }
}
```

**Key properties:**
- **Single-pass**: One call both filters and classifies — no generic `PegOutGraphConfirmation` catch-all
- **State-aware**: Classification uses the SM's current state to determine which transaction types are possible, eliminating the `or_else` trial-and-error chain
- **Typed output**: Returns `Option<Self::Event>` so the event is already the correct variant when it reaches `process_event`
- **Opt-in**: Only SMs that care about on-chain transactions implement it; P2P-only SMs (e.g., a future `StakeChainSM`) don't need it

---

## 7. Pipeline Stage Implementation

### 7.1 Stage 1: Event Multiplexing (event_mux.rs)

Multiplexes multiple event streams into a single poll-able stream. Port the `select!` block from `contract_manager.rs:263-485` to `EventMux::next()`:

```rust
pub struct EventMux {
    // Ouroboros channels (self-publish for consistency)
    ouroboros_msg_rx: mpsc::UnboundedReceiver<UnsignedGossipsubMsg>,
    ouroboros_req_rx: mpsc::UnboundedReceiver<GetMessageRequest>,

    // Shutdown coordination
    shutdown_rx: Option<oneshot::Receiver<oneshot::Sender<ExecutionState>>>,

    // Bitcoin event sources
    block_sub: BlockSubscription,
    assignments_sub: AssignmentsSubscription,

    // P2P handles (separate for gossipsub vs request-response)
    gossip_handle: GossipHandle,      // Broadcast messages
    req_resp_handle: ReqRespHandle,   // Point-to-point requests

    // Nag timer
    nag_interval: Interval,
}

impl EventMux {
    /// Get the next event, respecting priority ordering (biased select).
    pub async fn next(&mut self) -> UnifiedEvent {
        tokio::select! {
            biased;

            // Priority 0: Self-published gossip (ouroboros consistency)
            Some(msg) = self.ouroboros_msg_rx.recv() => {
                UnifiedEvent::OuroborosMessage(msg)
            }

            // Priority 1: Self-published requests (ouroboros nag)
            Some(req) = self.ouroboros_req_rx.recv() => {
                UnifiedEvent::OuroborosRequest(req)
            }

            // Priority 2: Shutdown signal
            Ok(sender) = async {
                match self.shutdown_rx.as_mut() {
                    Some(rx) => rx.await,
                    None => std::future::pending().await,
                }
            } => {
                self.shutdown_rx = None; // Consume receiver
                UnifiedEvent::Shutdown(sender)
            }

            // Priority 3: Bitcoin blocks (skip non-buried as defensive check)
            Some(block_event) = self.block_sub.next() => {
                if block_event.status != BlockStatus::Buried {
                    // Stream should only produce buried blocks; skip if not
                    continue;
                }
                UnifiedEvent::Block(block_event)
            }

            // Priority 4: ASM assignment updates
            Some(assignments) = self.assignments_sub.next() => {
                UnifiedEvent::Assignment(assignments)
            }

            // Priority 5a: Gossipsub messages from network (broadcast)
            Some(event) = self.gossip_handle.next_event() => {
                match event {
                    GossipEvent::ReceivedMessage(raw_msg) => {
                        // Deserialize using rkyv zero-copy
                        let msg: GossipsubMsg = rkyv::from_bytes(&raw_msg)
                            .expect("valid gossipsub message");
                        UnifiedEvent::GossipMessage(msg)
                    }
                }
            }

            // Priority 5b: Request-response from network (point-to-point)
            Some(event) = self.req_resp_handle.next_event() => {
                match event {
                    ReqRespEvent::ReceivedRequest(raw_req, peer) => {
                        let request: GetMessageRequest = rkyv::from_bytes(&raw_req)
                            .expect("valid request message");
                        UnifiedEvent::ReqRespRequest { request, peer }
                    }
                }
            }

            // Priority 6: Nag timer tick
            _ = self.nag_interval.tick() => {
                UnifiedEvent::NagTick
            }
        }
    }
}
```

**P2P Bootstrap Handles** (from `p2p-service/src/bootstrap.rs`):
```rust
pub struct BootstrapHandles {
    pub command_handle: CommandHandle,   // Send commands to P2P layer
    pub gossip_handle: GossipHandle,     // Gossipsub interface (broadcast)
    pub req_resp_handle: ReqRespHandle,  // Request-response interface (point-to-point)
    pub cancel: CancellationToken,       // Shutdown signal
    pub listen_task: JoinHandle<()>,     // Event loop task
}
```

### 7.2 Stage 2: Event Router (event_router.rs)

Routes events to target SMs based on message content (scope, session_id, etc.). Stateless free functions - no operator table needed.

**Module API:**
- `pub fn route()` - Single public entry point called by orchestrator
- `fn route_gossip_message()` - Private helper for gossipsub messages
- `fn route_request()` - Private helper for request-response messages
- `fn route_musig2_session()` - Private helper for MuSig2 session routing

```rust
/// Route an event to target state machines based on message content.
/// This is the single entry point for the event_router module.
///
/// NOTE: Block events are NOT routed here. They are handled directly in the
/// orchestrator main loop using `TxClassifier::classify_tx()` on each SM,
/// which collapses filtering and event classification into a single pass.
/// See Section 8 for the block processing flow.
pub fn route(event: &UnifiedEvent, registry: &SMRegistry) -> Vec<SMId> {
        match event {
            UnifiedEvent::Assignment(state) => {
                // Route to specific deposit by index
                state.assignments.iter()
                    .filter_map(|a| registry.deposit_by_index(a.deposit_idx))
                    .map(SMId::Deposit)
                    .collect()
            }

            UnifiedEvent::GossipMessage(msg) => {
                route_gossip_message(&msg.unsigned, registry)
            }

            UnifiedEvent::ReqRespRequest { request, .. } => {
                route_request(request, registry)
            }

            // OuroborosMessage, OuroborosRequest, Shutdown, NagTick
            // are handled specially in the orchestrator (not routed to SMs)
            _ => vec![],
        }
}

/// Route gossipsub messages based on message variant and content.
fn route_gossip_message(msg: &UnsignedGossipsubMsg, registry: &SMRegistry) -> Vec<SMId> {
        match msg {
            UnsignedGossipsubMsg::StakeChainExchange { .. } => {
                // Stake chain messages don't route to deposit/graph SMs
                vec![]
            }

            UnsignedGossipsubMsg::DepositSetup { scope, .. } => {
                // Route to both Deposit and Graph SMs for this deposit
                registry.txid_by_scope(scope)
                    .map(|txid| vec![SMId::Deposit(txid), SMId::Graph(txid)])
                    .unwrap_or_default()
            }

            UnsignedGossipsubMsg::Musig2NoncesExchange { session_id, .. } |
            UnsignedGossipsubMsg::Musig2SignaturesExchange { session_id, .. } => {
                // Route to Graph SM - dual lookup by session_id
                route_musig2_session(session_id, registry)
            }
        }
}

/// Route request-response messages.
fn route_request(req: &GetMessageRequest, registry: &SMRegistry) -> Vec<SMId> {
        match req {
            GetMessageRequest::StakeChainExchange { .. } => vec![],

            GetMessageRequest::DepositSetup { scope, .. } => {
                registry.txid_by_scope(scope)
                    .map(|txid| vec![SMId::Deposit(txid), SMId::Graph(txid)])
                    .unwrap_or_default()
            }

            GetMessageRequest::Musig2NoncesExchange { session_id, .. } |
            GetMessageRequest::Musig2SignaturesExchange { session_id, .. } => {
                route_musig2_session(session_id, registry)
            }
        }
}

/// Dual lookup for MuSig2 sessions: by claim_txid OR deposit_request_txid.
fn route_musig2_session(session_id: &SessionId, registry: &SMRegistry) -> Vec<SMId> {
        // Try lookup by claim_txid first
        if let Some(deposit_txid) = registry.deposit_by_claim_session(session_id) {
            return vec![SMId::Graph(deposit_txid)];
        }
        // Fallback to deposit_request_txid lookup
        if let Some(deposit_txid) = registry.deposit_by_request_session(session_id) {
            return vec![SMId::Graph(deposit_txid)];
        }
        vec![]
}
```

**Routing Rules Summary:**

| Event Type | Target SMs | Lookup Key |
|------------|------------|------------|
| `Block` | *(handled via `TxClassifier`, not event router)* | - |
| `Assignment` | Specific Deposit | `deposit_idx` |
| `StakeChainExchange` | None (StakeChainSM) | - |
| `DepositSetup` | Deposit + Graph | `scope` |
| `Musig2NoncesExchange` | Graph | `session_id` (dual lookup) |
| `Musig2SignaturesExchange` | Graph | `session_id` (dual lookup) |

### 7.3 Stage 3: SM Processor (sm_processor.rs)

Stateless free functions for processing events through state machines. The module
is split into two concerns:

1. **Classification** (`classify`) — converts a `UnifiedEvent` + `SMId` into a typed `SMEvent`. This handles P2P and assignment events. Block transactions skip this step because `TxClassifier::classify_tx()` already produces typed events.
2. **Processing** (`process`) — takes a typed `SMEvent` and runs it through the SM's `process_event`. All events (P2P, block, signal) converge here.

The orchestrator composes these two steps: it builds a `Vec<(SMId, SMEvent)>` via
`classify` (for P2P) or `classify_block` (for blocks), then feeds them all through
the same `process` call.

**Module API:**
- `pub fn classify()` - Convert `UnifiedEvent` + `SMId` → `SMEvent` (P2P/assignment path)
- `pub fn process()` - Process a typed `SMEvent` through the target SM (all paths)
- `fn classify_for_deposit()` - Private: `UnifiedEvent` → `DepositEvent`
- `fn classify_for_graph()` - Private: `UnifiedEvent` → `GraphEvent`
- `pub enum SMEvent` - Wrapper for SM-specific typed events

```rust
/// Typed wrapper for SM-specific events.
/// Produced by classify(), TxClassifier::classify_tx(), or signal routing.
pub enum SMEvent {
    Deposit(DepositEvent),
    Graph(GraphEvent),
}

// ─── Classification ─────────────────────────────────────────────────

/// Classify a UnifiedEvent into a typed SMEvent for the given SM.
/// Handles P2P and assignment events only — block transactions are
/// classified externally by TxClassifier::classify_tx() in
/// Orchestrator::classify_block().
pub fn classify(
    sm_id: &SMId,
    event: &UnifiedEvent,
) -> Result<SMEvent, ProcessError> {
    match sm_id {
        SMId::Deposit(_) => classify_for_deposit(event).map(SMEvent::Deposit),
        SMId::Graph(_)   => classify_for_graph(event).map(SMEvent::Graph),
    }
}

fn classify_for_deposit(event: &UnifiedEvent) -> Result<DepositEvent, ProcessError> {
    match event {
        UnifiedEvent::GossipMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::DepositSetup { scope, index, hash, funding_txid, wots_pks } => {
                Ok(DepositEvent::DepositSetup {
                    operator: msg.key.clone(),
                    scope: *scope,
                    index: *index,
                    hash: *hash,
                    funding_txid: *funding_txid,
                    wots_pks: wots_pks.clone(),
                })
            }
            _ => Err(ProcessError::EventNotApplicable),
        }
        UnifiedEvent::Assignment(state) => {
            Ok(DepositEvent::Assignment {
                assignments: state.clone(),
            })
        }
        _ => Err(ProcessError::EventNotApplicable),
    }
}

fn classify_for_graph(event: &UnifiedEvent) -> Result<GraphEvent, ProcessError> {
    match event {
        UnifiedEvent::GossipMessage(msg) => match &msg.unsigned {
            UnsignedGossipsubMsg::Musig2NoncesExchange { session_id, nonces } => {
                Ok(GraphEvent::NoncesReceived {
                    operator: msg.operator_idx()?,
                    nonces: nonces.clone(),
                })
            }
            UnsignedGossipsubMsg::Musig2SignaturesExchange { session_id, signatures } => {
                Ok(GraphEvent::PartialsReceived {
                    operator: msg.operator_idx()?,
                    partials: signatures.clone(),
                })
            }
            _ => Err(ProcessError::EventNotApplicable),
        }
        _ => Err(ProcessError::EventNotApplicable),
    }
}

// ─── Processing ─────────────────────────────────────────────────────

/// Process a typed SMEvent through the appropriate state machine.
///
/// This is the single processing entry point. All event sources converge here:
/// - Block transactions (classified by TxClassifier::classify_tx())
/// - P2P / assignment events (classified by classify())
/// - Signals (already typed by signal_router::route_signal())
pub fn process(
    sm_id: &SMId,
    sm_event: SMEvent,
    registry: &mut SMRegistry,
) -> Result<SMOutput<UnifiedDuty, Signal>, ProcessError> {
    match (sm_id, sm_event) {
        (SMId::Deposit(txid), SMEvent::Deposit(event)) => {
            let sm = registry.deposits.get_mut(txid)
                .ok_or(ProcessError::SMNotFound(*sm_id))?;
            let output = sm.process_event(event)?;
            Ok(output.map_duties(UnifiedDuty::Deposit))
        }
        (SMId::Graph(txid), SMEvent::Graph(event)) => {
            let sm = registry.graphs.get_mut(txid)
                .ok_or(ProcessError::SMNotFound(*sm_id))?;
            let output = sm.process_event(event)?;
            Ok(output.map_duties(UnifiedDuty::Graph))
        }
        _ => Err(ProcessError::EventTypeMismatch),
    }
}
```

### 7.4 Stage 4: Signal Router (signal_router.rs)

Stateless free functions for routing inter-SM signals.

**Module API:**
- `pub fn route_signal()` - Single public entry point called by orchestrator
- `fn route_deposit_to_graph()` - Private helper for Deposit→Graph signals
- `fn route_graph_to_deposit()` - Private helper for Graph→Deposit signals

```rust
/// Route a signal to target state machines with their converted events.
/// This is the single entry point for the signal_router module.
pub fn route_signal(
    signal: &Signal,
    registry: &SMRegistry,
) -> Vec<(SMId, SMEvent)> {
    match signal {
        Signal::FromDeposit(DepositSignal::ToGraph(msg)) => {
            route_deposit_to_graph(msg, registry)
        }

        Signal::FromGraph(GraphSignal::ToDeposit(msg)) => {
            route_graph_to_deposit(msg, registry)
        }
    }
}

fn route_deposit_to_graph(msg: &DepositToGraph, registry: &SMRegistry) -> Vec<(SMId, SMEvent)> {
    match msg {
        DepositToGraph::CooperativePayoutFailed { assignee, deposit_idx } => {
            registry.deposit_txid_by_index(*deposit_idx)
                .map(|txid| vec![(
                    SMId::Graph(txid),
                    SMEvent::Graph(GraphEvent::CooperativePayoutFailed {
                        assignee: *assignee,
                        deposit_idx: *deposit_idx,
                    }),
                )])
                .unwrap_or_default()
        }
    }
}

fn route_graph_to_deposit(msg: &GraphToDeposit, registry: &SMRegistry) -> Vec<(SMId, SMEvent)> {
    match msg {
        GraphToDeposit::GraphAvailable { operator_idx } => {
            // Route to deposit SM
            todo!()
        }
    }
}
```

### 7.5 Stage 5: Duty Dispatcher (duty_dispatcher.rs)

```rust
pub struct DutyDispatcher {
    cfg: Arc<ExecutionConfig>,
    handles: Arc<OutputHandles>,
}

impl DutyDispatcher {
    pub async fn dispatch(&self, duty: UnifiedDuty) -> Result<(), DispatchError> {
        match duty {
            UnifiedDuty::Deposit(d) => {
                bridge_exec::deposit::execute(&self.cfg, &self.handles, &d).await
                    .map_err(DispatchError::Deposit)
            }
            UnifiedDuty::Graph(d) => {
                bridge_exec::graph::execute(&self.cfg, &self.handles, &d).await
                    .map_err(DispatchError::Graph)
            }
        }
    }
}
```

### 7.6 Stage 6: Persistence (persister.rs)

When SM A produces a signal that affects SM B, both must be persisted atomically —
otherwise a crash between the two writes leaves the system in an inconsistent state
(A advanced but B didn't receive the signal). However, persisting *all* SMs in a
single DB transaction isn't feasible due to transaction size limits.

The solution splits persistence into two concerns:

1. **`PersistenceTracker`** (in `orchestrator.rs`) — tracks which SMs are causally
   linked during a processing cycle. The orchestrator already knows this from the
   signal queue. No persistence logic here.
2. **`Persister`** — receives pre-computed batches of `SMId`s and writes each batch
   in a single DB transaction. No knowledge of signals or routing.

#### PersistenceTracker

Tracks causal groups during the processing loop. Each initial target starts a new
group. When a signal flows from SM A to SM B, B joins A's group.

```rust
/// Tracks which SMs must be persisted together based on signal causality.
/// Lives in the orchestrator, not the persister.
pub struct PersistenceTracker {
    /// Which group each SM belongs to
    membership: HashMap<SMId, usize>,
    /// Which SMs are in each group
    groups: HashMap<usize, BTreeSet<SMId>>,
    /// Monotonic group counter
    next_group: usize,
}

impl PersistenceTracker {
    pub fn new() -> Self {
        Self {
            membership: HashMap::new(),
            groups: HashMap::new(),
            next_group: 0,
        }
    }

    /// Assign an SM to a new group (called for each initial target).
    /// If the SM was already recorded (e.g. multiple events for the same SM
    /// in a block), this is a no-op.
    pub fn record(&mut self, sm_id: SMId) {
        if self.membership.contains_key(&sm_id) {
            return;
        }
        let group = self.next_group;
        self.next_group += 1;
        self.membership.insert(sm_id, group);
        self.groups.entry(group).or_default().insert(sm_id);
    }

    /// Record that `source` produced a signal that reached `target`.
    /// Target joins source's group. If target already had a different group,
    /// the two groups merge.
    pub fn link(&mut self, source: &SMId, target: SMId) {
        let source_group = self.membership[source];

        if let Some(&target_group) = self.membership.get(&target) {
            if target_group != source_group {
                // Merge target's group into source's group
                if let Some(members) = self.groups.remove(&target_group) {
                    for member in &members {
                        self.membership.insert(*member, source_group);
                    }
                    self.groups.entry(source_group).or_default().extend(members);
                }
            }
        } else {
            self.membership.insert(target, source_group);
            self.groups.entry(source_group).or_default().insert(target);
        }
    }

    /// Consume the tracker and return persistence batches.
    pub fn into_batches(self) -> Vec<Vec<SMId>> {
        self.groups.into_values()
            .map(|set| set.into_iter().collect())
            .collect()
    }
}
```

#### Persister

The persister receives pre-computed batches and writes each one atomically.
It has no knowledge of why these SMs are grouped.

```rust
pub struct Persister {
    db: SqliteDb,
    contract_persister: ContractPersister,
    graph_persister: GraphPersister,
    stake_chain_persister: StakeChainPersister,
}

impl Persister {
    /// Persist a group of causally-linked state machines in a single
    /// database transaction. The caller determines the grouping;
    /// this method is oblivious to signal routing..clone()
    pub async fn persist_batch(
        &self,
        sm_ids: &[SMId],
        registry: &SMRegistry,
    ) -> Result<(), PersistError> {
        let txn = self.db.begin_transaction().await?;
        for sm_id in sm_ids {
            match sm_id {
                SMId::Deposit(txid) => {
                    if let Some(sm) = registry.deposits.get(txid) {
                        self.contract_persister.save_in(&txn, sm).await?;
                    }
                }
                SMId::Graph(txid) => {
                    if let Some(sm) = registry.graphs.get(txid) {
                        self.graph_persister.save_in(&txn, sm).await?;
                    }
                }
            }
        }
        txn.commit().await?;
        Ok(())
    }
}
```

**Key properties:**
- **Groups are naturally small**: signals flow between Deposit↔Graph for the same deposit, so a typical group is `{DepositSM(x), GraphSM(x)}` — two SMs. No risk of hitting DB transaction size limits.
- **Fewer DB round-trips**: instead of one write per `process()` call, we write once per causal group after the full cascade completes.
- **Clean separation**: the orchestrator computes groups (it already knows the causal chain from signal processing); the persister just writes batches atomically.

### 7.7 Nag Mechanism (nag.rs)

The nag mechanism ensures P2P consistency by periodically requesting missing data from peers. Uses a **cascading approach** to avoid network waste.

Each SM knows its own operator table and provides the missing operator P2P keys directly - no global operator table needed.

**Module API:**
- `pub fn generate_nags()` - Single public entry point called by orchestrator on NagTick

```rust
/// Generate list of GetMessageRequest for missing data.
/// Called on NagTick events (default: every 10 seconds).
///
/// Each SM provides its own missing operator info (including P2P keys)
/// since operator tables can differ per-SM.
pub fn generate_nags(
    registry: &SMRegistry,
    stake_chains: &StakeChainSM,
) -> Vec<GetMessageRequest> {
    let mut nags = Vec::new();

    // Phase 1: Stake Chain Exchange - request missing pre-stake info
    // StakeChainSM knows its operator table and returns full requests
    nags.extend(stake_chains.missing_stake_chain_requests());

    // Phase 2: Deposit Setup - request missing WOTS PKs
    for (_txid, deposit_sm) in registry.deposits.iter() {
        // DepositSM returns requests with P2P keys from its operator table
        nags.extend(deposit_sm.missing_setup_requests());
    }

    // Phase 3: Graph Nonces - request missing nonces
    for (_txid, graph_sm) in registry.graphs.iter() {
        nags.extend(graph_sm.missing_nonce_requests());
    }

    // Phase 4: Graph Signatures - request missing partials
    for (_txid, graph_sm) in registry.graphs.iter() {
        nags.extend(graph_sm.missing_signature_requests());
    }

    nags
}
```

**SM Methods for Nagging:**
```rust
// Each SM implements these methods using its own operator table:
impl DepositSM {
    /// Returns DepositSetup requests for operators we haven't heard from.
    pub fn missing_setup_requests(&self) -> Vec<GetMessageRequest> {
        let missing = self.missing_setup_operators();
        missing.iter().map(|op_idx| {
            GetMessageRequest::DepositSetup {
                scope: self.scope(),
                operator_pk: self.cfg.operator_table.p2p_key(*op_idx).clone(),
            }
        }).collect()
    }
}

impl GraphSM {
    pub fn missing_nonce_requests(&self) -> Vec<GetMessageRequest> { ... }
    pub fn missing_signature_requests(&self) -> Vec<GetMessageRequest> { ... }
}
```

**Nag Cascade Order:**
```
1. StakeChainExchange    ← Foundation: pre-stake tx info
         ↓
2. DepositSetup          ← Requires: stake chain data
         ↓
3. Musig2NoncesExchange  ← Requires: deposit setup complete
         ↓
4. Musig2SignaturesExchange ← Requires: nonces collected
```

**Key Properties:**
- Periodic (default 10 seconds, configurable)
- Uses set difference to detect missing data
- Skips phases if prerequisites incomplete
- Avoids duplicate requests for in-flight messages

---

## 8. Main Loop (orchestrator.rs)

The main loop has a single processing path. The only fork is in how events are
classified into `Vec<(SMId, SMEvent)>`:
- **Block events** → `classify_block()` uses `TxClassifier::classify_tx()` per SM, plus appends `NewBlock`/`BlockAdvanced` cursor events
- **P2P / assignment events** → `event_router::route()` + `sm_processor::classify()` per target

Once classified, all events flow through the same process → signal cascade → batch persist → duty dispatch pipeline.

```rust
impl Orchestrator {
    pub async fn run(mut self) -> Result<(), OrchestratorError> {
        loop {
            // Stage 1: Multiplex event streams
            let event = self.event_mux.next().await;

            // Handle special events that don't route to SMs
            match &event {
                UnifiedEvent::OuroborosMessage(msg) => {
                    // Self-consistency: process our own message before broadcasting
                    match self.handle_ouroboros_message(msg.clone()).await {
                        Ok(duties) => {
                            // Sign and broadcast to network
                            let signed = self.p2p_command.sign_message(msg.clone());
                            self.p2p_command.publish(signed).await;
                            self.execute_duties(duties).await;
                        }
                        Err(e) => {
                            // Don't panic - ouroboros failures can happen during catch-up
                            error!(%e, "failed to process ouroboros message");
                        }
                    }
                    continue;
                }

                UnifiedEvent::OuroborosRequest(req) => {
                    // Self-nag: check if request is for us or forward to network
                    if req.operator_pubkey() == self.operator_table.pov_p2p_key() {
                        let duties = self.handle_request(req.clone()).await?;
                        self.execute_duties(duties).await;
                    } else {
                        self.p2p_command.request(req.clone()).await;
                    }
                    continue;
                }

                UnifiedEvent::Shutdown(sender) => {
                    return self.handle_shutdown(sender).await;
                }

                UnifiedEvent::NagTick => {
                    // Generate and send nag requests for missing data
                    let nags = nag::generate_nags(&self.registry, &self.stake_chains);
                    for nag in nags {
                        self.msg_handler.request(nag).await;
                    }
                    continue;
                }

                // Routable events — fall through to unified processing
                _ => {}
            }

            // ── Classification (the only fork) ──────────────────────────

            let targets: Vec<(SMId, SMEvent)> = match &event {
                UnifiedEvent::Block(block_event) => {
                    self.classify_block(block_event)
                }
                _ => {
                    // P2P / assignment: route to SM ids, then classify each
                    event_router::route(&event, &self.registry)
                        .into_iter()
                        .filter_map(|sm_id| {
                            sm_processor::classify(&sm_id, &event)
                                .ok()
                                .map(|sm_event| (sm_id, sm_event))
                        })
                        .collect()
                }
            };

            // ── Unified processing pipeline ─────────────────────────────

            let mut all_duties = Vec::new();
            let mut signal_queue: VecDeque<(SMId, SMEvent)> = VecDeque::new();
            let mut tracker = PersistenceTracker::new();

            // Process initial targets
            for (sm_id, sm_event) in targets {
                match sm_processor::process(&sm_id, sm_event, &mut self.registry) {
                    Ok(output) => {
                        all_duties.extend(output.duties);

                        tracker.record(sm_id);
                        for signal in output.signals {
                            for (target_id, target_event) in
                                signal_router::route_signal(&signal, &self.registry)
                            {
                                tracker.link(&sm_id, target_id);
                                signal_queue.push_back((target_id, target_event));
                            }
                        }
                    }
                    Err(e) => error!(?sm_id, %e, "STF failed"),
                }
            }

            // Signal cascade
            while let Some((sm_id, sm_event)) = signal_queue.pop_front() {
                match sm_processor::process(&sm_id, sm_event, &mut self.registry) {
                    Ok(output) => {
                        all_duties.extend(output.duties);
                        for signal in output.signals {
                            for (target_id, target_event) in
                                signal_router::route_signal(&signal, &self.registry)
                            {
                                tracker.link(&sm_id, target_id);
                                signal_queue.push_back((target_id, target_event));
                            }
                        }
                    }
                    Err(e) => error!(?sm_id, %e, "signal STF failed"),
                }
            }

            // Batch persistence (one DB transaction per causal group)
            for batch in tracker.into_batches() {
                self.persister.persist_batch(&batch, &self.registry).await?;
            }

            // Duty dispatch (at the very end, after persistence)
            self.execute_duties(all_duties).await;
        }
    }

    /// Classify a buried block into a list of (SMId, SMEvent) targets.
    ///
    /// 1. Detects new deposit requests (spawns new SMs into the registry)
    /// 2. Runs TxClassifier::classify_tx() on each SM for each transaction
    /// 3. Appends a NewBlock / BlockAdvanced cursor event for every active SM
    ///
    /// Returns the full list of typed events ready for sm_processor::process().
    fn classify_block(&mut self, block_event: &BlockEvent) -> Vec<(SMId, SMEvent)> {
        let height = block_event.height;
        let block = &block_event.block;
        let mut targets = Vec::new();

        // Phase 1: Detect new deposit requests (creates new SMs)
        for tx in &block.txdata {
            if let Some(deposit_info) = deposit_request_info(tx) {
                let (deposit_sm, graph_sm) = self.create_sms(&deposit_info);
                self.registry.insert_deposit(
                    deposit_info.txid,
                    deposit_sm,
                    graph_sm,
                );
            }
        }

        // Phase 2: Classify transactions against all active SMs
        for tx in &block.txdata {
            for (txid, sm) in self.registry.deposits.iter() {
                if let Some(event) = sm.classify_tx(tx, height) {
                    targets.push((SMId::Deposit(*txid), SMEvent::Deposit(event)));
                }
            }
            for (txid, sm) in self.registry.graphs.iter() {
                if let Some(event) = sm.classify_tx(tx, height) {
                    targets.push((SMId::Graph(*txid), SMEvent::Graph(event)));
                }
            }
        }

        // Phase 3: Append block cursor events for all active SMs
        for (txid, _) in self.registry.deposits.iter() {
            targets.push((
                SMId::Deposit(*txid),
                SMEvent::Deposit(DepositEvent::NewBlock(NewBlockEvent {
                    block_height: height,
                })),
            ));
        }
        for (txid, _) in self.registry.graphs.iter() {
            targets.push((
                SMId::Graph(*txid),
                SMEvent::Graph(GraphEvent::BlockAdvanced(height)),
            ));
        }

        targets
    }

    async fn execute_duties(&self, duties: Vec<UnifiedDuty>) {
        for duty in duties {
            if let Err(e) = self.dispatcher.dispatch(duty.clone()).await {
                error!(?duty, %e, "duty execution failed");
            }
        }
    }
}
```

---

## 9. Files to Port

### 9.1 To orchestrator crate

| Source (duty-tracker) | Destination (orchestrator) |
|----------------------|----------------------------|
| `contract_manager.rs:263-485` (select loop) | `pipeline/event_mux.rs` |
| `contract_manager.rs` (process_* methods) | `pipeline/event_router.rs`, `sm_processor.rs` |
| `predicates.rs` | `pipeline/event_router.rs` |
| `contract_persister.rs` | `persistence/coordinator.rs` |
| `stake_chain_persister.rs` | `persistence/coordinator.rs` |
| `shutdown.rs` | `shutdown.rs` |
| `errors.rs` | `errors.rs` |

### 9.2 To bridge-exec crate

**Expand ExecutionConfig (config.rs):**

```rust
pub struct ExecutionConfig {
    pub network: Network,
    pub connector_params: ConnectorParams,           // ADD
    pub pegout_graph_params: PegOutGraphParams,      // ADD
    pub stake_chain_params: StakeChainParams,        // ADD
    pub sidesystem_params: RollupParams,             // ADD
    pub operator_table: OperatorTable,               // ADD
    pub stake_tx_retry_config: StakeTxRetryConfig,   // ADD
    pub pre_stake_pubkey: ScriptBuf,                 // ADD
    pub funding_address: Address,                    // ADD
    pub is_faulty: bool,                             // ADD
    pub min_withdrawal_fulfillment_window: u64,      // EXISTS
    pub stake_funding_pool_size: usize,              // ADD
}
```

**Expand OutputHandles (output_handles.rs):**

```rust
pub struct OutputHandles {
    pub wallet: RwLock<OperatorWallet>,              // EXISTS
    pub msg_handler: MessageHandler,                 // EXISTS
    pub bitcoind_rpc_client: BitcoinClient,          // EXISTS
    pub s2_client: SecretServiceClient,              // EXISTS
    pub tx_driver: TxDriver,                         // EXISTS
    pub db: SqliteDb,                                // ADD
}
```

**Port Executor Functions:**

| Source (duty-tracker) | Destination (bridge-exec) |
|----------------------|---------------------------|
| `executors/deposit.rs:handle_publish_graph_nonces` | `graph.rs` |
| `executors/deposit.rs:handle_publish_graph_sigs` | `graph.rs` |
| `executors/deposit.rs:handle_publish_root_nonce` | `graph.rs` |
| `executors/deposit.rs:handle_publish_root_signature` | `graph.rs` |
| `executors/deposit.rs:handle_publish_deposit` | `deposit.rs` |
| `executors/optimistic_withdrawal.rs:*` | `withdrawal/optimistic.rs` |
| `executors/contested_withdrawal.rs:*` | `withdrawal/contested.rs` |
| `executors/proof_handler.rs:*` | `helpers/proof_handler.rs` |
| `executors/wots_handler.rs:*` | `helpers/wots_handler.rs` |
| `executors/config.rs:StakeTxRetryConfig` | `config.rs` |

### 9.3 To bridge-sm crate

**New GraphSM Module:**

```
crates/bridge-sm/src/graph/
├── mod.rs
├── state.rs        # GraphSM implementing StateMachine trait
├── events.rs       # GraphEvent enum
├── duties.rs       # GraphDuty enum
└── errors.rs       # GraphError
```

**GraphDuty variants (derived from duty-tracker's OperatorDuty):**
- `PublishGraphNonces { claim_txid, pog_prevouts, pog_witnesses, nonces }`
- `PublishGraphSignatures { claim_txid, aggnonces, pog_prevouts, pog_sighashes, partials }`
- `PublishRootNonce { deposit_request_txid, witness, nonce }`
- `PublishRootSignature { deposit_request_txid, aggnonce, sighash, witness, partial }`

---

## 10. Critical Files to Modify

| File | Action |
|------|--------|
| `crates/orchestrator/` | Create new crate |
| `crates/bridge-exec/src/config.rs` | Expand `ExecutionConfig` |
| `crates/bridge-exec/src/output_handles.rs` | Add `db: SqliteDb` field |
| `crates/bridge-exec/src/deposit.rs` | Implement `todo!()` stubs |
| `crates/bridge-exec/src/graph.rs` | NEW: Graph duty executors |
| `crates/bridge-exec/src/withdrawal/` | NEW: Port withdrawal executors |
| `crates/bridge-exec/src/helpers/` | NEW: Port proof/wots handlers |
| `crates/bridge-sm/src/graph/` | NEW: GraphSM module |
| `crates/bridge-sm/src/deposit/state.rs` | Complete TODOs in STF functions |
| `bin/alpen-bridge/src/mode/operator.rs` | Update to create `Orchestrator` |
| `bin/alpen-bridge/Cargo.toml` | Replace `duty-tracker` with `orchestrator` |

---

## 11. Migration Strategy

### Phase 1: Expand bridge-sm
1. Add `GraphSM` module with `StateMachine` trait impl
2. Define `GraphState`, `GraphEvent`, `GraphDuty`, `GraphError`
3. Complete `DepositSM` TODOs (fill in `todo!()` functions)
4. Add tests for new state machine

### Phase 2: Expand bridge-exec
1. Expand `ExecutionConfig` with all required fields
2. Add `db: SqliteDb` to `OutputHandles`
3. Port executor implementations from `duty-tracker/executors/`
4. Implement `todo!()` placeholders in `deposit.rs`
5. Create `graph.rs` with graph-related executors
6. Create `withdrawal/` directory with optimistic and contested handlers
7. Create `helpers/` directory with proof and wots handlers

### Phase 3: Create orchestrator crate
1. Create crate skeleton with `Cargo.toml`
2. Implement `EventMux` (multiplexer that ports select! block)
3. Implement `EventRouter` (port predicates)
4. Implement `SMRegistry` for state machine management
5. Implement `SMProcessor` for event processing
6. Implement `SignalRouter` for inter-SM communication
7. Implement `DutyDispatcher` (calls bridge-exec)
8. Implement `Persister` (port persisters)
9. Implement main `Orchestrator` struct and `run()` loop
10. Implement `shutdown.rs` for graceful shutdown
11. Implement `nag.rs` for P2P consistency mechanism

### Phase 4: Integration
1. Update `operator.rs` to use `Orchestrator` instead of `ContractManager`
2. Add feature flag for gradual migration (optional)
3. Test in parallel with `duty-tracker`
4. Verify all existing functionality works

### Phase 5: Cleanup
1. Remove `duty-tracker` dependency from `alpen-bridge`
2. Delete `duty-tracker` crate
3. Update documentation
4. Clean up any remaining references

---

## 12. Verification

### 12.1 Unit Tests
- Port existing tests from `duty-tracker` and `bridge-sm`
- Add tests for new `GraphSM` state transitions
- Add tests for `EventRouter` predicates
- Add tests for `SignalRouter` routing logic

### 12.2 Integration Tests
- Run full deposit→withdrawal cycle
- Test P2P message routing between operators
- Test shutdown/restart with state recovery
- Test signal cascading between `DepositSM` and `GraphSM`

### 12.3 Manual Testing
1. Start operator node with new `Orchestrator`
2. Process deposit request through full lifecycle:
   - Deposit request → Graph generation → Nonce collection → Partial collection → Deposited
   - Assignment → Fulfillment → Payout (cooperative or contested)
3. Verify nag mechanism works for P2P consistency
4. Test graceful shutdown with state persistence
5. Restart and verify state recovery

### 12.4 Build Verification
```bash
# Build all affected crates
cargo build -p bridge-sm
cargo build -p bridge-exec
cargo build -p orchestrator
cargo build -p alpen-bridge

# Run tests
cargo test -p bridge-sm
cargo test -p bridge-exec
cargo test -p orchestrator

# Run clippy
cargo clippy -p orchestrator -- -D warnings
```

---

## 13. Open Questions

1. **Stake Chain SM**: Should `StakeChainSM` be moved to `bridge-sm` and integrated into the orchestrator, or kept separate?

2. **Graph Persistence**: Does `GraphSM` state need its own persister, or can it be stored with the associated contract?

3. **Error Recovery**: How should the orchestrator handle partial failures during signal cascades?

4. **Concurrency**: Should duty execution be parallelized, or kept sequential for simplicity?

---

## 14. References

- `crates/bridge-sm/src/state_machine.rs` - StateMachine trait definition
- `crates/bridge-sm/src/signals.rs` - Signal types
- `crates/bridge-sm/src/deposit/state.rs` - DepositSM implementation
- `crates/duty-tracker/src/contract_manager.rs` - Current event loop
- `crates/duty-tracker/src/executors/` - Current executor implementations
- `crates/bridge-exec/src/` - Executor crate structure
