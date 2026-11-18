//! Regression tests for state-machine telemetry (STR-4692).
//!
//! These drive events through the production path (applicator -> registry) under a subscriber
//! shaped like `strata-logging`'s: a compact, `FmtSpan::CLOSE` stdout layer behind its own
//! `EnvFilter`, next to a layer with no filter (as its OTLP layer is). The unfiltered layer means
//! DEBUG spans are really created, and span close lines are part of the default INFO output, so
//! asserting only on explicit log statements would miss the noise this guards against.

use std::{
    io,
    sync::{Arc, Mutex},
};

use bitcoin::OutPoint;
use metrics_util::{
    CompositeKey, MetricKind,
    debugging::{DebugValue, DebuggingRecorder},
};
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_sm::{
    deposit::events::{DepositEvent, UserTakeBackEvent},
    graph::events::{GraphEvent, NagTickEvent as GraphNagTick},
    stake::events::{NagTickEvent, NewBlockEvent, StakeEvent},
};
use strata_bridge_test_utils::bitcoin::generate_txid;
use tracing_subscriber::{
    EnvFilter, Layer,
    fmt::{MakeWriter, format::FmtSpan},
    layer::SubscriberExt,
};

use crate::{
    applicator::{Applicator, BatchOutput},
    duty_dispatcher, pipeline,
    sm_registry::SMRegistry,
    sm_types::{SMEvent, SMId, UnifiedDuty},
    testing::{
        INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, TEST_POV_IDX, insert_confirmed_stake,
        insert_created_stake, takeback_tx, test_empty_registry, test_operator_table,
        test_populated_registry,
    },
};

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("log buffer lock").write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

struct Captured<T> {
    value: T,
    /// Output of the layer filtered by the requested directive.
    logs: String,
    /// Output of an unfiltered TRACE layer in the same run.
    all: String,
    metrics: Vec<(CompositeKey, DebugValue)>,
}

impl<T> Captured<T> {
    /// Sums a counter over every series whose labels include `labels`.
    fn counter(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
        self.metrics
            .iter()
            .filter(|(key, _)| key.kind() == MetricKind::Counter && key.key().name() == name)
            .filter(|(key, _)| {
                labels.iter().all(|(k, v)| {
                    key.key()
                        .labels()
                        .any(|label| label.key() == *k && label.value() == *v)
                })
            })
            .map(|(_, value)| match value {
                DebugValue::Counter(count) => *count,
                other => panic!("{name} is not a counter: {other:?}"),
            })
            .sum()
    }

    fn has_series(&self, name: &str) -> bool {
        self.metrics.iter().any(|(key, _)| key.key().name() == name)
    }
}

impl Buffer {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().expect("log buffer lock").clone()).expect("logs are utf-8")
    }
}

fn fmt_layer<S>(buffer: &Buffer) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .compact()
        .with_ansi(false)
        .with_span_events(FmtSpan::CLOSE)
        .with_writer(buffer.clone())
}

/// Runs `f` with a production-shaped log subscriber, whose stdout-like layer is filtered by
/// `filter`, and a local metrics recorder, returning everything they captured.
fn capture<T>(filter: &str, f: impl FnOnce() -> T) -> Captured<T> {
    let filtered = Buffer::default();
    let unfiltered = Buffer::default();
    let subscriber = tracing_subscriber::registry()
        .with(fmt_layer(&filtered).with_filter(EnvFilter::new(filter)))
        .with(fmt_layer(&unfiltered).with_filter(EnvFilter::new("trace")));
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let value = metrics::with_local_recorder(&recorder, || {
        tracing::subscriber::with_default(subscriber, f)
    });

    let logs = filtered.contents();
    let all = unfiltered.contents();
    let metrics = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(key, _, _, value)| (key, value))
        .collect();
    Captured {
        value,
        logs,
        all,
        metrics,
    }
}

fn apply(registry: &mut SMRegistry, id: SMId, event: SMEvent) -> BatchOutput {
    let mut applicator = Applicator::new(registry, Some(TEST_POV_IDX));
    applicator
        .apply_batch(vec![(id, event)])
        .expect("event must apply");
    applicator.finish()
}

const EVENTS_TOTAL: &str = "strata_bridge_sm_events_total";
const TRANSITIONS_TOTAL: &str = "strata_bridge_sm_transitions_total";

fn created_stake_registry() -> (SMRegistry, SMId) {
    let mut registry = test_empty_registry();
    let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
    insert_created_stake(&mut registry, TEST_POV_IDX, table);
    let key = *registry.stakes().next().expect("stake inserted").0;
    (registry, SMId::Stake(key))
}

fn confirmed_stake_registry() -> (SMRegistry, SMId) {
    let mut registry = test_empty_registry();
    let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
    insert_confirmed_stake(&mut registry, TEST_POV_IDX, table, generate_txid());
    let key = *registry.stakes().next().expect("stake inserted").0;
    (registry, SMId::Stake(key))
}

fn nag_tick() -> SMEvent {
    StakeEvent::NagTick(NagTickEvent).into()
}

/// Asserts that nothing about an unchanged event reached INFO output, although the unfiltered
/// layer in the same run saw the event-processing span.
fn assert_quiet_at_info<T>(captured: &Captured<T>) {
    assert!(
        captured.all.contains("bridge_sm_event") && captured.all.contains("applied_unchanged"),
        "the unfiltered layer must still see the diagnostic span:\n{}",
        captured.all
    );
    let logs = &captured.logs;
    for needle in [
        "bridge_sm_transition",
        "bridge_sm_event",
        "applied_unchanged",
        "state-machine transition applied",
    ] {
        assert!(
            !logs.contains(needle),
            "unchanged event leaked {needle:?} into INFO output:\n{logs}"
        );
    }
}

#[test]
fn unchanged_nag_tick_without_duties_is_not_a_transition() {
    let (mut registry, id) = confirmed_stake_registry();
    let info = capture("info", || apply(&mut registry, id, nag_tick()));
    assert!(info.value.duties.is_empty(), "fixture must emit no duties");
    assert_quiet_at_info(&info);
    assert_eq!(info.counter(TRANSITIONS_TOTAL, &[]), 0);
    assert_eq!(
        info.counter(EVENTS_TOTAL, &[("result", "applied_unchanged")]),
        1
    );
}

#[test]
fn unchanged_nag_tick_with_duties_still_emits_them_quietly() {
    let (mut registry, id) = created_stake_registry();
    let info = capture("info", || apply(&mut registry, id, nag_tick()));
    assert_eq!(info.value.duties.len(), 1, "nag duty must still be emitted");
    assert!(matches!(info.value.duties[0], UnifiedDuty::Stake { .. }));
    assert_quiet_at_info(&info);
    assert_eq!(info.counter(TRANSITIONS_TOTAL, &[]), 0);
    assert_eq!(
        info.counter(
            EVENTS_TOTAL,
            &[("sm_kind", "stake"), ("result", "applied_unchanged")]
        ),
        1
    );
}

#[test]
fn repeated_nag_ticks_across_many_graphs_stay_out_of_info() {
    let mut registry = test_populated_registry(4);
    let ids: Vec<_> = (0..4)
        .flat_map(|deposit| {
            (0..N_TEST_OPERATORS as u32)
                .map(move |operator| SMId::Graph(GraphIdx { deposit, operator }))
        })
        .collect();
    let info = capture("info", || {
        for _ in 0..3 {
            for id in &ids {
                apply(
                    &mut registry,
                    *id,
                    SMEvent::Graph(Box::new(GraphEvent::NagTick(GraphNagTick))),
                );
            }
        }
    });
    assert_quiet_at_info(&info);
    assert_eq!(info.counter(TRANSITIONS_TOTAL, &[]), 0);
    assert_eq!(
        info.counter(EVENTS_TOTAL, &[("sm_kind", "graph")]),
        3 * ids.len() as u64
    );
}

#[test]
fn unchanged_event_diagnostics_remain_available_at_debug() {
    let (mut registry, id) = created_stake_registry();
    let debug = capture("debug", || apply(&mut registry, id, nag_tick()));
    assert!(
        debug.logs.contains("bridge_sm_event") && debug.logs.contains("applied_unchanged"),
        "DEBUG output must keep the event-processing diagnostic:\n{}",
        debug.logs
    );
    assert!(
        debug.all.contains("bridge_sm_event"),
        "the diagnostic span must exist for unfiltered consumers:\n{}",
        debug.all
    );
    assert!(
        !debug.logs.contains("state-machine transition applied"),
        "an unchanged event must not be reported as a transition:\n{}",
        debug.logs
    );
}

#[test]
fn same_variant_periodic_mutation_is_a_transition_at_debug() {
    let (mut registry, id) = created_stake_registry();
    let new_block: SMEvent = StakeEvent::NewBlock(NewBlockEvent {
        block_height: INITIAL_BLOCK_HEIGHT + 1,
    })
    .into();
    let debug = capture("debug", || apply(&mut registry, id, new_block));
    assert_eq!(
        debug.counter(
            TRANSITIONS_TOTAL,
            &[
                ("sm_kind", "stake"),
                ("from_state", "created"),
                ("to_state", "created")
            ]
        ),
        1,
        "a mutation within the same named variant is still a transition"
    );
    assert!(
        debug.logs.contains("state-machine transition applied"),
        "{}",
        debug.logs
    );
}

#[test]
fn variant_changing_mutation_is_visible_at_info() {
    let mut registry = test_populated_registry(1);
    let event = SMEvent::Deposit(Box::new(DepositEvent::UserTakeBack(UserTakeBackEvent {
        tx: takeback_tx(OutPoint::default()),
    })));
    let info = capture("info", || apply(&mut registry, SMId::Deposit(0), event));
    assert!(
        info.logs.contains("state-machine transition applied") && info.logs.contains("aborted"),
        "a real lifecycle transition must stay visible at INFO:\n{}",
        info.logs
    );
    assert_eq!(
        info.counter(
            TRANSITIONS_TOTAL,
            &[("sm_kind", "deposit"), ("to_state", "aborted")]
        ),
        1
    );
}

#[test]
fn invalid_events_are_counted_as_events_not_transitions() {
    let mut registry = test_empty_registry();
    let captured = capture("info", || {
        let mut applicator = Applicator::new(&mut registry, Some(TEST_POV_IDX));
        applicator.apply_batch(vec![(SMId::Deposit(999), nag_tick())])
    });
    assert!(
        captured.value.is_err(),
        "a missing SM is a fatal pipeline error"
    );
    assert_eq!(captured.counter(EVENTS_TOTAL, &[("result", "invalid")]), 1);
    assert_eq!(captured.counter(TRANSITIONS_TOTAL, &[]), 0);
    assert!(!captured.has_series("strata_bridge_sm_transition_duration_seconds"));
}

#[test]
fn periodic_pipeline_events_do_not_open_info_spans() {
    let info = capture("info", || {
        for periodic in [true, false] {
            let span = pipeline::bridge_event_span("tick_or_not", periodic);
            drop(span.entered());
        }
    });
    assert_eq!(
        info.logs.matches("bridge_event").count(),
        1,
        "only the non-periodic event span may close at INFO:\n{}",
        info.logs
    );
}

#[test]
fn nag_duty_spans_stay_below_info() {
    let info = capture("info", || {
        for nag in [true, false] {
            let span = duty_dispatcher::duty_span("some_duty", &"duty", nag);
            drop(span.entered());
        }
    });
    assert_eq!(
        info.logs.matches("bridge_duty_execution").count(),
        1,
        "only the non-nag duty span may close at INFO:\n{}",
        info.logs
    );
}
