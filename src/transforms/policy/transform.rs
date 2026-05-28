//! The async task transform that drives the `policy-rs` engine.

use std::pin::Pin;
use std::sync::Arc;

use async_stream::stream;
use futures::{Stream, StreamExt};
use policy_rs::{EvaluateResult, PolicyEngine, PolicyRegistry, PolicySnapshot};
use vector_lib::transform::TaskTransform;

use crate::event::{Event, LogEvent};

use super::adapter::VectorLogAdapter;
use super::config::PolicyMode;
use super::field_mapping::FieldMapping;
use super::internal_events::{DropReason, emit_dropped};
use super::otlp_adapter::evaluate_envelope;
use super::otlp_metric_adapter::evaluate_metrics_envelope;
use super::otlp_trace_adapter::evaluate_traces_envelope;

/// Per-task state for the `policy` transform.
///
/// `PolicyRegistry` and `PolicyEngine` are wrapped in `Arc` so the
/// `TaskTransform` machinery can move the struct freely while preserving
/// rate-limit and stats state across reconfigurations.
#[derive(Clone)]
pub struct Policy {
    registry: Arc<PolicyRegistry>,
    engine: Arc<PolicyEngine>,
    mapping: Arc<FieldMapping>,
    mode: PolicyMode,
}

impl Policy {
    pub const fn new(
        registry: Arc<PolicyRegistry>,
        engine: Arc<PolicyEngine>,
        mapping: Arc<FieldMapping>,
        mode: PolicyMode,
    ) -> Self {
        Self {
            registry,
            engine,
            mapping,
            mode,
        }
    }
}

impl TaskTransform<Event> for Policy {
    fn transform(
        self: Box<Self>,
        mut input_rx: Pin<Box<dyn Stream<Item = Event> + Send>>,
    ) -> Pin<Box<dyn Stream<Item = Event> + Send>>
    where
        Self: 'static,
    {
        let registry = Arc::clone(&self.registry);
        let engine = Arc::clone(&self.engine);
        let mapping = Arc::clone(&self.mapping);
        let mode = self.mode;

        Box::pin(stream! {
            while let Some(event) = input_rx.next().await {
                // Pull a fresh snapshot every event so live-reloaded policies
                // take effect on the next pass. Snapshots are cheap (Arc clone
                // of an immutable inner).
                let snapshot = registry.snapshot();
                match event {
                    Event::Log(log) => {
                        let outcome = match mode {
                            PolicyMode::Flat => {
                                evaluate_flat(&engine, &snapshot, &mapping, log).await
                            }
                            // In OTel mode a `Log` event is either a logs
                            // envelope (`resourceLogs`) or a metrics envelope
                            // (`resourceMetrics`) — the `opentelemetry` source
                            // decodes both into `Log` events.
                            PolicyMode::Otel if log.contains("resourceMetrics") => {
                                evaluate_metrics_envelope(&engine, &snapshot, log).await
                            }
                            PolicyMode::Otel => {
                                evaluate_envelope(&engine, &snapshot, log).await
                            }
                        };
                        if let Some(forwarded) = outcome {
                            yield Event::Log(forwarded);
                        }
                    }
                    Event::Trace(mut trace) => {
                        // OTLP traces arrive as `Trace` events
                        // (`resourceSpans`). Flat mode has no trace mapping, so
                        // only OTel mode evaluates them; otherwise pass through.
                        let keep = match mode {
                            PolicyMode::Otel => {
                                evaluate_traces_envelope(&engine, &snapshot, &mut trace).await
                            }
                            PolicyMode::Flat => true,
                        };
                        if keep {
                            yield Event::Trace(trace);
                        }
                    }
                    // Native Vector metrics (not OTLP envelopes) pass through.
                    other => {
                        yield other;
                    }
                }
            }
        })
    }
}

/// Flat-mode evaluation: one Vector event = one log record. Returns
/// `Some(log)` to forward, `None` to drop.
async fn evaluate_flat(
    engine: &PolicyEngine,
    snapshot: &PolicySnapshot,
    mapping: &FieldMapping,
    mut log: LogEvent,
) -> Option<LogEvent> {
    let result = {
        let mut adapter = VectorLogAdapter::new(&mut log, mapping);
        engine.evaluate_and_transform(snapshot, &mut adapter).await
    };
    match result {
        Ok(EvaluateResult::NoMatch)
        | Ok(EvaluateResult::Keep { .. })
        | Ok(EvaluateResult::Sample { keep: true, .. })
        | Ok(EvaluateResult::RateLimit { allowed: true, .. }) => Some(log),
        Ok(EvaluateResult::Drop { .. }) => {
            emit_dropped(DropReason::PolicyDrop, 1);
            None
        }
        Ok(EvaluateResult::Sample { keep: false, .. }) => {
            emit_dropped(DropReason::SampleRejected, 1);
            None
        }
        Ok(EvaluateResult::RateLimit { allowed: false, .. }) => {
            emit_dropped(DropReason::RateLimited, 1);
            None
        }
        Err(error) => {
            // Fail open: an evaluation error shouldn't silently drop
            // telemetry. Log and pass the event through untouched.
            error!(
                message = "Policy evaluation failed; event passed through unchanged.",
                %error,
            );
            Some(log)
        }
    }
}
