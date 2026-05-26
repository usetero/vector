//! The async task transform that drives the `policy-rs` engine.

use std::pin::Pin;
use std::sync::Arc;

use async_stream::stream;
use futures::{Stream, StreamExt};
use policy_rs::{EvaluateResult, PolicyEngine, PolicyRegistry};
use vector_lib::transform::TaskTransform;

use crate::event::Event;

use super::adapter::VectorLogAdapter;
use super::field_mapping::FieldMapping;
use super::internal_events::{DropReason, emit_dropped};

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
}

impl Policy {
    pub const fn new(
        registry: Arc<PolicyRegistry>,
        engine: Arc<PolicyEngine>,
        mapping: Arc<FieldMapping>,
    ) -> Self {
        Self {
            registry,
            engine,
            mapping,
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

        Box::pin(stream! {
            while let Some(event) = input_rx.next().await {
                match event {
                    Event::Log(mut log) => {
                        // Pull a fresh snapshot every event so live-reloaded
                        // policies take effect on the next pass. Snapshots
                        // are cheap (Arc clone of an immutable inner).
                        let snapshot = registry.snapshot();
                        let result = {
                            let mut adapter = VectorLogAdapter::new(&mut log, &mapping);
                            engine.evaluate_and_transform(&snapshot, &mut adapter).await
                        };
                        match result {
                            Ok(EvaluateResult::NoMatch)
                            | Ok(EvaluateResult::Keep { .. })
                            | Ok(EvaluateResult::Sample { keep: true, .. })
                            | Ok(EvaluateResult::RateLimit { allowed: true, .. }) => {
                                yield Event::Log(log);
                            }
                            Ok(EvaluateResult::Drop { .. }) => {
                                emit_dropped(DropReason::PolicyDrop);
                            }
                            Ok(EvaluateResult::Sample { keep: false, .. }) => {
                                emit_dropped(DropReason::SampleRejected);
                            }
                            Ok(EvaluateResult::RateLimit { allowed: false, .. }) => {
                                emit_dropped(DropReason::RateLimited);
                            }
                            Err(error) => {
                                // Fail open: an evaluation error shouldn't
                                // silently drop telemetry. Log and pass the
                                // event through untouched.
                                error!(
                                    message = "Policy evaluation failed; event passed through unchanged.",
                                    %error,
                                );
                                yield Event::Log(log);
                            }
                        }
                    }
                    other => {
                        // policy-rs only targets the log signal in this
                        // integration. Metrics and traces are forwarded
                        // untouched.
                        yield other;
                    }
                }
            }
        })
    }
}
