//! OTLP metrics adapter for the `policy` transform (`mode: otel`).
//!
//! When Vector's `opentelemetry` source decodes OTLP metrics with
//! `use_otlp_decoding`, the metrics arrive as a `Log` event shaped like
//! `{ resourceMetrics: [...] }`. This module iterates every metric inside the
//! envelope, evaluates it through `policy-rs` (match-only — metrics are not
//! transformed), drops metrics whose winning policy says so, and prunes empty
//! `scopeMetrics` / `resourceMetrics`.
//!
//! Mirrors the conformance reference (`MetricContext` in
//! `policy-conformance/runners/rs/src/eval.rs`): a metric is matched on the
//! attributes of its **first** data point, its descriptor fields, its type
//! (gauge/sum/…) and aggregation temporality.

use std::borrow::Cow;

use policy_rs::proto::tero::policy::v1::MetricField;
use policy_rs::{
    EvaluateResult, Matchable, MetricFieldSelector, PolicyEngine, PolicySnapshot,
    engine::MetricSignal,
};
use vector_lib::event::{LogEvent, Value};

use super::internal_events::{DropReason, emit_dropped};
use super::otlp_adapter::{attribute_exists_path, find_attribute_path, non_empty};

/// Data-variant keys of an OTLP `Metric` (proto3 JSON), paired with the
/// `MetricFieldSelector::Type` string the engine matches against.
const METRIC_TYPES: [(&str, &str); 5] = [
    ("gauge", "METRIC_TYPE_GAUGE"),
    ("sum", "METRIC_TYPE_SUM"),
    ("histogram", "METRIC_TYPE_HISTOGRAM"),
    ("exponentialHistogram", "METRIC_TYPE_EXPONENTIAL_HISTOGRAM"),
    ("summary", "METRIC_TYPE_SUMMARY"),
];

/// Iterate every metric in an OTLP metrics envelope, dropping filtered ones.
/// Returns `Some(log)` to forward or `None` to drop the whole event.
pub(super) async fn evaluate_metrics_envelope(
    engine: &PolicyEngine,
    snapshot: &PolicySnapshot,
    mut log: LogEvent,
) -> Option<LogEvent> {
    let Some(resource_metrics) = log.get_mut("resourceMetrics").and_then(Value::as_array_mut)
    else {
        return Some(log);
    };

    let mut i = 0;
    while i < resource_metrics.len() {
        // Metrics are read-only, so immutable snapshots of resource/scope are
        // enough (no remove/re-insert dance needed).
        let resource = resource_metrics[i].get("resource").cloned();
        let resource_schema_url = resource_metrics[i].get("schemaUrl").cloned();

        let mut prune_rm = false;

        if let Some(scope_metrics) = resource_metrics[i]
            .get_mut("scopeMetrics")
            .and_then(Value::as_array_mut)
        {
            let mut j = 0;
            while j < scope_metrics.len() {
                let scope = scope_metrics[j].get("scope").cloned();
                let scope_schema_url = scope_metrics[j].get("schemaUrl").cloned();

                let mut prune_sm = false;

                if let Some(metrics) = scope_metrics[j]
                    .get_mut("metrics")
                    .and_then(Value::as_array_mut)
                {
                    // Evaluate first (immutable borrows), then retain by index.
                    let mut keep = Vec::with_capacity(metrics.len());
                    for metric in metrics.iter() {
                        let adapter = MetricAdapter {
                            metric,
                            resource: resource.as_ref(),
                            scope: scope.as_ref(),
                            resource_schema_url: resource_schema_url.as_ref(),
                            scope_schema_url: scope_schema_url.as_ref(),
                        };
                        let drop = matches!(
                            engine.evaluate(snapshot, &adapter).await,
                            Ok(EvaluateResult::Drop { .. })
                        );
                        if drop {
                            emit_dropped(DropReason::PolicyDrop);
                        }
                        keep.push(!drop);
                    }
                    let mut idx = 0;
                    metrics.retain(|_| {
                        let k = keep[idx];
                        idx += 1;
                        k
                    });
                    prune_sm = metrics.is_empty();
                }

                if prune_sm {
                    scope_metrics.remove(j);
                } else {
                    j += 1;
                }
            }
            prune_rm = scope_metrics.is_empty();
        }

        if prune_rm {
            resource_metrics.remove(i);
        } else {
            i += 1;
        }
    }

    if resource_metrics.is_empty() {
        None
    } else {
        Some(log)
    }
}

/// Adapter exposing a single OTLP `metric` (plus parent resource/scope) to the
/// `policy-rs` engine. Read-only: metrics are filtered, never transformed.
struct MetricAdapter<'a> {
    metric: &'a Value,
    resource: Option<&'a Value>,
    scope: Option<&'a Value>,
    resource_schema_url: Option<&'a Value>,
    scope_schema_url: Option<&'a Value>,
}

impl MetricAdapter<'_> {
    /// The data variant object (gauge/sum/…) and its canonical type string.
    fn data(&self) -> Option<(&Value, &'static str)> {
        let obj = self.metric.as_object()?;
        METRIC_TYPES
            .iter()
            .find_map(|(key, ty)| obj.get(*key).map(|v| (v, *ty)))
    }

    /// Attributes array of the first data point, if any.
    fn first_datapoint_attributes(&self) -> Option<&Value> {
        let (data, _) = self.data()?;
        data.as_object()
            .and_then(|o| o.get("dataPoints"))
            .and_then(Value::as_array)
            .and_then(|points| points.first())
            .and_then(|p| p.as_object())
            .and_then(|o| o.get("attributes"))
    }

    fn resource_attributes(&self) -> Option<&Value> {
        self.resource.and_then(|r| r.get("attributes"))
    }

    fn scope_attributes(&self) -> Option<&Value> {
        self.scope.and_then(|s| s.get("attributes"))
    }
}

impl Matchable for MetricAdapter<'_> {
    type Signal = MetricSignal;

    fn get_field(&self, field: &MetricFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            MetricFieldSelector::Simple(MetricField::Name) => non_empty(self.metric.get("name")),
            MetricFieldSelector::Simple(MetricField::Description) => {
                non_empty(self.metric.get("description"))
            }
            MetricFieldSelector::Simple(MetricField::Unit) => non_empty(self.metric.get("unit")),
            MetricFieldSelector::Simple(MetricField::ScopeName) => {
                non_empty(self.scope.and_then(|s| s.get("name")))
            }
            MetricFieldSelector::Simple(MetricField::ScopeVersion) => {
                non_empty(self.scope.and_then(|s| s.get("version")))
            }
            MetricFieldSelector::Simple(MetricField::ResourceSchemaUrl) => {
                non_empty(self.resource_schema_url)
            }
            MetricFieldSelector::Simple(MetricField::ScopeSchemaUrl) => {
                non_empty(self.scope_schema_url)
            }
            MetricFieldSelector::Simple(MetricField::Unspecified) => None,
            MetricFieldSelector::DatapointAttribute(path) => {
                find_attribute_path(self.first_datapoint_attributes(), path)
            }
            MetricFieldSelector::ResourceAttribute(path) => {
                find_attribute_path(self.resource_attributes(), path)
            }
            MetricFieldSelector::ScopeAttribute(path) => {
                find_attribute_path(self.scope_attributes(), path)
            }
            MetricFieldSelector::Type => self.data().map(|(_, ty)| Cow::Borrowed(ty)),
            MetricFieldSelector::Temporality => {
                let (data, _) = self.data()?;
                non_empty(data.as_object().and_then(|o| o.get("aggregationTemporality")))
            }
        }
    }

    fn field_exists(&self, field: &MetricFieldSelector) -> bool {
        match field {
            MetricFieldSelector::DatapointAttribute(path) => {
                attribute_exists_path(self.first_datapoint_attributes(), path)
            }
            MetricFieldSelector::ResourceAttribute(path) => {
                attribute_exists_path(self.resource_attributes(), path)
            }
            MetricFieldSelector::ScopeAttribute(path) => {
                attribute_exists_path(self.scope_attributes(), path)
            }
            _ => self.get_field(field).is_some(),
        }
    }
}
