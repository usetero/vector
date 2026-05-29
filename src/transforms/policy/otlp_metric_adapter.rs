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
use super::otlp_common::{
    array_field_is_empty, attribute_exists_path, find_attribute_path, non_empty,
};

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

    let mut dropped = 0u64;
    let mut i = 0;
    while i < resource_metrics.len() {
        // Phase 1 — score every metric. Metric evaluation is filter-only (no
        // transform), so resource/scope/metric are all read-only here: we can
        // borrow them immutably and avoid both the deep clone and the
        // remove/re-insert lift the log/trace paths need. `keep[s][m]` is
        // whether scope `s`'s metric `m` survives.
        let keep: Vec<Vec<bool>> = {
            let rm = &resource_metrics[i];
            let resource = rm.get("resource");
            let resource_schema_url = rm.get("schemaUrl");
            let mut per_scope = Vec::new();
            if let Some(scope_metrics) = rm.get("scopeMetrics").and_then(Value::as_array) {
                for sm in scope_metrics {
                    let scope = sm.get("scope");
                    let scope_schema_url = sm.get("schemaUrl");
                    let mut per_metric = Vec::new();
                    if let Some(metrics) = sm.get("metrics").and_then(Value::as_array) {
                        for metric in metrics {
                            let adapter = MetricAdapter {
                                metric,
                                resource,
                                scope,
                                resource_schema_url,
                                scope_schema_url,
                            };
                            let drop = matches!(
                                engine.evaluate(snapshot, &adapter).await,
                                Ok(EvaluateResult::Drop { .. })
                            );
                            if drop {
                                dropped += 1;
                            }
                            per_metric.push(!drop);
                        }
                    }
                    per_scope.push(per_metric);
                }
            }
            per_scope
        };

        // Phase 2 — apply the decisions, then prune emptied scopes / resource.
        if let Some(scope_metrics) = resource_metrics[i]
            .get_mut("scopeMetrics")
            .and_then(Value::as_array_mut)
        {
            // Nothing mutates `scopeMetrics`/`metrics` between phases, so the
            // decision arrays line up with the live arrays. Index defensively
            // anyway (`.get(..)` + fail-open fallback) so a future desync
            // degrades to "keep" instead of panicking the transform task.
            debug_assert_eq!(keep.len(), scope_metrics.len());
            let mut scope_idx = 0;
            let mut j = 0;
            while j < scope_metrics.len() {
                let scope_keep: &[bool] = keep.get(scope_idx).map_or(&[], Vec::as_slice);
                scope_idx += 1;
                if let Some(metrics) = scope_metrics[j]
                    .get_mut("metrics")
                    .and_then(Value::as_array_mut)
                {
                    let mut m = 0;
                    metrics.retain(|_| {
                        let k = scope_keep.get(m).copied().unwrap_or(true);
                        m += 1;
                        k
                    });
                    if metrics.is_empty() {
                        scope_metrics.remove(j);
                        continue;
                    }
                }
                j += 1;
            }
        }

        let prune_rm = array_field_is_empty(&resource_metrics[i], "scopeMetrics");
        if prune_rm {
            resource_metrics.remove(i);
        } else {
            i += 1;
        }
    }

    emit_dropped(DropReason::PolicyDrop, dropped);

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn val(value: serde_json::Value) -> Value {
        Value::from(value)
    }

    fn adapter<'a>(
        metric: &'a Value,
        resource: Option<&'a Value>,
        scope: Option<&'a Value>,
    ) -> MetricAdapter<'a> {
        MetricAdapter {
            metric,
            resource,
            scope,
            resource_schema_url: None,
            scope_schema_url: None,
        }
    }

    fn get(metric: &Value, sel: MetricFieldSelector) -> Option<String> {
        adapter(metric, None, None)
            .get_field(&sel)
            .map(Cow::into_owned)
    }

    #[test]
    fn metric_type_derived_from_data_variant() {
        let cases = [
            (json!({"name": "m", "gauge": {"dataPoints": []}}), "METRIC_TYPE_GAUGE"),
            (json!({"name": "m", "sum": {"dataPoints": []}}), "METRIC_TYPE_SUM"),
            (
                json!({"name": "m", "histogram": {"dataPoints": []}}),
                "METRIC_TYPE_HISTOGRAM",
            ),
            (
                json!({"name": "m", "exponentialHistogram": {"dataPoints": []}}),
                "METRIC_TYPE_EXPONENTIAL_HISTOGRAM",
            ),
            (
                json!({"name": "m", "summary": {"dataPoints": []}}),
                "METRIC_TYPE_SUMMARY",
            ),
        ];
        for (metric, expected) in cases {
            let metric = val(metric);
            assert_eq!(
                get(&metric, MetricFieldSelector::Type),
                Some(expected.to_string()),
            );
        }
    }

    #[test]
    fn temporality_read_from_data_variant() {
        let delta = val(json!({
            "name": "m",
            "sum": {"dataPoints": [], "aggregationTemporality": "AGGREGATION_TEMPORALITY_DELTA"}
        }));
        assert_eq!(
            get(&delta, MetricFieldSelector::Temporality),
            Some("AGGREGATION_TEMPORALITY_DELTA".to_string()),
        );

        // Gauge has no temporality.
        let gauge = val(json!({"name": "m", "gauge": {"dataPoints": []}}));
        assert_eq!(get(&gauge, MetricFieldSelector::Temporality), None);
    }

    #[test]
    fn descriptor_fields() {
        let m = val(json!({
            "name": "http.requests", "description": "count", "unit": "1",
            "gauge": {"dataPoints": []}
        }));
        assert_eq!(
            get(&m, MetricFieldSelector::Simple(MetricField::Name)),
            Some("http.requests".to_string()),
        );
        assert_eq!(
            get(&m, MetricFieldSelector::Simple(MetricField::Description)),
            Some("count".to_string()),
        );
        assert_eq!(
            get(&m, MetricFieldSelector::Simple(MetricField::Unit)),
            Some("1".to_string()),
        );
    }

    #[test]
    fn datapoint_attribute_uses_first_datapoint() {
        let m = val(json!({"name": "m", "sum": {"dataPoints": [
            {"attributes": [{"key": "http.method", "value": {"stringValue": "GET"}}]},
            {"attributes": [{"key": "http.method", "value": {"stringValue": "POST"}}]}
        ]}}));
        assert_eq!(
            get(
                &m,
                MetricFieldSelector::DatapointAttribute(vec!["http.method".to_string()])
            ),
            Some("GET".to_string()),
        );
    }

    #[test]
    fn non_string_datapoint_attr_exists_but_is_unmatchable() {
        let m = val(json!({"name": "m", "sum": {"dataPoints": [
            {"attributes": [{"key": "count", "value": {"intValue": "42"}}]}
        ]}}));
        let sel = MetricFieldSelector::DatapointAttribute(vec!["count".to_string()]);
        // Not coercible to a string for matching...
        assert_eq!(get(&m, sel.clone()), None);
        // ...but `exists` still fires.
        assert!(adapter(&m, None, None).field_exists(&sel));
    }

    #[test]
    fn resource_and_scope_fields() {
        let m = val(json!({"name": "m", "gauge": {"dataPoints": []}}));
        let resource =
            val(json!({"attributes": [{"key": "service.name", "value": {"stringValue": "api"}}]}));
        let scope = val(json!({
            "name": "lib", "version": "1.2",
            "attributes": [{"key": "k", "value": {"stringValue": "x"}}]
        }));
        let adapter = adapter(&m, Some(&resource), Some(&scope));
        let g = |sel| adapter.get_field(&sel).map(Cow::into_owned);
        assert_eq!(
            g(MetricFieldSelector::ResourceAttribute(vec![
                "service.name".to_string()
            ])),
            Some("api".to_string()),
        );
        assert_eq!(
            g(MetricFieldSelector::ScopeAttribute(vec!["k".to_string()])),
            Some("x".to_string()),
        );
        assert_eq!(
            g(MetricFieldSelector::Simple(MetricField::ScopeName)),
            Some("lib".to_string()),
        );
        assert_eq!(
            g(MetricFieldSelector::Simple(MetricField::ScopeVersion)),
            Some("1.2".to_string()),
        );
    }
}
