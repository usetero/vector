//! OTLP traces adapter for the `policy` transform (`mode: otel`).
//!
//! Vector's `opentelemetry` source decodes OTLP traces into a `Trace` event
//! shaped like `{ resourceSpans: [...] }`. This module iterates every span,
//! evaluates it through `policy-rs` (`evaluate_trace`, which applies OTel
//! consistent-probability sampling), drops filtered spans, writes the sampling
//! threshold back into the span's `traceState`, and prunes empty
//! `scopeSpans` / `resourceSpans`.
//!
//! Mirrors the conformance reference (`MutTraceContext` in
//! `policy-conformance/runners/rs/src/eval.rs`). Resource and scope are
//! read-only in trace mode; only the span (its `traceState`) is mutated.

use std::borrow::Cow;

use policy_rs::proto::tero::policy::v1::TraceField;
use policy_rs::{
    EvaluateResult, Matchable, PolicyEngine, PolicySnapshot, TraceFieldSelector, Transformable,
    engine::TraceSignal,
};
use vector_lib::event::{TraceEvent, Value};

use super::internal_events::{DropReason, emit_dropped};
use super::otlp_adapter::{attribute_exists_path, find_attribute_path, non_empty};

/// Iterate every span in an OTLP traces envelope, sampling/dropping in place.
/// Returns `true` if any span survives (forward the event), `false` if the
/// envelope is now empty and the event should be dropped.
pub(super) async fn evaluate_traces_envelope(
    engine: &PolicyEngine,
    snapshot: &PolicySnapshot,
    trace: &mut TraceEvent,
) -> bool {
    let Some(resource_spans) = trace
        .value_mut()
        .get_mut("resourceSpans")
        .and_then(Value::as_array_mut)
    else {
        // Not an envelope. Forward unchanged.
        return true;
    };

    let mut i = 0;
    while i < resource_spans.len() {
        let resource = resource_spans[i].get("resource").cloned();
        let resource_schema_url = resource_spans[i].get("schemaUrl").cloned();

        let mut prune_rs = false;

        if let Some(scope_spans) = resource_spans[i]
            .get_mut("scopeSpans")
            .and_then(Value::as_array_mut)
        {
            let mut j = 0;
            while j < scope_spans.len() {
                let scope = scope_spans[j].get("scope").cloned();
                let scope_schema_url = scope_spans[j].get("schemaUrl").cloned();

                let mut prune_ss = false;

                if let Some(spans) = scope_spans[j]
                    .get_mut("spans")
                    .and_then(Value::as_array_mut)
                {
                    let mut k = 0;
                    while k < spans.len() {
                        let result = {
                            let mut adapter = TraceAdapter {
                                span: &mut spans[k],
                                resource: resource.as_ref(),
                                scope: scope.as_ref(),
                                resource_schema_url: resource_schema_url.as_ref(),
                                scope_schema_url: scope_schema_url.as_ref(),
                            };
                            engine.evaluate_trace(snapshot, &mut adapter).await
                        };

                        let keep = match result {
                            Ok(EvaluateResult::Drop { .. }) => {
                                emit_dropped(DropReason::PolicyDrop);
                                false
                            }
                            Ok(EvaluateResult::Sample { keep: false, .. }) => {
                                emit_dropped(DropReason::SampleRejected);
                                false
                            }
                            Ok(_) => true,
                            Err(error) => {
                                error!(
                                    message = "Policy evaluation failed; OTLP span passed through unchanged.",
                                    %error,
                                );
                                true
                            }
                        };

                        if keep {
                            k += 1;
                        } else {
                            spans.remove(k);
                        }
                    }
                    prune_ss = spans.is_empty();
                }

                if prune_ss {
                    scope_spans.remove(j);
                } else {
                    j += 1;
                }
            }
            prune_rs = scope_spans.is_empty();
        }

        if prune_rs {
            resource_spans.remove(i);
        } else {
            i += 1;
        }
    }

    !resource_spans.is_empty()
}

/// Adapter exposing a single OTLP span (plus parent resource/scope) to the
/// `policy-rs` engine. The span is mutable so the engine can write the
/// sampling threshold into `traceState`; resource/scope are read-only.
struct TraceAdapter<'a> {
    span: &'a mut Value,
    resource: Option<&'a Value>,
    scope: Option<&'a Value>,
    resource_schema_url: Option<&'a Value>,
    scope_schema_url: Option<&'a Value>,
}

impl TraceAdapter<'_> {
    fn span_attributes(&self) -> Option<&Value> {
        self.span.get("attributes")
    }

    fn resource_attributes(&self) -> Option<&Value> {
        self.resource.and_then(|r| r.get("attributes"))
    }

    fn scope_attributes(&self) -> Option<&Value> {
        self.scope.and_then(|s| s.get("attributes"))
    }

    /// First non-empty span event name, used by `EventName` matchers.
    fn event_name(&self) -> Option<Cow<'_, str>> {
        let events = self.span.get("events").and_then(Value::as_array)?;
        for event in events {
            if let Some(name) = non_empty(event.as_object().and_then(|o| o.get("name"))) {
                return Some(name);
            }
        }
        None
    }

    /// Map the OTel `Status.code` enum to the policy `SPAN_STATUS_CODE_*` form.
    ///
    /// A span carries a status only if the `status` message is present. Its
    /// `code` defaults to `STATUS_CODE_UNSET` (0), which proto3 omits on the
    /// wire — so a present-but-empty `status` (or one whose `code` decoded to
    /// the default) means UNSET, not "no status". A truly absent `status`
    /// message yields `None`.
    fn span_status(&self) -> Option<Cow<'_, str>> {
        let status = self.span.get("status").and_then(Value::as_object)?;
        match status.get("code").and_then(Value::as_str).as_deref() {
            Some("STATUS_CODE_OK") => Some(Cow::Borrowed("SPAN_STATUS_CODE_OK")),
            Some("STATUS_CODE_ERROR") => Some(Cow::Borrowed("SPAN_STATUS_CODE_ERROR")),
            Some("STATUS_CODE_UNSET") | None => {
                Some(Cow::Borrowed("SPAN_STATUS_CODE_UNSPECIFIED"))
            }
            Some(_) => None,
        }
    }
}

impl Matchable for TraceAdapter<'_> {
    type Signal = TraceSignal;

    fn get_field(&self, field: &TraceFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            TraceFieldSelector::Simple(TraceField::Name) => non_empty(self.span.get("name")),
            TraceFieldSelector::Simple(TraceField::TraceId) => non_empty(self.span.get("traceId")),
            TraceFieldSelector::Simple(TraceField::SpanId) => non_empty(self.span.get("spanId")),
            TraceFieldSelector::Simple(TraceField::ParentSpanId) => {
                non_empty(self.span.get("parentSpanId"))
            }
            TraceFieldSelector::Simple(TraceField::TraceState) => {
                non_empty(self.span.get("traceState"))
            }
            TraceFieldSelector::Simple(TraceField::ScopeName) => {
                non_empty(self.scope.and_then(|s| s.get("name")))
            }
            TraceFieldSelector::Simple(TraceField::ScopeVersion) => {
                non_empty(self.scope.and_then(|s| s.get("version")))
            }
            TraceFieldSelector::Simple(TraceField::ResourceSchemaUrl) => {
                non_empty(self.resource_schema_url)
            }
            TraceFieldSelector::Simple(TraceField::ScopeSchemaUrl) => {
                non_empty(self.scope_schema_url)
            }
            TraceFieldSelector::Simple(TraceField::Unspecified) => None,
            TraceFieldSelector::SpanAttribute(path) => {
                find_attribute_path(self.span_attributes(), path)
            }
            TraceFieldSelector::ResourceAttribute(path) => {
                find_attribute_path(self.resource_attributes(), path)
            }
            TraceFieldSelector::ScopeAttribute(path) => {
                find_attribute_path(self.scope_attributes(), path)
            }
            TraceFieldSelector::SpanKind => non_empty(self.span.get("kind")),
            TraceFieldSelector::SpanStatus => self.span_status(),
            TraceFieldSelector::EventName => self.event_name(),
            // Not exercised by the conformance suite / not representable here.
            TraceFieldSelector::EventAttribute(_)
            | TraceFieldSelector::LinkTraceId
            | TraceFieldSelector::SamplingThreshold => None,
        }
    }

    fn field_exists(&self, field: &TraceFieldSelector) -> bool {
        match field {
            TraceFieldSelector::SpanAttribute(path) => {
                attribute_exists_path(self.span_attributes(), path)
            }
            TraceFieldSelector::ResourceAttribute(path) => {
                attribute_exists_path(self.resource_attributes(), path)
            }
            TraceFieldSelector::ScopeAttribute(path) => {
                attribute_exists_path(self.scope_attributes(), path)
            }
            _ => self.get_field(field).is_some(),
        }
    }
}

impl Transformable for TraceAdapter<'_> {
    fn set_field(&mut self, field: &TraceFieldSelector, value: &str) {
        if matches!(field, TraceFieldSelector::SamplingThreshold) {
            let current = self
                .span
                .get("traceState")
                .and_then(Value::as_str)
                .unwrap_or(Cow::Borrowed(""));
            let merged = merge_ot_tracestate(&current, &format!("th:{value}"));
            if let Some(obj) = self.span.as_object_mut() {
                obj.insert("traceState".into(), Value::from(merged));
            }
        }
        // Other trace transforms are not exercised by the conformance suite.
    }

    fn delete_field(&mut self, _field: &TraceFieldSelector) -> bool {
        false
    }

    fn move_field(&mut self, _from: &TraceFieldSelector, _to: &TraceFieldSelector) {}
}

/// Merge an OpenTelemetry sub-key (e.g. `"th:8000"`) into a W3C tracestate
/// string under the `ot` vendor key, replacing any existing entry with the
/// same sub-key. Ported verbatim from the conformance reference adapter.
fn merge_ot_tracestate(tracestate: &str, sub_kv: &str) -> String {
    let sub_key = sub_kv.split(':').next().unwrap_or(sub_kv);

    let mut ot_parts: Vec<&str> = Vec::new();
    let mut other_vendors: Vec<&str> = Vec::new();

    if !tracestate.is_empty() {
        for vendor in tracestate.split(',') {
            let vendor = vendor.trim();
            if vendor.is_empty() {
                continue;
            }
            if let Some(ot_value) = vendor.strip_prefix("ot=") {
                for part in ot_value.split(';') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    let part_key = part.split(':').next().unwrap_or(part);
                    if part_key != sub_key {
                        ot_parts.push(part);
                    }
                }
            } else {
                other_vendors.push(vendor);
            }
        }
    }

    let mut result = format!("ot={}", ot_parts.join(";"));
    if !ot_parts.is_empty() {
        result.push(';');
    }
    result.push_str(sub_kv);
    if !other_vendors.is_empty() {
        result.push(',');
        result.push_str(&other_vendors.join(","));
    }
    result
}
