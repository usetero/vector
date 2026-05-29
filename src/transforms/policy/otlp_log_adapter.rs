//! OTLP envelope adapter for the `policy` transform.
//!
//! When the transform runs in `mode: otel`, each incoming Vector event is
//! treated as an OTLP envelope (`{ resourceLogs: [...] }`) emitted by
//! Vector's `opentelemetry` source with `use_otlp_decoding.logs = true`.
//! This module iterates every `logRecord` inside the envelope, evaluates
//! it through `policy-rs` via [`OtlpLogAdapter`], filters in place, and
//! prunes empty `scopeLogs` / `resourceLogs` entries.
//!
//! The adapter mirrors the conformance reference adapter
//! (`policy-conformance/runners/rs/src/eval.rs`) so behaviour matches the
//! spec exactly:
//!
//! * Field names are camelCase per the proto3 JSON mapping
//!   (`severityText`, not `severity_text`).
//! * `body` is an OTLP `AnyValue`; only a non-empty `stringValue` is
//!   matchable. Non-string variants (`intValue`, `boolValue`, …) are not
//!   coerced to strings for matching, so a regex redact targeting a string
//!   never mutates them.
//! * Simple string fields (`severityText`, `traceId`, `spanId`,
//!   `eventName`, schema URLs) treat the empty string as absent.
//! * `traceId` / `spanId` arrive already hex-encoded (the OTLP decoder
//!   normalizes the raw `bytes` to canonical OTLP/JSON hex), so they are
//!   plain strings here.
//! * Attributes are arrays of `{ key, value: AnyValue }`. Multi-segment
//!   selectors (`["http", "method"]`) walk nested `kvlistValue` entries.
//! * Resource and scope attributes are mutable: the envelope iteration
//!   lends the adapter `&mut` access to the parent `resource` / `scope`
//!   objects, so add / redact / remove / rename on
//!   `ResourceAttribute` / `ScopeAttribute` selectors mutate them in place.

use std::borrow::Cow;

use policy_rs::proto::tero::policy::v1::LogField;
use policy_rs::{
    EvaluateResult, LogFieldSelector, Matchable, PolicyEngine, PolicySnapshot, Transformable,
    engine::LogSignal,
};
use vector_lib::event::{LogEvent, ObjectMap, Value};

use super::internal_events::{DropCounts, DropReason, EvalErrors};
use super::otlp_common::{
    any_value_string, attribute_exists_path, attribute_key_eq, find_attribute_path, lift_child,
    non_empty, reattach_child,
};

/// Iterate every record inside an OTLP envelope event, applying policies
/// per-record. Returns `Some(log)` to forward (with mutated and possibly
/// pruned contents), or `None` if every record was filtered out and the
/// envelope should be dropped entirely.
///
/// If the event is not envelope-shaped (no `resourceLogs` key, or it's
/// not an array), the event is forwarded unchanged so users who
/// accidentally send non-envelope events through an `otel`-mode transform
/// don't lose data silently.
pub(super) async fn evaluate_logs_envelope(
    engine: &PolicyEngine,
    snapshot: &PolicySnapshot,
    mut log: LogEvent,
) -> Option<LogEvent> {
    let Some(resource_logs) = log.get_mut("resourceLogs").and_then(Value::as_array_mut) else {
        // Not an envelope. Pass through.
        return Some(log);
    };

    let mut drops = DropCounts::default();
    let mut errors = EvalErrors::default();
    let mut i = 0;
    while i < resource_logs.len() {
        // Lift `resource`/`scope` out (a move, not a clone) so the adapter can
        // mutate them alongside the mutable borrow of the records array (the
        // borrow checker can't prove those sibling paths are disjoint). They
        // are re-attached after the records under them are processed.
        let mut resource = lift_child(&mut resource_logs[i], "resource");
        let resource_schema_url = resource_logs[i].get("schemaUrl").cloned();

        let mut prune_this_rl = false;

        if let Some(scope_logs) = resource_logs[i]
            .get_mut("scopeLogs")
            .and_then(Value::as_array_mut)
        {
            let mut j = 0;
            while j < scope_logs.len() {
                let mut scope = lift_child(&mut scope_logs[j], "scope");
                let scope_schema_url = scope_logs[j].get("schemaUrl").cloned();

                let mut prune_this_sl = false;

                if let Some(records) = scope_logs[j]
                    .get_mut("logRecords")
                    .and_then(Value::as_array_mut)
                {
                    let mut k = 0;
                    while k < records.len() {
                        let result = {
                            let mut adapter = OtlpLogAdapter {
                                log_record: &mut records[k],
                                resource: resource.as_mut(),
                                scope: scope.as_mut(),
                                resource_schema_url: resource_schema_url.as_ref(),
                                scope_schema_url: scope_schema_url.as_ref(),
                            };
                            engine.evaluate_and_transform(snapshot, &mut adapter).await
                        };

                        match result {
                            Ok(EvaluateResult::NoMatch)
                            | Ok(EvaluateResult::Keep { .. })
                            | Ok(EvaluateResult::Sample { keep: true, .. })
                            | Ok(EvaluateResult::RateLimit { allowed: true, .. }) => {
                                k += 1;
                            }
                            Ok(EvaluateResult::Drop { .. }) => {
                                records.remove(k);
                                drops.record(DropReason::PolicyDrop);
                            }
                            Ok(EvaluateResult::Sample { keep: false, .. }) => {
                                records.remove(k);
                                drops.record(DropReason::SampleRejected);
                            }
                            Ok(EvaluateResult::RateLimit { allowed: false, .. }) => {
                                records.remove(k);
                                drops.record(DropReason::RateLimited);
                            }
                            Err(error) => {
                                errors.record(&error);
                                k += 1;
                            }
                        }
                    }
                    prune_this_sl = records.is_empty();
                }

                // Re-attach scope only if the entry survives (otherwise it's
                // about to be pruned, so re-inserting would be wasted work).
                if !prune_this_sl && let Some(scope) = scope {
                    reattach_child(&mut scope_logs[j], "scope", scope);
                }

                if prune_this_sl {
                    scope_logs.remove(j);
                } else {
                    j += 1;
                }
            }
            prune_this_rl = scope_logs.is_empty();
        }

        if !prune_this_rl && let Some(resource) = resource {
            reattach_child(&mut resource_logs[i], "resource", resource);
        }

        if prune_this_rl {
            resource_logs.remove(i);
        } else {
            i += 1;
        }
    }

    drops.emit();
    errors.emit();

    if resource_logs.is_empty() {
        None
    } else {
        Some(log)
    }
}

/// Adapter exposing a single OTLP `logRecord` (plus its parent resource
/// and scope) to the `policy-rs` engine.
pub(super) struct OtlpLogAdapter<'a> {
    log_record: &'a mut Value,
    resource: Option<&'a mut Value>,
    scope: Option<&'a mut Value>,
    resource_schema_url: Option<&'a Value>,
    scope_schema_url: Option<&'a Value>,
}

impl<'a> OtlpLogAdapter<'a> {
    /// Test-only positional constructor. Production code builds the adapter
    /// with a struct literal (see `evaluate_logs_envelope`) so the four same-typed
    /// optional borrows can't be transposed silently.
    #[cfg(test)]
    pub(super) fn new(
        log_record: &'a mut Value,
        resource: Option<&'a mut Value>,
        scope: Option<&'a mut Value>,
        resource_schema_url: Option<&'a Value>,
        scope_schema_url: Option<&'a Value>,
    ) -> Self {
        Self {
            log_record,
            resource,
            scope,
            resource_schema_url,
            scope_schema_url,
        }
    }

    /// Borrow the attributes array for an attribute-namespace selector.
    fn attributes_for(&self, selector: &LogFieldSelector) -> Option<&Value> {
        match selector {
            LogFieldSelector::LogAttribute(_) => self.log_record.get("attributes"),
            LogFieldSelector::ResourceAttribute(_) => {
                self.resource.as_deref().and_then(|r| r.get("attributes"))
            }
            LogFieldSelector::ScopeAttribute(_) => {
                self.scope.as_deref().and_then(|s| s.get("attributes"))
            }
            LogFieldSelector::Simple(_) => None,
        }
    }
}

impl Matchable for OtlpLogAdapter<'_> {
    type Signal = LogSignal;

    fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            LogFieldSelector::Simple(LogField::Body) => {
                any_value_string(self.log_record.get("body"))
            }
            LogFieldSelector::Simple(LogField::SeverityText) => {
                non_empty(self.log_record.get("severityText"))
            }
            LogFieldSelector::Simple(LogField::TraceId) => {
                non_empty(self.log_record.get("traceId"))
            }
            LogFieldSelector::Simple(LogField::SpanId) => non_empty(self.log_record.get("spanId")),
            LogFieldSelector::Simple(LogField::EventName) => {
                non_empty(self.log_record.get("eventName"))
            }
            LogFieldSelector::Simple(LogField::ResourceSchemaUrl) => {
                non_empty(self.resource_schema_url)
            }
            LogFieldSelector::Simple(LogField::ScopeSchemaUrl) => non_empty(self.scope_schema_url),
            LogFieldSelector::Simple(LogField::Unspecified) => None,
            LogFieldSelector::LogAttribute(path)
            | LogFieldSelector::ResourceAttribute(path)
            | LogFieldSelector::ScopeAttribute(path) => {
                find_attribute_path(self.attributes_for(field), path)
            }
        }
    }

    fn field_exists(&self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(LogField::Body) => {
                log_body_present(self.log_record.get("body"))
            }
            LogFieldSelector::Simple(LogField::Unspecified) => false,
            LogFieldSelector::Simple(_) => self.get_field(field).is_some(),
            LogFieldSelector::LogAttribute(path)
            | LogFieldSelector::ResourceAttribute(path)
            | LogFieldSelector::ScopeAttribute(path) => {
                attribute_exists_path(self.attributes_for(field), path)
            }
        }
    }
}

impl Transformable for OtlpLogAdapter<'_> {
    fn set_field(&mut self, field: &LogFieldSelector, value: &str) {
        match field {
            LogFieldSelector::Simple(LogField::Body) => {
                if let Some(obj) = self.log_record.as_object_mut() {
                    obj.insert("body".into(), make_string_any_value(value));
                }
            }
            LogFieldSelector::Simple(LogField::SeverityText) => {
                insert_simple_string(self.log_record, "severityText", value);
            }
            LogFieldSelector::Simple(LogField::TraceId) => {
                insert_simple_string(self.log_record, "traceId", value);
            }
            LogFieldSelector::Simple(LogField::SpanId) => {
                insert_simple_string(self.log_record, "spanId", value);
            }
            LogFieldSelector::Simple(LogField::EventName) => {
                insert_simple_string(self.log_record, "eventName", value);
            }
            // Schema URLs / unspecified have no log-record-local storage.
            LogFieldSelector::Simple(_) => {}
            LogFieldSelector::LogAttribute(path) => {
                if let Some(attrs) = ensure_attributes(self.log_record) {
                    set_string_attr(attrs, path, value);
                }
            }
            LogFieldSelector::ResourceAttribute(path) => {
                if let Some(resource) = self.resource.as_deref_mut()
                    && let Some(attrs) = ensure_attributes(resource)
                {
                    set_string_attr(attrs, path, value);
                }
            }
            LogFieldSelector::ScopeAttribute(path) => {
                if let Some(scope) = self.scope.as_deref_mut()
                    && let Some(attrs) = ensure_attributes(scope)
                {
                    set_string_attr(attrs, path, value);
                }
            }
        }
    }

    fn delete_field(&mut self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(LogField::Body) => remove_key(self.log_record, "body"),
            LogFieldSelector::Simple(LogField::SeverityText) => {
                remove_key(self.log_record, "severityText")
            }
            LogFieldSelector::Simple(LogField::TraceId) => remove_key(self.log_record, "traceId"),
            LogFieldSelector::Simple(LogField::SpanId) => remove_key(self.log_record, "spanId"),
            LogFieldSelector::Simple(LogField::EventName) => {
                remove_key(self.log_record, "eventName")
            }
            LogFieldSelector::Simple(_) => false,
            LogFieldSelector::LogAttribute(path) => attributes_of_mut(self.log_record)
                .map(|attrs| remove_attr(attrs, path))
                .unwrap_or(false),
            LogFieldSelector::ResourceAttribute(path) => self
                .resource
                .as_deref_mut()
                .and_then(attributes_of_mut)
                .map(|attrs| remove_attr(attrs, path))
                .unwrap_or(false),
            LogFieldSelector::ScopeAttribute(path) => self
                .scope
                .as_deref_mut()
                .and_then(attributes_of_mut)
                .map(|attrs| remove_attr(attrs, path))
                .unwrap_or(false),
        }
    }

    fn move_field(&mut self, from: &LogFieldSelector, to: &LogFieldSelector) {
        // The engine guarantees `from` exists. Remove the underlying
        // `{key, value}` entry (preserving the OTel value type) and re-insert
        // it under `to`'s key in `to`'s namespace, overwriting any existing
        // entry there (upsert semantics, matching the reference adapter).
        let source = match from {
            LogFieldSelector::LogAttribute(path) => {
                attributes_of_mut(self.log_record).and_then(|attrs| remove_attr_kv(attrs, path))
            }
            LogFieldSelector::ResourceAttribute(path) => self
                .resource
                .as_deref_mut()
                .and_then(attributes_of_mut)
                .and_then(|attrs| remove_attr_kv(attrs, path)),
            LogFieldSelector::ScopeAttribute(path) => self
                .scope
                .as_deref_mut()
                .and_then(attributes_of_mut)
                .and_then(|attrs| remove_attr_kv(attrs, path)),
            LogFieldSelector::Simple(_) => None,
        };
        let Some(mut entry) = source else {
            return;
        };

        let target_key = match to {
            LogFieldSelector::LogAttribute(path)
            | LogFieldSelector::ResourceAttribute(path)
            | LogFieldSelector::ScopeAttribute(path) => path.first().cloned(),
            LogFieldSelector::Simple(_) => None,
        };
        let Some(key) = target_key else {
            return;
        };
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("key".into(), Value::from(key.clone()));
        }

        match to {
            LogFieldSelector::LogAttribute(_) => {
                if let Some(attrs) = ensure_attributes(self.log_record) {
                    upsert_entry(attrs, &key, entry);
                }
            }
            LogFieldSelector::ResourceAttribute(_) => {
                if let Some(resource) = self.resource.as_deref_mut()
                    && let Some(attrs) = ensure_attributes(resource)
                {
                    upsert_entry(attrs, &key, entry);
                }
            }
            LogFieldSelector::ScopeAttribute(_) => {
                if let Some(scope) = self.scope.as_deref_mut()
                    && let Some(attrs) = ensure_attributes(scope)
                {
                    upsert_entry(attrs, &key, entry);
                }
            }
            LogFieldSelector::Simple(_) => {}
        }
    }
}

// =============================================================================
// Log-record `body` presence (log-specific `AnyValue` semantics).
// =============================================================================

/// Presence semantics for the `body` field: an empty `stringValue` counts as
/// missing, but any other present variant counts as present.
fn log_body_present(value: Option<&Value>) -> bool {
    let Some(obj) = value.and_then(Value::as_object) else {
        return false;
    };
    if let Some(s) = obj.get("stringValue").and_then(Value::as_str) {
        return !s.is_empty();
    }
    [
        "boolValue",
        "intValue",
        "doubleValue",
        "arrayValue",
        "kvlistValue",
        "bytesValue",
    ]
    .iter()
    .any(|k| obj.get(*k).is_some())
}

// =============================================================================
// Attribute mutation.
// =============================================================================

/// Set or overwrite the first-segment attribute key with a string value.
fn set_string_attr(attrs: &mut Vec<Value>, path: &[String], value: &str) {
    let Some(key) = path.first() else {
        return;
    };
    if let Some(entry) = attrs.iter_mut().find(|kv| attribute_key_eq(kv, key)) {
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("value".into(), make_string_any_value(value));
        }
        return;
    }
    attrs.push(make_attribute_entry(key, make_string_any_value(value)));
}

/// Remove the first-segment attribute key. Returns whether anything was removed.
fn remove_attr(attrs: &mut Vec<Value>, path: &[String]) -> bool {
    let Some(key) = path.first() else {
        return false;
    };
    let before = attrs.len();
    attrs.retain(|kv| !attribute_key_eq(kv, key));
    attrs.len() < before
}

/// Remove and return the first-segment attribute entry, preserving its value.
fn remove_attr_kv(attrs: &mut Vec<Value>, path: &[String]) -> Option<Value> {
    let key = path.first()?;
    let idx = attrs.iter().position(|kv| attribute_key_eq(kv, key))?;
    Some(attrs.remove(idx))
}

/// Insert an entry under `key`, removing any existing entry with that key first.
fn upsert_entry(attrs: &mut Vec<Value>, key: &str, entry: Value) {
    attrs.retain(|kv| !attribute_key_eq(kv, key));
    attrs.push(entry);
}

// =============================================================================
// Value construction.
// =============================================================================

/// Build an `AnyValue` object wrapping a string.
fn make_string_any_value(value: &str) -> Value {
    let mut obj = ObjectMap::new();
    obj.insert("stringValue".into(), Value::from(value.to_string()));
    Value::Object(obj)
}

/// Build a single OTLP attribute entry `{ key, value }`.
fn make_attribute_entry(key: &str, value: Value) -> Value {
    let mut obj = ObjectMap::new();
    obj.insert("key".into(), Value::from(key.to_string()));
    obj.insert("value".into(), value);
    Value::Object(obj)
}

/// Get-or-create the `attributes` array of a record / resource / scope.
fn ensure_attributes(parent: &mut Value) -> Option<&mut Vec<Value>> {
    let obj = parent.as_object_mut()?;
    if !matches!(obj.get("attributes"), Some(Value::Array(_))) {
        obj.insert("attributes".into(), Value::Array(Vec::new()));
    }
    obj.get_mut("attributes").and_then(Value::as_array_mut)
}

/// Borrow the existing `attributes` array, if present.
fn attributes_of_mut(parent: &mut Value) -> Option<&mut Vec<Value>> {
    parent
        .as_object_mut()
        .and_then(|o| o.get_mut("attributes"))
        .and_then(Value::as_array_mut)
}

fn remove_key(record: &mut Value, key: &str) -> bool {
    match record.as_object_mut() {
        Some(obj) => obj.remove(key).is_some(),
        None => false,
    }
}

fn insert_simple_string(record: &mut Value, key: &str, value: &str) {
    if let Some(obj) = record.as_object_mut() {
        obj.insert(key.into(), Value::from(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_int(v: i64) -> Value {
        let mut obj = ObjectMap::new();
        obj.insert("intValue".into(), Value::Integer(v));
        Value::Object(obj)
    }

    fn record_with_attr(attr_key: &str, attr_val: Value) -> Value {
        let mut record = ObjectMap::new();
        record.insert("body".into(), make_string_any_value("hi"));
        record.insert("severityText".into(), Value::from("INFO".to_string()));
        record.insert(
            "attributes".into(),
            Value::Array(vec![make_attribute_entry(attr_key, attr_val)]),
        );
        Value::Object(record)
    }

    fn obj_with_attrs(pairs: Vec<(&str, Value)>) -> Value {
        let mut o = ObjectMap::new();
        o.insert(
            "attributes".into(),
            Value::Array(
                pairs
                    .into_iter()
                    .map(|(k, v)| make_attribute_entry(k, v))
                    .collect(),
            ),
        );
        Value::Object(o)
    }

    fn get(adapter: &OtlpLogAdapter, sel: LogFieldSelector) -> Option<String> {
        adapter.get_field(&sel).map(|c| c.into_owned())
    }

    #[test]
    fn matches_string_attribute() {
        let mut record = record_with_attr("user_id", make_string_any_value("42"));
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            get(
                &adapter,
                LogFieldSelector::LogAttribute(vec!["user_id".into()])
            ),
            Some("42".to_string())
        );
    }

    #[test]
    fn int_attribute_is_not_matchable_but_exists() {
        let mut record = record_with_attr("count", any_int(42));
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        // get_field must return None (not "42") so a regex redact won't fire.
        assert_eq!(
            get(
                &adapter,
                LogFieldSelector::LogAttribute(vec!["count".into()])
            ),
            None
        );
        // but exists: true must still match.
        assert!(adapter.field_exists(&LogFieldSelector::LogAttribute(vec!["count".into()])));
    }

    #[test]
    fn empty_string_simple_field_is_absent() {
        let mut record = ObjectMap::new();
        record.insert("spanId".into(), Value::from(String::new()));
        record.insert("severityText".into(), Value::from("INFO".to_string()));
        let mut record = Value::Object(record);
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert!(!adapter.field_exists(&LogFieldSelector::Simple(LogField::SpanId)));
        assert!(adapter.field_exists(&LogFieldSelector::Simple(LogField::SeverityText)));
    }

    #[test]
    fn hex_span_id_is_matched_verbatim() {
        let mut record = ObjectMap::new();
        record.insert("spanId".into(), Value::from("7370616e30303031".to_string()));
        let mut record = Value::Object(record);
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            get(&adapter, LogFieldSelector::Simple(LogField::SpanId)),
            Some("7370616e30303031".to_string())
        );
    }

    #[test]
    fn body_present_only_when_non_empty() {
        // Missing body.
        let mut record = Value::Object(ObjectMap::new());
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert!(!adapter.field_exists(&LogFieldSelector::Simple(LogField::Body)));

        // Empty AnyValue (body: {}) counts as missing.
        let mut record = ObjectMap::new();
        record.insert("body".into(), Value::Object(ObjectMap::new()));
        let mut record = Value::Object(record);
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert!(!adapter.field_exists(&LogFieldSelector::Simple(LogField::Body)));
    }

    #[test]
    fn add_body_when_missing() {
        let mut record = Value::Object(ObjectMap::new());
        {
            let mut adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
            adapter.set_field(
                &LogFieldSelector::Simple(LogField::Body),
                "[no body provided]",
            );
        }
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            get(&adapter, LogFieldSelector::Simple(LogField::Body)),
            Some("[no body provided]".to_string())
        );
    }

    #[test]
    fn walks_nested_kvlist() {
        let mut inner = ObjectMap::new();
        inner.insert(
            "values".into(),
            Value::Array(vec![make_attribute_entry(
                "method",
                make_string_any_value("GET"),
            )]),
        );
        let mut http_val = ObjectMap::new();
        http_val.insert("kvlistValue".into(), Value::Object(inner));
        let mut record = record_with_attr("http", Value::Object(http_val));
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            get(
                &adapter,
                LogFieldSelector::LogAttribute(vec!["http".into(), "method".into()])
            ),
            Some("GET".to_string())
        );
        assert!(adapter.field_exists(&LogFieldSelector::LogAttribute(vec![
            "http".into(),
            "method".into()
        ])));
    }

    #[test]
    fn resource_attribute_is_mutable() {
        let mut record = record_with_attr("noise", make_string_any_value("v"));
        let mut resource = obj_with_attrs(vec![("existing", make_string_any_value("x"))]);
        {
            let mut adapter =
                OtlpLogAdapter::new(&mut record, Some(&mut resource), None, None, None);
            adapter.set_field(
                &LogFieldSelector::ResourceAttribute(vec!["processed_by".into()]),
                "policy",
            );
        }
        let adapter = OtlpLogAdapter::new(&mut record, Some(&mut resource), None, None, None);
        assert_eq!(
            get(
                &adapter,
                LogFieldSelector::ResourceAttribute(vec!["processed_by".into()])
            ),
            Some("policy".to_string())
        );
    }

    #[test]
    fn scope_attribute_remove_and_rename() {
        let mut record = record_with_attr("noise", make_string_any_value("v"));
        let mut scope = obj_with_attrs(vec![
            ("secret", make_string_any_value("abc")),
            ("old", make_string_any_value("val")),
        ]);
        {
            let mut adapter = OtlpLogAdapter::new(&mut record, None, Some(&mut scope), None, None);
            assert!(adapter.delete_field(&LogFieldSelector::ScopeAttribute(vec!["secret".into()])));
            adapter.move_field(
                &LogFieldSelector::ScopeAttribute(vec!["old".into()]),
                &LogFieldSelector::ScopeAttribute(vec!["new".into()]),
            );
        }
        let adapter = OtlpLogAdapter::new(&mut record, None, Some(&mut scope), None, None);
        assert!(
            get(
                &adapter,
                LogFieldSelector::ScopeAttribute(vec!["secret".into()])
            )
            .is_none()
        );
        assert!(
            get(
                &adapter,
                LogFieldSelector::ScopeAttribute(vec!["old".into()])
            )
            .is_none()
        );
        assert_eq!(
            get(
                &adapter,
                LogFieldSelector::ScopeAttribute(vec!["new".into()])
            ),
            Some("val".to_string())
        );
    }

    #[test]
    fn redact_regex_skips_non_string_value() {
        // Mirrors logs_transform_redact_regex_non_string_value: an intValue
        // attribute must be left untouched because get_field returns None.
        let mut record = record_with_attr("count", any_int(42));
        {
            let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
            // The engine reads the value first; None means redact is skipped.
            assert!(
                adapter
                    .get_field(&LogFieldSelector::LogAttribute(vec!["count".into()]))
                    .is_none()
            );
        }
        // The underlying intValue is still present and unchanged.
        let count = record
            .get("attributes")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|kv| kv.as_object())
            .and_then(|o| o.get("value"))
            .and_then(Value::as_object)
            .and_then(|o| o.get("intValue"))
            .cloned();
        assert_eq!(count, Some(Value::Integer(42)));
    }
}
