//! OTLP envelope adapter for the `policy` transform.
//!
//! When the transform runs in `mode: otel`, each incoming Vector event is
//! treated as an OTLP envelope (`{ resourceLogs: [...] }`) emitted by
//! Vector's `opentelemetry` source with `use_otlp_decoding.logs = true`.
//! This module iterates every `logRecord` inside the envelope, evaluates
//! it through `policy-rs` via [`OtlpLogAdapter`], filters in place, and
//! prunes empty `scopeLogs` / `resourceLogs` entries.
//!
//! Differences from [`super::adapter::VectorLogAdapter`]:
//!
//! * Field names are camelCase per the proto3 JSON mapping
//!   (`severityText`, not `severity_text`).
//! * `body` is an OTLP `AnyValue`, so `body.stringValue` (and other
//!   variants) is the real path to the value.
//! * Attributes are always arrays of `{ key, value: AnyValue }` — not
//!   key-value maps. Lookup is a linear scan by key.
//! * Resource and scope are read-only in this mode: mutating cloned
//!   siblings would not affect the underlying envelope, so
//!   `set_field` / `delete_field` / `move_field` on
//!   `ResourceAttribute` / `ScopeAttribute` selectors are no-ops. We
//!   can lift this restriction later by restructuring the iteration if
//!   real users need it.
//! * Multi-segment `LogAttribute(["http", "method"])` paths are
//!   dot-joined and looked up as the single OTel key `"http.method"`.
//!   Walking `kvlistValue` for true nesting is a future extension.

use std::borrow::Cow;

use policy_rs::proto::tero::policy::v1::LogField;
use policy_rs::{
    EvaluateResult, LogFieldSelector, Matchable, PolicyEngine, PolicySnapshot, Transformable,
    engine::LogSignal,
};
use vector_lib::event::{LogEvent, ObjectMap, Value};

use super::internal_events::{DropReason, emit_dropped};

/// Iterate every record inside an OTLP envelope event, applying policies
/// per-record. Returns `Some(log)` to forward (with mutated and possibly
/// pruned contents), or `None` if every record was filtered out and the
/// envelope should be dropped entirely.
///
/// If the event is not envelope-shaped (no `resourceLogs` key, or it's
/// not an array), the event is forwarded unchanged so users who
/// accidentally send non-envelope events through an `otel`-mode transform
/// don't lose data silently.
pub(super) async fn evaluate_envelope(
    engine: &PolicyEngine,
    snapshot: &PolicySnapshot,
    mut log: LogEvent,
) -> Option<LogEvent> {
    let Some(resource_logs) = log.get_mut("resourceLogs").and_then(Value::as_array_mut) else {
        // Not an envelope. Pass through.
        return Some(log);
    };

    let mut i = 0;
    while i < resource_logs.len() {
        // Clone the resource sub-object and the resourceLogs entry's
        // schemaUrl so the adapter can hold immutable refs to them without
        // aliasing the mutable borrow we'll take of `scopeLogs` below.
        let resource = resource_logs[i].get("resource").cloned();
        let resource_schema_url = resource_logs[i].get("schemaUrl").cloned();

        let mut prune_this_rl = false;

        if let Some(scope_logs) = resource_logs[i]
            .get_mut("scopeLogs")
            .and_then(Value::as_array_mut)
        {
            let mut j = 0;
            while j < scope_logs.len() {
                let scope = scope_logs[j].get("scope").cloned();
                let scope_schema_url = scope_logs[j].get("schemaUrl").cloned();

                let mut prune_this_sl = false;

                if let Some(records) = scope_logs[j]
                    .get_mut("logRecords")
                    .and_then(Value::as_array_mut)
                {
                    let mut k = 0;
                    while k < records.len() {
                        let result = {
                            let mut adapter = OtlpLogAdapter::new(
                                &mut records[k],
                                resource.as_ref(),
                                scope.as_ref(),
                                resource_schema_url.as_ref(),
                                scope_schema_url.as_ref(),
                            );
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
                                emit_dropped(DropReason::PolicyDrop);
                            }
                            Ok(EvaluateResult::Sample { keep: false, .. }) => {
                                records.remove(k);
                                emit_dropped(DropReason::SampleRejected);
                            }
                            Ok(EvaluateResult::RateLimit { allowed: false, .. }) => {
                                records.remove(k);
                                emit_dropped(DropReason::RateLimited);
                            }
                            Err(error) => {
                                error!(
                                    message = "Policy evaluation failed; OTLP record passed through unchanged.",
                                    %error,
                                );
                                k += 1;
                            }
                        }
                    }
                    prune_this_sl = records.is_empty();
                }

                if prune_this_sl {
                    scope_logs.remove(j);
                } else {
                    j += 1;
                }
            }
            prune_this_rl = scope_logs.is_empty();
        }

        if prune_this_rl {
            resource_logs.remove(i);
        } else {
            i += 1;
        }
    }

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
    resource: Option<&'a Value>,
    scope: Option<&'a Value>,
    resource_schema_url: Option<&'a Value>,
    scope_schema_url: Option<&'a Value>,
}

impl<'a> OtlpLogAdapter<'a> {
    pub(super) const fn new(
        log_record: &'a mut Value,
        resource: Option<&'a Value>,
        scope: Option<&'a Value>,
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

    /// Look up the value at a simple-field selector for reads. Returns the
    /// `&Value` (still wrapped) so callers can choose between
    /// stringification (for `get_field`) and presence-only checks (for
    /// `field_exists`).
    fn simple_value(&self, field: LogField) -> Option<&Value> {
        match field {
            LogField::Body => self.log_record.get("body"),
            LogField::SeverityText => self.log_record.get("severityText"),
            LogField::TraceId => self.log_record.get("traceId"),
            LogField::SpanId => self.log_record.get("spanId"),
            LogField::EventName => self.log_record.get("eventName"),
            LogField::ResourceSchemaUrl => self.resource_schema_url,
            LogField::ScopeSchemaUrl => self.scope_schema_url,
            LogField::Unspecified => None,
        }
    }

    /// Look up the attributes array for an attribute-namespace selector.
    fn attributes_for(&self, selector: &LogFieldSelector) -> Option<&Value> {
        match selector {
            LogFieldSelector::LogAttribute(_) => self.log_record.get("attributes"),
            LogFieldSelector::ResourceAttribute(_) => {
                self.resource.and_then(|r| r.get("attributes"))
            }
            LogFieldSelector::ScopeAttribute(_) => self.scope.and_then(|s| s.get("attributes")),
            LogFieldSelector::Simple(_) => None,
        }
    }
}

impl Matchable for OtlpLogAdapter<'_> {
    type Signal = LogSignal;

    fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            LogFieldSelector::Simple(LogField::Body) => {
                self.log_record.get("body").and_then(any_value_to_string)
            }
            LogFieldSelector::Simple(simple) => {
                self.simple_value(*simple).and_then(plain_value_to_string)
            }
            LogFieldSelector::LogAttribute(path)
            | LogFieldSelector::ResourceAttribute(path)
            | LogFieldSelector::ScopeAttribute(path) => {
                let attrs = self.attributes_for(field)?;
                find_attribute_value(attrs, &join_path(path))
            }
        }
    }

    fn field_exists(&self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(LogField::Unspecified) => false,
            LogFieldSelector::Simple(simple) => self.simple_value(*simple).is_some(),
            LogFieldSelector::LogAttribute(path)
            | LogFieldSelector::ResourceAttribute(path)
            | LogFieldSelector::ScopeAttribute(path) => match self.attributes_for(field) {
                Some(attrs) => attribute_exists(attrs, &join_path(path)),
                None => false,
            },
        }
    }
}

impl Transformable for OtlpLogAdapter<'_> {
    fn set_field(&mut self, field: &LogFieldSelector, value: &str) {
        match field {
            LogFieldSelector::Simple(LogField::Body) => {
                self.log_record.insert("body", make_string_any_value(value));
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
            // Simple fields whose backing storage isn't on the log record
            // itself (schema URLs live on the parent entries) are read-only
            // for the same reason ResourceAttribute / ScopeAttribute are:
            // we only hold immutable refs.
            LogFieldSelector::Simple(_) => {}
            LogFieldSelector::LogAttribute(path) => {
                let key = join_path(path);
                ensure_attributes_array(self.log_record);
                if let Some(attrs) = self
                    .log_record
                    .get_mut("attributes")
                    .and_then(Value::as_array_mut)
                {
                    set_attribute(attrs, &key, value);
                }
            }
            LogFieldSelector::ResourceAttribute(_) | LogFieldSelector::ScopeAttribute(_) => {
                // Read-only in OTel mode; see module docstring.
            }
        }
    }

    fn delete_field(&mut self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(LogField::Body) => self.log_record_remove("body"),
            LogFieldSelector::Simple(LogField::SeverityText) => {
                self.log_record_remove("severityText")
            }
            LogFieldSelector::Simple(LogField::TraceId) => self.log_record_remove("traceId"),
            LogFieldSelector::Simple(LogField::SpanId) => self.log_record_remove("spanId"),
            LogFieldSelector::Simple(LogField::EventName) => self.log_record_remove("eventName"),
            LogFieldSelector::Simple(_) => false,
            LogFieldSelector::LogAttribute(path) => {
                let key = join_path(path);
                self.log_record
                    .get_mut("attributes")
                    .and_then(Value::as_array_mut)
                    .map(|attrs| remove_attribute(attrs, &key))
                    .unwrap_or(false)
            }
            LogFieldSelector::ResourceAttribute(_) | LogFieldSelector::ScopeAttribute(_) => false,
        }
    }

    fn move_field(&mut self, from: &LogFieldSelector, to: &LogFieldSelector) {
        // The engine guarantees `from` exists and `to` does not. In OTel
        // mode we only support moves within the log-record's own
        // attributes array.
        let (LogFieldSelector::LogAttribute(from_path), LogFieldSelector::LogAttribute(to_path)) =
            (from, to)
        else {
            return;
        };
        let from_key = join_path(from_path);
        let to_key = join_path(to_path);
        if let Some(attrs) = self
            .log_record
            .get_mut("attributes")
            .and_then(Value::as_array_mut)
            && let Some(idx) = attribute_index(attrs, &from_key)
        {
            let entry = attrs.remove(idx);
            if let Some(value) = entry.as_object().and_then(|o| o.get("value")).cloned() {
                attrs.push(make_attribute_entry(&to_key, value));
            }
        }
    }
}

impl OtlpLogAdapter<'_> {
    fn log_record_remove(&mut self, key: &str) -> bool {
        match self.log_record.as_object_mut() {
            Some(obj) => obj.remove(key).is_some(),
            None => false,
        }
    }
}

// =============================================================================
// Value-shape helpers.
// =============================================================================

/// Coerce an OTLP `AnyValue` object to a string for matching purposes.
///
/// `AnyValue` is a oneof with seven variants (`stringValue`, `intValue`,
/// `boolValue`, `doubleValue`, `bytesValue`, `arrayValue`, `kvlistValue`).
/// Scalar variants get stringified; container/binary variants return
/// `None` because there's no canonical text form for matching.
fn any_value_to_string(value: &Value) -> Option<Cow<'_, str>> {
    let obj = value.as_object()?;
    if let Some(v) = obj.get("stringValue")
        && let Some(s) = v.as_str()
    {
        return Some(s);
    }
    if let Some(v) = obj.get("intValue")
        && let Some(i) = v.as_integer()
    {
        return Some(Cow::Owned(i.to_string()));
    }
    if let Some(v) = obj.get("boolValue")
        && let Some(b) = v.as_boolean()
    {
        return Some(Cow::Borrowed(if b { "true" } else { "false" }));
    }
    if let Some(v) = obj.get("doubleValue")
        && let Some(f) = v.as_float()
    {
        return Some(Cow::Owned(f.to_string()));
    }
    None
}

/// Coerce a plain (non-`AnyValue`) `Value` to a string for matching —
/// used for simple OTLP fields like `severityText`, `traceId`, `spanId`,
/// which are flat strings rather than wrapped `AnyValue` objects.
fn plain_value_to_string(value: &Value) -> Option<Cow<'_, str>> {
    match value {
        Value::Bytes(_) => value.as_str(),
        Value::Integer(i) => Some(Cow::Owned(i.to_string())),
        Value::Float(f) => Some(Cow::Owned(f.to_string())),
        Value::Boolean(b) => Some(Cow::Borrowed(if *b { "true" } else { "false" })),
        _ => None,
    }
}

/// Linear scan of an OTLP attributes array for the entry whose key
/// matches.
fn find_attribute_value<'a>(attrs: &'a Value, key: &str) -> Option<Cow<'a, str>> {
    let array = attrs.as_array()?;
    for item in array {
        if attribute_key(item) == Some(key) {
            return item
                .as_object()
                .and_then(|o| o.get("value"))
                .and_then(any_value_to_string);
        }
    }
    None
}

/// Like [`find_attribute_value`] but returns whether the key exists at
/// all — used by `field_exists` so OTLP attributes with non-string
/// `AnyValue` variants (`intValue`, `boolValue`, `arrayValue`, …) still
/// satisfy `exists: true` matchers.
fn attribute_exists(attrs: &Value, key: &str) -> bool {
    attrs
        .as_array()
        .map(|array| array.iter().any(|item| attribute_key(item) == Some(key)))
        .unwrap_or(false)
}

fn attribute_index(attrs: &[Value], key: &str) -> Option<usize> {
    attrs
        .iter()
        .position(|item| attribute_key(item) == Some(key))
}

fn attribute_key(item: &Value) -> Option<&str> {
    item.as_object()
        .and_then(|o| o.get("key"))
        .and_then(|v| match v {
            Value::Bytes(b) => std::str::from_utf8(b).ok(),
            _ => None,
        })
}

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

/// Insert (or overwrite) an attribute entry by key, wrapping the value
/// as a string `AnyValue`.
fn set_attribute(attrs: &mut Vec<Value>, key: &str, value: &str) {
    let any_value = make_string_any_value(value);
    if let Some(idx) = attribute_index(attrs, key) {
        if let Some(obj) = attrs[idx].as_object_mut() {
            obj.insert("value".into(), any_value);
        }
    } else {
        attrs.push(make_attribute_entry(key, any_value));
    }
}

/// Remove an attribute entry by key. Returns whether an entry was
/// removed.
fn remove_attribute(attrs: &mut Vec<Value>, key: &str) -> bool {
    match attribute_index(attrs, key) {
        Some(idx) => {
            attrs.remove(idx);
            true
        }
        None => false,
    }
}

/// Ensure the log record has an `attributes` array — create an empty one
/// if absent so `set_attribute` has somewhere to push.
fn ensure_attributes_array(log_record: &mut Value) {
    let needs_init = log_record
        .as_object()
        .and_then(|o| o.get("attributes"))
        .map(|v| !matches!(v, Value::Array(_)))
        .unwrap_or(true);
    if needs_init && let Some(obj) = log_record.as_object_mut() {
        obj.insert("attributes".into(), Value::Array(Vec::new()));
    }
}

/// `policy-rs` attribute selectors are multi-segment paths. In OTel mode
/// we collapse them with a literal dot — the OTel convention is that
/// nested attribute keys (e.g. `"service.name"`) live as a single
/// flat key with embedded dots.
fn join_path(segments: &[String]) -> String {
    segments.join(".")
}

fn insert_simple_string(record: &mut Value, key: &str, value: &str) {
    if let Some(obj) = record.as_object_mut() {
        obj.insert(key.into(), Value::from(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a single OTLP log record `Value` with the given body and a
    /// `user_id` string attribute. Keeps the test bodies tiny.
    fn record_with_body_and_attr(body: &str, attr_key: &str, attr_val: &str) -> Value {
        let mut record = ObjectMap::new();
        record.insert("body".into(), make_string_any_value(body));
        record.insert("severityText".into(), Value::from("INFO".to_string()));
        record.insert(
            "attributes".into(),
            Value::Array(vec![make_attribute_entry(
                attr_key,
                make_string_any_value(attr_val),
            )]),
        );
        Value::Object(record)
    }

    fn resource_with_attr(key: &str, val: &str) -> Value {
        let mut resource = ObjectMap::new();
        resource.insert(
            "attributes".into(),
            Value::Array(vec![make_attribute_entry(key, make_string_any_value(val))]),
        );
        Value::Object(resource)
    }

    fn scope_with_attr(key: &str, val: &str) -> Value {
        let mut scope = ObjectMap::new();
        scope.insert("name".into(), Value::from("test".to_string()));
        scope.insert(
            "attributes".into(),
            Value::Array(vec![make_attribute_entry(key, make_string_any_value(val))]),
        );
        Value::Object(scope)
    }

    #[test]
    fn any_value_string() {
        let v = make_string_any_value("hello");
        assert_eq!(any_value_to_string(&v).as_deref(), Some("hello"));
    }

    #[test]
    fn any_value_int_stringifies() {
        let mut obj = ObjectMap::new();
        obj.insert("intValue".into(), Value::Integer(42));
        assert_eq!(
            any_value_to_string(&Value::Object(obj)).as_deref(),
            Some("42"),
        );
    }

    #[test]
    fn any_value_bool_stringifies() {
        let mut obj = ObjectMap::new();
        obj.insert("boolValue".into(), Value::Boolean(true));
        assert_eq!(
            any_value_to_string(&Value::Object(obj)).as_deref(),
            Some("true"),
        );
    }

    #[test]
    fn any_value_double_stringifies() {
        let mut obj = ObjectMap::new();
        obj.insert(
            "doubleValue".into(),
            Value::Float(ordered_float::NotNan::new(1.5).unwrap()),
        );
        assert!(matches!(
            any_value_to_string(&Value::Object(obj)).as_deref(),
            Some(s) if s.starts_with("1.5"),
        ));
    }

    #[test]
    fn any_value_array_returns_none_for_matching() {
        let mut obj = ObjectMap::new();
        obj.insert("arrayValue".into(), Value::Array(vec![]));
        assert_eq!(any_value_to_string(&Value::Object(obj)), None);
    }

    #[test]
    fn get_body_string() {
        let mut record = record_with_body_and_attr("hi", "user_id", "42");
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::Simple(LogField::Body))
                .as_deref(),
            Some("hi"),
        );
    }

    #[test]
    fn get_log_attribute_flat() {
        let mut record = record_with_body_and_attr("hi", "user_id", "42");
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]))
                .as_deref(),
            Some("42"),
        );
    }

    #[test]
    fn get_log_attribute_nested_dot_joins() {
        let mut record = record_with_body_and_attr("x", "http.method", "GET");
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec![
                    "http".to_string(),
                    "method".to_string()
                ]))
                .as_deref(),
            Some("GET"),
        );
    }

    #[test]
    fn get_resource_attribute_via_immutable_ref() {
        let mut record = record_with_body_and_attr("x", "noise", "v");
        let resource = resource_with_attr("service.name", "frontend");
        let adapter = OtlpLogAdapter::new(&mut record, Some(&resource), None, None, None);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::ResourceAttribute(vec![
                    "service.name".to_string()
                ]))
                .as_deref(),
            Some("frontend"),
        );
    }

    #[test]
    fn get_scope_attribute_via_immutable_ref() {
        let mut record = record_with_body_and_attr("x", "noise", "v");
        let scope = scope_with_attr("library", "tracer");
        let adapter = OtlpLogAdapter::new(&mut record, None, Some(&scope), None, None);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::ScopeAttribute(vec![
                    "library".to_string()
                ]))
                .as_deref(),
            Some("tracer"),
        );
    }

    #[test]
    fn get_resource_schema_url() {
        let mut record = record_with_body_and_attr("x", "noise", "v");
        let schema = Value::from("https://opentelemetry.io/schemas/1.0".to_string());
        let adapter = OtlpLogAdapter::new(&mut record, None, None, Some(&schema), None);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::Simple(LogField::ResourceSchemaUrl))
                .as_deref(),
            Some("https://opentelemetry.io/schemas/1.0"),
        );
    }

    #[test]
    fn field_exists_for_non_string_attribute() {
        // intValue attribute must satisfy exists matchers even though
        // get_field returns Some("42").
        let mut record = ObjectMap::new();
        record.insert("body".into(), make_string_any_value("x"));
        let mut attr_value = ObjectMap::new();
        attr_value.insert("intValue".into(), Value::Integer(42));
        record.insert(
            "attributes".into(),
            Value::Array(vec![make_attribute_entry(
                "count",
                Value::Object(attr_value),
            )]),
        );
        let mut record = Value::Object(record);
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert!(adapter.field_exists(&LogFieldSelector::LogAttribute(vec!["count".to_string()])));
    }

    #[test]
    fn set_attribute_overwrites_existing() {
        let mut record = record_with_body_and_attr("x", "user_id", "42");
        {
            let mut adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
            adapter.set_field(
                &LogFieldSelector::LogAttribute(vec!["user_id".to_string()]),
                "99",
            );
        }
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]))
                .as_deref(),
            Some("99"),
        );
    }

    #[test]
    fn set_attribute_creates_when_absent() {
        let mut record = ObjectMap::new();
        record.insert("body".into(), make_string_any_value("x"));
        let mut record = Value::Object(record);
        {
            let mut adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
            adapter.set_field(
                &LogFieldSelector::LogAttribute(vec!["new".to_string()]),
                "v",
            );
        }
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["new".to_string()]))
                .as_deref(),
            Some("v"),
        );
    }

    #[test]
    fn set_simple_body_replaces_any_value() {
        let mut record = record_with_body_and_attr("old", "k", "v");
        {
            let mut adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
            adapter.set_field(&LogFieldSelector::Simple(LogField::Body), "new");
        }
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::Simple(LogField::Body))
                .as_deref(),
            Some("new"),
        );
    }

    #[test]
    fn set_resource_attribute_is_noop() {
        let mut record = record_with_body_and_attr("x", "k", "v");
        let resource = resource_with_attr("a", "b");
        let resource_before = resource.clone();
        {
            let mut adapter = OtlpLogAdapter::new(&mut record, Some(&resource), None, None, None);
            adapter.set_field(
                &LogFieldSelector::ResourceAttribute(vec!["a".to_string()]),
                "ignored",
            );
        }
        assert_eq!(resource, resource_before, "resource must not be mutated");
    }

    #[test]
    fn delete_attribute_present() {
        let mut record = record_with_body_and_attr("x", "user_id", "42");
        let removed = {
            let mut adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
            adapter.delete_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]))
        };
        assert!(removed);
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]))
                .is_none(),
        );
    }

    #[test]
    fn delete_attribute_absent_returns_false() {
        let mut record = record_with_body_and_attr("x", "user_id", "42");
        let removed = {
            let mut adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
            adapter.delete_field(&LogFieldSelector::LogAttribute(vec!["other".to_string()]))
        };
        assert!(!removed);
    }

    #[test]
    fn delete_simple_body() {
        let mut record = record_with_body_and_attr("x", "k", "v");
        let removed = {
            let mut adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
            adapter.delete_field(&LogFieldSelector::Simple(LogField::Body))
        };
        assert!(removed);
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert!(
            adapter
                .get_field(&LogFieldSelector::Simple(LogField::Body))
                .is_none(),
        );
    }

    #[test]
    fn move_attribute_within_log_attributes() {
        let mut record = record_with_body_and_attr("x", "usr", "admin");
        {
            let mut adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
            adapter.move_field(
                &LogFieldSelector::LogAttribute(vec!["usr".to_string()]),
                &LogFieldSelector::LogAttribute(vec!["user_id".to_string()]),
            );
        }
        let adapter = OtlpLogAdapter::new(&mut record, None, None, None, None);
        assert!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["usr".to_string()]))
                .is_none(),
        );
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]))
                .as_deref(),
            Some("admin"),
        );
    }
}
