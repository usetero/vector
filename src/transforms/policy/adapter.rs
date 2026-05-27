//! Adapter that exposes a Vector `LogEvent` to the `policy-rs` engine.
//!
//! `policy-rs` evaluates against types that implement its `Matchable` and
//! `Transformable` traits. Vector's `LogEvent` is schema-less, so we wrap a
//! mutable borrow alongside a [`FieldMapping`] and translate every
//! `LogFieldSelector` into an event path on the fly.
//!
//! The adapter is intentionally side-effect free outside the borrow it
//! holds: every read/write goes through `LogEvent`'s own API, so future
//! `policy-rs` versions can change their evaluation strategy without
//! requiring changes anywhere else in Vector.

use std::borrow::Cow;

use policy_rs::proto::tero::policy::v1::LogField;
use policy_rs::{LogFieldSelector, Matchable, Transformable, engine::LogSignal};
use vector_lib::{
    event::{LogEvent, Value},
    lookup::{OwnedTargetPath, OwnedValuePath, lookup_v2::ConfigValuePath},
};

use super::field_mapping::FieldMapping;

/// Wraps a mutable `LogEvent` and a `FieldMapping` so the `policy-rs` engine
/// can read and mutate it through `Matchable` and `Transformable`.
pub struct VectorLogAdapter<'a> {
    log: &'a mut LogEvent,
    mapping: &'a FieldMapping,
}

impl<'a> VectorLogAdapter<'a> {
    pub const fn new(log: &'a mut LogEvent, mapping: &'a FieldMapping) -> Self {
        Self { log, mapping }
    }

    /// Resolve a `LogFieldSelector` to the corresponding `LogEvent` path.
    ///
    /// Returns `None` for selectors that the current mapping does not
    /// represent — for example, the protobuf-default `LogField::Unspecified`
    /// variant or fields that haven't been wired up yet. The engine treats
    /// `None` as "field not present", which is the correct fail-soft
    /// behaviour for matching.
    fn path_for(&self, selector: &LogFieldSelector) -> Option<OwnedValuePath> {
        match selector {
            LogFieldSelector::Simple(field) => self.simple_path(*field),
            LogFieldSelector::LogAttribute(path) => Some(FieldMapping::append_segments(
                &self.mapping.log_attributes,
                path,
            )),
            LogFieldSelector::ResourceAttribute(path) => Some(FieldMapping::append_segments(
                &self.mapping.resource_attributes,
                path,
            )),
            LogFieldSelector::ScopeAttribute(path) => Some(FieldMapping::append_segments(
                &self.mapping.scope_attributes,
                path,
            )),
        }
    }

    fn simple_path(&self, field: LogField) -> Option<OwnedValuePath> {
        let mapped: &ConfigValuePath = match field {
            LogField::Body => &self.mapping.body,
            LogField::SeverityText => &self.mapping.severity_text,
            LogField::TraceId => &self.mapping.trace_id,
            LogField::SpanId => &self.mapping.span_id,
            LogField::EventName => &self.mapping.event_name,
            LogField::ResourceSchemaUrl => &self.mapping.resource_schema_url,
            LogField::ScopeSchemaUrl => &self.mapping.scope_schema_url,
            LogField::Unspecified => return None,
        };
        Some(mapped.0.clone())
    }
}

impl Matchable for VectorLogAdapter<'_> {
    type Signal = LogSignal;

    fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
        let path = self.path_for(field)?;
        let target = OwnedTargetPath::event(path);
        let value = self.log.get(&target)?;
        value_to_match_string(value)
    }

    fn field_exists(&self, field: &LogFieldSelector) -> bool {
        let Some(path) = self.path_for(field) else {
            return false;
        };
        let target = OwnedTargetPath::event(path);
        self.log.get(&target).is_some()
    }
}

impl Transformable for VectorLogAdapter<'_> {
    fn set_field(&mut self, field: &LogFieldSelector, value: &str) {
        if let Some(path) = self.path_for(field) {
            let target = OwnedTargetPath::event(path);
            self.log.insert(&target, value.to_string());
        }
    }

    fn delete_field(&mut self, field: &LogFieldSelector) -> bool {
        let Some(path) = self.path_for(field) else {
            return false;
        };
        let target = OwnedTargetPath::event(path);
        self.log.remove(&target).is_some()
    }

    fn move_field(&mut self, from: &LogFieldSelector, to: &LogFieldSelector) {
        // The engine guarantees `from` exists and `to` does not, so we can
        // remove from the source and unconditionally insert at the target
        // without losing data on a name collision.
        let (Some(from_path), Some(to_path)) = (self.path_for(from), self.path_for(to)) else {
            return;
        };
        let from_target = OwnedTargetPath::event(from_path);
        let to_target = OwnedTargetPath::event(to_path);
        if let Some(value) = self.log.remove(&from_target) {
            self.log.insert(&to_target, value);
        }
    }
}

/// Coerce a `LogEvent` value to a string suitable for `policy-rs` pattern
/// matching.
///
/// Strings (`Bytes` containing valid UTF-8) are borrowed; scalars are
/// stringified. Containers, timestamps, nulls, and regexes can't drive a
/// string match cleanly and return `None` — `field_exists` still reports
/// them as present so `exists: true` matchers fire correctly.
fn value_to_match_string(value: &Value) -> Option<Cow<'_, str>> {
    match value {
        Value::Bytes(bytes) => std::str::from_utf8(bytes).ok().map(Cow::Borrowed),
        Value::Integer(i) => Some(Cow::Owned(i.to_string())),
        Value::Float(f) => Some(Cow::Owned(f.to_string())),
        Value::Boolean(b) => Some(Cow::Borrowed(if *b { "true" } else { "false" })),
        Value::Timestamp(_)
        | Value::Object(_)
        | Value::Array(_)
        | Value::Regex(_)
        | Value::Null => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use policy_rs::proto::tero::policy::v1::LogField;
    use vector_lib::event::LogEvent;

    fn make_log() -> LogEvent {
        let mut log = LogEvent::default();
        log.insert("message", "hello world");
        log.insert("severity_text", "ERROR");
        log.insert("trace_id", "abc123");
        log.insert("span_id", "def456");
        log.insert("event_name", "user.login");
        log.insert(
            "resource.schema_url",
            "https://opentelemetry.io/schemas/1.0",
        );
        log.insert("scope.schema_url", "https://opentelemetry.io/schemas/1.0");
        log.insert("attributes.user_id", "42");
        log.insert("attributes.flagged", true);
        log.insert("attributes.ratio", 1.5);
        log.insert("resource.attributes.service\\.name", "frontend");
        log.insert("scope.attributes.library", "tracer");
        log
    }

    fn mapping() -> FieldMapping {
        FieldMapping::default()
    }

    // --- Matchable: get_field --------------------------------------------

    #[test]
    fn get_simple_body() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::Simple(LogField::Body))
                .as_deref(),
            Some("hello world"),
        );
    }

    #[test]
    fn get_simple_severity_text() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::Simple(LogField::SeverityText))
                .as_deref(),
            Some("ERROR"),
        );
    }

    #[test]
    fn get_simple_trace_and_span_ids() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::Simple(LogField::TraceId))
                .as_deref(),
            Some("abc123"),
        );
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::Simple(LogField::SpanId))
                .as_deref(),
            Some("def456"),
        );
    }

    #[test]
    fn get_unspecified_field_returns_none() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert_eq!(
            adapter.get_field(&LogFieldSelector::Simple(LogField::Unspecified)),
            None,
        );
    }

    #[test]
    fn get_log_attribute_flat() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]))
                .as_deref(),
            Some("42"),
        );
    }

    #[test]
    fn get_log_attribute_nested() {
        let mut log = LogEvent::default();
        log.insert("attributes.http.method", "GET");
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
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
    fn get_resource_attribute_with_dot_in_key() {
        // policy-rs surfaces OTel attributes as single-segment selectors
        // even when the OTel key contains dots (e.g. "service.name"). The
        // adapter must treat each segment literally — segments containing
        // dots are not re-parsed as dotted paths.
        //
        // Insert through a typed path that mirrors what `append_segments`
        // produces, then confirm the adapter can read it back through the
        // same selector.
        let mut log = LogEvent::default();
        let m = mapping();
        let attr_path =
            FieldMapping::append_segments(&m.resource_attributes, &["service.name".to_string()]);
        log.insert(&OwnedTargetPath::event(attr_path), "frontend");

        let adapter = VectorLogAdapter::new(&mut log, &m);
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
    fn get_scope_attribute() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
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
    fn get_integer_value_stringifies() {
        let mut log = LogEvent::default();
        log.insert("attributes.count", 42_i64);
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["count".to_string()]))
                .as_deref(),
            Some("42"),
        );
    }

    #[test]
    fn get_boolean_value_stringifies() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["flagged".to_string()]))
                .as_deref(),
            Some("true"),
        );
    }

    #[test]
    fn get_float_value_stringifies() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        let v = adapter
            .get_field(&LogFieldSelector::LogAttribute(vec!["ratio".to_string()]))
            .map(Cow::into_owned);
        // We don't pin the exact float representation — just confirm it's a string starting with "1.5".
        assert!(
            matches!(v, Some(ref s) if s.starts_with("1.5")),
            "got: {v:?}"
        );
    }

    #[test]
    fn get_timestamp_returns_none_for_matching() {
        let mut log = LogEvent::default();
        log.insert("attributes.ts", Value::Timestamp(Utc::now()));
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert_eq!(
            adapter.get_field(&LogFieldSelector::LogAttribute(vec!["ts".to_string()])),
            None,
        );
    }

    #[test]
    fn get_missing_field_returns_none() {
        let mut log = LogEvent::default();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert_eq!(
            adapter.get_field(&LogFieldSelector::Simple(LogField::Body)),
            None,
        );
    }

    // --- Matchable: field_exists -----------------------------------------

    #[test]
    fn exists_true_for_string_field() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert!(adapter.field_exists(&LogFieldSelector::Simple(LogField::Body)));
    }

    #[test]
    fn exists_true_for_non_string_field() {
        // OTel-style: integer/bool/timestamp values should still satisfy
        // `exists: true` matchers even though `get_field` returns None.
        let mut log = LogEvent::default();
        log.insert("attributes.count", 42_i64);
        log.insert("attributes.ts", Value::Timestamp(Utc::now()));
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert!(adapter.field_exists(&LogFieldSelector::LogAttribute(vec!["count".to_string()])));
        assert!(adapter.field_exists(&LogFieldSelector::LogAttribute(vec!["ts".to_string()])));
    }

    #[test]
    fn exists_false_for_missing_field() {
        let mut log = LogEvent::default();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert!(!adapter.field_exists(&LogFieldSelector::Simple(LogField::Body)));
        assert!(
            !adapter.field_exists(&LogFieldSelector::LogAttribute(vec!["missing".to_string()]))
        );
    }

    #[test]
    fn exists_false_for_unspecified() {
        let mut log = make_log();
        let m = mapping();
        let adapter = VectorLogAdapter::new(&mut log, &m);
        assert!(!adapter.field_exists(&LogFieldSelector::Simple(LogField::Unspecified)));
    }

    // --- Transformable: set_field ----------------------------------------

    #[test]
    fn set_field_creates_when_absent() {
        let mut log = LogEvent::default();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.set_field(
                &LogFieldSelector::LogAttribute(vec!["new_key".to_string()]),
                "value",
            );
        }
        assert_eq!(
            log.get("attributes.new_key").and_then(|v| v.as_str()),
            Some("value".into()),
        );
    }

    #[test]
    fn set_field_overwrites_when_present() {
        let mut log = make_log();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.set_field(&LogFieldSelector::Simple(LogField::Body), "replaced");
        }
        assert_eq!(
            log.get("message").and_then(|v| v.as_str()),
            Some("replaced".into()),
        );
    }

    #[test]
    fn set_nested_attribute_creates_intermediate_maps() {
        let mut log = LogEvent::default();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.set_field(
                &LogFieldSelector::LogAttribute(vec!["http".to_string(), "method".to_string()]),
                "POST",
            );
        }
        assert_eq!(
            log.get("attributes.http.method").and_then(|v| v.as_str()),
            Some("POST".into()),
        );
    }

    #[test]
    fn set_unspecified_is_noop() {
        let mut log = make_log();
        let snapshot_before = log.clone();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.set_field(&LogFieldSelector::Simple(LogField::Unspecified), "x");
        }
        assert_eq!(log, snapshot_before);
    }

    // --- Transformable: delete_field -------------------------------------

    #[test]
    fn delete_field_removes_present_field() {
        let mut log = make_log();
        let was_present = {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.delete_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]))
        };
        assert!(was_present);
        assert!(log.get("attributes.user_id").is_none());
    }

    #[test]
    fn delete_field_returns_false_when_absent() {
        let mut log = LogEvent::default();
        let was_present = {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.delete_field(&LogFieldSelector::LogAttribute(vec!["nope".to_string()]))
        };
        assert!(!was_present);
    }

    #[test]
    fn delete_field_returns_false_for_unspecified() {
        let mut log = make_log();
        let was_present = {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.delete_field(&LogFieldSelector::Simple(LogField::Unspecified))
        };
        assert!(!was_present);
    }

    #[test]
    fn delete_simple_body() {
        let mut log = make_log();
        let was_present = {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.delete_field(&LogFieldSelector::Simple(LogField::Body))
        };
        assert!(was_present);
        assert!(log.get("message").is_none());
    }

    // --- Transformable: move_field ---------------------------------------

    #[test]
    fn move_field_within_log_attributes() {
        let mut log = LogEvent::default();
        log.insert("attributes.usr", "admin");
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.move_field(
                &LogFieldSelector::LogAttribute(vec!["usr".to_string()]),
                &LogFieldSelector::LogAttribute(vec!["user_id".to_string()]),
            );
        }
        assert!(log.get("attributes.usr").is_none());
        assert_eq!(
            log.get("attributes.user_id").and_then(|v| v.as_str()),
            Some("admin".into()),
        );
    }

    #[test]
    fn move_field_preserves_non_string_value() {
        let mut log = LogEvent::default();
        log.insert("attributes.count", 42_i64);
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.move_field(
                &LogFieldSelector::LogAttribute(vec!["count".to_string()]),
                &LogFieldSelector::LogAttribute(vec!["renamed".to_string()]),
            );
        }
        assert!(log.get("attributes.count").is_none());
        assert_eq!(
            log.get("attributes.renamed").and_then(|v| v.as_integer()),
            Some(42),
        );
    }

    #[test]
    fn move_field_absent_source_is_noop() {
        let mut log = LogEvent::default();
        let snapshot_before = log.clone();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.move_field(
                &LogFieldSelector::LogAttribute(vec!["missing".to_string()]),
                &LogFieldSelector::LogAttribute(vec!["target".to_string()]),
            );
        }
        assert_eq!(log, snapshot_before);
    }

    #[test]
    fn move_field_unspecified_endpoints_noop() {
        let mut log = make_log();
        let snapshot_before = log.clone();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.move_field(
                &LogFieldSelector::Simple(LogField::Unspecified),
                &LogFieldSelector::LogAttribute(vec!["x".to_string()]),
            );
            adapter.move_field(
                &LogFieldSelector::LogAttribute(vec!["user_id".to_string()]),
                &LogFieldSelector::Simple(LogField::Unspecified),
            );
        }
        assert_eq!(log, snapshot_before);
    }

    // --- Custom mappings -------------------------------------------------

    #[test]
    fn custom_body_path_is_honored() {
        use vector_lib::lookup::lookup_v2::ConfigValuePath;
        let mut log = LogEvent::default();
        log.insert("log.body", "custom");
        let mapping = FieldMapping {
            body: ConfigValuePath::try_from("log.body".to_string()).unwrap(),
            ..FieldMapping::default()
        };
        let adapter = VectorLogAdapter::new(&mut log, &mapping);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::Simple(LogField::Body))
                .as_deref(),
            Some("custom"),
        );
    }

    #[test]
    fn custom_attribute_root_is_honored() {
        use vector_lib::lookup::lookup_v2::ConfigValuePath;
        let mut log = LogEvent::default();
        log.insert("data.user_id", "42");
        let mapping = FieldMapping {
            log_attributes: ConfigValuePath::try_from("data".to_string()).unwrap(),
            ..FieldMapping::default()
        };
        let adapter = VectorLogAdapter::new(&mut log, &mapping);
        assert_eq!(
            adapter
                .get_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]))
                .as_deref(),
            Some("42"),
        );
    }

    // --- Simple-field exhaustive coverage --------------------------------
    //
    // Every `LogField` variant goes through the same `simple_path` table.
    // The cases below confirm get/set/delete behave consistently across
    // every variant we expose (Body and SeverityText already had bespoke
    // tests; these round out the rest).

    /// One get/delete/set cycle for a simple field. Helper rather than
    /// per-variant duplication so future `LogField` additions just append a
    /// caller below.
    fn assert_simple_round_trip(field: LogField, event_path: &str) {
        let m = mapping();

        // get
        let mut log = LogEvent::default();
        log.insert(event_path, "initial");
        {
            let adapter = VectorLogAdapter::new(&mut log, &m);
            assert_eq!(
                adapter
                    .get_field(&LogFieldSelector::Simple(field))
                    .as_deref(),
                Some("initial"),
                "get failed for {field:?} at {event_path:?}",
            );
        }

        // delete
        let was_present = {
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.delete_field(&LogFieldSelector::Simple(field))
        };
        assert!(was_present, "delete returned false for {field:?}");
        assert!(
            log.get(event_path).is_none(),
            "delete left {event_path:?} present for {field:?}",
        );

        // set
        {
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.set_field(&LogFieldSelector::Simple(field), "after-set");
        }
        assert_eq!(
            log.get(event_path).and_then(|v| v.as_str()),
            Some("after-set".into()),
            "set didn't insert at {event_path:?} for {field:?}",
        );
    }

    #[test]
    fn round_trip_simple_body() {
        assert_simple_round_trip(LogField::Body, "message");
    }

    #[test]
    fn round_trip_simple_severity_text() {
        assert_simple_round_trip(LogField::SeverityText, "severity_text");
    }

    #[test]
    fn round_trip_simple_trace_id() {
        assert_simple_round_trip(LogField::TraceId, "trace_id");
    }

    #[test]
    fn round_trip_simple_span_id() {
        assert_simple_round_trip(LogField::SpanId, "span_id");
    }

    #[test]
    fn round_trip_simple_event_name() {
        assert_simple_round_trip(LogField::EventName, "event_name");
    }

    #[test]
    fn round_trip_simple_resource_schema_url() {
        assert_simple_round_trip(LogField::ResourceSchemaUrl, "resource.schema_url");
    }

    #[test]
    fn round_trip_simple_scope_schema_url() {
        assert_simple_round_trip(LogField::ScopeSchemaUrl, "scope.schema_url");
    }

    // --- Resource / scope attribute Transformable coverage ---------------
    //
    // `LogAttribute` is already covered in detail. These mirror the same
    // operations for the resource and scope namespaces so the namespace
    // dispatch in `path_for` is exercised end-to-end.

    #[test]
    fn set_resource_attribute_flat() {
        let mut log = LogEvent::default();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.set_field(
                &LogFieldSelector::ResourceAttribute(vec!["region".to_string()]),
                "us-east-1",
            );
        }
        assert_eq!(
            log.get("resource.attributes.region")
                .and_then(|v| v.as_str()),
            Some("us-east-1".into()),
        );
    }

    #[test]
    fn set_resource_attribute_nested() {
        let mut log = LogEvent::default();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.set_field(
                &LogFieldSelector::ResourceAttribute(vec!["k8s".to_string(), "pod".to_string()]),
                "vector-0",
            );
        }
        assert_eq!(
            log.get("resource.attributes.k8s.pod")
                .and_then(|v| v.as_str()),
            Some("vector-0".into()),
        );
    }

    #[test]
    fn delete_resource_attribute() {
        let mut log = LogEvent::default();
        log.insert("resource.attributes.region", "us-east-1");
        let was_present = {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.delete_field(&LogFieldSelector::ResourceAttribute(vec![
                "region".to_string(),
            ]))
        };
        assert!(was_present);
        assert!(log.get("resource.attributes.region").is_none());
    }

    #[test]
    fn move_resource_attribute_within_namespace() {
        let mut log = LogEvent::default();
        log.insert("resource.attributes.zone", "ap-south-1a");
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.move_field(
                &LogFieldSelector::ResourceAttribute(vec!["zone".to_string()]),
                &LogFieldSelector::ResourceAttribute(vec!["availability_zone".to_string()]),
            );
        }
        assert!(log.get("resource.attributes.zone").is_none());
        assert_eq!(
            log.get("resource.attributes.availability_zone")
                .and_then(|v| v.as_str()),
            Some("ap-south-1a".into()),
        );
    }

    #[test]
    fn set_scope_attribute_flat() {
        let mut log = LogEvent::default();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.set_field(
                &LogFieldSelector::ScopeAttribute(vec!["lib_version".to_string()]),
                "1.2.3",
            );
        }
        assert_eq!(
            log.get("scope.attributes.lib_version")
                .and_then(|v| v.as_str()),
            Some("1.2.3".into()),
        );
    }

    #[test]
    fn set_scope_attribute_nested() {
        let mut log = LogEvent::default();
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.set_field(
                &LogFieldSelector::ScopeAttribute(vec!["vendor".to_string(), "name".to_string()]),
                "otel",
            );
        }
        assert_eq!(
            log.get("scope.attributes.vendor.name")
                .and_then(|v| v.as_str()),
            Some("otel".into()),
        );
    }

    #[test]
    fn delete_scope_attribute() {
        let mut log = LogEvent::default();
        log.insert("scope.attributes.lib_version", "1.2.3");
        let was_present = {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.delete_field(&LogFieldSelector::ScopeAttribute(vec![
                "lib_version".to_string(),
            ]))
        };
        assert!(was_present);
        assert!(log.get("scope.attributes.lib_version").is_none());
    }

    #[test]
    fn move_scope_attribute_within_namespace() {
        let mut log = LogEvent::default();
        log.insert("scope.attributes.legacy", "x");
        {
            let m = mapping();
            let mut adapter = VectorLogAdapter::new(&mut log, &m);
            adapter.move_field(
                &LogFieldSelector::ScopeAttribute(vec!["legacy".to_string()]),
                &LogFieldSelector::ScopeAttribute(vec!["renamed".to_string()]),
            );
        }
        assert!(log.get("scope.attributes.legacy").is_none());
        assert_eq!(
            log.get("scope.attributes.renamed").and_then(|v| v.as_str()),
            Some("x".into()),
        );
    }
}
