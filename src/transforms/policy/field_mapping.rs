//! Configurable mapping between `policy-rs` log field selectors and Vector
//! `LogEvent` paths.
//!
//! Vector's `LogEvent` is schema-less: the `policy` transform must therefore
//! be told where in each event the body, severity, attributes, etc. live.
//! Defaults follow OpenTelemetry semantic conventions so that events emitted
//! by Vector's `opentelemetry` source work out of the box.

use vector_lib::{
    configurable::configurable_component,
    lookup::lookup_v2::{ConfigValuePath, OwnedValuePath},
};

/// Maps `policy-rs` log field selectors onto paths inside a Vector `LogEvent`.
///
/// All defaults follow OpenTelemetry semantic conventions so that logs emitted
/// by the `opentelemetry` source are matched without additional configuration.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct FieldMapping {
    /// Path to the log body (`LogField::Body`). Default: `.message`.
    pub body: ConfigValuePath,

    /// Path to the severity-text field (`LogField::SeverityText`). Default: `.severity_text`.
    pub severity_text: ConfigValuePath,

    /// Path to the trace ID field (`LogField::TraceId`). Default: `.trace_id`.
    pub trace_id: ConfigValuePath,

    /// Path to the span ID field (`LogField::SpanId`). Default: `.span_id`.
    pub span_id: ConfigValuePath,

    /// Path to the event name field (`LogField::EventName`). Default: `.event_name`.
    pub event_name: ConfigValuePath,

    /// Path to the resource schema URL (`LogField::ResourceSchemaUrl`). Default: `.resource.schema_url`.
    pub resource_schema_url: ConfigValuePath,

    /// Path to the scope schema URL (`LogField::ScopeSchemaUrl`). Default: `.scope.schema_url`.
    pub scope_schema_url: ConfigValuePath,

    /// Root path for log attributes (`LogFieldSelector::LogAttribute`). Default: `.attributes`.
    ///
    /// The selector's path segments are appended below this root to form the full event path.
    pub log_attributes: ConfigValuePath,

    /// Root path for resource attributes (`LogFieldSelector::ResourceAttribute`). Default: `.resource.attributes`.
    pub resource_attributes: ConfigValuePath,

    /// Root path for scope attributes (`LogFieldSelector::ScopeAttribute`). Default: `.scope.attributes`.
    pub scope_attributes: ConfigValuePath,
}

impl Default for FieldMapping {
    fn default() -> Self {
        Self {
            body: parse("message"),
            severity_text: parse("severity_text"),
            trace_id: parse("trace_id"),
            span_id: parse("span_id"),
            event_name: parse("event_name"),
            resource_schema_url: parse("resource.schema_url"),
            scope_schema_url: parse("scope.schema_url"),
            log_attributes: parse("attributes"),
            resource_attributes: parse("resource.attributes"),
            scope_attributes: parse("scope.attributes"),
        }
    }
}

impl FieldMapping {
    /// Compose `root` with `segments`, returning a fresh `OwnedValuePath`.
    ///
    /// Used to map e.g. `LogAttribute(["http", "method"])` to
    /// `.attributes.http.method` under the default mapping.
    pub(crate) fn append_segments(root: &ConfigValuePath, segments: &[String]) -> OwnedValuePath {
        let mut path = root.0.clone();
        for segment in segments {
            path = path.with_field_appended(segment);
        }
        path
    }
}

fn parse(path: &str) -> ConfigValuePath {
    // SAFETY: the inputs here are static, fully-controlled strings. A panic
    // would be a developer error caught by the unit tests below, never a
    // runtime input.
    ConfigValuePath::try_from(path.to_string())
        .unwrap_or_else(|err| panic!("invalid default path {path:?}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_render_as_expected() {
        let m = FieldMapping::default();
        assert_eq!(String::from(m.body.clone()), "message");
        assert_eq!(String::from(m.severity_text.clone()), "severity_text");
        assert_eq!(String::from(m.trace_id.clone()), "trace_id");
        assert_eq!(String::from(m.span_id.clone()), "span_id");
        assert_eq!(String::from(m.event_name.clone()), "event_name");
        assert_eq!(
            String::from(m.resource_schema_url.clone()),
            "resource.schema_url"
        );
        assert_eq!(String::from(m.scope_schema_url.clone()), "scope.schema_url");
        assert_eq!(String::from(m.log_attributes.clone()), "attributes");
        assert_eq!(
            String::from(m.resource_attributes.clone()),
            "resource.attributes"
        );
        assert_eq!(String::from(m.scope_attributes.clone()), "scope.attributes");
    }

    #[test]
    fn append_single_segment() {
        let m = FieldMapping::default();
        let path = FieldMapping::append_segments(&m.log_attributes, &["user_id".to_string()]);
        assert_eq!(path.to_string(), "attributes.user_id");
    }

    #[test]
    fn append_nested_segments() {
        let m = FieldMapping::default();
        let path = FieldMapping::append_segments(
            &m.log_attributes,
            &["http".to_string(), "method".to_string()],
        );
        assert_eq!(path.to_string(), "attributes.http.method");
    }

    #[test]
    fn append_no_segments_returns_root() {
        let m = FieldMapping::default();
        let path = FieldMapping::append_segments(&m.resource_attributes, &[]);
        assert_eq!(path.to_string(), "resource.attributes");
    }

    #[test]
    fn segment_with_special_chars_is_quoted() {
        let m = FieldMapping::default();
        let path = FieldMapping::append_segments(&m.log_attributes, &["http.method".to_string()]);
        // The dot inside the segment must be escaped/quoted in the rendered path.
        assert_eq!(path.to_string(), "attributes.\"http.method\"");
    }

    #[test]
    fn default_round_trips_through_serde() {
        let original = FieldMapping::default();
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: FieldMapping = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
    }

    #[test]
    fn empty_object_uses_defaults() {
        let parsed: FieldMapping = serde_json::from_str("{}").expect("deserialize {}");
        assert_eq!(parsed, FieldMapping::default());
    }

    #[test]
    fn partial_override_keeps_other_defaults() {
        let parsed: FieldMapping =
            serde_json::from_str(r#"{"body":"log.body"}"#).expect("deserialize");
        assert_eq!(String::from(parsed.body), "log.body");
        // Other fields fall back to defaults.
        assert_eq!(
            String::from(parsed.severity_text),
            String::from(FieldMapping::default().severity_text)
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let result: Result<FieldMapping, _> = serde_json::from_str(r#"{"unknown":"x"}"#);
        assert!(result.is_err(), "unknown fields should be rejected");
    }
}
