//! Shared OTLP value helpers used by the log, metric, and trace adapters.
//!
//! These operate on the JSON-shaped `Value` tree the `opentelemetry` source
//! produces (camelCase keys, `AnyValue`-wrapped attribute values, attributes as
//! `{ key, value }` arrays). They are the read-side primitives — attribute
//! lookup, `AnyValue` coercion, and the envelope lift/prune helpers — that all
//! three signal adapters need; per-signal matching/transform logic lives in the
//! respective `otlp_*_adapter` module.

use std::borrow::Cow;

use vector_lib::event::Value;

// =============================================================================
// AnyValue coercion.
// =============================================================================

/// Coerce a plain string `Value` to a non-empty string. Empty strings count
/// as absent, matching the conformance reference adapter's `non_empty` helper.
pub(super) fn non_empty(value: Option<&Value>) -> Option<Cow<'_, str>> {
    match value?.as_str() {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Coerce an OTLP `AnyValue` to a string for matching. Only a non-empty
/// `stringValue` is matchable; all other variants (`intValue`, `boolValue`,
/// `arrayValue`, …) return `None` so string matchers and regex redaction
/// never operate on them.
pub(super) fn any_value_string(value: Option<&Value>) -> Option<Cow<'_, str>> {
    let obj = value?.as_object()?;
    match obj.get("stringValue").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Whether an `AnyValue` carries any value variant at all. Powers
/// `exists: true` matchers for attributes whose value isn't a string.
fn any_value_present(value: Option<&Value>) -> bool {
    const VARIANTS: [&str; 7] = [
        "stringValue",
        "boolValue",
        "intValue",
        "doubleValue",
        "arrayValue",
        "kvlistValue",
        "bytesValue",
    ];
    match value.and_then(Value::as_object) {
        Some(obj) => VARIANTS.iter().any(|k| obj.get(*k).is_some()),
        None => false,
    }
}

// =============================================================================
// Attribute lookup (walks nested kvlistValue).
// =============================================================================

/// Resolve an attribute path against an attributes array, walking nested
/// `kvlistValue` entries for multi-segment paths. Returns the leaf's matchable
/// string value, if any.
pub(super) fn find_attribute_path<'a>(
    attrs: Option<&'a Value>,
    path: &[String],
) -> Option<Cow<'a, str>> {
    let array = attrs?.as_array()?;
    find_in_kvlist(array, path)
}

fn find_in_kvlist<'a>(attrs: &'a [Value], path: &[String]) -> Option<Cow<'a, str>> {
    let first = path.first()?;
    for kv in attrs {
        if !attribute_key_eq(kv, first) {
            continue;
        }
        let value = kv.as_object().and_then(|o| o.get("value"));
        if path.len() == 1 {
            return any_value_string(value);
        }
        return nested_values(value).and_then(|nested| find_in_kvlist(nested, &path[1..]));
    }
    None
}

/// Whether an attribute path resolves to a present value (any `AnyValue`
/// variant), walking nested `kvlistValue` entries.
pub(super) fn attribute_exists_path(attrs: Option<&Value>, path: &[String]) -> bool {
    let Some(array) = attrs.and_then(Value::as_array) else {
        return false;
    };
    exists_in_kvlist(array, path)
}

fn exists_in_kvlist(attrs: &[Value], path: &[String]) -> bool {
    let Some(first) = path.first() else {
        return false;
    };
    for kv in attrs {
        if !attribute_key_eq(kv, first) {
            continue;
        }
        let value = kv.as_object().and_then(|o| o.get("value"));
        if path.len() == 1 {
            return any_value_present(value);
        }
        return nested_values(value)
            .map(|nested| exists_in_kvlist(nested, &path[1..]))
            .unwrap_or(false);
    }
    false
}

/// Unwrap an `AnyValue`'s `kvlistValue.values` array.
fn nested_values(value: Option<&Value>) -> Option<&[Value]> {
    value
        .and_then(Value::as_object)
        .and_then(|o| o.get("kvlistValue"))
        .and_then(Value::as_object)
        .and_then(|o| o.get("values"))
        .and_then(Value::as_array)
}

/// Whether an attribute entry's `key` equals `key`, comparing raw bytes so we
/// skip UTF-8 validation on every entry of a linear scan (the key is an OTLP
/// `string`, but for an equality test the byte representation is sufficient).
pub(super) fn attribute_key_eq(item: &Value, key: &str) -> bool {
    matches!(
        item.as_object().and_then(|o| o.get("key")),
        Some(Value::Bytes(b)) if b.as_ref() == key.as_bytes()
    )
}

// =============================================================================
// Envelope iteration helpers.
// =============================================================================

/// Remove an object child by key and return it (a move, not a clone). Used to
/// lift `resource` / `scope` out of an envelope entry so they can be borrowed
/// alongside a mutable borrow of a sibling array.
pub(super) fn lift_child(entry: &mut Value, key: &str) -> Option<Value> {
    entry.as_object_mut().and_then(|o| o.remove(key))
}

/// Re-attach a previously [`lift_child`]ed value under `key`.
pub(super) fn reattach_child(entry: &mut Value, key: &str, child: Value) {
    if let Some(obj) = entry.as_object_mut() {
        obj.insert(key.into(), child);
    }
}

/// Whether `entry`'s array field at `key` is empty or absent — i.e. the entry
/// should be pruned from its parent.
pub(super) fn array_field_is_empty(entry: &Value, key: &str) -> bool {
    entry
        .as_object()
        .and_then(|o| o.get(key))
        .and_then(Value::as_array)
        .map(|a| a.is_empty())
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(value: serde_json::Value) -> Value {
        Value::from(value)
    }

    #[test]
    fn non_empty_treats_blank_as_absent() {
        assert_eq!(non_empty(Some(&v(json!("x")))).as_deref(), Some("x"));
        assert_eq!(non_empty(Some(&v(json!("")))), None);
        assert_eq!(non_empty(None), None);
    }

    #[test]
    fn any_value_string_only_matches_non_empty_string() {
        assert_eq!(
            any_value_string(Some(&v(json!({"stringValue": "hi"})))).as_deref(),
            Some("hi"),
        );
        assert_eq!(any_value_string(Some(&v(json!({"stringValue": ""})))), None);
        assert_eq!(any_value_string(Some(&v(json!({"intValue": "42"})))), None);
        assert_eq!(any_value_string(Some(&v(json!({"boolValue": true})))), None);
        assert_eq!(any_value_string(None), None);
    }

    #[test]
    fn find_attribute_path_flat_and_nested() {
        let attrs = v(json!([
            {"key": "user_id", "value": {"stringValue": "42"}},
            {"key": "http", "value": {"kvlistValue": {"values": [
                {"key": "method", "value": {"stringValue": "GET"}}
            ]}}}
        ]));
        assert_eq!(
            find_attribute_path(Some(&attrs), &["user_id".to_string()]).as_deref(),
            Some("42"),
        );
        assert_eq!(
            find_attribute_path(Some(&attrs), &["http".to_string(), "method".to_string()])
                .as_deref(),
            Some("GET"),
        );
        // Missing top-level key, and a missing nested segment, both resolve to None.
        assert_eq!(find_attribute_path(Some(&attrs), &["nope".to_string()]), None);
        assert_eq!(
            find_attribute_path(Some(&attrs), &["http".to_string(), "nope".to_string()]),
            None,
        );
    }

    #[test]
    fn find_attribute_path_non_string_leaf_is_none() {
        let attrs = v(json!([{"key": "count", "value": {"intValue": "42"}}]));
        assert_eq!(find_attribute_path(Some(&attrs), &["count".to_string()]), None);
    }

    #[test]
    fn attribute_exists_path_covers_non_string_and_nested() {
        let attrs = v(json!([
            {"key": "count", "value": {"intValue": "42"}},
            {"key": "http", "value": {"kvlistValue": {"values": [
                {"key": "method", "value": {"stringValue": "GET"}}
            ]}}}
        ]));
        // A non-string value still satisfies `exists`.
        assert!(attribute_exists_path(Some(&attrs), &["count".to_string()]));
        assert!(attribute_exists_path(
            Some(&attrs),
            &["http".to_string(), "method".to_string()]
        ));
        assert!(!attribute_exists_path(Some(&attrs), &["missing".to_string()]));
        assert!(!attribute_exists_path(None, &["count".to_string()]));
    }

    #[test]
    fn attribute_key_eq_compares_key_bytes() {
        let kv = v(json!({"key": "service.name", "value": {"stringValue": "api"}}));
        assert!(attribute_key_eq(&kv, "service.name"));
        assert!(!attribute_key_eq(&kv, "service"));
        // Non-object entries never match.
        assert!(!attribute_key_eq(&v(json!("x")), "x"));
    }

    #[test]
    fn lift_and_reattach_round_trip() {
        let mut entry = v(json!({"resource": {"attributes": []}, "scopeLogs": []}));
        let lifted = lift_child(&mut entry, "resource").expect("resource lifted");
        assert!(entry.as_object().unwrap().get("resource").is_none());
        reattach_child(&mut entry, "resource", lifted);
        assert!(entry.as_object().unwrap().get("resource").is_some());
        // Lifting an absent child is a no-op returning None.
        assert!(lift_child(&mut entry, "missing").is_none());
    }

    #[test]
    fn array_field_is_empty_cases() {
        assert!(array_field_is_empty(&v(json!({"a": []})), "a"));
        assert!(!array_field_is_empty(&v(json!({"a": [1]})), "a"));
        // Absent field, and a present-but-not-array field, both count as empty.
        assert!(array_field_is_empty(&v(json!({})), "a"));
        assert!(array_field_is_empty(&v(json!({"a": "x"})), "a"));
    }
}
