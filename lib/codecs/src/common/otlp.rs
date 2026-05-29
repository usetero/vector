//! Shared helpers for converting OTLP trace/span identifiers between their
//! protobuf wire form (raw `bytes`) and their OTLP/JSON form (hex strings).
//!
//! The protobuf `LogRecord.trace_id` / `Span.span_id` etc. are `bytes`, but the
//! canonical OTLP/JSON representation (and what every other tool in the
//! ecosystem, including downstream policy evaluation, expects) is a lowercase
//! hex string. Vector decodes OTLP protobuf into a JSON-shaped event tree, so we
//! normalize these identifiers to hex on decode and convert them back to raw
//! bytes on encode. Keeping the in-memory representation canonical means a plain
//! JSON serializer round-trips correctly and matchers see the hex string they
//! expect.

use bytes::Bytes;
use vrl::value::Value;

/// OTLP identifier fields (proto3 JSON camelCase) that are `bytes` on the wire
/// but hex strings in OTLP/JSON.
const ID_FIELDS: [&str; 3] = ["traceId", "spanId", "parentSpanId"];

/// Recursively hex-encode every OTLP id field carried as raw bytes. Called
/// after decoding OTLP protobuf so the event tree holds canonical hex strings.
pub fn hex_encode_ids(value: &mut Value) {
    walk(value, true);
}

/// Recursively hex-decode every OTLP id field carried as a hex string back into
/// raw bytes. Called before encoding to OTLP protobuf.
pub fn hex_decode_ids(value: &mut Value) {
    walk(value, false);
}

fn walk(value: &mut Value, encode: bool) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if ID_FIELDS.contains(&key.as_str()) {
                    convert(child, encode);
                } else {
                    walk(child, encode);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                walk(item, encode);
            }
        }
        _ => {}
    }
}

fn convert(value: &mut Value, encode: bool) {
    let Value::Bytes(bytes) = value else {
        return;
    };
    if encode {
        *value = Value::Bytes(Bytes::from(hex_encode(bytes)));
    } else if let Some(raw) = hex_decode(bytes) {
        *value = Value::Bytes(Bytes::from(raw));
    }
}

fn hex_encode(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize]);
        out.push(DIGITS[(b & 0x0f) as usize]);
    }
    out
}

fn hex_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vrl::value::Value;

    fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Object(
            pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v))
                .collect(),
        )
    }

    #[test]
    fn round_trips_span_id() {
        let raw = Bytes::from_static(b"span0001");
        let mut tree = obj(vec![("spanId", Value::Bytes(raw.clone()))]);
        hex_encode_ids(&mut tree);
        assert_eq!(
            tree.as_object().unwrap().get("spanId").unwrap(),
            &Value::Bytes(Bytes::from_static(b"7370616e30303031")),
        );
        hex_decode_ids(&mut tree);
        assert_eq!(
            tree.as_object().unwrap().get("spanId").unwrap(),
            &Value::Bytes(raw),
        );
    }

    #[test]
    fn walks_nested_arrays() {
        let mut tree = obj(vec![(
            "resourceSpans",
            Value::Array(vec![obj(vec![(
                "spans",
                Value::Array(vec![obj(vec![(
                    "traceId",
                    Value::Bytes(Bytes::from_static(&[0x12, 0x34])),
                )])]),
            )])]),
        )]);
        hex_encode_ids(&mut tree);
        let trace_id = tree
            .as_object()
            .unwrap()
            .get("resourceSpans")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .as_object()
            .unwrap()
            .get("spans")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .as_object()
            .unwrap()
            .get("traceId")
            .unwrap();
        assert_eq!(trace_id, &Value::Bytes(Bytes::from_static(b"1234")));
    }

    #[test]
    fn leaves_attribute_key_named_span_id_untouched() {
        // A user attribute whose *key string* is "spanId" lives under the "key"
        // field, not as an object field named spanId, so it must not be touched.
        let mut tree = obj(vec![(
            "attributes",
            Value::Array(vec![obj(vec![
                ("key", Value::from("spanId")),
                ("value", obj(vec![("stringValue", Value::from("not-an-id"))])),
            ])]),
        )]);
        let before = tree.clone();
        hex_encode_ids(&mut tree);
        assert_eq!(tree, before);
    }
}
