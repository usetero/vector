//! End-to-end tests for the `policy` transform driven through Vector's
//! topology layer.
//!
//! These exercise the integration with the `policy-rs` engine using real
//! JSON policy files on disk and the same `create_topology` helper used by
//! every other transform's integration tests.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde_json::json;
use tempfile::NamedTempFile;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use vector_lib::config::LogNamespace;
use vector_lib::event::{LogEvent, Metric, MetricKind, MetricValue, TraceEvent};

use crate::event::{Event, Value};
use crate::test_util::components::init_test;
use crate::transforms::test::create_topology;

use super::config::{PolicyConfig, PolicyMode, PolicyProviderConfig};
use super::field_mapping::FieldMapping;

/// Write `body` to a fresh NamedTempFile with the `.json` suffix and return
/// it. The caller must keep the handle alive for the test's duration —
/// dropping it deletes the file out from under the `FileProvider`.
fn write_policies(body: &str) -> NamedTempFile {
    let mut file = tempfile::Builder::new()
        .prefix("vector-policy-test-")
        .suffix(".json")
        .tempfile()
        .expect("create temp file");
    file.write_all(body.as_bytes()).expect("write policies");
    file.flush().expect("flush policies");
    file
}

fn policy_config(path: &Path) -> PolicyConfig {
    PolicyConfig {
        policy_providers: vec![PolicyProviderConfig::file(
            "local",
            path.to_string_lossy().into_owned(),
        )],
        mode: PolicyMode::Flat,
        field_mapping: FieldMapping::default(),
    }
}

#[allow(dead_code)]
fn policy_config_otel(path: &Path) -> PolicyConfig {
    PolicyConfig {
        policy_providers: vec![PolicyProviderConfig::file(
            "local",
            path.to_string_lossy().into_owned(),
        )],
        mode: PolicyMode::Otel,
        field_mapping: FieldMapping::default(),
    }
}

/// Initialize metrics + tracing and build a topology in one step. Every test
/// in this file needs both, so funnel the boilerplate through a single helper.
async fn build_topology(
    config: PolicyConfig,
) -> (
    mpsc::Sender<Event>,
    mpsc::Receiver<Event>,
    crate::topology::RunningTopology,
) {
    init_test();
    let (tx, rx) = mpsc::channel(8);
    let (topology, out) = create_topology(ReceiverStream::new(rx), config).await;
    (tx, out, topology)
}

/// Build a representative log event with the fields the default
/// `FieldMapping` expects.
fn log(body: &str) -> Event {
    let mut log = LogEvent::default();
    log.insert("message", body);
    log.insert("severity_text", "INFO");
    log.into()
}

/// Receive the next event with a generous timeout — failures here typically
/// mean the transform silently dropped the event rather than yielding it.
async fn recv(out: &mut mpsc::Receiver<Event>) -> Option<Event> {
    tokio::time::timeout(Duration::from_secs(2), out.recv())
        .await
        .ok()
        .flatten()
}

/// Confirm the next operation drops, with a timeout so a buggy passthrough
/// can't mask a failure.
async fn assert_no_event(out: &mut mpsc::Receiver<Event>) {
    let result = tokio::time::timeout(Duration::from_millis(300), out.recv()).await;
    assert!(
        result.is_err(),
        "expected no event but received {:?}",
        result.ok().flatten()
    );
}

const POLICY_DROP_DEBUG: &str = r#"{
  "policies": [
    {
      "id": "drop-debug",
      "name": "drop-debug",
      "log": {
        "match": [
          { "log_field": "body", "regex": "debug" }
        ],
        "keep": "none"
      }
    }
  ]
}"#;

const POLICY_KEEP_ALL_MATCHING: &str = r#"{
  "policies": [
    {
      "id": "keep-errors",
      "name": "keep-errors",
      "log": {
        "match": [
          { "log_field": "body", "regex": "error" }
        ],
        "keep": "all"
      }
    }
  ]
}"#;

const POLICY_SAMPLE_ZERO: &str = r#"{
  "policies": [
    {
      "id": "drop-sampled",
      "name": "drop-sampled",
      "log": {
        "match": [
          { "log_field": "body", "regex": "drop-me" }
        ],
        "keep": "0%"
      }
    }
  ]
}"#;

const POLICY_SAMPLE_HUNDRED: &str = r#"{
  "policies": [
    {
      "id": "keep-sampled",
      "name": "keep-sampled",
      "log": {
        "match": [
          { "log_field": "body", "regex": "keep-me" }
        ],
        "keep": "100%"
      }
    }
  ]
}"#;

const POLICY_RATE_LIMIT_ONE_PER_SEC: &str = r#"{
  "policies": [
    {
      "id": "rate-limit-noisy",
      "name": "rate-limit-noisy",
      "log": {
        "match": [
          { "log_field": "body", "regex": "noisy" }
        ],
        "keep": "1/s"
      }
    }
  ]
}"#;

const POLICY_REDACT_PASSWORD: &str = r#"{
  "policies": [
    {
      "id": "redact-password",
      "name": "redact-password",
      "log": {
        "match": [
          { "log_field": "body", "regex": "login" }
        ],
        "keep": "all",
        "transform": {
          "redact": [
            { "log_attribute": "password", "replacement": "[REDACTED]" }
          ]
        }
      }
    }
  ]
}"#;

const POLICY_REMOVE_DEBUG_TRACE: &str = r#"{
  "policies": [
    {
      "id": "remove-debug-trace",
      "name": "remove-debug-trace",
      "log": {
        "match": [
          { "log_field": "body", "regex": ".+" }
        ],
        "keep": "all",
        "transform": {
          "remove": [
            { "log_attribute": "debug_trace" }
          ]
        }
      }
    }
  ]
}"#;

const POLICY_RENAME_USER: &str = r#"{
  "policies": [
    {
      "id": "rename-user",
      "name": "rename-user",
      "log": {
        "match": [
          { "log_field": "body", "regex": ".+" }
        ],
        "keep": "all",
        "transform": {
          "rename": [
            { "from_log_attribute": "usr", "to": "user_id", "upsert": true }
          ]
        }
      }
    }
  ]
}"#;

const POLICY_ADD_PROCESSED_BY: &str = r#"{
  "policies": [
    {
      "id": "add-processed-by",
      "name": "add-processed-by",
      "log": {
        "match": [
          { "log_field": "body", "regex": ".+" }
        ],
        "keep": "all",
        "transform": {
          "add": [
            { "log_attribute": "processed_by", "value": "vector", "upsert": false }
          ]
        }
      }
    }
  ]
}"#;

// =============================================================================
// Pass-through and basic filter behaviour.
// =============================================================================

#[tokio::test]
async fn empty_policy_file_passes_events_through() {
    let policies = write_policies(r#"{ "policies": [] }"#);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    tx.send(log("hello world")).await.unwrap();
    let received = recv(&mut out).await.expect("event passed through");
    let log_event = received.into_log();
    assert_eq!(
        log_event.get("message").and_then(|v| v.as_str()),
        Some("hello world".into())
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn no_matching_policy_passes_event_through() {
    let policies = write_policies(POLICY_DROP_DEBUG);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    tx.send(log("regular informational event")).await.unwrap();
    let received = recv(&mut out)
        .await
        .expect("non-matching event passes through");
    let log_event = received.into_log();
    assert_eq!(
        log_event.get("message").and_then(|v| v.as_str()),
        Some("regular informational event".into())
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn matched_drop_policy_discards_event() {
    let policies = write_policies(POLICY_DROP_DEBUG);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    tx.send(log("debug message")).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn matched_keep_policy_forwards_event() {
    let policies = write_policies(POLICY_KEEP_ALL_MATCHING);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    tx.send(log("an error occurred")).await.unwrap();
    let received = recv(&mut out).await.expect("matching keep-all forwards");
    assert_eq!(
        received.into_log().get("message").and_then(|v| v.as_str()),
        Some("an error occurred".into())
    );

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Sampling at the extremes (0% drops everything, 100% keeps everything) is
// deterministic and therefore safe to assert. Intermediate percentages are
// inherently probabilistic and intentionally not tested here.
// =============================================================================

#[tokio::test]
async fn sample_zero_percent_drops_all_matches() {
    let policies = write_policies(POLICY_SAMPLE_ZERO);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    for _ in 0..5 {
        tx.send(log("drop-me please")).await.unwrap();
    }
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn sample_hundred_percent_keeps_all_matches() {
    let policies = write_policies(POLICY_SAMPLE_HUNDRED);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    for _ in 0..3 {
        tx.send(log("keep-me please")).await.unwrap();
    }
    for _ in 0..3 {
        let received = recv(&mut out).await.expect("100% sample forwards");
        assert_eq!(
            received.into_log().get("message").and_then(|v| v.as_str()),
            Some("keep-me please".into())
        );
    }

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Rate-limit policy: the first matching event in the window passes; the
// rest are dropped. Asserting more precise quantities would race with the
// rate-limiter's per-window clock.
// =============================================================================

#[tokio::test]
async fn rate_limit_drops_after_first_event() {
    let policies = write_policies(POLICY_RATE_LIMIT_ONE_PER_SEC);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    // Fire several matching events in quick succession. With 1/s, only the
    // first should clear the limiter; subsequent ones are dropped.
    for _ in 0..5 {
        tx.send(log("noisy chatter")).await.unwrap();
    }

    let first = recv(&mut out).await.expect("first event passes");
    assert_eq!(
        first.into_log().get("message").and_then(|v| v.as_str()),
        Some("noisy chatter".into())
    );

    // Nothing else should arrive within the 1-second window.
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Transform actions: redact, remove, rename, add.
// =============================================================================

#[tokio::test]
async fn redact_replaces_field_value() {
    let policies = write_policies(POLICY_REDACT_PASSWORD);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    let mut event = LogEvent::default();
    event.insert("message", "user login attempt");
    event.insert("severity_text", "INFO");
    event.insert("attributes.password", "super_secret");
    tx.send(event.into()).await.unwrap();

    let received = recv(&mut out)
        .await
        .expect("redact forwards transformed event");
    let log = received.into_log();
    assert_eq!(
        log.get("attributes.password").and_then(|v| v.as_str()),
        Some("[REDACTED]".into())
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn remove_deletes_field() {
    let policies = write_policies(POLICY_REMOVE_DEBUG_TRACE);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    let mut event = LogEvent::default();
    event.insert("message", "anything");
    event.insert("severity_text", "INFO");
    event.insert("attributes.debug_trace", "stack trace here");
    tx.send(event.into()).await.unwrap();

    let received = recv(&mut out)
        .await
        .expect("remove forwards transformed event");
    let log = received.into_log();
    assert!(log.get("attributes.debug_trace").is_none());

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn rename_moves_field() {
    let policies = write_policies(POLICY_RENAME_USER);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    let mut event = LogEvent::default();
    event.insert("message", "anything");
    event.insert("severity_text", "INFO");
    event.insert("attributes.usr", "admin");
    tx.send(event.into()).await.unwrap();

    let received = recv(&mut out)
        .await
        .expect("rename forwards transformed event");
    let log = received.into_log();
    assert!(log.get("attributes.usr").is_none());
    assert_eq!(
        log.get("attributes.user_id").and_then(|v| v.as_str()),
        Some("admin".into())
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn add_inserts_field() {
    let policies = write_policies(POLICY_ADD_PROCESSED_BY);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    let mut event = LogEvent::default();
    event.insert("message", "anything");
    event.insert("severity_text", "INFO");
    tx.send(event.into()).await.unwrap();

    let received = recv(&mut out)
        .await
        .expect("add forwards transformed event");
    let log = received.into_log();
    assert_eq!(
        log.get("attributes.processed_by").and_then(|v| v.as_str()),
        Some("vector".into())
    );

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Non-log signals are forwarded untouched.
// =============================================================================

#[tokio::test]
async fn metric_event_passes_through_untouched() {
    let policies = write_policies(POLICY_DROP_DEBUG);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    let metric = Event::from(Metric::new(
        "test_metric",
        MetricKind::Incremental,
        MetricValue::Counter { value: 1.0 },
    ));
    tx.send(metric.clone()).await.unwrap();

    let received = recv(&mut out).await.expect("metric passes through");
    match received {
        Event::Metric(_) => {} // expected
        other => panic!("expected metric, got {other:?}"),
    }

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Hot reload: rewriting the policies file changes the engine's behaviour
// without restarting the transform.
// =============================================================================

#[tokio::test]
async fn policies_reload_on_file_change() {
    use std::io::Seek;

    // Start with a no-op policy file.
    let mut policies = write_policies(r#"{ "policies": [] }"#);
    let path = policies.path().to_path_buf();
    let config = policy_config(&path);

    let (tx, mut out, topology) = build_topology(config).await;

    // Initially: an event with body "noisy" passes (no policy matches).
    tx.send(log("noisy event")).await.unwrap();
    let _ = recv(&mut out).await.expect("initial pass-through");

    // Rewrite the file with a drop policy. The FileProvider watches the
    // parent directory and reloads on change.
    policies.as_file_mut().set_len(0).unwrap();
    policies.as_file_mut().rewind().unwrap();
    policies
        .write_all(
            r#"{
              "policies": [
                {
                  "id": "drop-noisy",
                  "name": "drop-noisy",
                  "log": {
                    "match": [{ "log_field": "body", "regex": "noisy" }],
                    "keep": "none"
                  }
                }
              ]
            }"#
            .as_bytes(),
        )
        .unwrap();
    policies.as_file_mut().flush().unwrap();

    // notify-driven reload is asynchronous: poll the transform up to a few
    // seconds while the new policy installs.
    let mut reloaded = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        tx.send(log("noisy event")).await.unwrap();
        match tokio::time::timeout(Duration::from_millis(250), out.recv()).await {
            Err(_) => {
                reloaded = true;
                break;
            }
            Ok(Some(_)) => {
                // Old policy still in effect; try again shortly.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(None) => break,
        }
    }
    assert!(
        reloaded,
        "policy file change did not propagate within 5s; events still pass through"
    );

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Robustness: events that don't carry the body field still flow through.
// =============================================================================

#[tokio::test]
async fn event_missing_body_field_passes_through() {
    let policies = write_policies(POLICY_DROP_DEBUG);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    // No `message` field at all — the body matcher should miss and the
    // event should pass through unchanged.
    let mut event = LogEvent::default();
    event.insert("attributes.other", "value");
    tx.send(event.into()).await.unwrap();

    let received = recv(&mut out)
        .await
        .expect("body-less event passes through");
    let log = received.into_log();
    assert_eq!(
        log.get("attributes.other").and_then(|v| v.as_str()),
        Some("value".into())
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn non_string_attribute_satisfies_exists_matcher() {
    // Body matchers operate on strings, but `exists` matchers must fire
    // for non-string attribute values too — the engine asks
    // `Matchable::field_exists`, which our adapter overrides to true for
    // any present value type.
    let policy = r#"{
      "policies": [
        {
          "id": "drop-anything-with-count",
          "name": "drop-anything-with-count",
          "log": {
            "match": [{ "log_attribute": "count", "exists": true }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let config = policy_config(policies.path());

    let (tx, mut out, topology) = build_topology(config).await;

    // Integer attribute — should still trigger the drop.
    let mut event = LogEvent::default();
    event.insert("message", "anything");
    event.insert("severity_text", "INFO");
    event.insert("attributes.count", 42_i64);
    tx.send(event.into()).await.unwrap();
    assert_no_event(&mut out).await;

    // Boolean attribute — should also trigger.
    let mut event = LogEvent::default();
    event.insert("message", "anything");
    event.insert("severity_text", "INFO");
    event.insert("attributes.count", Value::Boolean(true));
    tx.send(event.into()).await.unwrap();
    assert_no_event(&mut out).await;

    // No `count` attribute — should pass through.
    let mut event = LogEvent::default();
    event.insert("message", "anything");
    event.insert("severity_text", "INFO");
    tx.send(event.into()).await.unwrap();
    let _ = recv(&mut out).await.expect("missing count -> pass through");

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Matcher-type coverage. Each test confirms that a single matcher variant
// (other than `regex`/`exists`, which already had their own tests above)
// drives a `keep: "none"` policy as expected.
// =============================================================================

/// Build a one-policy `keep: "none"` JSON document from a single matcher
/// expressed as a raw JSON snippet (e.g. `r#""exact": "foo""#`). Keeps the
/// matcher tests tiny while still exercising the full deserialize → compile
/// → evaluate chain.
fn drop_policy_with_matcher(matcher_json: &str) -> String {
    format!(
        r#"{{
  "policies": [
    {{
      "id": "drop",
      "name": "drop",
      "log": {{
        "match": [{{ "log_field": "body", {matcher_json} }}],
        "keep": "none"
      }}
    }}
  ]
}}"#
    )
}

#[tokio::test]
async fn exact_match_drops_on_full_string_equal() {
    let policies = write_policies(&drop_policy_with_matcher(r#""exact": "hello""#));
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    tx.send(log("hello")).await.unwrap();
    assert_no_event(&mut out).await;

    // A non-exact match (substring) must NOT drop.
    tx.send(log("hello world")).await.unwrap();
    let _ = recv(&mut out).await.expect("non-exact body passes through");

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn starts_with_match_drops() {
    let policies = write_policies(&drop_policy_with_matcher(r#""starts_with": "DEBUG:""#));
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    tx.send(log("DEBUG: trace info")).await.unwrap();
    assert_no_event(&mut out).await;

    tx.send(log("INFO: app started")).await.unwrap();
    let _ = recv(&mut out)
        .await
        .expect("non-prefix body passes through");

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn ends_with_match_drops() {
    let policies = write_policies(&drop_policy_with_matcher(
        r#""ends_with": "[health-check]""#,
    ));
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    tx.send(log("ping [health-check]")).await.unwrap();
    assert_no_event(&mut out).await;

    tx.send(log("user request received")).await.unwrap();
    let _ = recv(&mut out)
        .await
        .expect("non-suffix body passes through");

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn contains_match_drops() {
    let policies = write_policies(&drop_policy_with_matcher(r#""contains": "secret""#));
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    tx.send(log("user said the secret word")).await.unwrap();
    assert_no_event(&mut out).await;

    tx.send(log("nothing sensitive here")).await.unwrap();
    let _ = recv(&mut out)
        .await
        .expect("non-substring body passes through");

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn negate_inverts_match_outcome() {
    // Drop everything EXCEPT events whose body equals "keep".
    let policies = write_policies(&drop_policy_with_matcher(
        r#""exact": "keep", "negate": true"#,
    ));
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    tx.send(log("anything")).await.unwrap();
    assert_no_event(&mut out).await;

    tx.send(log("keep")).await.unwrap();
    let _ = recv(&mut out)
        .await
        .expect("negated match keeps the matching body");

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn case_insensitive_match_drops_regardless_of_case() {
    let policies = write_policies(&drop_policy_with_matcher(
        r#""regex": "error", "case_insensitive": true"#,
    ));
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    for body in ["ERROR boom", "Error boom", "error boom", "ErRoR boom"] {
        tx.send(log(body)).await.unwrap();
        assert_no_event(&mut out).await;
    }

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Match-field namespace coverage: each policy field selector resolves to a
// LogEvent path, and we want one drop-policy test per supported selector to
// catch any regression in the adapter's `path_for` dispatch.
// =============================================================================

#[tokio::test]
async fn severity_text_matcher_drops() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-debug-severity",
          "name": "drop-debug-severity",
          "log": {
            "match": [{ "log_field": "severity_text", "exact": "DEBUG" }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "anything");
    e.insert("severity_text", "DEBUG");
    tx.send(e.into()).await.unwrap();
    assert_no_event(&mut out).await;

    tx.send(log("anything")).await.unwrap(); // severity_text = INFO
    let _ = recv(&mut out).await.expect("non-DEBUG passes");

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn trace_id_matcher_drops() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-by-trace",
          "name": "drop-by-trace",
          "log": {
            "match": [{ "log_field": "trace_id", "exists": true }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "x");
    e.insert("severity_text", "INFO");
    e.insert("trace_id", "abc123");
    tx.send(e.into()).await.unwrap();
    assert_no_event(&mut out).await;

    tx.send(log("x")).await.unwrap(); // no trace_id
    let _ = recv(&mut out).await.expect("no trace_id passes");

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn span_id_matcher_drops() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-by-span",
          "name": "drop-by-span",
          "log": {
            "match": [{ "log_field": "span_id", "exists": true }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "x");
    e.insert("severity_text", "INFO");
    e.insert("span_id", "def456");
    tx.send(e.into()).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn event_name_matcher_drops() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-by-event-name",
          "name": "drop-by-event-name",
          "log": {
            "match": [{ "log_field": "event_name", "exact": "noisy.event" }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "x");
    e.insert("severity_text", "INFO");
    e.insert("event_name", "noisy.event");
    tx.send(e.into()).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn resource_schema_url_matcher_drops() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-by-resource-schema",
          "name": "drop-by-resource-schema",
          "log": {
            "match": [{ "log_field": "resource_schema_url", "contains": "v1.0" }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "x");
    e.insert("severity_text", "INFO");
    e.insert(
        "resource.schema_url",
        "https://opentelemetry.io/schemas/v1.0",
    );
    tx.send(e.into()).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn scope_schema_url_matcher_drops() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-by-scope-schema",
          "name": "drop-by-scope-schema",
          "log": {
            "match": [{ "log_field": "scope_schema_url", "exists": true }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "x");
    e.insert("severity_text", "INFO");
    e.insert("scope.schema_url", "https://opentelemetry.io/schemas/foo");
    tx.send(e.into()).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn resource_attribute_matcher_drops() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-by-service",
          "name": "drop-by-service",
          "log": {
            "match": [{ "resource_attribute": "service.name", "exact": "noisy-service" }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    // The OTel-style "service.name" attribute key contains a literal dot,
    // so we insert through a typed path that quotes the segment.
    let mut e = LogEvent::default();
    e.insert("message", "x");
    e.insert("severity_text", "INFO");
    e.insert(r#"resource.attributes."service.name""#, "noisy-service");
    tx.send(e.into()).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn scope_attribute_matcher_drops() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-by-scope-attr",
          "name": "drop-by-scope-attr",
          "log": {
            "match": [{ "scope_attribute": "library", "exact": "deprecated-tracer" }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "x");
    e.insert("severity_text", "INFO");
    e.insert("scope.attributes.library", "deprecated-tracer");
    tx.send(e.into()).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Multi-policy and multi-matcher semantics.
// =============================================================================

#[tokio::test]
async fn multiple_match_clauses_are_anded() {
    // Drops only when BOTH the body matches AND the severity matches.
    let policy = r#"{
      "policies": [
        {
          "id": "drop-error-from-frontend",
          "name": "drop-error-from-frontend",
          "log": {
            "match": [
              { "log_field": "body", "regex": "error" },
              { "log_field": "severity_text", "exact": "ERROR" }
            ],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    // Both clauses match -> dropped.
    let mut e = LogEvent::default();
    e.insert("message", "an error occurred");
    e.insert("severity_text", "ERROR");
    tx.send(e.into()).await.unwrap();
    assert_no_event(&mut out).await;

    // Body matches but severity does not -> passes through.
    let mut e = LogEvent::default();
    e.insert("message", "an error occurred");
    e.insert("severity_text", "INFO");
    tx.send(e.into()).await.unwrap();
    let _ = recv(&mut out)
        .await
        .expect("AND fails on severity mismatch");

    // Severity matches but body does not -> passes through.
    let mut e = LogEvent::default();
    e.insert("message", "all good");
    e.insert("severity_text", "ERROR");
    tx.send(e.into()).await.unwrap();
    let _ = recv(&mut out).await.expect("AND fails on body mismatch");

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn transforms_from_all_matching_policies_apply() {
    // Two policies both match the same event. The keep action comes from
    // the winning policy (one of them), but per the policy-rs engine, the
    // transforms from BOTH matching policies are applied.
    let policy = r#"{
      "policies": [
        {
          "id": "a-redact-secret",
          "name": "a-redact-secret",
          "log": {
            "match": [{ "log_field": "body", "regex": "audit" }],
            "keep": "all",
            "transform": {
              "redact": [
                { "log_attribute": "secret", "replacement": "[REDACTED]" }
              ]
            }
          }
        },
        {
          "id": "b-add-processed-by",
          "name": "b-add-processed-by",
          "log": {
            "match": [{ "log_field": "body", "regex": "audit" }],
            "keep": "all",
            "transform": {
              "add": [
                { "log_attribute": "processed_by", "value": "vector", "upsert": false }
              ]
            }
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "audit event");
    e.insert("severity_text", "INFO");
    e.insert("attributes.secret", "hunter2");
    tx.send(e.into()).await.unwrap();

    let received = recv(&mut out).await.expect("event forwarded");
    let log = received.into_log();
    assert_eq!(
        log.get("attributes.secret").and_then(|v| v.as_str()),
        Some("[REDACTED]".into()),
        "redact from policy A should have applied",
    );
    assert_eq!(
        log.get("attributes.processed_by").and_then(|v| v.as_str()),
        Some("vector".into()),
        "add from policy B should have applied",
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn winning_policy_determines_keep_action() {
    // Two policies both match. One says "keep: all", the other "keep: none".
    // The engine sorts policies by ID alphabetically and selects a winner
    // for the keep decision; for this test we just assert the event ends up
    // in *some* deterministic state. Because the engine's choice is stable,
    // we accept either outcome as long as it's consistent across the batch.
    let policy = r#"{
      "policies": [
        {
          "id": "aaa-drop",
          "name": "aaa-drop",
          "log": {
            "match": [{ "log_field": "body", "regex": "contested" }],
            "keep": "none"
          }
        },
        {
          "id": "zzz-keep",
          "name": "zzz-keep",
          "log": {
            "match": [{ "log_field": "body", "regex": "contested" }],
            "keep": "all"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    // Send a batch — every event must take the same path. If the winner is
    // unstable across events the batch would mix drops and passes, which is
    // what this test rules out.
    for _ in 0..5 {
        tx.send(log("contested event")).await.unwrap();
    }
    let first = tokio::time::timeout(Duration::from_millis(500), out.recv()).await;
    let dropped_consistently = first.is_err();
    let kept_consistently = first.as_ref().map(|r| r.is_some()).unwrap_or(false);

    if kept_consistently {
        // First event was kept; the remaining four must also be kept.
        for _ in 0..4 {
            let _ = recv(&mut out)
                .await
                .expect("remaining contested events kept");
        }
    } else if dropped_consistently {
        // First event was dropped; the remaining four must also be dropped.
        assert_no_event(&mut out).await;
    } else {
        panic!("ambiguous outcome: first event returned None during run");
    }

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Transform-op variant coverage.
// =============================================================================

#[tokio::test]
async fn redact_with_regex_redacts_substring_only() {
    let policy = r#"{
      "policies": [
        {
          "id": "redact-cc",
          "name": "redact-cc",
          "log": {
            "match": [{ "log_field": "body", "regex": "card" }],
            "keep": "all",
            "transform": {
              "redact": [
                {
                  "log_attribute": "card_number",
                  "replacement": "X",
                  "regex": "[0-9]"
                }
              ]
            }
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "card event");
    e.insert("severity_text", "INFO");
    e.insert("attributes.card_number", "4242 1111 2222 3333");
    tx.send(e.into()).await.unwrap();

    let received = recv(&mut out).await.expect("event forwarded");
    let log = received.into_log();
    assert_eq!(
        log.get("attributes.card_number").and_then(|v| v.as_str()),
        Some("XXXX XXXX XXXX XXXX".into()),
        "regex redact replaces each digit individually",
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn rename_without_upsert_skips_when_target_exists() {
    let policy = r#"{
      "policies": [
        {
          "id": "rename-no-upsert",
          "name": "rename-no-upsert",
          "log": {
            "match": [{ "log_field": "body", "regex": "." }],
            "keep": "all",
            "transform": {
              "rename": [
                { "from_log_attribute": "usr", "to": "user_id", "upsert": false }
              ]
            }
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    // Target `user_id` already exists; rename without upsert must leave
    // both keys in place (the source is NOT moved).
    let mut e = LogEvent::default();
    e.insert("message", "x");
    e.insert("severity_text", "INFO");
    e.insert("attributes.usr", "admin");
    e.insert("attributes.user_id", "existing");
    tx.send(e.into()).await.unwrap();

    let received = recv(&mut out).await.expect("event forwarded");
    let log = received.into_log();
    assert_eq!(
        log.get("attributes.usr").and_then(|v| v.as_str()),
        Some("admin".into()),
        "source key must be preserved when upsert is false and target exists",
    );
    assert_eq!(
        log.get("attributes.user_id").and_then(|v| v.as_str()),
        Some("existing".into()),
        "existing target must NOT be overwritten",
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn add_with_upsert_overwrites_existing_value() {
    let policy = r#"{
      "policies": [
        {
          "id": "add-upsert",
          "name": "add-upsert",
          "log": {
            "match": [{ "log_field": "body", "regex": "." }],
            "keep": "all",
            "transform": {
              "add": [
                { "log_attribute": "processed_by", "value": "vector", "upsert": true }
              ]
            }
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let mut e = LogEvent::default();
    e.insert("message", "x");
    e.insert("severity_text", "INFO");
    e.insert("attributes.processed_by", "something-else");
    tx.send(e.into()).await.unwrap();

    let received = recv(&mut out).await.expect("event forwarded");
    assert_eq!(
        received
            .into_log()
            .get("attributes.processed_by")
            .and_then(|v| v.as_str()),
        Some("vector".into()),
        "upsert=true overwrites the existing value",
    );

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// Misc: trace pass-through + rate-limit-per-minute parse + provider list.
// =============================================================================

#[tokio::test]
async fn trace_event_passes_through_untouched() {
    use vector_lib::event::TraceEvent;

    let policies = write_policies(POLICY_DROP_DEBUG);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    let trace = Event::from(TraceEvent::default());
    tx.send(trace).await.unwrap();

    match recv(&mut out).await {
        Some(Event::Trace(_)) => {}
        other => panic!("expected trace passthrough, got {other:?}"),
    }

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn rate_limit_per_minute_first_event_passes() {
    // We can't realistically test the *reset* of a per-minute window in a
    // unit test (it would have to wait 60s). This guards the parse path
    // and confirms the first matching event is still forwarded.
    let policy = r#"{
      "policies": [
        {
          "id": "rate-limit-per-minute",
          "name": "rate-limit-per-minute",
          "log": {
            "match": [{ "log_field": "body", "regex": "minutely" }],
            "keep": "60/m"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config(policies.path())).await;

    tx.send(log("minutely event")).await.unwrap();
    let _ = recv(&mut out).await.expect("first /m event passes");

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// OTel envelope-mode tests.
//
// These exercise the full envelope iteration path (resourceLogs[]→scopeLogs[]
// →logRecords[]) — per-record filtering, pruning of empty children, and
// dropping the whole event when all records are filtered out.
// =============================================================================

/// Build a single OTLP record body wrapped as an AnyValue.
fn otlp_any_string(s: &str) -> serde_json::Value {
    json!({ "stringValue": s })
}

/// Build a single OTLP attribute entry `{ key, value: { stringValue: ... } }`.
fn otlp_attr(key: &str, value: &str) -> serde_json::Value {
    json!({ "key": key, "value": otlp_any_string(value) })
}

/// Build an OTLP envelope with a single resourceLogs+scopeLogs entry and
/// the supplied records inside.
fn otlp_envelope(records: Vec<serde_json::Value>) -> Event {
    Event::from_json_value(
        json!({
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            otlp_attr("service.name", "test-service"),
                        ]
                    },
                    "schemaUrl": "https://opentelemetry.io/schemas/test",
                    "scopeLogs": [
                        {
                            "scope": {
                                "name": "test.scope",
                                "attributes": [
                                    otlp_attr("library", "test-lib"),
                                ]
                            },
                            "schemaUrl": "https://opentelemetry.io/schemas/test",
                            "logRecords": records
                        }
                    ]
                }
            ]
        }),
        LogNamespace::Legacy,
    )
    .expect("valid envelope")
}

/// Build a minimal OTLP log record with the given body string.
fn otlp_record(body: &str) -> serde_json::Value {
    json!({
        "severityText": "INFO",
        "body": otlp_any_string(body),
        "attributes": []
    })
}

const OTEL_POLICY_DROP_DEBUG: &str = r#"{
  "policies": [
    {
      "id": "drop-debug",
      "name": "drop-debug",
      "log": {
        "match": [{ "log_field": "body", "regex": "debug" }],
        "keep": "none"
      }
    }
  ]
}"#;

#[tokio::test]
async fn otel_mode_passes_non_envelope_event_through() {
    // Backwards-compat: if someone configures `mode: otel` but routes a
    // non-envelope (flat) event through it, we forward it unchanged
    // rather than silently dropping data.
    let policies = write_policies(OTEL_POLICY_DROP_DEBUG);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let mut event = LogEvent::default();
    event.insert("message", "not an envelope");
    tx.send(event.into()).await.unwrap();

    let received = recv(&mut out).await.expect("flat event passes through");
    assert_eq!(
        received.into_log().get("message").and_then(|v| v.as_str()),
        Some("not an envelope".into()),
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_drops_single_matching_record() {
    let policies = write_policies(OTEL_POLICY_DROP_DEBUG);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    // The single record matches `debug`, so it's filtered out — leaving
    // an empty logRecords → empty scopeLogs → empty resourceLogs → the
    // whole event is dropped.
    let envelope = otlp_envelope(vec![otlp_record("debug message")]);
    tx.send(envelope).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_filters_some_records_keeps_envelope() {
    let policies = write_policies(OTEL_POLICY_DROP_DEBUG);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let envelope = otlp_envelope(vec![
        otlp_record("info message"),
        otlp_record("debug message"),
        otlp_record("warn message"),
        otlp_record("another debug here"),
    ]);
    tx.send(envelope).await.unwrap();

    let received = recv(&mut out).await.expect("envelope forwarded");
    let log = received.into_log();

    // Drill into resourceLogs[0].scopeLogs[0].logRecords and verify only
    // the two non-debug records remained.
    let records = log
        .get("resourceLogs")
        .and_then(|v| v.as_array())
        .and_then(|rl| rl.first())
        .and_then(|rl| rl.get("scopeLogs"))
        .and_then(|v| v.as_array())
        .and_then(|sl| sl.first())
        .and_then(|sl| sl.get("logRecords"))
        .and_then(|v| v.as_array())
        .expect("records array still present");
    assert_eq!(records.len(), 2);

    let bodies: Vec<String> = records
        .iter()
        .filter_map(|r| {
            r.get("body")
                .and_then(|b| b.get("stringValue"))
                .and_then(|s| s.as_str())
                .map(|s| s.into_owned())
        })
        .collect();
    assert_eq!(bodies, vec!["info message", "warn message"]);

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_prunes_empty_scope_logs() {
    let policies = write_policies(OTEL_POLICY_DROP_DEBUG);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    // Two scopeLogs entries: the first has only matching records, the
    // second has a non-matching record. The first entry should be pruned.
    let envelope = Event::from_json_value(
        json!({
            "resourceLogs": [
                {
                    "scopeLogs": [
                        {
                            "scope": { "name": "scope-a" },
                            "logRecords": [
                                otlp_record("debug 1"),
                                otlp_record("debug 2"),
                            ]
                        },
                        {
                            "scope": { "name": "scope-b" },
                            "logRecords": [
                                otlp_record("info kept"),
                            ]
                        }
                    ]
                }
            ]
        }),
        LogNamespace::Legacy,
    )
    .unwrap();
    tx.send(envelope).await.unwrap();

    let received = recv(&mut out).await.expect("envelope forwarded");
    let log = received.into_log();

    let scope_logs = log
        .get("resourceLogs")
        .and_then(|v| v.as_array())
        .and_then(|rl| rl.first())
        .and_then(|rl| rl.get("scopeLogs"))
        .and_then(|v| v.as_array())
        .expect("scopeLogs still present");
    assert_eq!(scope_logs.len(), 1, "empty scope must be pruned");
    let scope_name = scope_logs[0]
        .get("scope")
        .and_then(|s| s.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.into_owned());
    assert_eq!(scope_name.as_deref(), Some("scope-b"));

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_prunes_empty_resource_logs() {
    let policies = write_policies(OTEL_POLICY_DROP_DEBUG);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    // Two resourceLogs entries. The first ends up empty after filtering;
    // the second still has a record. Expect: only the second remains.
    let envelope = Event::from_json_value(
        json!({
            "resourceLogs": [
                {
                    "resource": { "attributes": [ otlp_attr("service.name", "dropped") ] },
                    "scopeLogs": [
                        {
                            "scope": { "name": "s" },
                            "logRecords": [ otlp_record("debug a") ]
                        }
                    ]
                },
                {
                    "resource": { "attributes": [ otlp_attr("service.name", "kept") ] },
                    "scopeLogs": [
                        {
                            "scope": { "name": "s" },
                            "logRecords": [ otlp_record("info b") ]
                        }
                    ]
                }
            ]
        }),
        LogNamespace::Legacy,
    )
    .unwrap();
    tx.send(envelope).await.unwrap();

    let received = recv(&mut out).await.expect("envelope forwarded");
    let log = received.into_log();

    let resource_logs = log
        .get("resourceLogs")
        .and_then(|v| v.as_array())
        .expect("resourceLogs present");
    assert_eq!(
        resource_logs.len(),
        1,
        "empty resource entry must be pruned"
    );

    let service = resource_logs[0]
        .get("resource")
        .and_then(|r| r.get("attributes"))
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|kv| kv.get("value"))
        .and_then(|v| v.get("stringValue"))
        .and_then(|s| s.as_str())
        .map(|s| s.into_owned());
    assert_eq!(service.as_deref(), Some("kept"));

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_resource_attribute_matcher_drops_record() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-by-service",
          "name": "drop-by-service",
          "log": {
            "match": [{ "resource_attribute": "service.name", "exact": "noisy-service" }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let envelope = Event::from_json_value(
        json!({
            "resourceLogs": [
                {
                    "resource": { "attributes": [ otlp_attr("service.name", "noisy-service") ] },
                    "scopeLogs": [
                        {
                            "scope": { "name": "s" },
                            "logRecords": [ otlp_record("hello") ]
                        }
                    ]
                }
            ]
        }),
        LogNamespace::Legacy,
    )
    .unwrap();
    tx.send(envelope).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_scope_attribute_matcher_drops_record() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-by-lib",
          "name": "drop-by-lib",
          "log": {
            "match": [{ "scope_attribute": "library", "exact": "deprecated-tracer" }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let envelope = Event::from_json_value(
        json!({
            "resourceLogs": [
                {
                    "scopeLogs": [
                        {
                            "scope": { "attributes": [ otlp_attr("library", "deprecated-tracer") ] },
                            "logRecords": [ otlp_record("hello") ]
                        }
                    ]
                }
            ]
        }),
        LogNamespace::Legacy,
    )
    .unwrap();
    tx.send(envelope).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_redact_mutates_attribute_array() {
    let policy = r#"{
      "policies": [
        {
          "id": "redact-secret",
          "name": "redact-secret",
          "log": {
            "match": [{ "log_field": "body", "regex": "login" }],
            "keep": "all",
            "transform": {
              "redact": [
                { "log_attribute": "password", "replacement": "[REDACTED]" }
              ]
            }
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let envelope = otlp_envelope(vec![json!({
        "severityText": "INFO",
        "body": otlp_any_string("user login attempt"),
        "attributes": [
            otlp_attr("password", "super-secret"),
            otlp_attr("user", "alice"),
        ]
    })]);
    tx.send(envelope).await.unwrap();

    let received = recv(&mut out).await.expect("envelope forwarded");
    let log = received.into_log();

    let attrs = log
        .get("resourceLogs")
        .and_then(|v| v.as_array())
        .and_then(|rl| rl.first())
        .and_then(|rl| rl.get("scopeLogs"))
        .and_then(|v| v.as_array())
        .and_then(|sl| sl.first())
        .and_then(|sl| sl.get("logRecords"))
        .and_then(|v| v.as_array())
        .and_then(|r| r.first())
        .and_then(|r| r.get("attributes"))
        .and_then(|v| v.as_array())
        .expect("attributes array present");

    let password = attrs
        .iter()
        .find(|a| a.get("key").and_then(|k| k.as_str()).as_deref() == Some("password"));
    let password_val = password
        .and_then(|a| a.get("value"))
        .and_then(|v| v.get("stringValue"))
        .and_then(|s| s.as_str())
        .map(|s| s.into_owned());
    assert_eq!(password_val.as_deref(), Some("[REDACTED]"));

    // Untouched attribute stays put.
    let user_val = attrs
        .iter()
        .find(|a| a.get("key").and_then(|k| k.as_str()).as_deref() == Some("user"))
        .and_then(|a| a.get("value"))
        .and_then(|v| v.get("stringValue"))
        .and_then(|s| s.as_str())
        .map(|s| s.into_owned());
    assert_eq!(user_val.as_deref(), Some("alice"));

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_add_inserts_attribute_into_array() {
    let policy = r#"{
      "policies": [
        {
          "id": "tag-processed",
          "name": "tag-processed",
          "log": {
            "match": [{ "log_field": "body", "regex": ".+" }],
            "keep": "all",
            "transform": {
              "add": [
                { "log_attribute": "processed_by", "value": "vector", "upsert": false }
              ]
            }
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let envelope = otlp_envelope(vec![otlp_record("anything")]);
    tx.send(envelope).await.unwrap();

    let received = recv(&mut out).await.expect("envelope forwarded");
    let log = received.into_log();

    let attrs = log
        .get("resourceLogs")
        .and_then(|v| v.as_array())
        .and_then(|rl| rl.first())
        .and_then(|rl| rl.get("scopeLogs"))
        .and_then(|v| v.as_array())
        .and_then(|sl| sl.first())
        .and_then(|sl| sl.get("logRecords"))
        .and_then(|v| v.as_array())
        .and_then(|r| r.first())
        .and_then(|r| r.get("attributes"))
        .and_then(|v| v.as_array())
        .expect("attributes array present");

    let processed_by = attrs
        .iter()
        .find(|a| a.get("key").and_then(|k| k.as_str()).as_deref() == Some("processed_by"))
        .and_then(|a| a.get("value"))
        .and_then(|v| v.get("stringValue"))
        .and_then(|s| s.as_str())
        .map(|s| s.into_owned());
    assert_eq!(processed_by.as_deref(), Some("vector"));

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_severity_text_matcher_drops_record() {
    let policy = r#"{
      "policies": [
        {
          "id": "drop-debug-severity",
          "name": "drop-debug-severity",
          "log": {
            "match": [{ "log_field": "severity_text", "exact": "DEBUG" }],
            "keep": "none"
          }
        }
      ]
    }"#;
    let policies = write_policies(policy);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let envelope = otlp_envelope(vec![json!({
        "severityText": "DEBUG",
        "body": otlp_any_string("anything"),
        "attributes": []
    })]);
    tx.send(envelope).await.unwrap();
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_metric_event_passes_through_untouched() {
    // Same guarantee as flat mode: non-log signals are forwarded as-is.
    let policies = write_policies(OTEL_POLICY_DROP_DEBUG);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let metric = Event::from(Metric::new(
        "test",
        MetricKind::Incremental,
        MetricValue::Counter { value: 1.0 },
    ));
    tx.send(metric).await.unwrap();
    let received = recv(&mut out).await.expect("metric passes through");
    assert!(matches!(received, Event::Metric(_)));

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// OTel mode: OTLP metrics envelopes (`resourceMetrics`).
// =============================================================================

const OTEL_POLICY_DROP_METRIC_BY_NAME: &str = r#"{
  "policies": [
    {
      "id": "drop-system-load",
      "name": "drop-system-load",
      "metric": {
        "match": [ { "metric_field": "name", "regex": "^system\\.load.*$" } ],
        "keep": false
      }
    }
  ]
}"#;

#[tokio::test]
async fn otel_mode_metrics_envelope_drops_and_prunes() {
    let policies = write_policies(OTEL_POLICY_DROP_METRIC_BY_NAME);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    // scope-a holds only a system.load metric (dropped → scope pruned);
    // scope-b holds system.load (dropped) + http.requests (kept). This
    // exercises the two-phase keep/prune index bookkeeping across scopes.
    let envelope = Event::from_json_value(
        json!({
            "resourceMetrics": [{
                "resource": { "attributes": [] },
                "scopeMetrics": [
                    {
                        "scope": { "name": "scope-a" },
                        "metrics": [
                            { "name": "system.load.1", "gauge": { "dataPoints": [{ "attributes": [] }] } }
                        ]
                    },
                    {
                        "scope": { "name": "scope-b" },
                        "metrics": [
                            { "name": "system.load.5", "gauge": { "dataPoints": [{ "attributes": [] }] } },
                            { "name": "http.requests", "sum": { "dataPoints": [{ "attributes": [] }], "aggregationTemporality": "AGGREGATION_TEMPORALITY_DELTA" } }
                        ]
                    }
                ]
            }]
        }),
        LogNamespace::Legacy,
    )
    .unwrap();
    tx.send(envelope).await.unwrap();

    let received = recv(&mut out).await.expect("metrics envelope forwarded");
    let log = received.into_log();

    let scope_metrics = log
        .get("resourceMetrics")
        .and_then(|v| v.as_array())
        .and_then(|rm| rm.first())
        .and_then(|rm| rm.get("scopeMetrics"))
        .and_then(|v| v.as_array())
        .expect("scopeMetrics present");
    assert_eq!(scope_metrics.len(), 1, "empty scope-a must be pruned");
    assert_eq!(
        scope_metrics[0]
            .get("scope")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
            .as_deref(),
        Some("scope-b"),
    );
    let metrics = scope_metrics[0]
        .get("metrics")
        .and_then(|v| v.as_array())
        .expect("metrics present");
    assert_eq!(metrics.len(), 1, "only the non-matching metric survives");
    assert_eq!(
        metrics[0].get("name").and_then(|n| n.as_str()).as_deref(),
        Some("http.requests"),
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_metrics_envelope_all_dropped_drops_event() {
    let policies = write_policies(OTEL_POLICY_DROP_METRIC_BY_NAME);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let envelope = Event::from_json_value(
        json!({
            "resourceMetrics": [{
                "scopeMetrics": [{
                    "metrics": [
                        { "name": "system.load.1", "gauge": { "dataPoints": [{ "attributes": [] }] } }
                    ]
                }]
            }]
        }),
        LogNamespace::Legacy,
    )
    .unwrap();
    tx.send(envelope).await.unwrap();

    // The only metric is dropped, so the whole envelope is pruned away.
    assert_no_event(&mut out).await;

    drop(tx);
    topology.stop().await;
}

// =============================================================================
// OTel mode: OTLP traces envelopes (`resourceSpans`).
// =============================================================================

const OTEL_POLICY_DROP_TRACE_BY_NAME: &str = r#"{
  "policies": [
    {
      "id": "drop-basic",
      "name": "drop-basic",
      "trace": {
        "match": [ { "trace_field": "TRACE_FIELD_NAME", "exact": "basic" } ],
        "keep": { "percentage": 0.0 }
      }
    }
  ]
}"#;

const OTEL_POLICY_KEEP_ERROR_SPANS: &str = r#"{
  "policies": [
    {
      "id": "keep-error",
      "name": "keep-error",
      "trace": {
        "match": [ { "span_status": "SPAN_STATUS_CODE_ERROR", "exists": true } ],
        "keep": { "percentage": 100.0 }
      }
    }
  ]
}"#;

fn otlp_trace(value: serde_json::Value) -> Event {
    Event::Trace(TraceEvent::from(Value::from(value)))
}

#[tokio::test]
async fn otel_mode_traces_envelope_drops_and_prunes() {
    let policies = write_policies(OTEL_POLICY_DROP_TRACE_BY_NAME);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let envelope = otlp_trace(json!({
        "resourceSpans": [{
            "resource": { "attributes": [] },
            "scopeSpans": [{
                "scope": { "name": "s" },
                "spans": [
                    { "name": "basic", "spanId": "a", "traceId": "t" },
                    { "name": "keep-me", "spanId": "b", "traceId": "t" }
                ]
            }]
        }]
    }));
    tx.send(envelope).await.unwrap();

    let received = recv(&mut out).await.expect("traces envelope forwarded");
    let spans = received
        .as_trace()
        .get("resourceSpans")
        .and_then(|v| v.as_array())
        .and_then(|rs| rs.first())
        .and_then(|rs| rs.get("scopeSpans"))
        .and_then(|v| v.as_array())
        .and_then(|ss| ss.first())
        .and_then(|ss| ss.get("spans"))
        .and_then(|v| v.as_array())
        .expect("spans present");
    assert_eq!(spans.len(), 1, "the matching span is dropped");
    assert_eq!(
        spans[0].get("name").and_then(|n| n.as_str()).as_deref(),
        Some("keep-me"),
    );

    drop(tx);
    topology.stop().await;
}

#[tokio::test]
async fn otel_mode_traces_sampling_writes_tracestate() {
    let policies = write_policies(OTEL_POLICY_KEEP_ERROR_SPANS);
    let (tx, mut out, topology) = build_topology(policy_config_otel(policies.path())).await;

    let envelope = otlp_trace(json!({
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [
                    { "name": "checkout", "spanId": "a", "traceId": "t", "status": { "code": "STATUS_CODE_ERROR" } }
                ]
            }]
        }]
    }));
    tx.send(envelope).await.unwrap();

    let received = recv(&mut out).await.expect("traces envelope forwarded");
    let span = received
        .as_trace()
        .get("resourceSpans")
        .and_then(|v| v.as_array())
        .and_then(|rs| rs.first())
        .and_then(|rs| rs.get("scopeSpans"))
        .and_then(|v| v.as_array())
        .and_then(|ss| ss.first())
        .and_then(|ss| ss.get("spans"))
        .and_then(|v| v.as_array())
        .and_then(|s| s.first())
        .cloned()
        .expect("span kept");
    // 100% sampling writes the OTel threshold `th=0` into the tracestate.
    assert_eq!(
        span.get("traceState").and_then(|v| v.as_str()).as_deref(),
        Some("ot=th:0"),
    );

    drop(tx);
    topology.stop().await;
}
