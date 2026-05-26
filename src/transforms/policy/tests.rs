//! End-to-end tests for the `policy` transform driven through Vector's
//! topology layer.
//!
//! These exercise the integration with the `policy-rs` engine using real
//! JSON policy files on disk and the same `create_topology` helper used by
//! every other transform's integration tests.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use tempfile::NamedTempFile;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use vector_lib::event::{LogEvent, Metric, MetricKind, MetricValue};

use crate::event::{Event, Value};
use crate::test_util::components::init_test;
use crate::transforms::test::create_topology;

use super::config::PolicyConfig;
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
        policies_path: path.to_path_buf(),
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

const POLICY_RENAME_LEGACY: &str = r#"{
  "policies": [
    {
      "id": "rename-legacy",
      "name": "rename-legacy",
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
    let policies = write_policies(POLICY_RENAME_LEGACY);
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
