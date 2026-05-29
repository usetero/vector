//! Internal events emitted by the `policy` transform.
//!
//! These live inside the transform module so the file under
//! `src/internal_events/` stays untouched — any future schema change can be
//! confined to this one file.

use vector_lib::internal_event::{ComponentEventsDropped, INTENTIONAL};

/// Reason tag attached to `component_discarded_events_total` for events the
/// policy engine declined to forward.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DropReason {
    /// A matching policy's `keep` action is `"none"` — drop unconditionally.
    PolicyDrop,
    /// A percentage-sample policy decided not to keep this event.
    SampleRejected,
    /// A rate-limited policy's window quota is exhausted.
    RateLimited,
}

impl DropReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            DropReason::PolicyDrop => "policy_drop",
            DropReason::SampleRejected => "policy_sample_rejected",
            DropReason::RateLimited => "policy_rate_limited",
        }
    }
}

/// Per-envelope accumulator for dropped-record counts.
///
/// OTLP envelopes can drop many records in a single event; emitting one
/// `ComponentEventsDropped` per record would hammer the metrics path. Instead
/// callers `record` each drop and `emit` once per envelope, collapsing N
/// `emit!` calls into at most one per reason.
#[derive(Default)]
pub(crate) struct DropCounts {
    policy_drop: u64,
    sample_rejected: u64,
    rate_limited: u64,
}

impl DropCounts {
    pub(crate) const fn record(&mut self, reason: DropReason) {
        match reason {
            DropReason::PolicyDrop => self.policy_drop += 1,
            DropReason::SampleRejected => self.sample_rejected += 1,
            DropReason::RateLimited => self.rate_limited += 1,
        }
    }

    pub(crate) fn emit(&self) {
        emit_dropped(DropReason::PolicyDrop, self.policy_drop);
        emit_dropped(DropReason::SampleRejected, self.sample_rejected);
        emit_dropped(DropReason::RateLimited, self.rate_limited);
    }
}

/// Emit a single aggregated `ComponentEventsDropped` for `count` records. A
/// zero count emits nothing.
pub(crate) fn emit_dropped(reason: DropReason, count: u64) {
    if count == 0 {
        return;
    }
    emit!(ComponentEventsDropped::<INTENTIONAL> {
        count: count as usize,
        reason: reason.as_str(),
    });
}

/// Per-envelope accumulator for fail-open evaluation errors.
///
/// The transform fails open — an evaluation error passes the record through
/// untouched rather than dropping it. Logging one `error!` per record would
/// spam under a systematic failure (e.g. a single malformed input replayed
/// across an envelope), so we record the first error and a count and emit one
/// line per envelope.
#[derive(Default)]
pub(crate) struct EvalErrors {
    count: u64,
    first: Option<String>,
}

impl EvalErrors {
    pub(crate) fn record(&mut self, error: &dyn std::fmt::Display) {
        if self.first.is_none() {
            self.first = Some(error.to_string());
        }
        self.count += 1;
    }

    pub(crate) fn emit(&self) {
        if self.count == 0 {
            return;
        }
        error!(
            message = "Policy evaluation failed; affected OTLP records were passed through unchanged.",
            count = self.count,
            error = self.first.as_deref().unwrap_or_default(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_strings_are_stable() {
        // These tag values flow into emitted metrics. Changing them would be
        // a user-visible break, so the test exists to draw attention to it.
        assert_eq!(DropReason::PolicyDrop.as_str(), "policy_drop");
        assert_eq!(
            DropReason::SampleRejected.as_str(),
            "policy_sample_rejected"
        );
        assert_eq!(DropReason::RateLimited.as_str(), "policy_rate_limited");
    }
}
