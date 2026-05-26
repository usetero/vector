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

pub(crate) fn emit_dropped(reason: DropReason) {
    emit!(ComponentEventsDropped::<INTENTIONAL> {
        count: 1,
        reason: reason.as_str(),
    });
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
