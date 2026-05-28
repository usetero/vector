//! Transform that delegates filtering, sampling, rate-limiting, and field
//! transformation to the [`policy-rs`](https://github.com/usetero/policy-rs)
//! library.
//!
//! The transform is fully self-contained inside this directory — no other
//! file in the Vector tree depends on `policy-rs` types — so future updates
//! to the library are isolated to this module.

mod adapter;
mod field_mapping;
mod internal_events;
mod otlp_adapter;
mod otlp_metric_adapter;
mod otlp_trace_adapter;

pub mod config;
pub mod transform;

#[cfg(test)]
mod tests;
