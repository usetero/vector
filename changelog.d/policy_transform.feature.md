Added a new `policy` transform that evaluates log events against a JSON policy file using the [`policy-rs`](https://github.com/usetero/policy-rs) engine. The transform can keep, drop, sample, and rate-limit logs, and can apply field-level transformations (remove, redact, rename, add) based on the matched policy. Policies are watched and reloaded on file change. The transform is gated behind the `transforms-policy` cargo feature.

authors: jaronoff97
