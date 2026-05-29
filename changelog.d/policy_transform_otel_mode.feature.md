Added `mode: otel` option to the `policy` transform. When enabled, the transform treats each Vector event as an OTLP envelope (`{ resourceLogs: [...] }`) produced by the `opentelemetry` source with `use_otlp_decoding.logs = true`, iterates every `logRecord` inside, and applies policies per-record. Empty `scopeLogs` and `resourceLogs` entries are pruned automatically; if every record is filtered out the entire event is dropped. The default `mode: flat` preserves the previous one-event-per-decision behaviour.

authors: jaronoff97
