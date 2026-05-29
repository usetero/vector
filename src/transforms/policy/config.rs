//! Configuration for the `policy` transform.

use std::cell::RefCell;
use std::sync::Arc;

use policy_rs::{
    PolicyEngine, PolicyRegistry,
    config::{FileProviderConfig, ProviderConfig as PolicyRsProviderConfig, register_providers},
};
use serde::{Deserialize, Serialize};
use vector_lib::{
    config::clone_input_definitions,
    configurable::{
        Configurable, GenerateError, Metadata, ToValue, configurable_component,
        schema::{SchemaGenerator, SchemaObject},
    },
};

use crate::{
    config::{
        DataType, GenerateConfig, Input, OutputId, TransformConfig, TransformContext,
        TransformOutput,
    },
    schema,
    transforms::Transform,
};

use super::field_mapping::FieldMapping;
use super::transform::Policy;

/// Configuration for the `policy` transform.
///
/// The transform delegates filtering, sampling, rate-limiting, and field
/// transformation to the external [`policy-rs`](https://github.com/usetero/policy-rs)
/// engine. Policies are loaded from configured policy providers and
/// reloaded automatically when the providers report changes.
#[configurable_component(transform(
    "policy",
    "Evaluate log events against a policy file and apply the resulting keep/drop/sample/rate-limit and field-transform actions."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Policy providers to register with the policy registry.
    ///
    /// Each provider uses policy-rs' tagged provider configuration format,
    /// such as `{ type = "file", id = "local", path = "/etc/vector/policies.json" }`.
    #[configurable(derived)]
    pub policy_providers: Vec<PolicyProviderConfig>,

    /// How Vector events are mapped to policy-rs records.
    ///
    /// `flat` (the default) treats every Vector event as a single log
    /// record and uses the configurable `field_mapping`.
    ///
    /// `otel` treats every Vector event as an OTLP envelope and iterates
    /// `resourceLogs[].scopeLogs[].logRecords[]` internally, applying
    /// policies per-record and pruning empty children. `field_mapping`
    /// is ignored in this mode — OTLP field locations are fixed by the
    /// protocol.
    #[configurable(derived)]
    #[serde(default)]
    pub mode: PolicyMode,

    /// Mapping between `policy-rs` log field selectors and paths within a
    /// Vector `LogEvent`. Only used when `mode = flat`.
    ///
    /// Defaults follow OpenTelemetry semantic conventions so logs produced
    /// by the `opentelemetry` source are matched without further
    /// configuration.
    #[configurable(derived)]
    #[serde(default)]
    pub field_mapping: FieldMapping,
}

/// Iteration mode for the `policy` transform.
///
/// NOTE: the two modes intentionally use different matching semantics, because
/// they target different data models — `flat` wraps Vector's schema-less
/// `LogEvent`, while `otel` follows the OTLP/JSON spec exactly (matching the
/// `policy-rs` conformance suite). Two differences are worth knowing when
/// moving a policy between modes:
///
/// * Non-string values: in `flat` mode an integer/float/boolean attribute is
///   stringified and is therefore matchable (and redactable); in `otel` mode
///   only a `stringValue` is matchable — other `AnyValue` variants satisfy
///   `exists` but never a regex/exact match.
/// * Empty values: `otel` mode treats an empty string / valueless `AnyValue`
///   as absent (a `""` body does not `exist`); `flat` mode treats any present
///   value as present.
#[configurable_component]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// One Vector event maps to one log record. Use this mode for sources
    /// that emit flat Vector events (the default for most sources).
    ///
    /// Policy field selectors are resolved through `field_mapping`.
    #[default]
    Flat,

    /// One Vector event is an OTLP envelope (`{ resourceLogs: [...] }`).
    ///
    /// The transform iterates every `logRecord` inside the envelope,
    /// applies policies per-record, and prunes empty `scopeLogs` and
    /// `resourceLogs` entries. If every record is filtered out, the
    /// entire envelope event is dropped.
    ///
    /// Use this mode with Vector's `opentelemetry` source when
    /// `use_otlp_decoding.logs` is `true`.
    Otel,
}

/// Policy provider configuration.
///
/// This wraps policy-rs' provider configuration so Vector can embed the
/// library's tagged provider enum directly in the transform config.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct PolicyProviderConfig(PolicyRsProviderConfig);

impl PolicyProviderConfig {
    pub(super) fn file(id: impl Into<String>, path: impl Into<String>) -> Self {
        Self(PolicyRsProviderConfig::File(FileProviderConfig {
            id: id.into(),
            path: path.into(),
        }))
    }

    fn into_inner(self) -> PolicyRsProviderConfig {
        self.0
    }
}

impl Configurable for PolicyProviderConfig {
    fn metadata() -> Metadata {
        let mut metadata = Metadata::default();
        metadata.set_description(
            "Policy provider configuration using policy-rs' tagged provider format.",
        );
        metadata
    }

    fn generate_schema(_: &RefCell<SchemaGenerator>) -> Result<SchemaObject, GenerateError> {
        Ok(SchemaObject::default())
    }
}

impl ToValue for PolicyProviderConfig {
    fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("Could not convert policy provider config to JSON")
    }
}

impl GenerateConfig for PolicyConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            policy_providers: vec![PolicyProviderConfig::file(
                "local",
                "/etc/vector/policies.json",
            )],
            mode: PolicyMode::default(),
            field_mapping: FieldMapping::default(),
        })
        .unwrap()
    }
}

impl PolicyConfig {
    fn provider_configs(&self) -> crate::Result<Vec<PolicyRsProviderConfig>> {
        if !self.policy_providers.is_empty() {
            return Ok(self
                .policy_providers
                .iter()
                .cloned()
                .map(PolicyProviderConfig::into_inner)
                .collect());
        }

        Err("policy transform requires at least one policy provider".into())
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "policy")]
impl TransformConfig for PolicyConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        let registry = PolicyRegistry::new();
        let provider_configs = self.provider_configs()?;
        register_providers(&provider_configs, &registry)
            .await
            .map_err(|error| format!("failed to register policy providers: {error}"))?;

        let policy = Policy::new(
            Arc::new(registry),
            Arc::new(PolicyEngine::new()),
            Arc::new(self.field_mapping.clone()),
            self.mode,
        );
        Ok(Transform::event_task(policy))
    }

    fn input(&self) -> Input {
        // Accept everything; metrics and traces pass through unchanged.
        Input::all()
    }

    fn outputs(
        &self,
        _: &TransformContext,
        input_definitions: &[(OutputId, schema::Definition)],
    ) -> Vec<TransformOutput> {
        vec![TransformOutput::new(
            DataType::all_bits(),
            clone_input_definitions(input_definitions),
        )]
    }

    fn enable_concurrency(&self) -> bool {
        // Rate-limit state lives inside a single `PolicyEngine` instance, so
        // running multiple copies of the transform would split the
        // per-window counters and silently raise the effective rate limit.
        // Keep concurrency disabled until policy-rs offers a shared
        // rate-limiter handle.
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<super::PolicyConfig>();
    }

    #[test]
    fn deserialize_minimal() {
        let config: PolicyConfig = toml::from_str(
            r#"
[[policy_providers]]
id = "local"
type = "file"
path = "/tmp/policies.json"
"#,
        )
        .unwrap();
        let providers = config.provider_configs().unwrap();
        assert_eq!(providers.len(), 1);
        assert!(matches!(providers[0], PolicyRsProviderConfig::File(_)));
        assert_eq!(config.field_mapping, FieldMapping::default());
    }

    #[test]
    fn deserialize_with_field_mapping_overrides() {
        let config: PolicyConfig = toml::from_str(
            r#"
[[policy_providers]]
id = "local"
type = "file"
path = "/tmp/policies.json"

[field_mapping]
body = "log.body"
"#,
        )
        .unwrap();
        assert_eq!(String::from(config.field_mapping.body.clone()), "log.body");
    }

    #[test]
    fn deserialize_rejects_unknown_field() {
        // The unknown top-level key must come BEFORE the `[[policy_providers]]`
        // header — otherwise TOML attaches it to the array element instead of
        // the root table, which would slip past `deny_unknown_fields` on
        // `PolicyConfig`.
        let result: Result<PolicyConfig, _> = toml::from_str(
            r#"
unknown = "value"

[[policy_providers]]
id = "local"
type = "file"
path = "/tmp/policies.json"
"#,
        );
        assert!(
            result.is_err(),
            "unknown top-level fields should be rejected"
        );
    }

    #[test]
    fn deserialize_requires_policy_providers() {
        let result: Result<PolicyConfig, _> = toml::from_str("");
        assert!(result.is_err(), "policy_providers is required");
    }

    #[test]
    fn empty_config_has_no_provider_configs() {
        let config: PolicyConfig = toml::from_str(
            r#"
policy_providers = []
"#,
        )
        .unwrap();
        let result = config.provider_configs();
        assert!(result.is_err(), "policy_providers must not be empty");
    }

    #[test]
    fn deserialize_multiple_policy_providers() {
        let config: PolicyConfig = toml::from_str(
            r#"
[[policy_providers]]
id = "primary"
type = "file"
path = "/etc/vector/primary.json"

[[policy_providers]]
id = "secondary"
type = "file"
path = "/etc/vector/secondary.json"
"#,
        )
        .unwrap();
        let providers = config.provider_configs().unwrap();
        assert_eq!(providers.len(), 2);
        assert!(
            providers
                .iter()
                .all(|p| matches!(p, PolicyRsProviderConfig::File(_)))
        );
    }

    #[test]
    fn deserialize_rejects_unknown_provider_type() {
        // policy-rs' `ProviderConfig` is a tagged enum on the `type` key.
        // An unknown discriminator must fail to deserialize so users get a
        // clear error rather than silently dropping the provider.
        let result: Result<PolicyConfig, _> = toml::from_str(
            r#"
[[policy_providers]]
id = "bogus"
type = "nonexistent-provider-type"
path = "/dev/null"
"#,
        );
        assert!(
            result.is_err(),
            "unknown provider `type` value should be rejected",
        );
    }
}
