//! Configuration for the `policy` transform.

use std::path::PathBuf;
use std::sync::Arc;

use policy_rs::{FileProvider, PolicyEngine, PolicyRegistry};
use vector_lib::{config::clone_input_definitions, configurable::configurable_component};

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
/// engine. Policies are loaded from a JSON file that the file-watcher
/// reloads automatically on changes.
#[configurable_component(transform(
    "policy",
    "Evaluate log events against a policy file and apply the resulting keep/drop/sample/rate-limit and field-transform actions."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Path to a JSON file containing the Tero Policy Specification document
    /// to evaluate against. The file is watched and re-loaded on changes.
    #[configurable(metadata(docs::examples = "/etc/vector/policies.json"))]
    pub policies_path: PathBuf,

    /// Mapping between `policy-rs` log field selectors and paths within a
    /// Vector `LogEvent`.
    ///
    /// Defaults follow OpenTelemetry semantic conventions so logs produced
    /// by the `opentelemetry` source are matched without further
    /// configuration.
    #[configurable(derived)]
    #[serde(default)]
    pub field_mapping: FieldMapping,
}

impl GenerateConfig for PolicyConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            policies_path: PathBuf::from("/etc/vector/policies.json"),
            field_mapping: FieldMapping::default(),
        })
        .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "policy")]
impl TransformConfig for PolicyConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        let registry = PolicyRegistry::new();
        let provider = FileProvider::new(&self.policies_path);
        registry.subscribe(&provider).map_err(|error| {
            format!(
                "failed to load policies from {:?}: {error}",
                self.policies_path
            )
        })?;

        let policy = Policy::new(
            Arc::new(registry),
            Arc::new(PolicyEngine::new()),
            Arc::new(self.field_mapping.clone()),
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
policies_path = "/tmp/policies.json"
"#,
        )
        .unwrap();
        assert_eq!(config.policies_path, PathBuf::from("/tmp/policies.json"));
        assert_eq!(config.field_mapping, FieldMapping::default());
    }

    #[test]
    fn deserialize_with_field_mapping_overrides() {
        let config: PolicyConfig = toml::from_str(
            r#"
policies_path = "/tmp/policies.json"
[field_mapping]
body = "log.body"
"#,
        )
        .unwrap();
        assert_eq!(String::from(config.field_mapping.body.clone()), "log.body");
    }

    #[test]
    fn deserialize_rejects_unknown_field() {
        let result: Result<PolicyConfig, _> = toml::from_str(
            r#"
policies_path = "/tmp/policies.json"
unknown = "value"
"#,
        );
        assert!(
            result.is_err(),
            "unknown top-level fields should be rejected"
        );
    }

    #[test]
    fn deserialize_requires_policies_path() {
        let result: Result<PolicyConfig, _> = toml::from_str("");
        assert!(result.is_err(), "policies_path is required");
    }
}
