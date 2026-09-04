//! Build-time compile check for the shipped default policy.
//!
//! `policies/arbiter/default-policy.rego` is consumed outside the Rust
//! workspace: the arbiter-manager setup wizard imports its source
//! (`arbiter-manager/src/lib/default-policy.ts`) and installs it as a
//! community's first pipeline layer. Nothing in the Rust crates compiles it
//! before that install, so a broken default policy would only surface at
//! setup runtime. These tests read the source from the repo, apply the same
//! `${owner}` substitution the setup wizard performs
//! (`defaultPolicyWithOwner`), and compile it through the pipeline-layer
//! machinery (`validate_policy` — the same `PolicyVm` compile path
//! [`Layer::compile`] runs) exactly as an `installPolicy` would.

use arbiter_core::arbiter::validate_policy;

/// Location of the default policy source, relative to this crate's manifest
/// (`crates/arbiter-core`): the workspace root's `policies/` directory.
const DEFAULT_POLICY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../policies/arbiter/default-policy.rego"
);

/// The `${owner}` placeholder the setup wizard substitutes with the selected
/// admin DID before installing. Both the doc comment and the `allow` rule
/// carry it, so every occurrence must be replaced.
const OWNER_PLACEHOLDER: &str = "${owner}";

/// A fixture DID for the substitution. Shape only: compilation does not
/// resolve it.
const FIXTURE_OWNER: &str = "did:plc:defaultpolicyowner";

#[test]
fn default_policy_ships_with_the_owner_placeholder() {
    let source = std::fs::read_to_string(DEFAULT_POLICY_PATH)
        .expect("read the default policy source from the repo");
    assert!(
        source.contains(OWNER_PLACEHOLDER),
        "the default policy must carry the `{OWNER_PLACEHOLDER}` placeholder the \
         setup wizard substitutes"
    );
}

#[test]
fn default_policy_compiles_as_a_pipeline_layer() {
    let source = std::fs::read_to_string(DEFAULT_POLICY_PATH)
        .expect("read the default policy source from the repo");

    // The shipped source compiles as-is: the placeholder sits inside a string
    // literal, so nothing blocks compilation before substitution.
    validate_policy(&source).expect("the shipped default policy must compile");

    // The substituted form — the exact text an `installPolicy` would receive —
    // compiles too, and no placeholder occurrence survives the substitution.
    let installed = source.replace(OWNER_PLACEHOLDER, FIXTURE_OWNER);
    assert!(
        !installed.contains(OWNER_PLACEHOLDER),
        "the substitution must replace every `{OWNER_PLACEHOLDER}` occurrence"
    );
    validate_policy(&installed).expect("the substituted default policy must compile");
}