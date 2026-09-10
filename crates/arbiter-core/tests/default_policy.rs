//! Build-time compile check for the shipped default policy.
//!
//! `policies/arbiter/default-policy.rego` is consumed outside the Rust
//! workspace: the arbiter-manager setup wizard imports its source
//! (`arbiter-manager/src/lib/default-policy.ts`) and installs it as a
//! community's first pipeline layer. Nothing in the Rust crates compiles it
//! before that install, so a broken default policy would only surface at
//! setup runtime. These tests read the source from the repo and compile it
//! through the pipeline-layer machinery (`validate_policy` — the same
//! `PolicyVm` compile path [`Layer::compile`] runs, with the `xrpc` host
//! function allowed) exactly as an `installPolicy` would.

use arbiter_core::arbiter::validate_policy;

/// Location of the default policy source, relative to this crate's manifest
/// (`crates/arbiter-core`): the workspace root's `policies/` directory.
const DEFAULT_POLICY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../policies/arbiter/default-policy.rego"
);

/// The `${owner}` placeholder the default policy used to carry. It must stay
/// owner-agnostic — adminship is resolved at evaluation time from the
/// account's `town.muni.arbiter.simple.admins` record — so one shared copy
/// can be published for all communities.
const OWNER_PLACEHOLDER: &str = "${owner}";

#[test]
fn default_policy_is_owner_agnostic() {
    let source = std::fs::read_to_string(DEFAULT_POLICY_PATH)
        .expect("read the default policy source from the repo");
    assert!(
        !source.contains(OWNER_PLACEHOLDER),
        "the default policy must stay owner-agnostic — no `{OWNER_PLACEHOLDER}` \
         placeholder: adminship comes from the `town.muni.arbiter.simple.admins` \
         record at evaluation time"
    );
}

#[test]
fn default_policy_compiles_as_a_pipeline_layer() {
    let source = std::fs::read_to_string(DEFAULT_POLICY_PATH)
        .expect("read the default policy source from the repo");

    // The shipped source is installed verbatim — no substitution — and must
    // compile as a pipeline layer, host functions included (the `xrpc` fetch
    // of the admins record).
    validate_policy(&source).expect("the shipped default policy must compile");
}