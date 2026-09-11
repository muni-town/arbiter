/**
 * This module no longer ships bootstrap machinery.
 *
 * Decision: the manager has no default policy at all. There is no published
 * shared default policy record; the default-policy URI placeholder — and the
 * import flow's app-password direct writes it existed to work around — have
 * been removed. Both setup flows and the policy tab's "Reset Config" sheet now
 * take operator-provided policy-layer `at://` URIs (published from the Library
 * tab, which is the publishing surface) plus trusted scopes, and write them
 * verbatim via `town.muni.arbiter.resetConfig`.
 *
 * `policies/arbiter/default-policy.rego` stays in the repo as the shipped
 * authoring reference template. Nothing in the manager imports it any more:
 * its only consumer is the compile-guard test
 * `crates/arbiter-core/tests/default_policy.rs`, which compiles it as a
 * pipeline layer and asserts it remains owner-agnostic — adminship is resolved
 * at evaluation time from each account's `town.muni.arbiter.simple.admins`
 * record, never a `${owner}` placeholder.
 */