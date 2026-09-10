/**
 * Default policy helpers.
 *
 * The default policy is owner-agnostic: one copy can be published once and
 * referenced by every community's pipeline (adminship is resolved at
 * evaluation time from each account's `town.muni.arbiter.simple.admins`
 * record). Two bootstrap flows:
 *
 * - Create: provisions a brand-new account and points its config at
 *   {@link DEFAULT_POLICY_URI} — the `at://` URI of a shared, pre-published
 *   default policy record.
 * - Import: writes the default policy record (plus the admins + config
 *   records) directly into the steward's repo via the app-password session,
 *   so the flow is self-contained before the shared record exists.
 *
 * Once the shared record is published, the import flow can reference
 * {@link DEFAULT_POLICY_URI} instead of writing its own copy.
 */

import defaultPolicySource from '/policies/arbiter/default-policy.rego?raw';

/**
 * The `at://` URI of the shared default policy record referenced by the
 * create bootstrap flow.
 *
 * PLACEHOLDER: point this at the published default policy record when one
 * exists. Until then the create flow's bootstrap policy layers reference a
 * record that does not resolve, so a freshly bootstrapped arbiter fails
 * closed (denies everything) — which is the safe default for an
 * unconfigured community.
 */
export const DEFAULT_POLICY_URI = 'at://did:plc:TODO/town.muni.arbiter.policy/default';

/**
 * The rkey (policy name) of a default policy record in a community's repo,
 * e.g. `at://<did>/town.muni.arbiter.policy/default`. Kept for the PolicyTab
 * authoring flow.
 */
export const DEFAULT_POLICY_RKEY = 'default';

/**
 * The raw owner-agnostic default policy source (loaded at compile time via
 * the Vite raw import). The import flow writes it as the community's policy
 * record verbatim — no substitution.
 */
export const defaultPolicy = defaultPolicySource as string;
