/**
 * Default policy helpers.
 *
 * Getting started assumes PRE-EXISTING policies: the setup wizard does not
 * author any policy record. Both bootstrap flows (create + import) reference
 * {@link DEFAULT_POLICY_URI} — the `at://` URI of a shared, pre-published
 * default policy record.
 */

import defaultPolicySource from '/policies/arbiter/default-policy.rego?raw';

/**
 * The `at://` URI of the pre-existing default policy record referenced by
 * the bootstrap policy layers.
 *
 * PLACEHOLDER: point this at the published default policy record when one
 * exists. Until then the bootstrap policy layers reference a record that does
 * not resolve, so a freshly bootstrapped arbiter fails closed (denies
 * everything) — which is the safe default for an unconfigured community.
 */
export const DEFAULT_POLICY_URI = 'at://did:plc:TODO/town.muni.arbiter.policy/default';

/**
 * The rkey (policy name) of a default policy record in a community's repo,
 * e.g. `at://<did>/town.muni.arbiter.policy/default`. Kept for the PolicyTab
 * authoring flow.
 */
export const DEFAULT_POLICY_RKEY = 'default';

/**
 * The raw default policy source with the `${owner}` placeholder (loaded at
 * compile time via Vite raw import).
 */
export const defaultPolicy = defaultPolicySource as string;

/**
 * Substitute the `${owner}` placeholder in the default policy with the
 * given DID, returning the final policy string ready to write as a policy
 * record.
 *
 * Available for the PolicyTab authoring flow (write the record to the
 * steward's repo via the arbiter proxy, then append its URI via
 * installPolicy). NOT used at bootstrap: a shared pre-existing default
 * policy cannot bake a per-community `${owner}` — it would need to be
 * owner-agnostic instead (e.g. allow the caller matching the DID in the
 * account's `town.muni.arbiter.recovery/self` record, fetched via an `xrpc`
 * host function).
 */
export function defaultPolicyWithOwner(ownerDid: string): string {
  // The template contains `${owner}` in both the doc comment and the actual
  // `allow` rule, so replace every occurrence — a single `.replace` would only
  // fix the comment and leave the rule's placeholder intact.
  return defaultPolicy.replaceAll('${owner}', ownerDid);
}