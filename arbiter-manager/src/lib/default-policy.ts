/**
 * Default Rego policy loaded at compile time via Vite raw import.
 *
 * The policy file contains a `${owner}` placeholder that must be
 * replaced with the actual owner DID before sending to the arbiter.
 */

import defaultPolicySource from '/policies/arbiter/default-policy.rego?raw';

/**
 * The raw default policy source with the `${owner}` placeholder.
 */
export const defaultPolicy = defaultPolicySource as string;

/**
 * Substitute the `${owner}` placeholder in the default policy with the
 * given DID, returning the final policy string ready to send to the arbiter.
 */
export function defaultPolicyWithOwner(ownerDid: string): string {
  // The template contains `${owner}` in both the doc comment and the actual
  // `allow` rule, so replace every occurrence — a single `.replace` would only
  // fix the comment and leave the rule's placeholder intact.
  return defaultPolicy.replaceAll('${owner}', ownerDid);
}