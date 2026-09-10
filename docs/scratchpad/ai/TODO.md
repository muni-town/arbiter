# Arbiter TODO — open items

Companion to `arbiter-scopes-policy-pipeline.md` (the design/decision record). All
items below are non-blocking follow-ups deferred during the 2026-09-08/09
implementation sprint. Nothing here blocks the change set from being committed.

## Pre-deployment (Roomy cutover, 4k spaces)

- **Rewrite Roomy policies for the new engine.** The hard cut removed the
  `policy` host function and the root/sub record model; existing Romy Rego must
  be re-expressed as one or more `town.muni.arbiter.policy` records using the
  layer outcome vocabulary (`pass` defers, ok/err envelope handles/denies,
  `{"handleBuiltin": true}` hands to built-in; sub-policies become separate
  records referenced as later layers, or inline Rego).
- **Per-space cutover.** Every space is offline (fail-closed) until it has a
  `town.muni.arbiter.config/self` record. Two paths: (a) `resetConfig` loop —
  the Roomy appview is each space's recovery admin (per the space's
  `recovery/self` record); (b) direct PDS writes of the config record via the
  app-password sessions Roomy holds — staggerable, no recovery gate involved.
  Decide which; both keep spaces deny-all until migrated.
- **Seed `trustedScopes` in the migration config.** `resetConfig` sets scopes
  wholesale — spaces' scoped endpoints 403 until the migration config carries
  the scope NSIDs their apps were using.
- **Publish the shared default policy record.** `DEFAULT_POLICY_URI` in
  `arbiter-manager/src/lib/default-policy.ts` is a placeholder; publish the
  project's (owner-agnostic) default policy — the shipped
  `policies/arbiter/default-policy.rego`, which resolves adminship per
  community from each account's `town.muni.arbiter.simple.admins` record —
  as a shared record and point the constant at it. Then the import
  bootstrap can reference the shared record instead of writing a
  per-community copy.

## Manager

- **`resetConfig` OAuth scope.** The client metadata does not carry
  `rpc:town.muni.arbiter.resetConfig?aud=*` yet — add it when a UI surface
  calls `resetConfig` (the import flow currently bootstraps via app-password
  writes, so nothing calls it from the UI). Adding a scope invalidates
  existing localhost grants; do it deliberately.
- **PolicyTab Add-Policy duplicate-URI dedupe.** Add-Policy can push an entry
  duplicating an Add-Reference URI (rkey-vs-uri identity mismatch) → duplicate
  layer evaluation on Install. (Review5, P3)
- **PolicyTab stale-load guard.** `PolicyTab.load()` has no guard when
  switching communities mid-fetch — a slow earlier load can overwrite the
  newer community's editor state. (Review5, P3)
- **Prefer remote references for app-owned policies.** The install flow
  supports Add-Reference but defaults to writing local records; for shared
  policies (one record, 4k referencers) make the remote-reference path the
  prominent UX so operators don't stamp thousands of local copies. (Review5,
  "policy registry" discussion)

## Engine / server

- **Reverse-index window.** A policy-record write landing between a load's
  record fetch and its `index_pipeline` call is missed until the next event,
  reconnect, or restart. Sub-second, self-healing — a fix would be a
  re-scan/refetch guard after indexing. (Review5, P3)
- **Structural namespace enforcement for non-trusted scopes.** Deferred by
  decision 4 (first pass: only whitelisted scopes are accepted at all). When
  non-whitelisted scopes are supported, enforce in host code that their
  requests only touch NSIDs/collections under the scope's own prefix —
  structurally, not by Rego convention. (Blog "caveats" section.)
- **`town.muni.arbiter.proxy` retention.** The legacy all-or-nothing proxy
  endpoint is kept for the owner/manager path; undecided whether it folds into
  the trusted-scope model or gets deprecated. (Plan doc open item.)
- **Regorus VM memory at scale.** Each serving arbiter holds clones of its
  compiled layers' VMs; measure at 4k-arbiter scale. If it matters, the lever
  is a copy-on-write / shared-read VM architecture in `arbiter-core`.
  ("Policy registry" discussion — storage dedup already exists via remote
  `at://` references + `LAYER_CACHE`.)
- **Policy record read cache — not yet; explore the host-fn shape first.**
  The default policy fetches the `town.muni.arbiter.simple.admins` record
  through the `xrpc` host function on every request — one extra PDS
  round-trip per request. Caching is deliberately deferred for now. When we
  pick it up, explore whether authorization-data reads want a **new `record`
  host function** with automatic firehose-based caching (records keyed
  (repo, collection, rkey) → (cid, value), maintained by the unfiltered
  Jetstream subscription the server already runs — push-not-pull, always
  fresh, no policy-visible TTL decisions) **or whether `xrpc` can be
  integrated with caching properly** instead (e.g. transparent read-through
  caching for getRecord-shaped calls against watched repos, with the cache
  key including the acting steward DID since private-record visibility
  differs per session). Explicit TTL/cache-hint parameters on `xrpc` remain
  the escape hatch for genuinely remote, non-record lookups either way.
  The firehose-fed model means the arbiter + Jetstream already acts as the
  local authorization engine — no separate SpiceDB-style server needed.

## Known acceptable behavior (documented, not bugs)

- `installPolicy` append is idempotent but scope union/ordering means
  re-installs never reorder existing layers (by design).
- TOCTOU between pipeline evaluation and the CAS'd config write: decisions are
  made against possibly-stale policies; the repo-head CAS prevents lost
  updates. Accepted for admin endpoints.