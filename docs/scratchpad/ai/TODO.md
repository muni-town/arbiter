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
- **Decision — no shipped default policy; bootstrap is operator-provided.**
  The default-policy URI placeholder and the import flow's app-password
  direct writes are gone. Both setup flows ask the operator for one or more
  `town.muni.arbiter.policy` `at://` URIs (published from the Library tab —
  the referenced records must already exist) plus optional trusted scopes and
  bootstrap via `town.muni.arbiter.resetConfig`; the policy tab's "Reset
  Config" sheet is the recovery/bootstrap surface. The shipped
  `policies/arbiter/default-policy.rego` remains only as the authoring
  reference template (compiled by
  `crates/arbiter-core/tests/default_policy.rs`). If a shared default policy
  is ever published after all, keep it owner-agnostic: no `${owner}` —
  adminship must keep resolving from each account's
  `town.muni.arbiter.simple.admins` record at evaluation time.
- **Admins-record editor.** With bootstrap no longer writing a
  `town.muni.arbiter.simple.admins` record, policies that fetch it (the
  reference template does) have no UI surface to create/update it — the
  Library tab only manages `town.muni.arbiter.policy` records. Add an admins
  editor (PolicyTab section or Library extension).

## Manager

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

- **Persist the record store to `cache.db` (deferred 2026-09-12).** The
  in-memory record store (moka, jetstream-fed, rev-gated — see
  `crates/arbiter-server/src/record_store.rs`) plus the jetstream-cursor
  resume makes reconnects cheap, but a process restart still re-fetches every
  record on first reference (~4k accounts × service/config/layers). The
  planned shape: keep moka as the serving layer (per-key coalescing needs it);
  add a separate `cache.db` (turso, same driver as the credstore) as
  write-through durability — store mutations enqueue into a dirty set flushed
  every couple of seconds (`record_cache(uri PRIMARY KEY, rev, source_json,
  cid)`); boot loads it into moka, then subscribes with the persisted cursor.
  Freshness gate unchanged: replayed events apply rev-gated; the first-replayed
  event is checked against the persisted cursor and an unverified gap wipes
  the table and cold-fetches (same failure mode as today). Recovery records
  stay excluded. Only worth it if restarts are frequent enough for the boot
  storm (~12k fetches → ~4k rev fetches) to matter.

## Known acceptable behavior (documented, not bugs)

- `installPolicy` append is idempotent but scope union/ordering means
  re-installs never reorder existing layers (by design).
- TOCTOU between pipeline evaluation and the CAS'd config write: decisions are
  made against possibly-stale policies; the repo-head CAS prevents lost
  updates. Accepted for admin endpoints.