# Arbiter Scopes + Policy Pipeline — alignment plan (Progress Report 4)

Source: https://zicklag.leaflet.pub/3muq24tg6lc2a (2026-09-04).
Decisions locked with Zicklag on 2026-09-08. Implemented 2026-09-08
(workstream E / simulator deferred by design decision; first pass = trusted
scopes only, decision 4).

## Problem

Current arbiter: a single `town.muni.arbiter.proxy` endpoint means OAuth can only
grant all-or-nothing `rpc:town.muni.arbiter.proxy` across every community account
an admin manages, with no user-visible, granular consent. The root+sub policy
model also forces per-account policy pushes (a Romy-wide policy change = 4k
record updates).

## Decisions (locked)

1. **Reach path — through the PDS proxy.** Apps OAuth into the user's PDS with
   scope `rpc:<scope>.arbiter.proxy?aud=<arbiter did#arbiter>` (or an
   `include:` permission set bundling it), then call
   `/xrpc/<scope>.arbiter.proxy` with `atproto-proxy: <arbiter-did>#arbiter`.
   The PDS enforces the scope grant; the arbiter keeps verifying serviceAuth.
   No resource-server role for the arbiter. Long term, layer 1 moves into the
   PDS ("the hope is that long term we will not have to have layer 1 in the
   arbiter, because it will be in the PDS").
2. **Trusted scopes live in a per-account PDS record** (the community config),
   read like policy records, hot-reloaded over Jetstream.
3. **Layer-1 policy is embedded as a field in the permission-set lexicon**
   itself; the arbiter resolves the permission set for the stripped NSID
   prefix.
4. **First pass: only whitelisted (trusted) scopes are accepted at all.**
   Non-trusted scopes are rejected outright — no structural namespace
   enforcement is needed yet; it comes later.
5. **Policy pipeline = ordered list, every entry an at:// URI.** Custom
   policies are policy records in the community repo referenced by at:// URI;
   remote (app-owned) shared policies are the same shape in another repo.
6. **Remote at:// layers refresh via Jetstream** (watch referenced records;
   refetch gated by repo rev, like current policy reloads).
7. **installPolicy is gated on the recovery admin designated in the repo.**
   The `town.muni.arbiter.recovery/self` record is the source of truth — the
   arbiter re-reads it on every installPolicy call, and rewriting it rotates
   the admin with effect on the next call (identity gate, not a scope gate:
   even serviceAuth minting requires an `rpc:` scope, so scopes cannot
   distinguish installers). The server-side store keeps only the password
   (private) and a bootstrap designation of the admin, used solely to
   create/repair the record for half-provisioned accounts. (2026-09-09
   revision of the original stored-admin gate; the record is now lexiconed.)
   (2026-09-09 second revision — append semantics:) installPolicy APPENDS
   one policy layer — by at:// URI reference ONLY (the caller writes the
   policy record to a repo first; no inline policies) — to the END of the
   pipeline and APPENDS trusted scopes (union, deduped); it never removes
   or reorders existing entries. The pipeline gates
   the request (handleBuiltin → the built-in performs the append; the
   recovery admin bypasses). Full config control stays with the admin via
   direct config-record writes (normal operation) or resetConfig
   (recovery).
8. **Scope policy = pure allow/deny predicate on the request core.**
   Entrypoint `data.arbiter.allow` → boolean (`true` = in the virtual scope;
   false/undefined/non-boolean/VM error → deny, fail-closed). Input is the
   request core `{method, nsid, parameters, body, encoding}` only — no
   context fields (account/endpoint/caller context is layer-2 territory). No
   host functions; compilation rejects them.
9. **Pipeline layer contract: pass / handle / deny.** First layer that handles
   or denies wins; falling off the end denies by default.
10. **Hard cut.** No auto-migration from `policy.root`/`policy.sub`;
    deployed arbiters are re-provisioned via installPolicy.

## Request flow (end-to-end)

1. App login: OAuth against the user's PDS requesting
   `include:community.lexicon.authCalendar` (or the raw
   `rpc:community.lexicon.authCalendar.arbiter.proxy?aud=...`). The PDS
   consent screen renders title/detail from the permission-set lexicon.
2. App → user's PDS `/xrpc/community.lexicon.authCalendar.arbiter.proxy` with
   `atproto-proxy: <arbiter-did>#arbiter`.
3. PDS validates the token's `rpc:` scope (lxm + aud) and forwards to the
   arbiter with the user's serviceAuth (`iss` = user DID, `aud` =
   `<arbiter did>#arbiter`, `lxm` = the scoped NSID).
4. Arbiter verifies serviceAuth and routes by the lxm wildcard
   `*.arbiter.proxy`.
5. **Layer 1 (scope gate).** Strip the `.arbiter.proxy` suffix → prefix
   `community.lexicon.authCalendar`; require prefix ∈ the account's
   `trustedScopes` (config record); resolve the permission-set lexicon for the
   prefix (NSID authority resolution, cached); evaluate its embedded Rego as a
   host-fn-free predicate over the request core — entrypoint
   `data.arbiter.allow`, input `{method, nsid, parameters, body, encoding}`.
   Deny → 403.
6. **Layer 2 (community pipeline).** Evaluate the config record's ordered
   at:// layers: `pass` → next layer; `handle` → return the policy-issued
   response; `deny` → error response. End of list → deny. Layers run on the
   full engine (the `xrpc` host fn is allowed here).
7. Policy-issued remote xrpc executes as the steward — `proxy.rs` machinery
   unchanged.

## Lexicon / record surface

New:
- `town.muni.arbiter.config` (record, `literal:self`):
  `trustedScopes: string[]` (prefix NSIDs), `policyLayers: string[]` (ordered
  at:// URIs). One record = atomic install + one Jetstream collection.
- `town.muni.arbiter.policy` (record, rkey = policy name): `policy: string`
  (Rego source). Referenced as `at://<did>/town.muni.arbiter.policy/<rkey>`.
- `town.muni.arbiter.simple.admins` (record, `literal:self`):
  `admins: did[]` — designates the account's day-to-day admins. The default
  policy fetches it via the `xrpc` host function at evaluation time and
  gates everything on membership (steward self-calls always pass), making
  the default policy owner-agnostic and publishable once for all
  communities; rewriting the record rotates day-to-day adminship. The
  `town.muni.arbiter.recovery/self` record remains the separate, ultimate
  trust root for `resetConfig`.
- `town.muni.arbiter.installPolicy` (procedure): body
  `{arbiterDid, trustedScopes?, policyLayers, policies?: [{rkey, policy}]}`.
  Writes policy + config records to the community repo via the steward
  session (`putRecord` with `swap_commit` CAS), then reloads the arbiter.
  Replaces `resetPolicy`.
- Permission-set extension field: the embedded Rego inside the permission-set
  lexicon def. Exact key TBD at implementation (e.g.
  `defs.main["x-town-muni-arbiter"] = { policy: "<rego>" }`); must verify
  lexicon-schema tolerance for extra keys, else adopt a documented
  arbiter-side convention.

Retired (hard cut): `town.muni.arbiter.policy.root`,
`town.muni.arbiter.policy.sub`, `town.muni.arbiter.resetPolicy`.

Kept unchanged: `town.muni.arbiter.proxy` (owner/manager path; the default
policy hands management NSIDs to the built-in for admins), `createArbiter`,
`createAppPasswordArbiter`, `service`, `recovery`.

## Implementation workstreams

### A. arbiter-core
- Replace `Policies` (root + named subs) with a pipeline: ordered `Vec<Layer>`,
  each layer = compiled `PolicyVm` + provenance (at:// URI, record CID/rev).
- Evaluation loop in `ArbiterReqMachine::drive_loop`: interpret layer outputs
  as pass/handle/deny (envelope convention: `{ "pass": true }`, or the
  existing ok/err envelope for handle/deny). Remove the `policy` host fn and
  the `MAX_POLICY_DEPTH` machinery — composition is now positional.
- New pure scope evaluator: `PolicyVm` compiled with **no** host functions,
  entrypoint returns ok/err; synchronous (cannot suspend on host calls).
- Validate embedded scope policies at resolve time (compile without host fns;
  malformed → treat the scope as untrusted/deny).

### B. arbiter-server
- Routing (`handlers.rs`): the `/xrpc/{nsid}` catch-all gains a wildcard
  branch — any nsid ending in `.arbiter.proxy` routes to the scoped proxy
  handler; the lxm==nsid check already covers it. Built-ins stay explicit.
- `CallerDid` (`auth.rs`): accept `aud` as the bare server DID **or**
  `<server_did>#arbiter`. Current strict equality
  (`auth.rs: aud != CONFIG.server_did`) rejects the fragment form the PDS
  sends when proxying.
- Community config + policy records: load in `policy.rs::load_and_onboard`;
  add `town.muni.arbiter.config` + `town.muni.arbiter.policy` to
  `WATCHED_COLLECTIONS` (`jetstream.rs`); fail-closed when config or pipeline
  is absent (extends the existing `begin_request` offboarded-DID gating).
- Remote layer resolution: at:// → (DID, collection, rkey) → getRecord against
  the target repo's PDS (reuse `resolver.rs`); cache keyed by (uri, cid);
  maintain a reverse index uri → stewarded arbiters so Jetstream events for
  `town.muni.arbiter.policy` in *any* repo reload exactly the arbiters that
  reference it.
- Permission-set resolver: NSID prefix → authority (e.g. `community.lexicon.*`
  → `lexicon.community`) → lexicon document via the lexicon publication
  mechanism (well-known HTTP + DNS TXT); cache with a TTL (model the AS's
  24h-stale / 90d-refresh behavior, simplified); extract + compile the
  embedded Rego.
- `installPolicy` handler: caller == the `did` in the freshly-read
  `town.muni.arbiter.recovery/self` record (identity gate — rewriting the
  record rotates the admin; fail closed when absent); CAS record writes via
  the steward session; reload the arbiter.
- Remove the `resetPolicy` handler and root/sub record loading.
- Lifecycle: "online" = service record + valid config + resolvable pipeline;
  anything missing → fail-closed (offboarded), consistent with current
  semantics.

### C. Lexicons (typelex + JSON)
- Add `config`, `policy`, `installPolicy`; update the `proxy` lexicon to
  document the `*.arbiter.proxy` family; regenerate JSON from `main.tsp`.

### D. arbiter-manager
- Replace the root/sub policy editor + `resetPolicy` flow with: pipeline
  editor (ordered at:// list; create/edit policy records; reorder), trusted
  -scope editor, and an install flow that calls `installPolicy` as the reset
  admin. The setup wizard's default policy becomes a policy record + a single
  -entry pipeline.
- The import bootstrap writes the owner-agnostic default policy record
  verbatim (no per-community substitution), the
  `town.muni.arbiter.simple.admins` self record naming the importing
  account, and the config record, all into the steward's repo via the
  app-password session — self-contained until a shared default policy record
  is published (then the manager could reference it instead of the local
  write).
  Superseded 2026-09-10: no shared default policy record was ever published;
  the import bootstrap no longer writes records via the app-password session
  at all. Both setup flows take operator-provided policy-layer `at://` URIs
  plus trusted scopes and bootstrap via `resetConfig` (see TODO.md).

### E. arbiter-simulator
- Model the scope gate + pipeline layers in the node graph (this is the demo
  surface for the Romy integration).

### F. Tests
- Core: pass/handle/deny ordering; fall-off-the-end deny; pure scope evaluator
  (no host fns); layer provenance.
- Server integration: scoped endpoint through a fake PDS proxy (serviceAuth
  with `#arbiter` aud); untrusted scope prefix rejected; installPolicy
  authorization (recovery admin only); Jetstream reload of a remote layer
  update; fail-closed when config/pipeline absent.
- Update existing integration tests for the hard cut.

## Sequencing

1. Core engine (A) + core tests.
2. Lexicons (C) + config/policy record loading + Jetstream widening (B).
3. Scoped routing + permission-set resolution + layer-1 gate (B).
4. installPolicy + manager (B, D).
5. Simulator + default policy as record (E).
6. Integration tests + local dev-PDS verification.

## Open items / risks

- Exact extension field in the permission-set lexicon — confirm lexicon
  schemas tolerate extra keys; coordinate with the permission-set spec.
- Lexicon resolution is new infra (well-known HTTP + DNS TXT);
  `resolver.rs` today only resolves DIDs.
- Watched collections now include records in arbitrary repos (remote layers);
  the reload handler needs the uri→arbiter index to avoid refetch storms.
- `town.muni.arbiter.proxy` retention for non-owner callers is undecided —
  fold into the trusted-scope model or deprecate later.