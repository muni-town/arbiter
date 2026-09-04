# Arbiter Server Plan

A total rewrite of `arbiter-server`. The existing `crates/arbiter-server` code
(salvo, JSON-file persistence, the member/space XRPCs, the `atproto-proxy`
routing) is a throwaway — do not port from it. `arbiter-core` supplies the
model: an ordered policy pipeline (`arbiter_core::arbiter::Pipeline`) maps
directly onto the PDS record scheme below.

## 1. Identity & routing

An arbiter is **named after the single account it stewards**. The arbiter DID
*is* the stewarded account DID — one identity, used both to select the arbiter
instance and as the subject policy is evaluated for. There is no separate
"arbiter DID" vs "account DID".

The arbiter is **removed from the stewarded account's DID doc** (no `#arbiter`
service endpoint). Discovery is via a PDS record instead:

- `town.muni.arbiter.service/self` on the stewarded account's repo carries a
  `did` field pointing to the arbiter **server's** DID, e.g.
  `did:web:arbiter.example.com`.
- That arbiter-server DID's doc has an `#arbiter` service endpoint pointing at
  the server URL.

A client acting on a stewarded account: reads `town.muni.arbiter.service/self`
→ resolves the arbiter-server DID → reads `#arbiter` → sends requests there.

> **Caveat:** discovery couples to PDS availability — if the stewarded
> account's PDS is down, the client can't find the arbiter. The arbiter is not
> a PDS-outage escape hatch; it can't proxy to a dead PDS anyway. Accepted.

### Headers

Every steady-state request carries two headers:

- **`arbiter-did`** — the stewarded account DID. Selects the arbiter instance;
  becomes `data.arbiterDid`; its `#atproto_pds` becomes `data.pdsEndpoint`.
- **`arbiter-proxy`** — the destination, as `{did}#{serviceId}`
  (e.g. `did:plc:abc#atproto_pds`). The arbiter forwards here after policy
  allows. Becomes `input.xrpcEndpoint`.

`atproto-proxy` is gone — it was the standard header for routing to a
DID-doc-declared service, and the arbiter is no longer declared on any DID doc.

## 2. Authentication

Callers authenticate with a **serviceAuth token** (`com.atproto.server.getServiceAuth`)
issued by the caller's own PDS. The token is a short-lived JWT (default 60s
`exp`) signed by the caller's PDS.

- **`aud`** = the arbiter **server's** DID (the `did:web:...` from
  `town.muni.arbiter.service/self`), *not* the stewarded account DID — the
  stewarded DID no longer hosts a service. This is a change from the current
  `arbiter-manager` client, which sets `aud` to the community DID.
- **`lxm`** = the NSID of the XRPC being called (the request's path NSID).
  The server verifies `lxm` matches the path NSID. This scopes each token to a
  single method (least-privilege); it does **not** encode the destination —
  the destination lives in `arbiter-proxy`.
- **Signature verification** resolves the caller's `#atproto_pds` → PDS DID →
  PDS signing key, and verifies the JWT against that key. This is a different
  key-resolution path than "resolve the issuer's own DID-doc keys" — do not
  reuse the old `auth.rs` approach.
- **`sub`** (the caller DID) is extracted after verification and placed in the
  policy context as `data.callerDid`. The caller may differ from the stewarded
  account; policy uses `callerDid` vs `arbiterDid` to distinguish self-action
  from cross-account action.

Hot path: every request resolves the subject's `#atproto_pds` **and** the
caller's PDS signing key. Cache both (moka-style), not just DID docs.

## 3. Policy context

Rego `data` / `input` populated per request:

| Field | Source |
|---|---|
| `data.arbiterDid` | `arbiter-did` header (stewarded account) |
| `data.pdsEndpoint` | `arbiter-did#atproto_pds` (resolved) |
| `data.callerDid` | verified serviceAuth `sub` |
| `input.xrpcEndpoint` | `arbiter-proxy` header (destination) |
| `input.method` / `input.nsid` | request path NSID (== serviceAuth `lxm`) |
| `input.params` / `input.body` | query params or JSON body |

A subject DID with no `#atproto_pds` must produce a defined error, not a
panic/500-with-trace.

## 4. Policy storage & loading

Policies live as PDS records on the stewarded account's repo:

- `town.muni.arbiter.config/self` — the arbiter config: `trustedScopes`
  (NSID scopes accepted via the scoped `*.arbiter.proxy` endpoints) plus
  the ordered `at://` policy pipeline.
- `town.muni.arbiter.policy/<rkey>` — a named Rego policy (the rkey is
  the policy name), referenced from the config's `policyLayers` as
  `at://<did>/town.muni.arbiter.policy/<rkey>`. Remote (app-owned) shared
  policies use the same record shape in another repo.

### Startup

On boot the server loads each stewarded account's `config/self` record and
resolves its pipeline — fetching every referenced policy record (local or
remote) and compiling it. **Fail closed**: until an arbiter's config +
pipeline have loaded, it refuses requests for that arbiter. Each load is
retried with bounded exponential backoff; after repeated consecutive
failures the arbiter is left offboarded and a later Jetstream event or
restart retries. Do not serve stale/unknown policy.

### Hot reload

The server subscribes to Jetstream and watches for writes to the
`town.muni.arbiter.policy` collection in any repo — a shared policy-record
write reloads exactly the arbiters whose pipeline references it — and for
`town.muni.arbiter.config/self` writes in stewarded repos. On an update it
reinstantiates the arbiter so subsequent requests use the new pipeline.

**Monotonic versioning (required):** Jetstream can deliver reordered or
duplicate events. Track a per-arbiter `rev_floor` — the steward repo's
head `rev` (via `getRepoStatus`) captured before the records are read; if
the PDS reports none, the floor is unset. A steward-repo event with
`rev <= floor` describes state already reflected in the loaded records and
is discarded. Every accepted event re-runs the full load (re-reading the
PDS, never applying the event payload) and re-captures the floor from the
fresh head, so a reordered or duplicate event regresses nothing and no
per-record dedup map is needed. Events from other repos (remote
policy-record writes) skip the gate — each repo's `rev` stream is an
independent TID timeline — and only risk a redundant reload, never a
missed or regressed update.

In-flight requests keep the old pipeline: a request machine is built from
the arbiter's loaded pipeline at request start, so a concurrent reload
only affects subsequent requests.

### Lifecycle / auto-delete

There is no `deleteArbiter` XRPC. An arbiter tears itself down based on its own
service record. The server watches `town.muni.arbiter.service/self` on Jetstream
(and re-checks it at startup) and compares its `did` field to this server's own
DID:

- **Record absent** — stop serving the arbiter (remove it from the in-memory
  active set). Keep its Turso credentials; if the record reappears pointing
  back at this server, re-onboard. This avoids nuking state on a transient
  miss.
- **Record points to a different arbiter-server DID** — the account has been
  reassigned. Stop serving **and** purge that arbiter's credentials from Turso;
  this server is no longer the steward.

## 5. Server storage (Turso)

The arbiter server needs durable storage for PDS credentials (app passwords /
random passwords for accounts it created) and DID keys. Use **Turso** (libSQL)
with the **Toasty** ORM.

- **Single instance for now.** Arbiter state machines are in-memory,
  per-process. Turso is durable persistence for credentials, not a
  coordination layer. (Multi-instance is future work — see §10.)
- **Encryption at rest is deferred.** Passwords are currently stored in
  plaintext in the local Turso DB (see `storage.rs` for the explicit tradeoff).
  This was intentionally dropped from the production bar for now; password
  encryption (e.g. Turso whole-DB encryption or field-level AES-GCM) is a
  follow-up, not a launch requirement.

## 6. Bootstrap (built-in XRPCs)

The only built-in XRPCs are for creating arbiters. Two paths:

### New account

`town.muni.arbiter.createArbiter` (new account). The creator authenticates
**as themselves** via serviceAuth (`aud` = arbiter-server DID, `lxm` =
`town.muni.arbiter.createArbiter`). The server then:

1. Uses a configured **invite code** to call `com.atproto.server.createAccount`
   against a configured **default PDS**, with a **random password**.
2. Stores the resulting account DID + random password in Turso.
3. Writes the initial `town.muni.arbiter.service/self` and
   `town.muni.arbiter.recovery/self` records (see §7) to the new account's
   repo using the credentials it just stored.
4. Does **not** write any policy and does **not** bring the arbiter online:
   it stays offline (fail-closed) until it is configured. Bootstrap is
   out-of-band, by credential class:
   - **Imported accounts** (the manager holds the app password): the manager
     writes the default `town.muni.arbiter.policy` record and the initial
     `town.muni.arbiter.config/self` record directly to the repo via the
     app-password session (pre-arbiter — nothing installed yet, so there is
     no pipeline to gate it), and the arbiter comes online via Jetstream.
   - **Created accounts** (the manager holds no app password): the
     provisioning admin publishes the default policy record to their OWN
     repo (OAuth session), then calls `town.muni.arbiter.resetConfig` —
     they are the recovery admin per the freshly-written
     `recovery/self` record, and `resetConfig` is admin-only,
     offboarded-capable, shape-validated-only.
   `installPolicy` itself is for later app-initiated appends (see §7).
Config required: default PDS URL, invite code(s).

### Import existing account

`town.muni.arbiter.createAppPasswordArbiter` (import). The caller provides an
**app password** for an existing account (proving they control it). The server
stores the credentials in Turso and proceeds as above. Being able to log into
the existing account is itself the recovery guarantee — the holder can always
write policy records directly to the PDS repo (bypassing the arbiter), and
the arbiter reloads them via Jetstream.

> Bootstrap requests are **not** steady-state proxy requests: they use a
> built-in NSID, not `arbiter-proxy`, and the auth subject is the creator /
> importer, not (yet) a stewarded account acting through its arbiter.

## 7. Recovery

Recovery from a policy lockout is the server-enforced
`town.muni.arbiter.installPolicy` XRPC: APPEND semantics only. The
referenced policy layer (an existing `town.muni.arbiter.policy` record the
caller wrote to a repo beforehand — this endpoint never writes policy
records) is appended at the END of the pipeline (lowest priority) and
trusted scopes are unioned in; nothing already installed is ever removed or
reordered. When the merged config differs from the current one, it is
written to `town.muni.arbiter.config/self` in the stewarded repo via the
steward session — the config write is the install's activation point,
CAS-guarded against the repo head (putRecord swap_commit) and skipped
entirely on a no-op re-install. The arbiter is re-onboarded so it takes
effect. It works even when the installed policy blocks normal updates: the
gate is a plain identity check, not a policy evaluation.

The gate is the recovery admin designated in the account's
`town.muni.arbiter.recovery/self` PDS record. That record is the source of
truth: the server re-reads it from the repo on every `installPolicy` call,
so rewriting it rotates the admin with effect on the next call. The record
is written at provisioning/import time (did = the creator of a new account,
the importer of an app-password account); the server-side credential store
keeps only a bootstrap copy of the designation, used solely by repair to
re-write the record for half-provisioned accounts. If no (valid) recovery
admin is designated in the record, installPolicy is forbidden (fail-closed).

**Rotation:** rewriting `town.muni.arbiter.recovery/self` rotates the admin
with effect on the next `installPolicy` call; formal transfer/revocation
semantics are future work (see §11). For imported accounts the holder
retains PDS access and can additionally write policy records directly to
the repo (bypassing the arbiter), which the arbiter picks up via Jetstream.

## 8. HTTP

Switch from `salvo` to **`axum`**. The server is a transparent XRPC proxy with
two handler classes:

- Built-in NSIDs (`town.muni.arbiter.createArbiter`,
  `town.muni.arbiter.createAppPasswordArbiter`,
  `town.muni.arbiter.installPolicy`) — handled directly.
- Everything else — catch-all: verify serviceAuth, build policy context,
  evaluate policy via the arbiter's `StateMachine`, proxy to `arbiter-proxy`
  on allow, return the policy denial on deny.

Authn (serviceAuth verification + key resolution) is a tower layer/middleware;
policy evaluation + proxying is the handler.

## 9. Lexicon cleanup

Drop the member/space/config XRPCs — that data is now PDS records. Delete from
`lexicons/town/muni/arbiter/`:

`listSpaces`, `resolveSpaceMembers`, `getSpaceMembers`, `removeSpaceMember`,
`setSpaceMemberAccess`, `createSpace`, `deleteSpace`, `getSpaceConfig`,
`setSpaceConfig`, `getArbiterConfig`, `setArbiterConfig`, `createDid`,
`updateDidDoc`.

Surviving built-in XRPCs:

- `town.muni.arbiter.createArbiter`
- `town.muni.arbiter.createAppPasswordArbiter`
- `town.muni.arbiter.installPolicy`

No `deleteArbiter` XRPC — arbiter teardown is automatic via the
`town.muni.arbiter.service/self` record (see §4, Lifecycle / auto-delete).

New record collections (not XRPCs):

- `town.muni.arbiter.service/self`
- `town.muni.arbiter.config/self`
- `town.muni.arbiter.policy/<rkey>` (rkey = policy name)
- `town.muni.arbiter.recovery/self`

## 10. Testing

`arbiter-core` is tested. The server has no tests. The riskiest new behavior
is the Jetstream reload path; add an integration test:

- Fake PDS + fake Jetstream.
- A policy update applies to subsequent requests.
- An out-of-order / older `rev` is rejected (no regression).
- A duplicate event is not re-applied.

Plus: serviceAuth verification (valid/invalid/expired/wrong-`lxm`/wrong-`aud`),
fail-closed at startup (PDS unreachable → requests refused), the
create-new-account provisioning flow (invite code → account created →
credentials stored → arbiter online), and auto-delete (service record removed
→ arbiter stops serving but keeps credentials; service record repointed at
another server → arbiter stops serving and purges credentials).

## 11. Future / out of scope

- **Multi-instance.** Two replicas loading the same arbiter diverge on policy
  and race on `createArbiter`. Needs an ownership/partitioning layer (which
  replica owns which arbiter DID) before horizontal scale. Not now.
- **Recovery-admin rotation/revocation.** Rotation exists: rewriting the
  `town.muni.arbiter.recovery/self` record rotates the admin with effect on
  the next `installPolicy` call (the server-side stored designation is only
  the bootstrap value for repairing half-provisioned accounts). Formal
  transfer/revocation semantics and manager UX deferred.