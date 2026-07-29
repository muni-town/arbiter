# Arbiter Server Plan

A total rewrite of `arbiter-server`. The existing `crates/arbiter-server` code
(salvo, JSON-file persistence, the member/space XRPCs, the `atproto-proxy`
routing) is a throwaway — do not port from it. `arbiter-core` is unchanged and
already fits the model: `Policies { root_policy, sub_policies: HashMap<String, _> }`
maps directly onto the PDS record scheme below.

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

- `town.muni.arbiter.policy.root/self` — the root Rego policy.
- `town.muni.arbiter.policy.sub/<name>` — named sub-policies.

These map 1:1 onto `Policies::new(root, HashMap<name>)`.

### Startup

On boot the server fetches the latest root + sub-policies from each stewarded
account's PDS. **Fail closed**: until an arbiter's policies have loaded, it
refuses requests for that arbiter. Retry the fetch with exponential backoff.
Do not serve stale/unknown policy.

### Hot reload

The server subscribes to Jetstream and watches for writes to the
`town.muni.arbiter.policy.*` collections. On a policy update it reinstantiates
the arbiter so subsequent requests use the new policies.

**Monotonic versioning (required):** Jetstream can deliver reordered or
duplicate events. Track the last-applied `rev` (the repo commit `rev` from the
Jetstream commit event) per policy record key. Only apply an update when its
`rev` is strictly newer than the last-applied `rev` for that record; discard
older/duplicate events. Without this, a reordered event regresses policy — a
security bug in an enforcement server.

In-flight requests keep the old policy because `Arbiter::handle_request`
clones `Policies` per request.

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
- **Encryption at rest is still required** for app passwords and DID keys.
  Toasty is an ORM, not an encryption layer; encrypt credentials before
  storing. This is an explicit open implementation item, not solved by
  choosing Toasty.

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
4. Loads the (default/empty) policies and brings the arbiter online.

Config required: default PDS URL, invite code(s).

### Import existing account

`town.muni.arbiter.createAppPasswordArbiter` (import). The caller provides an
**app password** for an existing account (proving they control it). The server
stores the credentials in Turso and proceeds as above. Being able to log into
the existing account is itself the recovery guarantee — the holder can always
write policy records directly to the PDS repo (bypassing the arbiter), and the
arbiter reloads them via Jetstream.

> Bootstrap requests are **not** steady-state proxy requests: they use a
> built-in NSID, not `arbiter-proxy`, and the auth subject is the creator /
> importer, not (yet) a stewarded account acting through its arbiter.

## 7. Recovery

Recovery from a policy lockout is **direct PDS access** for now: whoever can
authenticate to the stewarded account's PDS writes the
`town.muni.arbiter.policy.*` records directly (bypassing the arbiter), and the
arbiter picks up the change via Jetstream. There is **no server-enforced reset
XRPC** in this phase — an arbiter-side escape hatch is future work.

The recovery-admin DID is still designated in a PDS record
(`town.muni.arbiter.recovery/self`), written at bootstrap (creator for new
accounts, importer for imports). The record documents who is intended to
recover, but the arbiter does not yet act on it.

**Known gap:** for new accounts the arbiter holds the credentials (random
password in Turso), so the creator does **not** have direct PDS access and
cannot self-recover via the record path until the escape hatch lands. For
imported accounts the holder retains PDS access and can reset directly.
Accepted for now.

## 8. HTTP

Switch from `salvo` to **`axum`**. The server is a transparent XRPC proxy with
two handler classes:

- Built-in NSIDs (`town.muni.arbiter.createArbiter`,
  `town.muni.arbiter.createAppPasswordArbiter`) — handled directly.
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

No `deleteArbiter` XRPC — arbiter teardown is automatic via the
`town.muni.arbiter.service/self` record (see §4, Lifecycle / auto-delete).

New record collections (not XRPCs):

- `town.muni.arbiter.service/self`
- `town.muni.arbiter.policy.root/self`
- `town.muni.arbiter.policy.sub/*`
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
- **Recovery escape hatch.** A server-enforced, scoped, audited policy-reset
  path for new accounts whose credentials the arbiter holds (the creator has
  no direct PDS access). Not now; recovery is direct-PDS-access-based until
  this lands (see §7).
- **Recovery-admin rotation/revocation.** The `town.muni.arbiter.recovery/self`
  record is editable by the account holder; formal transfer/revocation
  semantics deferred.