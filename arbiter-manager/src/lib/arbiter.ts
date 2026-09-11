/**
 * Arbiter XRPC helpers for the arbiter-manager UI.
 *
 * Provides a single `arbiter` object with methods to:
 *  - Obtain a service auth token scoped to the arbiter-server DID.
 *  - Read / write PDS records proxied through the arbiter's `town.muni.arbiter.proxy`
 *  - Read the community config record (trusted scopes + policy layers) and
 *    the policy records it references.
 *  - Append ONE policy layer — an `at://` URI of a `town.muni.arbiter.policy`
 *    record — and trusted scopes via `town.muni.arbiter.installPolicy`
 *    (approved by the installed policy layers via a `handleBuiltin` layer outcome;
 *    the recovery admin bypasses the layers). Appends only: existing layers
 *    and scopes are never removed or reordered, and no records are written —
 *    locally authored policies are published first via the proxied
 *    `putRecord` path and then installed by URI.
 *  - Replace the community config wholesale via `town.muni.arbiter.resetConfig`
 *    (recovery-admin-only recovery hatch; no policy evaluation, works while
 *    the arbiter is offline). Both setup flows bootstrap a freshly provisioned
 *    arbiter through it, and the policy tab's "Reset Config" sheet is the
 *    operator-facing recovery surface.
 *  - Discover whether a stewarded account has an arbiter service record.
 *  - Provision a new arbiter, or import an existing account via app password.
 */

import { PUBLIC_ARBITER_URL, PUBLIC_ARBITER_DID } from '$env/static/public';
import { xrpc, type LexMap, isDidString, isNsidString, isAtUriString, encodeLexBytes } from '@atproto/lex';
import { XrpcResponseError } from '@atproto/lex';
import type { AtprotoDid } from '@atcute/lexicons/syntax';
import * as town from '$lib/lexicons/town';
import * as com from '$lib/lexicons/com';
import { auth } from '$lib/auth.svelte';
import { didResolver } from '$lib/resolver';

/** Policy record collection (rkey = the policy name). */
export const POLICY_COLLECTION = 'town.muni.arbiter.policy';

/** Community config record collection + rkey. */
const CONFIG_COLLECTION = 'town.muni.arbiter.config';
const CONFIG_RKEY = 'self';

/** Service record collection + rkey (discovery). */
const SERVICE_COLLECTION = 'town.muni.arbiter.service';
const SERVICE_RKEY = 'self';

/** The `did#service` fragment for a steward's PDS. */
const AT_PROTO_PDS_FRAGMENT = 'atproto_pds';

/** Starter Rego source for a new policy layer entry. */
export const NEW_POLICY_TEMPLATE =
  '# A policy layer. The layers are evaluated in order:\n' +
  '#   { "pass": true }             — defer to the next layer\n' +
  '#   { "handleBuiltin": true }    — hand off to the arbiter\'s built-in handler\n' +
  '#   { "ok": true, "output": ... }  — handle: respond / proxy the request\n' +
  '#   { "ok": false, "error": ... }  — deny the request\n' +
  '\n' +
  'package arbiter\n' +
  '\n' +
  'result := { "pass": true }\n';

/** The community config record: trusted scopes + ordered policy layers. */
export interface ArbiterConfig {
  /** NSID scopes the arbiter accepts; a scoped request's scope must match one exactly. */
  trustedScopes: string[];
  /** Ordered `at://` URIs of policy records. */
  policyLayers: string[];
}

/** Minimal DID document shape we care about (for PDS endpoint discovery). */
interface MinimalDidDoc {
  service?: { id?: string; type?: string; serviceEndpoint?: string }[];
}

/** A single proxied XRPC operation to run against a stewarded account. */
export interface ProxyOperation {
  /** The inner XRPC method NSID (e.g. `com.atproto.repo.getRecord`). */
  nsid: string;
  /** HTTP method for the inner request. */
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** Optional query parameters for the inner request. */
  parameters?: LexMap;
  /** Optional JSON body for the inner request. */
  body?: LexMap;
  /** Optional raw-bytes body for the inner request (e.g. a blob upload). */
  bytes?: Uint8Array;
  /** Optional content-type (encoding) for the inner request body. */
  encoding?: string;
}

/** A proxied record value returned by the arbiter. */
type RecordValue = Record<string, unknown>;
/**
 * A failed public record fetch, carrying the HTTP status (and the XRPC error
 * code from the response body, when present) so callers can distinguish
 * "record missing" from network / server failures.
 */
export class PublicRecordError extends Error {
  constructor(
    message: string,
    /** HTTP status code of the failed response. */
    readonly status: number,
    /** The XRPC error code from the response body, if any (e.g. `RecordNotFound`). */
    readonly code?: string,
  ) {
    super(message);
    this.name = 'PublicRecordError';
  }
}

/** Read the string `policy` field off an arbitrary record value, if present. */
function policySource(value: unknown): string | undefined {
  if (value && typeof value === 'object' && 'policy' in value) {
    const candidate = value.policy;
    if (typeof candidate === 'string') return candidate;
  }
  return undefined;
}

/** The parsed parts of an `at://` record URI. */
export interface AtUriParts {
  did: string;
  collection: string;
  rkey: string;
}

/**
 * Parse an `at://<did>/<collection>/<rkey>` record URI into its parts, or
 * return `null` if it is malformed.
 */
export function parseAtUri(uri: string): AtUriParts | null {
  const match = /^at:\/\/([^/]+)\/([^/]+)\/(.+)$/.exec(uri);
  if (!match) return null;
  const [, did, collection, rkey] = match;
  return { did, collection, rkey };
}

/**
 * Parse the setup bootstrap step's textarea input: one policy-layer `at://`
 * URI per line (in evaluation order; at least one required) plus optional
 * trusted-scope NSIDs, one per line. This is only client-side sanity —
 * `resetConfig` writes the entries verbatim — but it catches malformed or
 * non-policy URIs before an arbiter is bootstrapped against them. Throws
 * with a line-numbered message on the first bad entry.
 */
export function parseBootstrapConfig(
  policyLayersText: string,
  trustedScopesText: string,
): ArbiterConfig {
  const policyLayers: string[] = [];
  for (const [i, line] of policyLayersText.split('\n').entries()) {
    const uri = line.trim();
    if (!uri) continue;
    const parts = parseAtUri(uri);
    if (!parts) {
      throw new Error(
        `Policy layer line ${i + 1}: not a valid \`at://<did>/<collection>/<rkey>\` URI`,
      );
    }
    if (parts.collection !== POLICY_COLLECTION) {
      throw new Error(
        `Policy layer line ${i + 1}: the referenced record must be a \`${POLICY_COLLECTION}\` record`,
      );
    }
    if (policyLayers.includes(uri)) {
      throw new Error(`Policy layer line ${i + 1}: duplicate policy layer URI`);
    }
    policyLayers.push(uri);
  }
  if (policyLayers.length === 0) {
    throw new Error('Enter at least one policy layer `at://` URI');
  }

  const trustedScopes: string[] = [];
  for (const [i, line] of trustedScopesText.split('\n').entries()) {
    const scope = line.trim();
    if (!scope) continue;
    if (!isNsidString(scope)) {
      throw new Error(`Trusted scope line ${i + 1}: not a valid NSID`);
    }
    if (trustedScopes.includes(scope)) {
      throw new Error(`Trusted scope line ${i + 1}: duplicate scope`);
    }
    trustedScopes.push(scope);
  }

  return { trustedScopes, policyLayers };
}

/** Build the `at://` URI of a policy record in a steward's repo. */
export function policyUri(did: string, rkey: string): string {
  return `at://${did}/${POLICY_COLLECTION}/${rkey}`;
}

/**
 * Resolve the `did#atproto_pds` service endpoint for an account from its DID
 * document. Throws if no such service exists.
 */
async function resolvePdsEndpoint(did: string): Promise<string> {
  const doc = (await didResolver.resolve(did as AtprotoDid)) as MinimalDidDoc;
  const pdsService = (doc.service ?? []).find((s) => {
    const id = typeof s.id === 'string' ? s.id.replace(/^#/, '') : '';
    return id === 'atproto_pds' && typeof s.serviceEndpoint === 'string';
  });
  if (!pdsService || typeof pdsService.serviceEndpoint !== 'string') {
    throw new Error(`no #atproto_pds service in DID doc for ${did}`);
  }
  return pdsService.serviceEndpoint;
}

export const arbiter = {
  /**
   * Obtain a service auth token scoped to the arbiter-server DID.
   *
   * The `aud` is always `PUBLIC_ARBITER_DID` (the arbiter server), and `lxm`
   * scopes the token to a single XRPC method. The token authorizes the caller
   * to act on behalf of the authenticated account when talking to the arbiter.
   */
  async getServiceAuth(lxm: string): Promise<string> {
    if (!auth.client) throw new Error('Not authenticated');
    if (!isNsidString(lxm)) throw new Error(`Invalid NSID scope \`${lxm}\``);

    const resp = await auth.client.xrpc(com.atproto.server.getServiceAuth, {
      params: {
        aud: PUBLIC_ARBITER_DID as AtprotoDid,
        lxm,
      },
    });
    return (resp.body as { token: string }).token;
  },

  /**
   * Run an XRPC operation against a stewarded account's PDS, proxied through
   * the arbiter's `town.muni.arbiter.proxy` procedure. This is the only way to
   * reach a stewarded account's PDS: the arbiter evaluates the operation
   * against the installed policy, then proxies it to the steward's PDS
   * (`did#atproto_pds`) authenticated as the stewarded account.
   *
   * Returns the body of the inner XRPC response (or throws if the operation or
   * its proxy fails).
   */
  async proxy(did: string, op: ProxyOperation, target?: string): Promise<LexMap> {
    if (!isDidString(did)) throw new Error(`Invalid arbiter DID \`${did}\``);
    const token = await this.getServiceAuth('town.muni.arbiter.proxy');

    const res = await xrpc(PUBLIC_ARBITER_URL, town.muni.arbiter.proxy, {
      body: {
        arbiterDid: did,
        target: target ?? `${did}#${AT_PROTO_PDS_FRAGMENT}`,
        method: op.method,
        nsid: op.nsid,
        parameters: op.parameters,
        // A raw-bytes body is carried in the envelope as the AT Protocol binary
        // marker `{ $bytes: base64 }`; the arbiter decodes it back to bytes.
        body: (op.bytes ? encodeLexBytes(op.bytes) : op.body) as LexMap | undefined,
        encoding: op.encoding,
      },
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    return res.body ?? {};
  },

  // ─── Record operations (proxied through the arbiter) ────────────────

  /**
   * Fetch a record from the stewarded account's PDS, proxied through the
   * arbiter. Returns the record `value` (the inner `com.atproto.repo.getRecord`
   * response body is `{ uri, cid, value }`).
   */
  async getRecord(
    did: string,
    collection: string,
    rkey: string,
  ): Promise<RecordValue> {
    const body = await this.proxy(did, {
      nsid: 'com.atproto.repo.getRecord',
      method: 'GET',
      parameters: { repo: did, collection, rkey },
    });
    const value = body.value;
    if (value == null || typeof value !== 'object') {
      throw new Error(`getRecord returned no value for ${collection}/${rkey}`);
    }
    return value as RecordValue;
  },

  /**
   * Fetch a public record directly from the steward's PDS (no auth, no
   * proxying). Resolves the `#atproto_pds` endpoint from the DID doc and
   * issues `com.atproto.repo.getRecord`. Returns the record `value`.
   *
   * Throws `PublicRecordError` (carrying the HTTP status and the XRPC error
   * code) when the fetch fails.
   */
  async getPublicRecord(
    did: string,
    collection: string,
    rkey: string,
  ): Promise<RecordValue> {
    const pds = await resolvePdsEndpoint(did);
    const url = new URL(`${pds}/xrpc/com.atproto.repo.getRecord`);
    url.searchParams.set('repo', did);
    url.searchParams.set('collection', collection);
    url.searchParams.set('rkey', rkey);

    const res = await fetch(url);
    if (!res.ok) {
      // Parse the XRPC error body (best effort) so callers can tell "record
      // missing" (`RecordNotFound`) from network / server failures.
      const errBody = (await res.json().catch(() => null)) as { error?: unknown } | null;
      const code = typeof errBody?.error === 'string' ? errBody.error : undefined;
      throw new PublicRecordError(
        `getRecord ${collection}/${rkey} failed: ${res.status}${code ? ` (${code})` : ''}`,
        res.status,
        code,
      );
    }
    const body: unknown = await res.json();
    if (!body || typeof body !== 'object' || !('value' in body)) {
      throw new Error(`getRecord ${collection}/${rkey} returned no value`);
    }
    const value = body.value;
    if (value == null || typeof value !== 'object') {
      throw new Error(`getRecord ${collection}/${rkey} returned no value`);
    }
    return value as RecordValue;
  },

  /**
   * Write (create/replace) a record on the stewarded account's PDS via
   * putRecord, proxied through the arbiter so the record ends up in the
   * stewarded account's repo.
   */
  async putRecord(
    did: string,
    collection: string,
    record: LexMap,
    rkey?: string,
  ): Promise<{ uri: string; cid: string }> {
    const body = await this.proxy(did, {
      nsid: 'com.atproto.repo.putRecord',
      method: 'POST',
      body: {
        repo: did,
        collection,
        rkey: rkey || undefined,
        record,
        // The PDS does not have the custom `town.muni.arbiter.*` lexicons
        // registered, so validating would reject them (`Unknown lexicon
        // type`). The arbiter validates Rego itself on install; write
        // without server-side lexicon validation.
        validate: false,
      },
    });
    const { uri, cid } = body;
    return { uri: typeof uri === 'string' ? uri : '', cid: typeof cid === 'string' ? cid : '' };
  },

  /**
   * Upload a blob (e.g. an avatar image) to the stewarded account's PDS,
   * proxied through the arbiter so the policy governs the upload and the blob
   * is stored in the stewarded account's repo. `contentType` becomes the
   * inner request's `Content-Type` (e.g. `image/png`).
   *
   * Returns the inner `com.atproto.blob.uploadBlob` response body, which
   * carries the blob reference (`{ blob: { $type, ref, mimeType, size } }`).
   */
  async uploadBlob(
    did: string,
    data: Uint8Array,
    contentType: string,
  ): Promise<LexMap> {
    return this.proxy(did, {
      nsid: 'com.atproto.blob.uploadBlob',
      method: 'POST',
      bytes: data,
      encoding: contentType,
    });
  },

  // ─── Policy layers (config + policy records) ──────────────────────────

  /**
   * Read a community's config record (`town.muni.arbiter.config/self`) —
   * trusted scopes + the ordered policy layers.
   *
   * The record lives in the steward's public repo, so it is read directly
   * from the steward's PDS (`com.atproto.repo.getRecord`) with no auth.
   * Empty defaults are returned only when the config record does not exist
   * yet (the arbiter is offline until its first install) — any other failure
   * (network, 5xx, …) is rethrown so callers surface the error instead of
   * silently editing an empty config.
   */
  async getConfig(did: string): Promise<ArbiterConfig> {
    let value: RecordValue;
    try {
      value = await this.getPublicRecord(did, CONFIG_COLLECTION, CONFIG_RKEY);
    } catch (err) {
      // A missing config record is the only recoverable case; network/5xx
      // failures must propagate so PolicyTab shows its error branch instead
      // of empty editors (which would misrepresent the live configuration).
      if (
        err instanceof PublicRecordError &&
        (err.status === 404 || err.code === 'RecordNotFound')
      ) {
        return { trustedScopes: [], policyLayers: [] };
      }
      throw err;
    }
    const strings = (v: unknown): string[] =>
      Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];
    return {
      trustedScopes: strings(value.trustedScopes),
      policyLayers: strings(value.policyLayers),
    };
  },

  /**
   * Read a policy record's Rego source from the steward's public repo.
   * Throws if the record does not exist or has no `policy` field.
   */
  async getPolicyRecord(did: string, rkey: string): Promise<string> {
    const value = await this.getPublicRecord(did, POLICY_COLLECTION, rkey);
    const source = policySource(value);
    if (source == null) {
      throw new Error(`Policy record \`${rkey}\` has no \`policy\` field`);
    }
    return source;
  },

  /**
   * Write a policy record (`town.muni.arbiter.policy/<rkey>`) — the Rego
   * source — to the stewarded account's repo via `com.atproto.repo.putRecord`,
   * proxied through the arbiter. This is how locally authored policies are
   * published: `installPolicy` only appends `at://` URIs and never writes
   * records, so a new or edited policy must be written here first and then
   * installed by URI (a fresh URI appends at the end of the policy layers; a
   * URI already in the layers updates the layer in place).
   *
   * The proxied write is evaluated by the installed policy layers (the
   * default policy allows the community's admin and the stewarded account).
   */

  async putPolicyRecord(did: string, rkey: string, rego: string): Promise<void> {
    await this.putRecord(did, POLICY_COLLECTION, { policy: rego }, rkey);
  },

  /**
   * Write the community config record (`town.muni.arbiter.config/self`) —
   * the full trusted-scopes + policy-layers replacement — directly to the
   * stewarded account's repo via `com.atproto.repo.putRecord`, proxied
   * through the arbiter. This is the full-restructuring path (reorder /
   * remove / replace layer entries, remove scopes): `installPolicy` can
   * only append.
   *
   * The proxied write is evaluated by the installed policy layers (the
   * default policy allows the community's admin and the stewarded account),
   * and the record is the source of truth — the arbiter hot-reloads it over
   * Jetstream. For the offline/recovery hatch use `resetConfig` instead.
   */
  async putConfig(
    did: string,
    config: {
      /** NSID scopes the arbiter accepts; a scoped request's scope must match one exactly. */
      trustedScopes: string[];
      /** Ordered `at://` URIs of policy records. */
      policyLayers: string[];
    },
  ): Promise<void> {
    await this.putRecord(
      did,
      CONFIG_COLLECTION,
      { trustedScopes: config.trustedScopes, policyLayers: config.policyLayers },
      CONFIG_RKEY,
    );
  },

  /**
   * Append one policy layer and/or trusted scopes to a stewarded arbiter's
   * configuration via `town.muni.arbiter.installPolicy`.
   *
   * `policy` is the `at://` URI of a `town.muni.arbiter.policy` record in any
   * repo (the community's own or an app's shared record) — installPolicy
   * never writes records, so publish a locally authored policy first with
   * `putPolicyRecord` and then install its URI.
   *
   * Append semantics: the policy layer is added to the END of the layers —
   * the lowest-priority position, so an appended layer only sees requests
   * the community's existing layers pass — and the trusted scopes are
   * unioned in (new entries appended + deduped, existing order preserved).
   * Nothing already in the config is ever removed or reordered.
   * Re-installing a URI that is already in the layers keeps its
   * position (no duplicate, no priority change). `trustedScopes` is required
   * and may be empty (a policy install without scope changes is legal);
   * omitting `policy` appends scopes only.
   *
   * Authenticated via a serviceAuth token scoped to
   * `town.muni.arbiter.installPolicy`. The request is evaluated by the
   * arbiter's installed policy layers: a layer approves the install by
   * emitting `{"handleBuiltin": true}`, which hands the request to the
   * server's built-in append handler; a layer may also deny the install.
   * The account designated in the arbiter's `town.muni.arbiter.recovery/self`
   * record (the recovery admin) bypasses the layers; the record is re-read
   * on every call, so rewriting it rotates the recovery admin with effect on
   * the next installPolicy call. The server writes the `config/self` record
   * when anything changed and synchronously re-onboards the arbiter.
   */
  async installPolicy(
    did: string,
    install: {
      /**
       * `at://` URI of the `town.muni.arbiter.policy` record to append
       * (omit for a scope-only install).
       */
      policy?: string;
      /**
       * NSID scopes to append to the arbiter's trusted set (deduped
       * server-side; may be empty).
       */
      trustedScopes: string[];
    },
  ): Promise<void> {
    if (!isDidString(did)) throw new Error(`Invalid arbiter DID \`${did}\``);
    if (
      install.policy !== undefined &&
      !isAtUriString(install.policy)
    ) {
      throw new Error(`Invalid policy URI \`${install.policy}\``);
    }
    await xrpc(PUBLIC_ARBITER_URL, town.muni.arbiter.installPolicy, {
      body: {
        arbiterDid: did,
        ...(install.policy !== undefined ? { policy: install.policy } : {}),
        trustedScopes: install.trustedScopes,
      },
      headers: {
        Authorization: `Bearer ${await this.getServiceAuth('town.muni.arbiter.installPolicy')}`,
      },
    });
  },

  /**
   * Replace a stewarded arbiter's community config (trusted scopes + policy
   * layers) wholesale. Recovery admin only. Also the setup wizard's
   * bootstrap step for a freshly provisioned (offline) arbiter: the operator
   * provides the policy-layer `at://` URIs (records published from the
   * Library tab — they must already exist) and the trusted scopes, and the
   * config record written here brings the arbiter online.
   *
   * Authenticated via a serviceAuth token scoped to
   * `town.muni.arbiter.resetConfig`. Only the account designated in the
   * arbiter's `town.muni.arbiter.recovery/self` record (the recovery admin)
   * may call it. This is the recovery hatch: the request performs no policy
   * evaluation and is served directly even while the arbiter is offboarded
   * (e.g. a broken config prevented the policy layers from loading). The body is
   * only shape-validated — if the new config fails to load, reset again. The
   * record is written with repo-head CAS and the arbiter is re-onboarded.
   */
  async resetConfig(
    did: string,
    config: {
      /** NSID scopes the arbiter accepts; a scoped request's scope must match one exactly. */
      trustedScopes: string[];
      /** Ordered `at://` URIs of policy records. */
      policyLayers: string[];
    },
  ): Promise<void> {
    if (!isDidString(did)) throw new Error(`Invalid arbiter DID \`${did}\``);
    await xrpc(PUBLIC_ARBITER_URL, town.muni.arbiter.resetConfig, {
      body: {
        arbiterDid: did,
        trustedScopes: config.trustedScopes,
        policyLayers: config.policyLayers,
      },
      headers: {
        Authorization: `Bearer ${await this.getServiceAuth('town.muni.arbiter.resetConfig')}`,
      },
    });
  },

  // ─── Discovery ─────────────────────────────────────────────────────

  /**
   * Check whether a stewarded account has an arbiter service record pointing
   * at this arbiter server.
   *
   * Resolves the DID → finds the `#atproto_pds` service endpoint → fetches
   * `town.muni.arbiter.service/self` directly from that PDS (public read, no
   * auth needed). Returns `true` only if the record exists and its `did`
   * field matches `PUBLIC_ARBITER_DID`. Any error resolves to `false`.
   */
  async hasArbiterService(did: string): Promise<boolean> {
    try {
      const value = await this.getPublicRecord(did, SERVICE_COLLECTION, SERVICE_RKEY);
      return value.did === PUBLIC_ARBITER_DID;
    } catch {
      return false;
    }
  },

  // ─── Arbiter provisioning ──────────────────────────────────────────

  /**
   * Provision a brand-new stewarded PDS account. No input body is needed —
   * the server creates the account on its configured default PDS and returns
   * the new account's DID. Authenticated via a serviceAuth token scoped to
   * `town.muni.arbiter.createArbiter`.
   */
  async createArbiter(): Promise<string> {
    const res = await xrpc(PUBLIC_ARBITER_URL, town.muni.arbiter.createArbiter, {
      headers: {
        Authorization: `Bearer ${await this.getServiceAuth('town.muni.arbiter.createArbiter')}`,
      },
    });
    const did = res.body?.did;
    if (typeof did !== 'string' || !isDidString(did)) {
      throw new Error('createArbiter did not return a valid DID');
    }
    return did;
  },

  /**
   * Import an existing account as a stewarded arbiter using an app password.
   * The caller proves control of the account via the app password; the server
   * stores the credentials and brings the arbiter online.
   *
   * The server resolves the PDS endpoint itself from the account's DID doc;
   * no PDS URL override is accepted.
   */
  async createAppPasswordArbiter(
    arbiterDid: string,
    appPassword: string,
  ): Promise<void> {
    if (!isDidString(arbiterDid)) throw new Error(`Invalid arbiter DID \`${arbiterDid}\``);
    await xrpc(PUBLIC_ARBITER_URL, town.muni.arbiter.createAppPasswordArbiter, {
      body: { arbiterDid, appPassword },
      headers: {
        Authorization: `Bearer ${await this.getServiceAuth('town.muni.arbiter.createAppPasswordArbiter')}`,
      },
    });
  },

  // ─── Helpers ───────────────────────────────────────────────────────

  /**
   * Extract a user-friendly message from an XRPC error.
   */
  formatError(err: unknown): string {
    if (err instanceof XrpcResponseError) {
      const code = err.error;
      const msg = err.message;
      return `Request failed (${err.status}): ${msg || code || 'unknown error'}`;
    }
    if (err instanceof Error) return err.message;
    return String(err);
  },
};
