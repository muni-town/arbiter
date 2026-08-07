/**
 * Arbiter XRPC helpers for the arbiter-manager UI.
 *
 * Provides a single `arbiter` object with methods to:
 *  - Obtain a service auth token scoped to the arbiter-server DID.
 *  - Read / write PDS records proxied through the arbiter's `town.muni.arbiter.proxy`
 *    procedure (the only way to reach a stewarded account's PDS).
 *  - Read / write the root Rego policy record.
 *  - Discover whether a stewarded account has an arbiter service record.
 *  - Provision a new arbiter, or import an existing account via app password.
 */

import { PUBLIC_ARBITER_URL, PUBLIC_ARBITER_DID } from '$env/static/public';
import { xrpc, type LexMap, isDidString, isNsidString } from '@atproto/lex';
import { XrpcResponseError } from '@atproto/lex';
import type { AtprotoDid } from '@atcute/lexicons/syntax';
import * as town from '$lib/lexicons/town';
import * as com from '$lib/lexicons/com';
import { auth } from '$lib/auth.svelte';
import { didResolver } from '$lib/resolver';

/** Policy record collection + rkey. */
const POLICY_COLLECTION = 'town.muni.arbiter.policy.root';
const POLICY_RKEY = 'self';

/** Service record collection + rkey (discovery). */
const SERVICE_COLLECTION = 'town.muni.arbiter.service';
const SERVICE_RKEY = 'self';

/** The `did#service` fragment for a steward's PDS. */
const AT_PROTO_PDS_FRAGMENT = 'atproto_pds';

/** Fallback policy returned when no root policy record exists yet. */
const DEFAULT_POLICY =
  '# Enter your Rego policy here\n\npackage arbiter\n\nresult := { "ok": true, "output": null }\n';

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
}

/** A proxied record value returned by the arbiter. */
type RecordValue = Record<string, unknown>;

/** Read the string `policy` field off an arbitrary record value, if present. */
function policySource(value: unknown): string | undefined {
  if (value && typeof value === 'object' && 'policy' in value) {
    const candidate = value.policy;
    if (typeof candidate === 'string') return candidate;
  }
  return undefined;
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
        body: op.body,
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
      throw new Error(`getRecord ${collection}/${rkey} failed: ${res.status}`);
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
        // type`). The arbiter validates Rego itself on reset; write without
        // server-side lexicon validation.
        validate: false,
      },
    });
    const { uri, cid } = body;
    return { uri: typeof uri === 'string' ? uri : '', cid: typeof cid === 'string' ? cid : '' };
  },

  // ─── Policy (root Rego record) ─────────────────────────────────────

  /**
   * Read the root Rego policy for a stewarded account.
   *
   * The policy record lives in the steward's public repo, so it is read
   * directly from the steward's PDS (`com.atproto.repo.getRecord`) with no
   * auth — proxying it through the arbiter would require the policy to allow
   * its own `getRecord`, which it must not. Returns the `policy` string; if
   * the record does not exist (or cannot be read), a default placeholder is
   * returned so the editor is still usable.
   */
  async getPolicy(did: string): Promise<string> {
    try {
      const value = await this.getPublicRecord(did, POLICY_COLLECTION, POLICY_RKEY);
      return policySource(value) ?? DEFAULT_POLICY;
    } catch {
      return DEFAULT_POLICY;
    }
  },

  /**
   * Write (replace) the root Rego policy for a stewarded account by writing
   * the `town.muni.arbiter.policy.root/self` record via the arbiter proxy.
   */
  async setPolicy(did: string, policy: string): Promise<void> {
    await this.putRecord(
      did,
      POLICY_COLLECTION,
      {
        $type: 'town.muni.arbiter.policy.root',
        policy,
      },
      POLICY_RKEY,
    );
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
   * Provision a brand-new stewarded PDS account and bring its arbiter online.
   * No input body is needed — the server creates the account. Authenticated
   * via a serviceAuth token scoped to `town.muni.arbiter.createArbiter`.
   */
  async createArbiter(): Promise<void> {
    await xrpc(PUBLIC_ARBITER_URL, town.muni.arbiter.createArbiter, {
      headers: {
        Authorization: `Bearer ${await this.getServiceAuth('town.muni.arbiter.createArbiter')}`,
      },
    });
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

  /**
   * Reset a stewarded arbiter's root policy (recovery admin only).
   *
   * Authenticated via a serviceAuth token scoped to
   * `town.muni.arbiter.resetPolicy`. Only the account designated in the
   * arbiter's `town.muni.arbiter.recovery/self` record may reset the policy.
   */
  async resetPolicy(did: string, policy: string): Promise<void> {
    if (!isDidString(did)) throw new Error(`Invalid arbiter DID \`${did}\``);
    await xrpc(PUBLIC_ARBITER_URL, town.muni.arbiter.resetPolicy, {
      body: { arbiterDid: did, policy },
      headers: {
        Authorization: `Bearer ${await this.getServiceAuth('town.muni.arbiter.resetPolicy')}`,
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
