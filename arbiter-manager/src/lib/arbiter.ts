/**
 * Arbiter XRPC helpers for the arbiter-manager UI.
 *
 * Provides a single `arbiter` object with methods to:
 *  - Obtain a service auth token scoped to the arbiter-server DID.
 *  - Read / write PDS records (proxied through the arbiter).
 *  - Read / write the root Rego policy record.
 *  - Discover whether a stewarded account has an arbiter service record.
 *  - Provision a new arbiter, or import an existing account via app password.
 */

import { PUBLIC_ARBITER_URL, PUBLIC_ARBITER_DID } from '$env/static/public';
import { xrpc } from '@atproto/lex';
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

/** Fallback policy returned when no root policy record exists yet. */
const DEFAULT_POLICY = '# Enter your Rego policy here\n\nallow = true\n';

/** Minimal DID document shape we care about (for PDS endpoint discovery). */
interface MinimalDidDoc {
  service?: { id?: string; type?: string; serviceEndpoint?: string }[];
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

    const resp = await auth.client.xrpc(com.atproto.server.getServiceAuth, {
      params: {
        aud: PUBLIC_ARBITER_DID as AtprotoDid,
        lxm,
      } as any,
    });
    return (resp.body as { token: string }).token;
  },

  // ─── Record operations (proxied through the arbiter) ────────────────

  /**
   * Fetch a record from the stewarded account's PDS, proxied through the
   * arbiter. Returns the raw `com.atproto.repo.getRecord` response body
   * (typically `{ uri, cid, value }`).
   */
  async getRecord(
    did: string,
    collection: string,
    rkey: string,
  ): Promise<Record<string, unknown>> {
    const token = await this.getServiceAuth('com.atproto.repo.getRecord');

    const url = new URL(`${PUBLIC_ARBITER_URL}/xrpc/com.atproto.repo.getRecord`);
    url.searchParams.set('repo', did);
    url.searchParams.set('collection', collection);
    url.searchParams.set('rkey', rkey);

    const res = await fetch(url, {
      headers: {
        'arbiter-did': did,
        'arbiter-proxy': `${did}#atproto_pds`,
        Authorization: `Bearer ${token}`,
      },
    });
    if (!res.ok) {
      throw new Error(
        `getRecord failed (${res.status}): ${await res.text()}`,
      );
    }
    return (await res.json()) as Record<string, unknown>;
  },

  /**
   * Write (create/replace) a record on the stewarded account's PDS via
   * putRecord, proxied through the arbiter so the record ends up in the
   * stewarded account's repo.
   */
  async putRecord(
    did: string,
    collection: string,
    record: Record<string, unknown>,
    rkey?: string,
  ): Promise<{ uri: string; cid: string }> {
    const token = await this.getServiceAuth('com.atproto.repo.putRecord');

    const res = await xrpc(
      PUBLIC_ARBITER_URL,
      com.atproto.repo.putRecord,
      {
        body: {
          repo: did as any,
          collection: collection as any,
          rkey: (rkey || undefined) as any,
          record: record as any,
          validate: true,
        } as any,
        headers: {
          'arbiter-did': did,
          'arbiter-proxy': `${did}#atproto_pds`,
          Authorization: `Bearer ${token}`,
        },
      },
    );
    return res.body as { uri: string; cid: string };
  },

  // ─── Policy (root Rego record) ─────────────────────────────────────

  /**
   * Read the root Rego policy for a stewarded account.
   *
   * Fetches `town.muni.arbiter.policy.root/self` via getRecord and returns the
   * `source` string. If the record does not exist (or any error occurs), a
   * default placeholder policy is returned so the editor is still usable.
   */
  async getPolicy(did: string): Promise<string> {
    try {
      const record = await this.getRecord(did, POLICY_COLLECTION, POLICY_RKEY);
      // getRecord returns `{ uri, cid, value }`; fall back to the body itself
      // in case the proxy returns the record unwrapped.
      const candidate: unknown =
        record.value !== undefined ? record.value : record;
      const source =
        candidate && typeof candidate === 'object' && 'source' in candidate
          ? candidate.source
          : undefined;
      return typeof source === 'string' ? source : DEFAULT_POLICY;
    } catch {
      return DEFAULT_POLICY;
    }
  },

  /**
   * Write (replace) the root Rego policy for a stewarded account by writing
   * the `town.muni.arbiter.policy.root/self` record via putRecord.
   */
  async setPolicy(did: string, source: string): Promise<void> {
    await this.putRecord(
      did,
      POLICY_COLLECTION,
      {
        $type: 'town.muni.arbiter.policy.root',
        source,
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
      const doc = (await didResolver.resolve(did as AtprotoDid)) as MinimalDidDoc;
      const pdsService = (doc.service ?? []).find((s) => {
        const id = typeof s.id === 'string' ? s.id.replace(/^#/, '') : '';
        return id === 'atproto_pds' && typeof s.serviceEndpoint === 'string';
      });
      if (!pdsService || typeof pdsService.serviceEndpoint !== 'string') {
        return false;
      }
      const url = new URL(`${pdsService.serviceEndpoint}/xrpc/com.atproto.repo.getRecord`);
      url.searchParams.set('repo', did);
      url.searchParams.set('collection', SERVICE_COLLECTION);
      url.searchParams.set('rkey', SERVICE_RKEY);

      const res = await fetch(url);
      if (!res.ok) return false;
      const body: unknown = await res.json();
      if (
        !body ||
        typeof body !== 'object' ||
        !('value' in body) ||
        body.value === null ||
        typeof body.value !== 'object' ||
        !('did' in body.value)
      ) {
        return false;
      }
      return body.value.did === PUBLIC_ARBITER_DID;
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
   */
  async createAppPasswordArbiter(
    arbiterDid: string,
    appPassword: string,
    pdsUrl?: string,
  ): Promise<void> {
    const body: Record<string, unknown> = { arbiterDid, appPassword };
    if (pdsUrl) body.pdsUrl = pdsUrl;

    await xrpc(PUBLIC_ARBITER_URL, town.muni.arbiter.createAppPasswordArbiter, {
      body: body as any,
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