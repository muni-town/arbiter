import {
  BrowserOAuthClient,
  atprotoLoopbackClientMetadata,
  buildLoopbackClientId,
  type OAuthClientMetadataInput,
  type OAuthSession,
} from '@atproto/oauth-client-browser';
import * as app from '$lib/lexicons/app';
import { Client } from '@atproto/lex';
import { goto } from '$app/navigation';
import { resetSetupState } from './setupState.svelte';

const SESSION_DID_KEY = 'session-did';
const atprotoOauthScope = [
  'atproto',
  'identity:*',
  'rpc:com.atproto.repo.putRecord?aud=*',
  'rpc:com.atproto.repo.getRecord?aud=*',
  'rpc:app.bsky.actor.getProfile?aud=*',
  'rpc:town.muni.arbiter.createArbiter?aud=*',
  'rpc:town.muni.arbiter.createAppPasswordArbiter?aud=*',
].join(' ');

export class Auth {
  oauth?: BrowserOAuthClient = $state(undefined);
  session?: OAuthSession = $state(undefined);
  client?: Client = $state(undefined);
  profile?: app.bsky.actor.defs.ProfileViewDetailed = $state(undefined);

  async init() {
    this.oauth = await makeOauthClient();
    const did = localStorage.getItem(SESSION_DID_KEY);
    try {
      if (did) this.session = await this.oauth.restore(did);
    } catch (_) {}
    await this.#loadSession();
  }

  async #loadSession() {
    if (this.session) {
      this.client = new Client(this.session);
      const resp = await this.client.xrpc(app.bsky.actor.getProfile, {
        params: { actor: this.session.did },
      });
      this.profile = resp.body;
      localStorage.setItem(SESSION_DID_KEY, this.session.did);
    }
  }

  async callback(params: URLSearchParams) {
    if (!this.oauth) this.oauth = await makeOauthClient();
    if (this.session) await this.session.signOut();
    const { session } = await this.oauth.callback(params);
    this.session = session;
    this.#loadSession();
  }

  get did(): string | undefined {
    return this.client?.did;
  }

  get name(): string | undefined {
    return this.profile?.displayName || this.profile?.handle;
  }

  async logout() {
    localStorage.removeItem(SESSION_DID_KEY);
    await this.session?.signOut();
    this.session = undefined;
    this.client = undefined;
    this.profile = undefined;
    resetSetupState();
    await goto('/');
  }

  async login(): Promise<void> {
    const handle = prompt('Enter your ATProto handle (e.g. user.bsky.social):');
    if (!handle) return;
    this.loginWithHandle(handle);
  }

  async loginWithHandle(handle: string): Promise<void> {
    if (!handle.trim()) return;
    await this.oauth?.signInRedirect(handle.trim());
  }
}

export const auth = new Auth();
(globalThis as any).auth = auth;

/**
 * Start the OAuth login flow for setup.
 * Accepts a handle directly (no prompt) and stores setup state before redirect.
 */
export async function loginWithHandle(handle: string): Promise<void> {
  const client = await makeOauthClient();
  // The OAuth signIn will redirect the browser
  await client.signIn(handle.trim(), {});
}

async function makeOauthClient(): Promise<BrowserOAuthClient> {
  // Build the client metadata
  let clientMetadata: OAuthClientMetadataInput;

  if (import.meta.env.DEV) {
    // Get the base URL and redirect URL for this deployment
    if (globalThis.location.hostname == 'localhost')
      throw new Error('Logging in only works from 127.0.0.1');
    const baseUrl = new URL(`http://127.0.0.1:${globalThis.location.port}`);
    baseUrl.hash = '';
    baseUrl.pathname = '/';
    const redirectUri = baseUrl.href + 'oauth/callback';
    // In dev, we build a development metadata
    clientMetadata = {
      ...atprotoLoopbackClientMetadata(buildLoopbackClientId(baseUrl)),
      redirect_uris: [redirectUri],
      scope: atprotoOauthScope,
      client_id: `http://localhost?redirect_uri=${encodeURIComponent(
        redirectUri,
      )}&scope=${encodeURIComponent(atprotoOauthScope)}`,
    };
  } else {
    // In prod, we fetch the `/oauth-client-metadata.json` which is expected to be deployed alongside the
    // static build.
    // native client metadata is not reuqired to be on the same domin as client_id,
    // so it can always use the deployed metadata
    const resp = await fetch(`/oauth-client-metadata.json`, {
      headers: [['accept', 'application/json']],
    });
    clientMetadata = await resp.json();
  }

  return new BrowserOAuthClient({
    responseMode: 'query',
    handleResolver: 'https://resolver.roomy.chat',
    clientMetadata: clientMetadata,
  });
}
