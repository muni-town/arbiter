import { Agent, CredentialSession } from '@atproto/api';
import { actorResolver } from './resolver';
import { isActorIdentifier } from '@atcute/lexicons/syntax';

/**
 * PDS client wrapper for the setup flow.
 *
 * Used to prove control of an account via its app password before importing
 * it as a stewarded arbiter. The import itself goes through the server
 * (`town.muni.arbiter.createAppPasswordArbiter`, which stores the credentials
 * and writes the service + recovery bootstrap records), and the config is
 * bootstrapped via `town.muni.arbiter.resetConfig` — no direct repo writes.
 */
export class PdsSetupClient {
  agent?: Agent;

  async login(user: string, password: string) {
    if (this.agent) return;

    if (!isActorIdentifier(user)) throw new Error('Invalid username');
    const actor = await actorResolver.resolve(user);
    const session = new CredentialSession(new URL(actor.pds));
    await session.login({
      identifier: user,
      password,
    });
    this.agent = new Agent(session);
  }
}