import { Agent, CredentialSession } from '@atproto/api';
import { actorResolver } from './resolver';
import { isActorIdentifier } from '@atcute/lexicons/syntax';

/**
 * PDS client wrapper for the setup flow.
 *
 * Used to prove control of an account via its app password before importing
 * it as a stewarded arbiter, and to publish the bootstrap records (the
 * default policy record, the day-to-day admins record, and the initial
 * config record) directly to the
 * steward's repo: pre-arbiter there is nothing to gate, and the arbiter
 * comes online on its own once the config record exists (startup onboarding
 * / Jetstream).
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

  /**
   * Write (upsert) a record to the logged-in account's repo.
   */
  async putRecord(
    collection: string,
    rkey: string,
    record: Record<string, unknown>,
  ): Promise<void> {
    if (!this.agent) throw new Error('Not logged in');
    await this.agent.com.atproto.repo.putRecord({
      repo: this.agent.assertDid,
      collection,
      rkey,
      record,
      // The PDS does not have the custom `town.muni.arbiter.*` lexicons
      // registered, so validating would reject them (`Unknown lexicon
      // type`).
      validate: false,
    });
  }
}