import { Agent, CredentialSession } from '@atproto/api';
import { actorResolver } from './resolver';
import { isActorIdentifier } from '@atcute/lexicons/syntax';

/** The root policy record collection + rkey on a stewarded account's repo. */
const ROOT_POLICY_COLLECTION = 'town.muni.arbiter.policy.root';
const ROOT_POLICY_RKEY = 'self';

/**
 * PDS client wrapper for the setup flow.
 *
 * Used to prove control of an account via its app password and to write the
 * initial root policy record directly to the PDS. The arbiter server reads the
 * root policy from this record when it onboards the account, so the manager
 * must write it before importing the account (importing fails otherwise).
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
   * Write the root Rego policy record (`town.muni.arbiter.policy.root/self`)
   * directly to the account's PDS, authenticated as the account via the app
   * password established in [`login`](self.login).
   */
  async writeRootPolicy(policy: string): Promise<void> {
    if (!this.agent) throw new Error('Not logged into the PDS yet');
    const did = this.agent.did;
    if (!did) throw new Error('Not logged into the PDS yet');
    await this.agent.com.atproto.repo.putRecord({
      repo: did,
      collection: ROOT_POLICY_COLLECTION,
      rkey: ROOT_POLICY_RKEY,
      record: {
        $type: ROOT_POLICY_COLLECTION,
        policy,
      },
    });
  }
}
