<script lang="ts">
  import { Button } from '@foxui/core';
  import { setupState, setupClient } from '$lib/setupState.svelte';
  import { AtprotoHandlePopup, type Profile } from '@foxui/all';
  import { isAtprotoDid } from '@atproto/oauth-client-browser';
  import { isActorIdentifier } from '@atcute/lexicons/syntax';
  import { defaultPolicyWithOwner } from '$lib/default-policy';
  import { arbiter } from '$lib/arbiter';
  import { auth } from '$lib/auth.svelte';
  import { actorResolver } from '$lib/resolver';

  let selectedAdmin: Profile | undefined = $state(undefined);

  function goBack() {
    setupState.step = 'app-password';
  }

  /**
   * The foxui `AtprotoHandlePopup` fires `onselected` with a hardcoded
   * `did: ''` when the user just types a handle and presses Enter without
   * picking a dropdown result, so `selectedAdmin.did` may be empty. Resolve
   * the handle to its DID in that case.
   */
  async function ownerDid(): Promise<string> {
    if (!selectedAdmin) throw new Error('Please resolve an admin DID first');
    if (selectedAdmin.did) return selectedAdmin.did;
    if (!selectedAdmin.handle) throw new Error('You must select an admin.');
    if (!isActorIdentifier(selectedAdmin.handle)) throw new Error('Invalid admin handle');
    const resolved = await actorResolver.resolve(selectedAdmin.handle);
    return resolved.did;
  }

  async function finishSetup() {
    if (!selectedAdmin) {
      setupState.error = 'Please resolve an admin DID first';
      return;
    }

    setupState.loading = true;
    setupState.error = undefined;

    try {
      if (!isAtprotoDid(auth.did)) throw new Error('Not logged in with valid DID');
      if (!setupState.appPassword) throw new Error('Must provide AppPassword');

      // Resolve the owner DID (see `ownerDid`).
      const did = await ownerDid();

      // Write the initial root policy directly to the account's PDS (via the
      // app-password session established earlier) BEFORE importing it as a
      // stewarded arbiter. The server fails to onboard an arbiter whose root
      // policy record is missing, so the policy must exist first.
      if (!setupClient.agent) {
        await setupClient.login(auth.did, setupState.appPassword);
        console.log(`Logged in as ${auth.did}`);
      }
      console.log('Preparing to write root policy');
      await setupClient.writeRootPolicy(defaultPolicyWithOwner(did));
      console.log('Wrote root policy');

      // Import the existing account as a stewarded arbiter. The server reads
      // the root policy record we just wrote and brings the arbiter online.
      await arbiter.createAppPasswordArbiter(auth.did, setupState.appPassword);
      console.log('Created app password arbiter');

      setupState.step = 'complete';
      setupState.error = undefined;
      setupState.loading = false;
    } catch (e) {
      setupState.error = `Failed: ${e instanceof Error ? e.message : String(e)}`;
      setupState.loading = false;
    }
  }
</script>

<div class="max-w-lg mx-auto px-6 py-12 space-y-6">
  <div class="space-y-2">
    <h2 class="text-xl font-semibold text-base-900 dark:text-base-50">Select an Admin</h2>
    <p class="text-sm text-base-600 dark:text-base-400">
      Choose someone to have <strong>Owner</strong> access to this community's arbiter. This person will
      be able to manage spaces, members, and policies on behalf of the community account.
    </p>
  </div>

  <div class="space-y-4">
    <AtprotoHandlePopup onselected={(actor) => (selectedAdmin = actor)} />

    {#if setupState.error}
      <p class="text-sm text-red-500">{setupState.error}</p>
    {/if}
  </div>

  <div class="flex justify-between pt-2">
    <Button variant="ghost" onclick={goBack} disabled={setupState.loading}>Back</Button>
    <Button onclick={finishSetup} disabled={setupState.loading || !selectedAdmin}>
      {setupState.loading ? 'Finalizing…' : 'Complete Setup'}
    </Button>
  </div>
</div>
