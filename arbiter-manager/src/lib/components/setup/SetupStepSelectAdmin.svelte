<script lang="ts">
  import { Button } from '@foxui/core';
  import { setupState, setupClient } from '$lib/setupState.svelte';
  import { AtprotoHandlePopup, type Profile } from '@foxui/all';
  import { isAtprotoDid } from '@atproto/oauth-client-browser';
  import { defaultPolicyWithOwner } from '$lib/default-policy';
  import { arbiter } from '$lib/arbiter';
  import { auth } from '$lib/auth.svelte';

  let selectedAdmin: Profile | undefined = $state(undefined);

  function goBack() {
    setupState.step = 'app-password';
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
      if (!selectedAdmin.did) throw new Error('You must select an admin.');

      // Write the initial root policy directly to the account's PDS (via the
      // app-password session established earlier) BEFORE importing it as a
      // stewarded arbiter. The server fails to onboard an arbiter whose root
      // policy record is missing, so the policy must exist first.
      if (!setupClient.agent) {
        await setupClient.login(auth.did, setupState.appPassword);
      }
      await setupClient.writeRootPolicy(defaultPolicyWithOwner(selectedAdmin.did));

      // Import the existing account as a stewarded arbiter. The server reads
      // the root policy record we just wrote and brings the arbiter online.
      await arbiter.createAppPasswordArbiter(auth.did, setupState.appPassword);

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
