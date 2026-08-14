<script lang="ts">
  import { Button } from '@foxui/core';
  import { setupState } from '$lib/setupState.svelte';
  import { AtprotoHandlePopup, type Profile } from '@foxui/all';
  import { isAtprotoDid } from '@atproto/oauth-client-browser';
  import { isActorIdentifier } from '@atcute/lexicons/syntax';
  import { defaultPolicyWithOwner } from '$lib/default-policy';
  import { arbiter } from '$lib/arbiter';
  import { auth } from '$lib/auth.svelte';
  import { actorResolver } from '$lib/resolver';

  let selectedAdmin: Profile | undefined = $state(undefined);

  function goBack() {
    setupState.step = 'oauth';
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

  async function createAndFinish() {
    if (!selectedAdmin) {
      setupState.error = 'Please resolve an admin DID first';
      return;
    }

    setupState.loading = true;
    setupState.error = undefined;

    try {
      if (!isAtprotoDid(auth.did)) throw new Error('Not logged in with valid DID');

      // Resolve the owner DID BEFORE provisioning. If this fails (e.g. an
      // unresolvable admin handle), we abort before creating any account, so
      // no orphan is left behind.
      const owner = await ownerDid();

      // If a previous attempt already provisioned the account but failed to
      // install the policy, skip createArbiter (which would hit the rate limit
      // or create a second account) and only retry the policy install.
      let did = setupState.createDid;
      if (!did) {
        // Provision a brand-new stewarded account on the server's default PDS.
        // The server returns the new account's DID; the caller (this OAuth
        // account) becomes its recovery admin.
        did = await arbiter.createArbiter();
        setupState.createDid = did;
      }

      // Install the first policy. The creator is the recovery admin, so they
      // may call resetPolicy to bring the freshly provisioned (offline) arbiter
      // online with the initial policy.
      await arbiter.resetPolicy(did, defaultPolicyWithOwner(owner));

      setupState.step = 'complete';
      setupState.error = undefined;
      setupState.loading = false;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // If createArbiter was rate-limited, the account may already have been
      // created on a prior attempt whose response was lost. Tell the user to
      // retry after the window rather than implying a hard failure.
      if (!setupState.createDid && /rate limit|ErrPermissionDenied/i.test(msg)) {
        setupState.error =
          'The arbiter server is rate-limiting account creation. If a previous attempt ' +
          'succeeded but the response was lost, the account may already exist — retry in a ' +
          'minute to install its policy.';
      } else {
        setupState.error = `Failed: ${msg}`;
      }
      setupState.loading = false;
    }
  }
</script>

<div class="max-w-lg mx-auto px-6 py-12 space-y-6">
  <div class="space-y-2">
    <h2 class="text-xl font-semibold text-base-900 dark:text-base-50">Create a New Account</h2>
    <p class="text-sm text-base-600 dark:text-base-400">
      The arbiter server will create a brand-new AT Protocol account on its configured PDS and
      return its DID. You (the signed-in account) become its recovery admin. Then choose an account
      to have <strong>Owner</strong> access to this community's arbiter.
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
    <Button onclick={createAndFinish} disabled={setupState.loading || !selectedAdmin}>
      {setupState.loading
        ? 'Working…'
        : setupState.createDid
          ? 'Retry Policy Install'
          : 'Create Account'}
    </Button>
  </div>
</div>
