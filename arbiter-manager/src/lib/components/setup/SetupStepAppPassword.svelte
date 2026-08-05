<script lang="ts">
  import { Button, Input } from '@foxui/core';
  import { setupClient, setupState } from '$lib/setupState.svelte';
  import { PdsSetupClient } from '$lib/pds-setup-client';
  import { auth } from '$lib/auth.svelte';
  import { onMount } from 'svelte';

  onMount(() => (setupState.loading = false));

  function goBack() {
    setupState.step = 'oauth';
  }

  async function verifyAndProceed() {
    if (!setupState.appPassword) {
      setupState.error = 'Please enter your App Password';
      return;
    }

    setupState.error = undefined;
    setupState.loading = true;

    try {
      if (!auth.client?.did) throw new Error('Missing DID');

      // Verify the app password works
      await setupClient.login(auth.client.did, setupState.appPassword);

      // Save the app password
      setupState.step = 'select-admin';
      setupState.error = undefined;
      setupState.loading = false;
    } catch (e) {
      setupState.error = `Verification failed: ${e instanceof Error ? e.message : String(e)}`;
      setupState.loading = false;
    }
  }
</script>

<div class="max-w-lg mx-auto px-6 py-12 space-y-6">
  <div class="space-y-2">
    <h2 class="text-xl font-semibold text-base-900 dark:text-base-50">Enter Your App Password</h2>
    <p class="text-sm text-base-600 dark:text-base-400">
      Create an <strong>App Password</strong> on your PDS and enter it below. The arbiter server will
      use this to execute requests on your PDS after authenticating them against your policy.
    </p>
  </div>

  <!-- Instructions link -->
  <div
    class="p-4 rounded-lg bg-accent-50 dark:bg-accent-900/20 border border-accent-200 dark:border-accent-800 text-sm space-y-2"
  >
    <p class="font-medium text-accent-800 dark:text-accent-200">How to create an App Password</p>
    <ol class="list-decimal list-inside text-accent-700 dark:text-accent-300 space-y-1 text-xs">
      <li>Go to your PDS settings (or Bluesky Settings &rarr; App Passwords)</li>
      <li>Create a new App Password with a name like "arbiter-manager"</li>
      <li>Copy the generated password and paste it below</li>
    </ol>
  </div>

  <div class="space-y-4">
    <div class="flex flex-col gap-2">
      <label for="app-password-input" class="text-sm font-medium text-base-700 dark:text-base-300">
        App Password
      </label>
      <Input
        id="app-password-input"
        type="password"
        bind:value={setupState.appPassword}
        placeholder="xxxx-xxxx-xxxx-xxxx"
        disabled={setupState.loading}
      />
      <p class="text-xs text-base-500">
        The arbiter server stores this securely and uses it to communicate with your PDS.
      </p>
    </div>

    {#if setupState.error}
      <p class="text-sm text-red-500">{setupState.error}</p>
    {/if}
  </div>

  <div class="flex justify-between pt-2">
    <Button variant="ghost" onclick={goBack} disabled={setupState.loading}>Back</Button>
    <Button
      onclick={verifyAndProceed}
      disabled={setupState.loading || !setupState.appPassword?.trim()}
    >
      {setupState.loading ? 'Verifying…' : 'Continue'}
    </Button>
  </div>
</div>
