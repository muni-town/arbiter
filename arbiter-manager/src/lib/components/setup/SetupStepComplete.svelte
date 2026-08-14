<script lang="ts">
  import { onMount } from 'svelte';
  import { Button } from '@foxui/core';
  import { resetSetupState, setupState } from '$lib/setupState.svelte';
  import { managedCommunities } from '$lib/store.svelte';
  import { goto } from '$app/navigation';
  import { auth } from '$lib/auth.svelte';

  let adminDid = $state('');

  onMount(() => {
    if (auth.did && auth.profile?.handle) {
      managedCommunities.add(auth.did, auth.profile?.handle);
    }
    // In the create flow the new account's DID is known; add it to the
    // managed list so it appears on the dashboard.
    if (setupState.createDid) {
      managedCommunities.add(setupState.createDid, 'New arbiter account');
    }
  });

  function goToDashboard() {
    // In the create flow the new account's DID is known; in the import flow the
    // stewarded account is the signed-in account (`auth.did`).
    const target = setupState.createDid || auth.did;
    if (!target) {
      setupState.error = 'No account DID to open';
      return;
    }
    resetSetupState();
    goto(`/dashboard/${encodeURIComponent(target)}`);
  }

  function startOver() {
    resetSetupState();
    goto('/setup');
  }
</script>

<div class="max-w-lg mx-auto px-6 py-12 space-y-8">
  <!-- Success header -->
  <div class="text-center space-y-3">
    <div
      class="w-14 h-14 rounded-full bg-green-100 dark:bg-green-900 flex items-center justify-center mx-auto"
    >
      <svg
        class="w-7 h-7 text-green-600 dark:text-green-400"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2.5"
          d="M5 13l4 4L19 7"
        />
      </svg>
    </div>
    <h2 class="text-2xl font-bold text-base-900 dark:text-base-50">Setup Complete!</h2>
    <p class="text-sm text-base-600 dark:text-base-400">
      Your account has been successfully connected to the arbiter.
    </p>
  </div>

  <!-- Summary -->
  <div class="space-y-3">
    {#if adminDid}
      <div
        class="p-4 rounded-lg bg-base-50 dark:bg-base-900 border border-base-200 dark:border-base-800 space-y-2"
      >
        <div class="flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-blue-500"></span>
          <span class="text-sm font-medium text-base-900 dark:text-base-50">Admin Selected</span>
        </div>
        <p class="text-xs text-base-500 font-mono">
          {adminDid}
        </p>
        <p class="text-xs text-base-500">
          This account will have Owner-level access once logged in.
        </p>
      </div>
    {/if}

    <div
      class="p-4 rounded-lg bg-accent-50 dark:bg-accent-900/20 border border-accent-200 dark:border-accent-800 space-y-2"
    >
      <div class="flex items-center gap-2">
        <span class="w-2 h-2 rounded-full bg-accent-500"></span>
        <span class="text-sm font-medium text-base-900 dark:text-base-50">Next Steps</span>
      </div>
      <ol class="text-sm text-base-600 dark:text-base-400 space-y-2 list-decimal list-inside">
        <li>
          <strong>Sign in as the admin</strong> — You can now login to this app with the admin account
          that you selected.
        </li>
        <li>
          <strong>Manage your community</strong> — Create spaces, add members, configure access levels,
          and define policies.
        </li>
      </ol>
    </div>

    <!-- Recovery info -->
    <div
      class="p-4 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 space-y-1"
    >
      <p class="text-xs font-medium text-yellow-700 dark:text-yellow-300">Recovery Note:</p>
      <p class="text-xs text-yellow-600 dark:text-yellow-400">
        If you ever need to reset the arbiter policy you can go through this process again.
      </p>
    </div>
  </div>

  <!-- Actions -->
  <div class="flex flex-col gap-3 pt-2">
    <Button size="lg" onclick={goToDashboard}>Go to Dashboard</Button>
    <Button variant="ghost" onclick={startOver}>Set Up Another Account</Button>
  </div>
</div>
