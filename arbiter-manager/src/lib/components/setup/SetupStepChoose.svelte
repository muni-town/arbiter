<script lang="ts">
  import { Button } from '@foxui/core';
  import { setupState } from '$lib/setupState.svelte';

  function goBack() {
    setupState.step = 'oauth';
  }

  function chooseCreate() {
    setupState.mode = 'create';
    setupState.step = 'create';
    setupState.error = undefined;
  }

  function chooseImport() {
    setupState.mode = 'import';
    setupState.step = 'app-password';
    setupState.error = undefined;
  }
</script>

<div class="max-w-lg mx-auto px-6 py-12 space-y-6">
  <div class="space-y-2">
    <h2 class="text-xl font-semibold text-base-900 dark:text-base-50">How do you want to set up your community account?</h2>
    <p class="text-sm text-base-600 dark:text-base-400">
      You can either create a brand-new AT Protocol account managed by the arbiter, or import an
      existing account you already control.
    </p>
  </div>

  <div class="space-y-4">
    <div
      class="p-4 rounded-lg bg-base-50 dark:bg-base-900 border border-base-200 dark:border-base-800 space-y-2"
    >
      <h3 class="font-semibold text-base-900 dark:text-base-50">Create a new account</h3>
      <p class="text-sm text-base-600 dark:text-base-400">
        The arbiter server provisions a brand-new account on its configured PDS. You become its
        recovery admin.
      </p>
      <Button onclick={chooseCreate}>Create New Account</Button>
    </div>

    <div
      class="p-4 rounded-lg bg-base-50 dark:bg-base-900 border border-base-200 dark:border-base-800 space-y-2"
    >
      <h3 class="font-semibold text-base-900 dark:text-base-50">Import an existing account</h3>
      <p class="text-sm text-base-600 dark:text-base-400">
        Use an app password to take stewardship of an account you already control.
      </p>
      <Button onclick={chooseImport}>Import Existing Account</Button>
    </div>

    {#if setupState.error}
      <p class="text-sm text-red-500">{setupState.error}</p>
    {/if}
  </div>

  <div class="flex justify-between pt-2">
    <Button variant="ghost" onclick={goBack}>Back</Button>
  </div>
</div>
