<script lang="ts">
  import { Button, Input } from '@foxui/core';
  import { setupState } from '$lib/setupState.svelte';
  import { auth } from '$lib/auth.svelte';

  let handleInput = $state('');

  async function proceedWithLogin() {
    const handle = handleInput.trim();
    if (!handle && auth.profile) {
      setupState.step = 'choose';
      setupState.error = undefined;
      setupState.loading = false;
      return;
    } else if (!handle) {
      setupState.error = 'You must provide a handle to login';
    }

    setupState.loading = true;

    try {
      // Save setup state before redirect
      setupState.step = 'oauth';
      setupState.error = undefined;

      await auth.loginWithHandle(handle);
      // After the above returns, the browser has redirected
      // (or will redirect). If we get here, something went wrong.
      setupState.error = 'OAuth login failed to initiate. Please try again.';
    } catch (e) {
      setupState.error = `Login failed: ${e}`;
      setupState.loading = false;
    }
  }

  function goBack() {
    setupState.step = 'intro';
  }
</script>

<form class="max-w-lg mx-auto px-6 py-12 space-y-6" onsubmit={proceedWithLogin}>
  <div class="space-y-2">
    <h2 class="text-xl font-semibold text-base-900 dark:text-base-50">Sign In with AT Protocol</h2>
    <p class="text-sm text-base-600 dark:text-base-400">
      Sign in with the account that owns the community DID. You'll be redirected to your PDS to
      authorize this app via OAuth.
    </p>
  </div>

  <div class="space-y-4">
    <div class="flex flex-col gap-2">
      <label for="handle-input" class="text-sm font-medium text-base-700 dark:text-base-300">
        Your AT Protocol Handle or DID
      </label>
      <Input
        id="handle-input"
        bind:value={handleInput}
        placeholder={auth.profile ? auth.profile.handle : 'account.bsky.social'}
        disabled={setupState.loading}
      />
      <p class="text-xs text-base-500">
        This is the account that will become the stewarded arbiter account.
      </p>
    </div>

    {#if setupState.error}
      <p class="text-sm text-red-500">{setupState.error}</p>
    {/if}
  </div>

  <div class="flex justify-between pt-2">
    <Button variant="ghost" onclick={goBack} disabled={setupState.loading}>Back</Button>
    <Button type="submit" disabled={(setupState.loading || !handleInput.trim()) && !auth.session}>
      {setupState.loading
        ? 'Redirecting to PDS…'
        : auth.profile && !handleInput
          ? `Use ${auth.profile.handle}`
          : 'Sign In with OAuth'}
    </Button>
  </div>
</form>
