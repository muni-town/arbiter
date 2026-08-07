<script lang="ts">
  import { Button, Box } from '@foxui/core';
  import PolicyEditor from './PolicyEditor.svelte';
  import ResetPolicySheet from './ResetPolicySheet.svelte';
  import { arbiter } from '$lib/arbiter';
  import { ensureWasm, checkPolicy } from '$lib/wasm';

  let { arbiterDid }: { arbiterDid?: string } = $props();

  // ── State ───────────────────────────────────────────────────────────────
  let policy = $state('');
  let loading = $state(false);
  let error = $state<string | null>(null);

  let saving = $state(false);
  let saveError = $state<string | null>(null);
  let saveSuccess = $state(false);

  let showReset = $state(false);

  let validationError = $state<string | null>(null);
  let wasmReady = $state(false);

  // ── Initialise WASM on mount ────────────────────────────────────────────
  $effect(() => {
    ensureWasm().then(() => { wasmReady = true; });
  });

  // ── Load policy when arbiterDid changes ─────────────────────────────────
  $effect(() => {
    if (arbiterDid) loadPolicy();
    else {
      policy = '';
      loading = false;
      error = null;
    }
  });

  async function loadPolicy() {
    if (!arbiterDid) return;

    loading = true;
    error = null;
    saveSuccess = false;

    try {
      policy = await arbiter.getPolicy(arbiterDid);
    } catch (e) {
      error = arbiter.formatError(e);
    } finally {
      loading = false;
    }
  }

  async function savePolicy() {
    if (!arbiterDid) return;

    // Validate policy locally before sending
    validationError = null;
    if (wasmReady) {
      const err = checkPolicy(policy);
      if (err) {
        validationError = err;
        return;
      }
    }

    saving = true;
    saveError = null;
    saveSuccess = false;

    try {
      await arbiter.setPolicy(arbiterDid, policy);
      saveSuccess = true;
    } catch (e) {
      saveError = arbiter.formatError(e);
    } finally {
      saving = false;
    }
  }

  /**
   * Open the reset-policy dialog: choose the owner account, then confirm to
   * reset the policy via the `resetPolicy` recovery endpoint. This bypasses the
   * policy itself, so it works even when the current policy denies normal
   * updates — the recovery path out of a broken policy.
   */
  function openResetDialog() {
    saveError = null;
    showReset = true;
  }</script>

<div class="flex-1 overflow-auto h-full">
  <div class="p-4 space-y-4 h-full flex flex-col">
    {#if loading}
      <Box class="animate-pulse h-48" />
    {:else if error}
      <Box class="p-4 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg">
        <p class="text-sm font-medium text-red-800 dark:text-red-300">Failed to load policy</p>
        <p class="text-xs text-red-700 dark:text-red-400 mt-1">{error}</p>
        <div class="mt-3">
          <Button size="sm" variant="secondary" onclick={loadPolicy}>Retry</Button>
        </div>
      </Box>
    {:else if arbiterDid && !loading && !error}
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-base-700 dark:text-base-300 uppercase tracking-wider">
          Policy (Rego)
        </h3>
        <div class="flex items-center gap-2">
          {#if saveSuccess}
            <span class="text-xs text-emerald-600 dark:text-emerald-400">Saved</span>
          {/if}
          {#if validationError}
            <span class="text-xs text-red-500">Policy has errors</span>
          {/if}
          <Button size="sm" variant="secondary" onclick={openResetDialog}>
            Reset Policy
          </Button>
          <Button size="sm" onclick={savePolicy} disabled={saving}>
            {saving ? 'Saving…' : 'Save Policy'}
          </Button>
        </div>
      </div>

      <div class="basis-full">
        <PolicyEditor value={policy} onChange={(v) => policy = v} />
      </div>

      {#if saveError}
        <Box class="text-sm text-red-500 p-3">{saveError}</Box>
      {/if}
      {#if validationError}
        <Box class="p-3 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg">
          <p class="text-xs font-semibold text-red-700 dark:text-red-300 mb-1">Policy validation failed</p>
          <pre class="text-xs text-red-600 dark:text-red-400 font-mono whitespace-pre-wrap">{validationError}</pre>
        </Box>
      {/if}
    {:else if !arbiterDid}
      <Box class="p-6 text-center text-sm text-base-500 dark:text-base-500">
        Search for a community above to view and edit its authorization policy.
      </Box>
    {/if}
  </div>
</div>

{#if arbiterDid}
  <ResetPolicySheet bind:open={showReset} {arbiterDid} onReset={loadPolicy} />
{/if}