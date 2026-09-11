<script lang="ts">
  import { isDidString } from '@atproto/lex';
  import { goto } from '$app/navigation';
  import { Button, Input, Box } from '@foxui/core';
  import { POLICY_COLLECTION, NEW_POLICY_TEMPLATE, arbiter } from '$lib/arbiter';
  import { auth } from '$lib/auth.svelte';
  import PolicyEditor from './PolicyEditor.svelte';
  import { ensureWasm, checkPolicy } from '$lib/wasm';

  let {
    /** The policy name (record rkey); empty for a new entry. */
    initialRkey = '',
  }: { initialRkey?: string } = $props();

  const isNew = $derived(!initialRkey);
  const did = $derived(auth.did);

  let rkey = $state(initialRkey);
  let source = $state('');
  let loading = $state(!isNew);
  let loadError = $state<string | null>(null);
  /** The record exists but has no string `policy` field. */
  let missingPolicyField = $state(false);
  let validationError = $state<string | null>(null);
  let formError = $state<string | null>(null);
  let saving = $state(false);
  let wasmReady = $state(false);

  // ── Seed / load the policy source ──────────────────────────────────────
  $effect(() => {
    ensureWasm().then(() => (wasmReady = true));

    if (isNew) {
      source = NEW_POLICY_TEMPLATE;
      loading = false;
      return;
    }

    const client = auth.client;
    if (!client || !did || !isDidString(did)) {
      loading = false;
      return;
    }

    let cancelled = false;
    loading = true;
    loadError = null;
    missingPolicyField = false;

    client
      .getRecord(POLICY_COLLECTION, initialRkey, { repo: did })
      .then((resp) => {
        if (cancelled) return;
        const value = resp.body.value as { policy?: unknown } | null;
        const policy = value?.policy;
        if (typeof policy === 'string') {
          source = policy;
        } else {
          source = '';
          missingPolicyField = true;
        }
        loading = false;
      })
      .catch((e) => {
        if (cancelled) return;
        loadError = arbiter.formatError(e);
        loading = false;
      });

    return () => {
      cancelled = true;
    };
  });

  /**
   * Policy names become record rkeys, so keep them URI-path safe.
   */
  function validate(): string | null {
    if (!rkey.trim()) return 'Enter a policy name';
    if (!/^[a-zA-Z0-9._~-]+$/.test(rkey)) {
      return 'Policy name may only contain letters, numbers, and `. _ ~ -`';
    }
    return null;
  }

  /**
   * Publishes the Rego source as a `town.muni.arbiter.policy` record directly
   * in the logged-in account's repo (create for a new record, put for an
   * existing one), then returns to the library list with a status flag.
   */
  async function save() {
    formError = validate();
    if (formError) return;

    if (wasmReady) {
      validationError = checkPolicy(source);
      if (validationError) return;
    }

    const client = auth.client;
    if (!client || !did || !isDidString(did)) return;
    saving = true;
    formError = null;
    try {
      const record = {
        $type: POLICY_COLLECTION as `${string}.${string}.${string}`,
        policy: source,
      };
      if (isNew) {
        await client.createRecord(record, rkey, { repo: did });
        await goto(`/library?created=${encodeURIComponent(rkey)}`);
      } else {
        await client.putRecord(record, initialRkey, { repo: did });
        await goto(`/library?saved=${encodeURIComponent(initialRkey)}`);
      }
    } catch (e) {
      formError = arbiter.formatError(e);
    } finally {
      saving = false;
    }
  }
</script>

<div class="flex-1 overflow-auto h-full">
  <div class="max-w-4xl mx-auto w-full p-4 h-full min-h-0 flex flex-col gap-4">
    <!-- ── Header ─────────────────────────────────────────────────────────── -->
    <div class="flex items-start justify-between gap-2">
      <div class="min-w-0">
        <h2 class="text-lg font-semibold text-base-900 dark:text-base-50 truncate">
          {isNew ? 'New Library Policy' : `Edit Library Policy: ${initialRkey}`}
        </h2>
        <p class="text-xs text-base-500 dark:text-base-500 mt-0.5">
          {isNew
            ? 'Creates a `town.muni.arbiter.policy` record in your own repo (the logged-in account). Copy its at:// URI afterwards to reference it from arbiter configs.'
            : 'Saving rewrites the record directly in your repo. Any arbiter config referencing this URI picks up the new source.'}
        </p>
      </div>
      <Button variant="ghost" size="sm" onclick={() => goto('/library')}>Back to Library</Button>
    </div>

    {#if loading}
      <Box class="animate-pulse h-48" />
    {:else if loadError}
      <Box class="p-4 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg">
        <p class="text-sm font-medium text-red-800 dark:text-red-300">Failed to load policy</p>
        <p class="text-xs text-red-700 dark:text-red-400 mt-1">{loadError}</p>
        <div class="mt-3">
          <Button size="sm" variant="secondary" onclick={() => goto('/library')}>
            Back to Library
          </Button>
        </div>
      </Box>
    {:else if !did}
      <Box class="p-6 text-center text-sm text-base-500 dark:text-base-500">
        Sign in to manage your policy library.
      </Box>
    {:else}
      {#if isNew}
        <div class="flex flex-col gap-2">
          <label for="policy-rkey-input" class="text-sm font-medium text-base-700 dark:text-base-300">
            Policy Name
          </label>
          <Input
            id="policy-rkey-input"
            bind:value={rkey}
            placeholder="default"
          />
          <p class="text-xs text-base-500">
            The record is stored as
            <code class="font-mono">at://&lt;did&gt;/{POLICY_COLLECTION}/{rkey || '<name>'}</code>
          </p>
        </div>
      {:else if missingPolicyField}
        <Box class="p-3 border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 rounded-lg">
          <p class="text-xs text-amber-800 dark:text-amber-300">
            This record has no <code class="font-mono">policy</code> (Rego source) field — saving
            will replace it with the source below.
          </p>
        </Box>
      {/if}

      <div class="flex flex-col gap-2 flex-1 min-h-0">
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium text-base-700 dark:text-base-300">Rego Source</span>
          {#if validationError}
            <span class="text-xs text-red-500">Policy has errors</span>
          {/if}
        </div>
        <div class="flex-1 min-h-0">
          <PolicyEditor value={source} onChange={(v) => (source = v)} />
        </div>
      </div>

      {#if validationError}
        <Box class="p-3 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg">
          <p class="text-xs font-semibold text-red-700 dark:text-red-300 mb-1">
            Policy validation failed
          </p>
          <pre class="text-xs text-red-600 dark:text-red-400 font-mono whitespace-pre-wrap">{validationError}</pre>
        </Box>
      {/if}
      {#if formError}
        <p class="text-sm text-red-500">{formError}</p>
      {/if}

      <div class="flex items-center justify-end gap-2">
        {#if saving}
          <span class="text-xs text-base-500 mr-auto">Saving…</span>
        {/if}
        <Button variant="secondary" onclick={() => goto('/library')} disabled={saving}>
          Cancel
        </Button>
        <Button onclick={save} disabled={saving}>
          {isNew ? 'Create Policy' : 'Save Changes'}
        </Button>
      </div>
    {/if}
  </div>
</div>