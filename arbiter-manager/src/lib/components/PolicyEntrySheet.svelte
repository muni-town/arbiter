<script lang="ts">
  import { Sheet, Button, Input, Box } from '@foxui/core';
  import PolicyEditor from './PolicyEditor.svelte';
  import { POLICY_COLLECTION } from '$lib/arbiter';
  import { ensureWasm, checkPolicy } from '$lib/wasm';

  let {
    open = $bindable(),
    /** The policy name (record rkey); empty for a new entry. */
    initialRkey = '',
    /** The Rego source to seed the editor with. */
    initialSource = '',
    /** Whether the policy name can be chosen (a brand-new record). */
    isNew = false,
    /** Sheet title override. */
    title,
    /** Sheet description override (explains where/how the record is written). */
    description,
    onSave,
  }: {
    open: boolean;
    initialRkey?: string;
    initialSource?: string;
    isNew?: boolean;
    title?: string;
    description?: string;
    onSave?: (rkey: string, source: string) => void;
  } = $props();

  let rkey = $state('');
  let source = $state('');
  let validationError = $state<string | null>(null);
  let formError = $state<string | null>(null);
  let wasmReady = $state(false);

  function onOpen() {
    rkey = initialRkey;
    source = initialSource;
    validationError = null;
    formError = null;
    wasmReady = false;
    ensureWasm().then(() => {
      wasmReady = true;
    });
  }

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

  function save() {
    formError = validate();
    if (formError) return;

    if (wasmReady) {
      validationError = checkPolicy(source);
      if (validationError) return;
    }

    onSave?.(rkey, source);
    open = false;
  }

  function onClose() {
    open = false;
  }
</script>

<Sheet
  bind:open
  title={title ?? (isNew ? 'Add Policy' : `Edit Policy: ${initialRkey}`)}
  description={
    description ??
      (isNew
        ? 'Creates a `town.muni.arbiter.policy` record in this community\'s repo (via the arbiter proxy) and appends it to the END of the policy layers. Both requests are evaluated by the installed policy and can be denied.'
        : 'Saving rewrites the policy record via the arbiter proxy and re-installs it: the layer keeps its position.')
  }
  onOpenAutoFocus={onOpen}
>
  <div class="flex flex-col gap-4 py-2">
    {#if isNew}
      <div class="flex flex-col gap-2">
        <label for="policy-rkey-input" class="text-sm font-medium text-base-700 dark:text-base-300">
          Policy Name
        </label>
        <Input
          id="policy-rkey-input"
          bind:value={rkey}
          placeholder="default"
          disabled={!isNew}
        />
        <p class="text-xs text-base-500">
          The record is stored as
          <code class="font-mono">at://&lt;did&gt;/{POLICY_COLLECTION}/{rkey || '<name>'}</code>
        </p>
      </div>
    {/if}

    <div class="flex flex-col gap-2">
      <div class="flex items-center justify-between">
        <span class="text-sm font-medium text-base-700 dark:text-base-300">Rego Source</span>
        {#if validationError}
          <span class="text-xs text-red-500">Policy has errors</span>
        {/if}
      </div>
      <div class="h-72">
        <PolicyEditor value={source} onChange={(v) => (source = v)} />
      </div>
    </div>

    {#if validationError}
      <Box class="p-3 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg">
        <p class="text-xs font-semibold text-red-700 dark:text-red-300 mb-1">Policy validation failed</p>
        <pre class="text-xs text-red-600 dark:text-red-400 font-mono whitespace-pre-wrap">{validationError}</pre>
      </Box>
    {/if}
    {#if formError}
      <p class="text-sm text-red-500">{formError}</p>
    {/if}
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={onClose}>Cancel</Button>
    <Button onclick={save}>{isNew ? 'Add Policy' : 'Save & Update'}</Button>
  {/snippet}
</Sheet>