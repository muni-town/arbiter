<script lang="ts">
  import { Modal, Button, Box } from '@foxui/core';
  import PolicyEditor from './PolicyEditor.svelte';
  import { arbiter, parseAtUri } from '$lib/arbiter';

  let {
    open = $bindable(),
    /** Readable policy name: `<handle-or-did>/<collection>/<rkey>`. */
    title,
    /** The full `at://` record URI (shown under the title). */
    uri,
    /** Pre-loaded Rego source; when omitted, the record is fetched from its repo. */
    source,
    /** Present when the policy record is editable (a local record) — shows an Edit button. */
    onEdit,
  }: {
    open: boolean;
    title: string;
    uri: string;
    source?: string;
    onEdit?: () => void;
  } = $props();

  let viewSource = $state<string | null>(null);
  let viewError = $state<string | null>(null);
  let viewLoading = $state(false);

  function onOpen() {
    viewError = null;

    // A pre-loaded source (a local policy record) is shown as-is; anything
    // else is read from the record's repo, guarded against a stale result
    // landing after the dialog is reopened for a different URI.
    if (source !== undefined) {
      viewSource = source;
      viewLoading = false;
      return;
    }

    const parts = parseAtUri(uri);
    if (!parts) {
      viewSource = null;
      viewError = `Not a valid \`at://\` record URI: ${uri}`;
      return;
    }

    const requested = uri;
    viewSource = null;
    viewLoading = true;
    arbiter
      .getPolicyRecord(parts.did, parts.rkey, parts.collection)
      .then((src) => {
        if (uri === requested) viewSource = src;
      })
      .catch((e) => {
        if (uri === requested) viewError = arbiter.formatError(e);
      })
      .finally(() => {
        if (uri === requested) viewLoading = false;
      });
  }

  function onClose() {
    open = false;
  }
</script>

<Modal
  bind:open
  class="max-w-3xl"
  onOpenAutoFocus={onOpen}
  contentProps={{
    'aria-labelledby': 'policy-view-title',
    'aria-describedby': 'policy-view-uri',
  }}
>
  <div class="flex flex-col gap-4">
    <div class="flex flex-col gap-1 pr-8">
      <h2
        id="policy-view-title"
        class="text-lg font-semibold text-base-900 dark:text-base-100 truncate"
      >
        {title}
      </h2>
      <p id="policy-view-uri" class="text-xs font-mono text-base-500 dark:text-base-400 break-all">
        {uri}
      </p>
    </div>

    {#if viewLoading}
      <Box class="animate-pulse h-96" />
    {:else if viewError}
      <Box
        class="p-3 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg"
      >
        <p class="text-xs font-semibold text-red-700 dark:text-red-300 mb-1">
          Could not load the policy record
        </p>
        <p class="text-xs text-red-600 dark:text-red-400 font-mono whitespace-pre-wrap">
          {viewError}
        </p>
      </Box>
    {:else}
      <div class="h-96">
        <PolicyEditor value={viewSource ?? ''} readOnly />
      </div>
    {/if}

    <div class="flex justify-end gap-2">
      <Button variant="secondary" onclick={onClose}>Close</Button>
      {#if onEdit}
        <Button onclick={onEdit}>Edit</Button>
      {/if}
    </div>
  </div>
</Modal>