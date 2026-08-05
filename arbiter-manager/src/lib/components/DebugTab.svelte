<script lang="ts">
  import { Button, Box } from '@foxui/core';
  import MonacoEditor from './MonacoEditor.svelte';
  import { TID } from '@atproto/common-web';
  import { arbiter } from '$lib/arbiter';
  import type { LexMap } from '@atproto/lex';

  let { did }: { did: string } = $props();

  let collection = $state('app.bsky.feed.post');
  let rkey = $state(TID.next().str);
  let recordJson = $state(
    `{\n  "$type": "app.bsky.feed.post",\n  "text": "Hello from arbiter debug!",\n  "createdAt":"${new Date().toISOString()}"\n}`,
  );

  let sending = $state(false);
  let result = $state<string | null>(null);
  let error = $state<string | null>(null);

  async function send() {
    sending = true;
    result = null;
    error = null;

    try {
      let record: LexMap;
      try {
        record = JSON.parse(recordJson);
      } catch {
        error = 'Invalid JSON in record';
        return;
      }

      // Use current DID as repo if none provided
      const res = await arbiter.putRecord(did, collection.trim(), record, rkey.trim() || undefined);
      result = JSON.stringify(res, null, 2);
    } catch (e) {
      error = arbiter.formatError(e);
    } finally {
      sending = false;
    }
  }
</script>

<div class="flex-1 overflow-auto h-full">
  <div class="p-4 space-y-4 h-full flex flex-col">
    <h3 class="text-sm font-semibold text-base-700 dark:text-base-300 uppercase tracking-wider">
      Debug: putRecord
    </h3>
    <p class="text-xs text-base-500">
      Create a record on the arbiter's PDS via <code class="font-mono"
        >com.atproto.repo.putRecord</code
      >, proxied through the arbiter service.
    </p>

    <div class="flex flex-col gap-3">
      <div class="flex items-center gap-3">
        <div class="flex-1 flex flex-col gap-1">
          <label class="text-xs font-medium text-base-600 dark:text-base-400" for="debug-collection"
            >Collection (NSID)</label
          >
          <input
            id="debug-collection"
            bind:value={collection}
            class="px-3 py-2 rounded-lg border border-base-200 dark:border-base-800 bg-base-50 dark:bg-base-950 text-sm text-base-800 dark:text-base-200 font-mono"
            placeholder="app.bsky.feed.post"
          />
        </div>
        <div class="flex-1 flex flex-col gap-1">
          <label class="text-xs font-medium text-base-600 dark:text-base-400" for="debug-rkey"
            >Record Key (optional)</label
          >
          <input
            id="debug-rkey"
            bind:value={rkey}
            class="px-3 py-2 rounded-lg border border-base-200 dark:border-base-800 bg-base-50 dark:bg-base-950 text-sm text-base-800 dark:text-base-200 font-mono"
            placeholder="auto-generated"
          />
        </div>
      </div>

      <div class="flex flex-col gap-1">
        <span class="text-xs font-medium text-base-600 dark:text-base-400">Record (JSON)</span>
        <div class="h-64">
          <MonacoEditor bind:value={recordJson} language="json" />
        </div>
      </div>

      <div class="flex items-center gap-2">
        <Button onclick={send} disabled={sending}>
          {sending ? 'Sending…' : 'Put Record'}
        </Button>
      </div>

      {#if result}
        <Box
          class="p-3 border border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-900/20 rounded-lg"
        >
          <p class="text-xs font-semibold text-emerald-700 dark:text-emerald-300 mb-1">Success</p>
          <pre
            class="text-xs text-emerald-600 dark:text-emerald-400 font-mono whitespace-pre-wrap">{result}</pre>
        </Box>
      {/if}

      {#if error}
        <Box
          class="p-3 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg"
        >
          <p class="text-xs font-semibold text-red-700 dark:text-red-300 mb-1">Error</p>
          <pre
            class="text-xs text-red-600 dark:text-red-400 font-mono whitespace-pre-wrap">{error}</pre>
        </Box>
      {/if}
    </div>
  </div>
</div>
