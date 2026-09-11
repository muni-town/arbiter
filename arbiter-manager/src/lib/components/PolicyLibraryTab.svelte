<script lang="ts">
  import { isDidString } from '@atproto/lex';
  import { Button, Box } from '@foxui/core';
  import { auth } from '$lib/auth.svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { POLICY_COLLECTION, parseAtUri, policyUri, arbiter } from '$lib/arbiter';

  /** A `town.muni.arbiter.policy` record in the logged-in account's own repo. */
  interface LibraryEntry {
    rkey: string;
    uri: string;
    /** Rego source of the record, when readable. */
    source?: string;
    /** Per-record load problem, if the record shape is unexpected. */
    error?: string;
  }

  let entries = $state<LibraryEntry[]>([]);
  let loading = $state(false);
  let error = $state<string | null>(null);
  let status = $state<string | null>(null);
  let deleting = $state(false);
  /** rkey of the row with an armed (two-step) delete confirmation. */
  let confirmDeleteRkey = $state<string | null>(null);
  /** rkey of the row whose at:// URI was just copied. */
  let copiedRkey = $state<string | null>(null);
  let copyError = $state<string | null>(null);

  const did = $derived(auth.did);

  // ── Save status handed back from the editor page (?created=/?saved=) ──
  const editorStatus = $derived.by(() => {
    const created = page.url.searchParams.get('created');
    if (created) return `Policy “${created}” created`;
    const saved = page.url.searchParams.get('saved');
    if (saved) return `Policy “${saved}” saved`;
    return null;
  });

  // ── Load the library whenever the session changes ──────────────────────
  $effect(() => {
    if (auth.client && did) void load();
    else {
      loading = false;
      error = null;
      entries = [];
    }
  });

  async function load() {
    const client = auth.client;
    if (!client || !did || !isDidString(did)) return;
    loading = true;
    error = null;
    try {
      const loaded: LibraryEntry[] = [];
      /** rkeys already collected — guards against overlapping/broken pages. */
      const seen = new Set<string>();
      let cursor: string | undefined;
      do {
        const resp = await client.listRecords(POLICY_COLLECTION, {
          repo: did,
          ...(cursor ? { cursor } : {}),
        });
        for (const record of resp.body.records) {
          const parts = parseAtUri(record.uri);
          const rkey = parts?.rkey;
          if (!rkey || seen.has(rkey)) continue;
          seen.add(rkey);
          const policy = record.value['policy'];
          loaded.push({
            rkey,
            uri: policyUri(did, rkey),
            source: typeof policy === 'string' ? policy : undefined,
            error: typeof policy !== 'string' ? 'Record has no policy (Rego source) field' : undefined,
          });
        }
        const next = resp.body.cursor;
        // Stop at the end of the list. Also stop when the server makes no
        // progress (same cursor again, or an empty page) — a server that
        // returns a cursor on every response would otherwise be re-requested
        // forever.
        if (!next || next === cursor || resp.body.records.length === 0) break;
        cursor = next;
      } while (cursor);
      entries = loaded;
    } catch (e) {
      error = arbiter.formatError(e);
    } finally {
      loading = false;
    }
  }

  /** First non-comment, non-empty Rego line — a one-line preview of the policy. */
  function previewLine(source: string | undefined): string {
    if (!source) return '';
    for (const line of source.split('\n')) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) return trimmed;
    }
    return '';
  }

  // ── Open the full-page editor (create / edit) ──────────────────────────
  function openNewPolicy() {
    void goto('/library/new');
  }

  function openEditPolicy(entry: LibraryEntry) {
    void goto(`/library/${encodeURIComponent(entry.rkey)}`);
  }

  // ── Delete ─────────────────────────────────────────────────────────────
  function deleteRecord(entry: LibraryEntry) {
    // Two-step confirmation: the first click arms the button, the second
    // (within a few seconds) actually deletes.
    if (confirmDeleteRkey !== entry.rkey) {
      confirmDeleteRkey = entry.rkey;
      setTimeout(() => {
        if (confirmDeleteRkey === entry.rkey) confirmDeleteRkey = null;
      }, 4000);
      return;
    }
    confirmDeleteRkey = null;
    void doDelete(entry);
  }

  async function doDelete(entry: LibraryEntry) {
    const client = auth.client;
    if (!client || !did || !isDidString(did)) return;
    deleting = true;
    error = null;
    status = null;
    try {
      await client.deleteRecord(POLICY_COLLECTION, entry.rkey, { repo: did });
      status = `Policy “${entry.rkey}” deleted`;
      await load();
    } catch (e) {
      error = arbiter.formatError(e);
    } finally {
      deleting = false;
    }
  }

  // ── Copy the at:// URI ─────────────────────────────────────────────────
  async function copyUri(entry: LibraryEntry) {
    if (!did) return;
    copyError = null;
    try {
      await navigator.clipboard.writeText(policyUri(did, entry.rkey));
      copiedRkey = entry.rkey;
      setTimeout(() => {
        if (copiedRkey === entry.rkey) copiedRkey = null;
      }, 1500);
    } catch (e) {
      copyError = `Could not copy to clipboard: ${arbiter.formatError(e)}`;
    }
  }
</script>

<div class="flex-1 overflow-auto h-full">
  <div class="max-w-4xl mx-auto w-full p-4 space-y-4 h-full flex flex-col">
    {#if loading}
      <Box class="animate-pulse h-48" />
    {:else if error}
      <Box class="p-4 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg">
        <p class="text-sm font-medium text-red-800 dark:text-red-300">Failed to load policy library</p>
        <p class="text-xs text-red-700 dark:text-red-400 mt-1">{error}</p>
        <div class="mt-3">
          <Button size="sm" variant="secondary" onclick={load}>Retry</Button>
        </div>
      </Box>
    {:else if !did}
      <Box class="p-6 text-center text-sm text-base-500 dark:text-base-500">
        Sign in to manage your policy library.
      </Box>
    {:else}
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-base-700 dark:text-base-300 uppercase tracking-wider">
          Policy Library
        </h3>
        <div class="flex items-center gap-2">
          {#if deleting}
            <span class="text-xs text-base-500 dark:text-base-500">Deleting…</span>
          {/if}
          {#if status}
            <span class="text-xs text-emerald-600 dark:text-emerald-400">{status}</span>
          {:else if editorStatus}
            <span class="text-xs text-emerald-600 dark:text-emerald-400">{editorStatus}</span>
          {/if}
          <Button size="sm" onclick={openNewPolicy} disabled={deleting}>
            New Policy
          </Button>
        </div>
      </div>
      <p class="text-xs text-base-500 dark:text-base-500">
        Shared, publishable policy records in your own repo (<code class="font-mono">{did}</code>):
        create a policy here, copy its <code class="font-mono">at://</code> URI, and reference it
        from arbiter configs — the setup bootstrap and the policy tab's “Reset Config” sheet take
        these URIs. Records here are written directly — not
        through an arbiter proxy — and are not installed anywhere until a config references them.
      </p>

      {#if copyError}
        <Box class="text-sm text-red-500 p-3">{copyError}</Box>
      {/if}

      <!-- ── Library entries ───────────────────────────────────────────── -->
      {#if entries.length === 0}
        <Box class="p-6 text-center space-y-2">
          <p class="text-sm font-medium text-base-700 dark:text-base-300">
            Your policy library is empty
          </p>
          <p class="text-sm text-base-500 dark:text-base-500">
            This library holds
            <code class="font-mono">town.muni.arbiter.policy</code>
            records in your own repo — a place to author and publish shared policies once, then
            reference their <code class="font-mono">at://</code> URIs from any arbiter's config
            instead of copying the Rego source into each community. Create your first policy to
            get started.
          </p>
          <div class="pt-2">
            <Button size="sm" variant="secondary" onclick={openNewPolicy} disabled={deleting}>
              New Policy
            </Button>
          </div>
        </Box>
      {:else}
        <ul class="space-y-1">
          {#each entries as entry (entry.rkey)}
            <li
              class="flex items-center gap-2 p-2 rounded-lg border border-base-200 dark:border-base-800 bg-base-50 dark:bg-base-900"
            >
              <div class="flex-1 min-w-0">
                <button
                  class="text-sm font-medium text-accent-700 dark:text-accent-300 hover:underline text-left"
                  onclick={() => openEditPolicy(entry)}
                >
                  {entry.rkey}
                </button>
                {#if previewLine(entry.source)}
                  <p class="text-xs text-base-500 dark:text-base-500 font-mono truncate">
                    {previewLine(entry.source)}
                  </p>
                {/if}
                <p class="text-xs text-base-400 font-mono truncate">{entry.uri}</p>
                {#if entry.error}
                  <p class="text-xs text-red-500">{entry.error}</p>
                {/if}
              </div>
              <div class="flex items-center gap-1">
                <Button
                  size="sm"
                  variant={copiedRkey === entry.rkey ? 'secondary' : 'ghost'}
                  onclick={() => copyUri(entry)}
                  title="Copy the at:// URI of this policy record"
                >
                  {copiedRkey === entry.rkey ? 'Copied!' : 'Copy URI'}
                </Button>
                <Button size="sm" variant="ghost" onclick={() => openEditPolicy(entry)}>
                  Edit
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  class="text-red-500"
                  disabled={deleting}
                  onclick={() => deleteRecord(entry)}
                  title={confirmDeleteRkey === entry.rkey
                    ? 'Click again to permanently delete this record'
                    : 'Delete this policy record'}
                >
                  {confirmDeleteRkey === entry.rkey ? 'Confirm delete' : '✕'}
                </Button>
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
  </div>
</div>