<script lang="ts">
  import { Button, Box, Input } from '@foxui/core';
  import { isNsidString } from '@atproto/lex';
  import PolicyEntrySheet from './PolicyEntrySheet.svelte';
  import {
    arbiter,
    parseAtUri,
    policyUri,
    POLICY_COLLECTION,
    NEW_POLICY_TEMPLATE,
  } from '$lib/arbiter';

  let { arbiterDid }: { arbiterDid?: string } = $props();

  // ── State ───────────────────────────────────────────────────────────────

  /** One entry of the ordered policy layers. */
  interface LayerEntry {
    /** The `at://` URI referenced by the config record's policy layers. */
    uri: string;
    /** For local policy records (`at://<arbiterDid>/<collection>/<rkey>`): the rkey. */
    rkey?: string;
    /** Rego source of a local policy record (loaded from the repo or edited here). */
    source?: string;
    /** Load error for this entry, if any. */
    error?: string;
  }

  /** The live policy-layer order from the config record (dirty detection). */
  let liveUris = $state<string[]>([]);
  /** The staged layers: the live order plus local move/remove edits. */
  let entries = $state<LayerEntry[]>([]);
  /** Loaded entry details by URI, so Discard can restore removed entries. */
  let entryDetails = $state(new Map<string, LayerEntry>());
  /** The live trusted scopes from the config record (dirty detection). */
  let liveScopes = $state<string[]>([]);
  /** The staged scopes: the live scopes minus locally removed ones. */
  let trustedScopes = $state<string[]>([]);
  /** New scopes staged for an append install (not yet sent). */
  let pendingScopes = $state<string[]>([]);

  let loading = $state(false);
  let error = $state<string | null>(null);

  /** An append (installPolicy) request in flight. */
  let installing = $state(false);
  /** A config-record restructure write in flight. */
  let saving = $state(false);
  let installError = $state<string | null>(null);
  let status = $state<string | null>(null);

  // Add-policy / add-reference controls.
  let newPolicyName = $state('');
  let newRefUri = $state('');
  let addError = $state<string | null>(null);

  // New-scope input.
  let newScope = $state('');

  // Policy entry editor sheet.
  let editorOpen = $state(false);
  let editorInitialRkey = $state('');
  let editorInitialSource = $state('');
  let editorIsNew = $state(false);

  // ── Load when arbiterDid changes ────────────────────────────────────────
  $effect(() => {
    if (arbiterDid) load();
    else {
      liveUris = [];
      entries = [];
      entryDetails = new Map();
      liveScopes = [];
      trustedScopes = [];
      pendingScopes = [];
      loading = false;
      error = null;
    }
  });

  /** The rkey if `uri` points at a policy record in this community's repo. */
  function localRkey(uri: string): string | undefined {
    const parts = parseAtUri(uri);
    if (parts && parts.did === arbiterDid && parts.collection === POLICY_COLLECTION) {
      return parts.rkey;
    }
    return undefined;
  }

  async function load() {
    if (!arbiterDid) return;

    loading = true;
    error = null;
    installError = null;
    status = null;

    try {
      const config = await arbiter.getConfig(arbiterDid);
      liveScopes = config.trustedScopes;
      trustedScopes = [...config.trustedScopes];
      pendingScopes = [];

      // Load every local policy record's source (public read). Remote
      // references are displayed as-is.
      liveUris = config.policyLayers;
      entries = await Promise.all(
        config.policyLayers.map(async (uri): Promise<LayerEntry> => {
          const rkey = localRkey(uri);
          if (rkey === undefined) return { uri };
          try {
            const source = await arbiter.getPolicyRecord(arbiterDid, rkey);
            return { uri, rkey, source };
          } catch (e) {
            return { uri, rkey, error: arbiter.formatError(e) };
          }
        }),
      );
      entryDetails = new Map(entries.map((e) => [e.uri, e]));
    } catch (e) {
      error = arbiter.formatError(e);
      entries = [];
      entryDetails = new Map();
      trustedScopes = [];
      liveUris = [];
      liveScopes = [];
    } finally {
      loading = false;
    }
  }

  // ── Staged-change tracking ──────────────────────────────────────────────

  /** Whether the staged layer order differs from the live config record. */
  let layersDirty = $derived(
    entries.length !== liveUris.length || entries.some((e, i) => e.uri !== liveUris[i]),
  );
  /** Whether the staged scopes differ from the live config record (removals). */
  let scopesDirty = $derived(
    trustedScopes.length !== liveScopes.length ||
      trustedScopes.some((s, i) => s !== liveScopes[i]),
  );
  /**
   * Whether a full config-record rewrite is staged (reorder / remove). While
   * it is pending, appends are disabled: a reload after an append would drop
   * the staged edits.
   */
  let restructuring = $derived(layersDirty || scopesDirty);

  // ── Policy layer editing (staged restructure) ──────────────────────────

  function moveEntry(index: number, delta: -1 | 1) {
    const target = index + delta;
    if (target < 0 || target >= entries.length) return;
    const [entry] = entries.splice(index, 1);
    entries.splice(target, 0, entry);
  }

  function removeEntry(index: number) {
    // Only removes the layer from the config's policy layers; the policy record itself
    // stays in the repo.
    entries.splice(index, 1);
  }

  /**
   * Restore the staged layer order and scopes to the live config record,
   * keeping any staged scope appends (they are a separate channel).
   */
  function discardChanges() {
    entries = liveUris.map((uri) => entryDetails.get(uri) ?? { uri });
    trustedScopes = [...liveScopes];
  }

  /**
   * Write the staged layer order and scope removals as the full config
   * record (`town.muni.arbiter.config/self`) directly to the community's
   * repo via the arbiter proxy. This is the only path that can reorder or
   * remove; the write is evaluated by the installed policy.
   */
  async function saveRestructure() {
    if (!arbiterDid || !restructuring) return;

    saving = true;
    installError = null;
    status = null;

    try {
      await arbiter.putConfig(arbiterDid, {
        trustedScopes,
        policyLayers: entries.map((e) => e.uri),
      });
      await load();
      status = 'Configuration saved';
    } catch (e) {
      installError = arbiter.formatError(e);
    } finally {
      saving = false;
    }
  }

  // ── Append installs (installPolicy) ─────────────────────────────────────

  /** Guard shared by every append: a staged restructure must be settled first. */
  function appendBlocked(): boolean {
    if (restructuring && !installing) {
      installError =
        'Save or discard the pending reorder / removal changes before appending.';
      return true;
    }
    return installing;
  }

  /**
   * Append one policy layer — the `at://` URI of a `town.muni.arbiter.policy`
   * record in any repo — plus any staged new scopes via
   * `town.muni.arbiter.installPolicy`, then reload. The append is evaluated
   * by the arbiter's installed policy layers and can be denied.
   */
  async function appendPolicy(uri: string) {
    if (!arbiterDid || appendBlocked()) return;

    installing = true;
    installError = null;
    status = null;

    try {
      await arbiter.installPolicy(arbiterDid, {
        policy: uri,
        trustedScopes: [...pendingScopes],
      });
      await load();
      status = 'Policy appended';
    } catch (e) {
      installError = arbiter.formatError(e);
    } finally {
      installing = false;
    }
  }

  // ── Policy entry editor sheet ───────────────────────────────────────────

  function openNewPolicy() {
    if (!arbiterDid) return;
    addError = null;
    const name = newPolicyName.trim();
    if (!name) {
      addError = 'Enter a policy name';
      return;
    }
    if (!/^[a-zA-Z0-9._~-]+$/.test(name)) {
      addError = 'Policy name may only contain letters, numbers, and `. _ ~ -`';
      return;
    }
    if (entries.some((e) => e.rkey === name)) {
      addError = `A policy named \`${name}\` is already in the policy layers`;
      return;
    }
    editorIsNew = true;
    editorInitialRkey = name;
    editorInitialSource = NEW_POLICY_TEMPLATE;
    editorOpen = true;
  }

  function openEditPolicy(entry: LayerEntry) {
    addError = null;
    editorIsNew = false;
    editorInitialRkey = entry.rkey ?? '';
    // A layer entry whose record went missing (a ghost) can be healed by
    // re-publishing it: seed the editor with the starter template.
    editorInitialSource = entry.source ?? NEW_POLICY_TEMPLATE;
    editorOpen = true;
  }

  /**
   * Called by the editor sheet. Publishes the Rego source as a
   * `town.muni.arbiter.policy/<rkey>` record in the community's repo (via
   * the arbiter proxy — installPolicy never writes records) and then
   * appends the record's URI: a fresh URI lands at the END of the policy layers,
   * a URI already in the layers updates the layer in place. Both requests
   * are evaluated by the installed policy and can be denied.
   */
  async function saveEntry(rkey: string, source: string) {
    if (!arbiterDid || appendBlocked()) return;

    installing = true;
    installError = null;
    status = null;

    try {
      // 1. Publish the policy record via the arbiter proxy.
      await arbiter.putPolicyRecord(arbiterDid, rkey, source);
    } catch (e) {
      installError = `Could not write the policy record: ${arbiter.formatError(e)}`;
      installing = false;
      return;
    }

    newPolicyName = '';

    try {
      // 2. Append the record's URI (an existing URI updates the layer in place).
      await arbiter.installPolicy(arbiterDid, {
        policy: policyUri(arbiterDid, rkey),
        trustedScopes: [...pendingScopes],
      });
      await load();
      status = 'Policy appended';
    } catch (e) {
      installError = arbiter.formatError(e);
    } finally {
      installing = false;
    }
  }

  async function addReference() {
    if (!arbiterDid) return;
    addError = null;
    const uri = newRefUri.trim();
    const parts = parseAtUri(uri);
    if (!parts) {
      addError = 'Enter a valid `at://<did>/<collection>/<rkey>` URI';
      return;
    }
    if (parts.collection !== POLICY_COLLECTION) {
      addError = `The referenced record must be a \`${POLICY_COLLECTION}\` record`;
      return;
    }
    if (entries.some((e) => e.uri === uri)) {
      addError = 'That record is already in the policy layers';
      return;
    }
    // Best-effort existence check: appending a reference to a missing or
    // malformed record would leave the config pointing at a layer that
    // cannot load (the arbiter fails closed).
    try {
      const value = await arbiter.getPublicRecord(parts.did, parts.collection, parts.rkey);
      if (typeof value.policy !== 'string') {
        addError = 'The referenced record has no `policy` Rego source';
        return;
      }
    } catch (e) {
      addError = `Referenced record could not be read: ${arbiter.formatError(e)}`;
      return;
    }
    newRefUri = '';
    await appendPolicy(uri);
  }

  // ── Trusted scopes editing ──────────────────────────────────────────────

  /** Stage a new scope for the append install (sent with one installPolicy call). */
  function addScope() {
    addError = null;
    const scope = newScope.trim();
    if (!scope) return;
    if (!isNsidString(scope)) {
      addError = 'Enter a valid NSID scope (e.g. `community.lexicon.authCalendar`)';
      return;
    }
    if (trustedScopes.includes(scope) || pendingScopes.includes(scope)) {
      addError = 'That scope is already trusted';
      return;
    }
    pendingScopes.push(scope);
    newScope = '';
  }

  function undoPendingScope(index: number) {
    pendingScopes.splice(index, 1);
  }

  function removeScope(index: number) {
    // Removing an existing scope is a full-restructure change: it stages a
    // removal applied by the config-record write (an append can never remove).
    trustedScopes.splice(index, 1);
  }

  /**
   * Append the staged new scopes via `town.muni.arbiter.installPolicy`
   * (scopes only — no policy layer). The append is evaluated by the
   * arbiter's installed policy layers and can be denied.
   */
  async function installScopes() {
    if (!arbiterDid || pendingScopes.length === 0 || appendBlocked()) return;

    installing = true;
    installError = null;
    status = null;

    try {
      await arbiter.installPolicy(arbiterDid, { trustedScopes: [...pendingScopes] });
      await load();
      status = 'Scopes appended';
    } catch (e) {
      installError = arbiter.formatError(e);
    } finally {
      installing = false;
    }
  }
</script>

<div class="flex-1 overflow-auto h-full">
  <div class="p-4 space-y-4 h-full flex flex-col">
    {#if loading}
      <Box class="animate-pulse h-48" />
    {:else if error}
      <Box class="p-4 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg">
        <p class="text-sm font-medium text-red-800 dark:text-red-300">Failed to load policy configuration</p>
        <p class="text-xs text-red-700 dark:text-red-400 mt-1">{error}</p>
        <div class="mt-3">
          <Button size="sm" variant="secondary" onclick={load}>Retry</Button>
        </div>
      </Box>
    {:else if arbiterDid && !loading && !error}
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-base-700 dark:text-base-300 uppercase tracking-wider">
          Policy Layers &amp; Scopes
        </h3>
        <div class="flex items-center gap-2">
          {#if installing}
            <span class="text-xs text-base-500 dark:text-base-500">Appending…</span>
          {/if}
          {#if status}
            <span class="text-xs text-emerald-600 dark:text-emerald-400">{status}</span>
          {/if}
          {#if restructuring}
            <Button size="sm" variant="ghost" onclick={discardChanges} disabled={saving || installing}>
              Discard
            </Button>
            <Button
              size="sm"
              onclick={saveRestructure}
              disabled={saving || installing || pendingScopes.length > 0}
              title={pendingScopes.length > 0
                ? 'Append or remove the staged new scopes first'
                : 'Writes the reordered policy layers and scope removals to the config record'}
            >
              {saving ? 'Saving…' : 'Save Changes'}
            </Button>
          {/if}
        </div>
      </div>
      <p class="text-xs text-base-500 dark:text-base-500">
        Adding a policy or a trusted scope appends it via
        <code class="font-mono">town.muni.arbiter.installPolicy</code> — the request is evaluated
        by the installed policy layers and can be denied (the arbiter's recovery admin bypasses
        the layers). Reordering or removing layers, or removing scopes, is staged below and
        written to the config record directly with “Save Changes” — that write is also evaluated
        by the installed policy. An append never removes or reorders anything.
      </p>

      {#if restructuring}
        <Box
          class="p-3 text-sm text-amber-700 dark:text-amber-400 border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 rounded-lg"
        >
          Unsaved reorder / removal changes — appends are disabled until you save or discard them.
        </Box>
      {/if}

      {#if installError}
        <Box class="text-sm text-red-500 p-3">{installError}</Box>
      {/if}

      <!-- ── Policy layer editor ─────────────────────────────────────── -->
      <section class="space-y-2">
        <div>
          <h4 class="text-sm font-semibold text-base-800 dark:text-base-200">Policy Layers</h4>
          <p class="text-xs text-base-500 dark:text-base-500">
            Ordered policy layers: the first layer that handles or denies wins; falling off the end
            denies. Newly added policies are appended to the END of the policy layers — the
            lowest-priority slot, so a new layer only sees requests the layers above it pass. Local
            policies are records in this community's repo; references point at
            <code class="font-mono">at://</code> records in any repo.
          </p>
        </div>

        {#if entries.length === 0}
          <Box class="p-3 text-sm text-base-500 dark:text-base-500">
            No policies — every request is denied until the first layer is appended.
          </Box>
        {:else}
          <ul class="space-y-1">
            {#each entries as entry, i (entry.uri)}
              <li
                class="flex items-center gap-2 p-2 rounded-lg border border-base-200 dark:border-base-800 bg-base-50 dark:bg-base-900"
              >
                <span class="text-xs text-base-400 font-mono w-5 text-right">{i + 1}</span>
                <div class="flex-1 min-w-0">
                  {#if entry.rkey !== undefined}
                    <button
                      class="text-sm font-medium text-accent-700 dark:text-accent-300 hover:underline text-left"
                      onclick={() => openEditPolicy(entry)}
                    >
                      {entry.rkey}
                    </button>
                    <p class="text-xs text-base-400 font-mono truncate">{entry.uri}</p>
                  {:else}
                    <p class="text-sm font-mono truncate" title={entry.uri}>{entry.uri}</p>
                  {/if}
                  {#if entry.rkey !== undefined && entry.source === undefined && !entry.error}
                    <p class="text-xs text-base-500">
                      Record missing — edit to re-create it (re-installing heals the layer).
                    </p>
                  {/if}
                  {#if entry.error}
                    <p class="text-xs text-red-500">{entry.error}</p>
                  {/if}
                </div>
                <div class="flex items-center gap-1">
                  {#if entry.rkey !== undefined}
                    <Button size="sm" variant="ghost" onclick={() => openEditPolicy(entry)}>
                      Edit
                    </Button>
                  {/if}
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={saving || installing || i === 0}
                    onclick={() => moveEntry(i, -1)}
                    title="Move up"
                  >
                    ↑
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={saving || installing || i === entries.length - 1}
                    onclick={() => moveEntry(i, 1)}
                    title="Move down"
                  >
                    ↓
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    class="text-red-500"
                    disabled={saving || installing}
                    onclick={() => removeEntry(i)}
                    title="Remove from policy layers"
                  >
                    ✕
                  </Button>
                </div>
              </li>
            {/each}
          </ul>
        {/if}

        <div class="flex flex-wrap items-center gap-2 pt-1">
          <Input
            class="w-48"
            placeholder="policy-name"
            bind:value={newPolicyName}
            onkeydown={(e) => e.key === 'Enter' && openNewPolicy()}
          />
          <Button
            size="sm"
            variant="secondary"
            onclick={openNewPolicy}
            disabled={installing || saving || restructuring}
          >
            Add Policy
          </Button>
          <Input
            class="flex-1 min-w-64"
            placeholder="at://did:.../town.muni.arbiter.policy/name"
            bind:value={newRefUri}
            onkeydown={(e) => e.key === 'Enter' && addReference()}
          />
          <Button
            size="sm"
            variant="secondary"
            onclick={addReference}
            disabled={installing || saving || restructuring}
          >
            Add Reference
          </Button>
        </div>
        {#if addError}
          <p class="text-sm text-red-500">{addError}</p>
        {/if}
      </section>

      <!-- ── Trusted scopes editor ─────────────────────────────────── -->
      <section class="space-y-2">
        <div>
          <h4 class="text-sm font-semibold text-base-800 dark:text-base-200">Trusted Scopes</h4>
          <p class="text-xs text-base-500 dark:text-base-500">
            NSID scopes (e.g. <code class="font-mono">community.lexicon.authCalendar</code>) this
            arbiter accepts on its scoped <code class="font-mono">*.arbiter.proxy</code> endpoints.
            A request's scope — its NSID with the <code class="font-mono">.arbiter.proxy</code>
            suffix stripped — must be exactly one of these entries; anything else is rejected
            before the policy layers run. New scopes are appended (deduplicated); removing a scope
            stages a config-record write (“Save Changes” above).
          </p>
        </div>

        {#if trustedScopes.length === 0 && pendingScopes.length === 0}
          <Box class="p-3 text-sm text-base-500 dark:text-base-500">
            No trusted scopes — scoped proxy requests are rejected.
          </Box>
        {:else}
          {#if trustedScopes.length > 0}
            <ul class="flex flex-wrap gap-2">
              {#each trustedScopes as scope, i (scope)}
                <li
                  class="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-base-200 dark:border-base-800 bg-base-50 dark:bg-base-900"
                >
                  <code class="text-xs font-mono">{scope}</code>
                  <button
                    class="text-xs text-base-400 hover:text-red-500"
                    onclick={() => removeScope(i)}
                    title="Stage removal (applied by the config-record write)"
                  >
                    ✕
                  </button>
                </li>
              {/each}
            </ul>
          {/if}
          {#if pendingScopes.length > 0}
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-xs text-base-500 dark:text-base-500">New scopes to append:</span>
              <ul class="flex flex-wrap gap-2">
                {#each pendingScopes as scope, i (scope)}
                  <li
                    class="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-dashed border-accent-400 dark:border-accent-600 bg-accent-50 dark:bg-accent-900/20"
                  >
                    <code class="text-xs font-mono">{scope}</code>
                    <button
                      class="text-xs text-base-400 hover:text-red-500"
                      onclick={() => undoPendingScope(i)}
                      title="Don't append this scope"
                    >
                      ✕
                    </button>
                  </li>
                {/each}
              </ul>
              <Button
                size="sm"
                variant="secondary"
                onclick={installScopes}
                disabled={installing || saving || restructuring}
              >
                {installing
                  ? 'Appending…'
                  : `Append ${pendingScopes.length} ${pendingScopes.length === 1 ? 'Scope' : 'Scopes'}`}
              </Button>
            </div>
          {/if}
        {/if}

        <div class="flex flex-wrap items-center gap-2 pt-1">
          <Input
            class="w-72"
            placeholder="community.lexicon.authCalendar"
            bind:value={newScope}
            onkeydown={(e) => e.key === 'Enter' && addScope()}
          />
          <Button size="sm" variant="secondary" onclick={addScope}>Add Scope</Button>
        </div>
      </section>
    {:else if !arbiterDid}
      <Box class="p-6 text-center text-sm text-base-500 dark:text-base-500">
        Search for a community above to view and edit its authorization policy.
      </Box>
    {/if}
  </div>
</div>

{#if arbiterDid}
  <PolicyEntrySheet
    bind:open={editorOpen}
    initialRkey={editorInitialRkey}
    initialSource={editorInitialSource}
    isNew={editorIsNew}
    onSave={saveEntry}
  />
{/if}