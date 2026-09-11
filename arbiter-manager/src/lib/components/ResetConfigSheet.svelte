<script lang="ts">
  import { Sheet, Button, Input, Box } from '@foxui/core';
  import { isNsidString } from '@atproto/lex';
  import { parseAtUri, POLICY_COLLECTION, type ArbiterConfig } from '$lib/arbiter';

  let {
    open = $bindable(),
    arbiterDid,
    /** Seed for the editors: the currently loaded config (empty when it failed to load). */
    initialConfig,
    onSave,
  }: {
    open: boolean;
    arbiterDid: string;
    initialConfig?: ArbiterConfig;
    onSave?: (config: ArbiterConfig) => void;
  } = $props();

  /** Ordered policy-layer `at://` URIs (one or more; evaluation order). */
  let layers = $state<string[]>([]);
  let trustedScopes = $state<string[]>([]);
  let newLayerUri = $state('');
  let newScope = $state('');
  let formError = $state<string | null>(null);

  function onOpen() {
    layers = initialConfig ? [...initialConfig.policyLayers] : [];
    trustedScopes = initialConfig ? [...initialConfig.trustedScopes] : [];
    newLayerUri = '';
    newScope = '';
    formError = null;
  }

  function addLayer() {
    formError = null;
    const uri = newLayerUri.trim();
    const parts = parseAtUri(uri);
    if (!parts) {
      formError = 'Enter a valid `at://<did>/<collection>/<rkey>` URI';
      return;
    }
    if (parts.collection !== POLICY_COLLECTION) {
      formError = `The referenced record must be a \`${POLICY_COLLECTION}\` record`;
      return;
    }
    if (layers.includes(uri)) {
      formError = 'That record is already in the policy layers';
      return;
    }
    layers.push(uri);
    newLayerUri = '';
  }

  function moveLayer(index: number, delta: -1 | 1) {
    const target = index + delta;
    if (target < 0 || target >= layers.length) return;
    const [layer] = layers.splice(index, 1);
    layers.splice(target, 0, layer);
  }

  function removeLayer(index: number) {
    layers.splice(index, 1);
  }

  function addScope() {
    formError = null;
    const scope = newScope.trim();
    if (!scope) return;
    if (!isNsidString(scope)) {
      formError = 'Enter a valid NSID scope (e.g. `community.lexicon.authCalendar`)';
      return;
    }
    if (trustedScopes.includes(scope)) {
      formError = 'That scope is already trusted';
      return;
    }
    trustedScopes.push(scope);
    newScope = '';
  }

  function removeScope(index: number) {
    trustedScopes.splice(index, 1);
  }

  function save() {
    formError = null;
    if (layers.length === 0) {
      formError = 'Enter at least one policy layer — an empty pipeline denies every request';
      return;
    }
    onSave?.({ trustedScopes: [...trustedScopes], policyLayers: [...layers] });
    open = false;
  }

  function onClose() {
    open = false;
  }
</script>

<Sheet
  bind:open
  title="Reset Config"
  description={`Replaces the ENTIRE config record of ${arbiterDid} verbatim — every policy layer and every trusted scope is swapped for what you enter here. Nothing is merged, and the previous config is not recoverable from this UI. This is the recovery/bootstrap hatch: it performs no policy evaluation and also works while the arbiter is offline (e.g. a broken config that fails closed).`}
  onOpenAutoFocus={onOpen}
>
  <div class="flex flex-col gap-4 py-2">
    <Box
      class="p-3 text-sm text-red-700 dark:text-red-400 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg"
    >
      <p class="font-semibold mb-1">This replaces the entire configuration</p>
      <p class="text-xs">
        Only for recovery and initial bootstrap — use the normal policy editor for day-to-day
        changes. Only the recovery admin (the account designated in the arbiter's
        <code class="font-mono">town.muni.arbiter.recovery/self</code> record) is authorized;
        anyone else gets <code class="font-mono">ErrPermissionDenied</code>.
      </p>
    </Box>

    <!-- ── Policy layers ─────────────────────────────────────────────── -->
    <div class="flex flex-col gap-2">
      <label
        for="reset-config-add-layer"
        class="text-sm font-medium text-base-700 dark:text-base-300"
      >
        Policy Layers
      </label>
      {#if layers.length === 0}
        <Box class="p-3 text-center text-sm text-base-500 dark:text-base-500">
          No policy layers — an arbiter reset with none stays offline (fail-closed).
        </Box>
      {:else}
        <ul class="space-y-1">
          {#each layers as layer, i (layer)}
            <li class="flex items-center gap-2 px-2 py-1.5 rounded-lg border border-base-200 dark:border-base-800 bg-base-50 dark:bg-base-900">
              <span class="text-xs text-base-400 font-mono w-5 text-right">{i + 1}</span>
              <span class="flex-1 text-xs font-mono truncate" title={layer}>{layer}</span>
              <Button
                size="sm"
                variant="ghost"
                disabled={i === 0}
                onclick={() => moveLayer(i, -1)}
                title="Move up"
              >
                ↑
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={i === layers.length - 1}
                onclick={() => moveLayer(i, 1)}
                title="Move down"
              >
                ↓
              </Button>
              <Button
                size="sm"
                variant="ghost"
                class="text-xs px-2 text-base-400 hover:text-red-500"
                onclick={() => removeLayer(i)}
                title="Remove from config"
              >
                ✕
              </Button>
            </li>
          {/each}
        </ul>
      {/if}
      <div class="flex flex-wrap items-center gap-2 pt-1">
        <Input
          id="reset-config-add-layer"
          class="w-96"
          placeholder="at://did…/town.muni.arbiter.policy/<name>"
          bind:value={newLayerUri}
          onkeydown={(e) => e.key === 'Enter' && addLayer()}
        />
        <Button size="sm" variant="secondary" onclick={addLayer}>Add Layer</Button>
      </div>
      <p class="text-xs text-base-500 dark:text-base-500">
        The referenced <code class="font-mono">{POLICY_COLLECTION}</code> records must already
        exist — publish them from the Library tab and paste their <code class="font-mono"
        >at://</code
        > URIs. The reset writes the entries verbatim: a URI that does not resolve leaves the
        arbiter failing closed until it is reset again.
      </p>
    </div>

    <!-- ── Trusted scopes ────────────────────────────────────────────── -->
    <div class="flex flex-col gap-2">
      <label
        for="reset-config-add-scope"
        class="text-sm font-medium text-base-700 dark:text-base-300"
      >
        Trusted Scopes
      </label>
      {#if trustedScopes.length === 0}
        <Box class="p-3 text-sm text-base-500 dark:text-base-500">
          No trusted scopes — scoped proxy requests are rejected.
        </Box>
      {:else}
        <div class="flex flex-wrap gap-1.5">
          {#each trustedScopes as scope, i (scope)}
            <span
              class="flex items-center gap-1.5 px-2 py-1 rounded-full border border-base-200 dark:border-base-800 bg-base-50 dark:bg-base-900"
            >
              <code class="text-xs font-mono">{scope}</code>
              <button
                class="text-xs px-1 text-base-400 hover:text-red-500"
                onclick={() => removeScope(i)}
                title="Remove scope"
              >
                ✕
              </button>
            </span>
          {/each}
        </div>
      {/if}
      <div class="flex flex-wrap items-center gap-2 pt-1">
        <Input
          id="reset-config-add-scope"
          class="w-72"
          placeholder="community.lexicon.authCalendar"
          bind:value={newScope}
          onkeydown={(e) => e.key === 'Enter' && addScope()}
        />
        <Button size="sm" variant="secondary" onclick={addScope}>Add Scope</Button>
      </div>
    </div>

    {#if formError}
      <p class="text-sm text-red-500">{formError}</p>
    {/if}
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={onClose}>Cancel</Button>
    <Button onclick={save}>Replace Config</Button>
  {/snippet}
</Sheet>