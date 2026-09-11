<script lang="ts">
  import { page } from '$app/state';
  import { Box } from '@foxui/core';
  import { Tabs } from '@foxui/core';
  import { arbiter } from '$lib/arbiter';

  let { children } = $props();

  const did = $derived(page.params.did as string);

  // ── Arbiter service check (runs once per DID) ─────────────────────────
  let checking = $state(true);
  let hasArbiter = $state(false);
  let checkError = $state<string | null>(null);

  $effect(() => {
    if (!did) {
      checking = false;
      hasArbiter = false;
      checkError = null;
      return;
    }

    let cancelled = false;
    checking = true;
    hasArbiter = false;
    checkError = null;

    arbiter.hasArbiterService(did).then((ok) => {
      if (cancelled) return;
      hasArbiter = ok;
      checking = false;
    }).catch((e) => {
      if (cancelled) return;
      checkError = arbiter.formatError(e);
      checking = false;
    });

    return () => { cancelled = true; };
  });

  const activeTab = $derived.by(() => {
    const path = page.url.pathname;
    if (path.endsWith('/policy')) return 'Policy';
    if (path.endsWith('/debug')) return 'Debug';
    return 'Policy';
  });
</script>

<div class="flex flex-col h-full min-w-0">
  {#if checking}
    <Box class="flex items-center gap-3 p-4 mx-4 mt-4 text-sm text-base-500">
      <div
        class="animate-spin w-4 h-4 border-2 border-accent-500 border-t-transparent rounded-full"
      ></div>
      Checking arbiter service…
    </Box>
  {:else if checkError}
    <Box class="mx-4 mt-4 p-4 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 rounded-lg">
      <p class="text-sm font-medium text-red-800 dark:text-red-300">Failed to check arbiter service</p>
      <p class="text-xs text-red-700 dark:text-red-400 mt-1">{checkError}</p>
    </Box>
  {:else if !hasArbiter}
    <Box class="mx-4 mt-4 p-4 border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 rounded-lg">
      <p class="text-sm font-medium text-amber-800 dark:text-amber-300">
        No arbiter service found
      </p>
      <p class="text-xs text-amber-700 dark:text-amber-400 mt-1">
        This account does not have a <code class="font-mono">town.muni.arbiter.service/self</code>
        record on its PDS repo. Only accounts with a Muni Town arbiter service record can be
        managed here.
      </p>
    </Box>
  {:else}
    <!-- Tabs navigation -->
    <Tabs
      items={[
        { name: 'Policy', href: `/dashboard/${encodeURIComponent(did)}/policy` },
        { name: 'Debug', href: `/dashboard/${encodeURIComponent(did)}/debug` },
      ]}
      active={activeTab}
      class="px-4 pt-0"
    />

    <!-- Page content -->
    <div class="flex-1 min-h-0 h-full">
      {@render children()}
    </div>
  {/if}
</div>