<script lang="ts">
  import { Textarea } from '@foxui/core';

  /**
   * The setup bootstrap step's inputs, shared by the create and import
   * flows: one policy-layer `at://` URI per line (evaluation order) plus
   * optional trusted-scope NSIDs, one per line. The parent parses them with
   * `parseBootstrapConfig` (in `$lib/arbiter`) on submit.
   */
  let {
    policyLayersText = $bindable(''),
    trustedScopesText = $bindable(''),
  }: {
    policyLayersText?: string;
    trustedScopesText?: string;
  } = $props();
</script>

<div class="space-y-4">
  <div class="flex flex-col gap-2">
    <label
      for="bootstrap-policy-layers"
      class="text-sm font-medium text-base-700 dark:text-base-300"
    >
      Policy Layers
    </label>
    <Textarea
      id="bootstrap-policy-layers"
      bind:value={policyLayersText}
      rows={3}
      class="resize-y font-mono text-xs"
      placeholder="at://did:plc:…/town.muni.arbiter.policy/…"
    />
    <p class="text-xs text-base-500 dark:text-base-500">
      One policy record <code class="font-mono">at://</code> URI per line, in evaluation order —
      the first layer that handles or denies a request wins. Copy the URIs from the Library tab.
    </p>
  </div>

  <div
    class="p-3 text-xs text-amber-700 dark:text-amber-400 border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 rounded-lg"
  >
    The referenced policy records must already exist: publish them from the Library tab first and
    paste their <code class="font-mono">at://</code> URIs here. A URI that does not resolve brings
    the arbiter online and then fails closed (it denies every request) — recoverable by resetting
    its config again.
  </div>

  <div class="flex flex-col gap-2">
    <label
      for="bootstrap-trusted-scopes"
      class="text-sm font-medium text-base-700 dark:text-base-300"
    >
      Trusted Scopes <span class="font-normal text-base-500 dark:text-base-500">(optional)</span>
    </label>
    <Textarea
      id="bootstrap-trusted-scopes"
      bind:value={trustedScopesText}
      rows={2}
      class="resize-y font-mono text-xs"
      placeholder="community.lexicon.authCalendar"
    />
    <p class="text-xs text-base-500 dark:text-base-500">
      One NSID scope per line. A scoped proxy request's scope must match one of these exactly.
    </p>
  </div>
</div>