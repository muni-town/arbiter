<script lang="ts">
  import { Button } from '@foxui/core';
  import { setupState } from '$lib/setupState.svelte';
  import { isAtprotoDid } from '@atproto/oauth-client-browser';
  import { arbiter, parseBootstrapConfig } from '$lib/arbiter';
  import { auth } from '$lib/auth.svelte';
  import BootstrapConfigInputs from './BootstrapConfigInputs.svelte';

  let policyLayersText = $state('');
  let trustedScopesText = $state('');

  function goBack() {
    setupState.step = 'oauth';
  }

  async function createAndFinish() {
    setupState.loading = true;
    setupState.error = undefined;

    try {
      if (!isAtprotoDid(auth.did)) throw new Error('Not logged in with valid DID');

      // Parse the operator-provided bootstrap config before provisioning, so
      // a malformed URI never leaves a half-bootstrapped account behind.
      const config = parseBootstrapConfig(policyLayersText, trustedScopesText);

      // If a previous attempt already provisioned the account (its DID was
      // persisted after a successful createArbiter), skip re-provisioning and
      // just redo the resetConfig below (idempotent).
      let did = setupState.createDid;
      if (!did) {
        // Provision a brand-new stewarded account on the server's default
        // PDS. The server returns the new account's DID; the caller (this
        // OAuth account) becomes its recovery admin. No policy is authored
        // here: the arbiter stays offline (fail-closed) until the bootstrap
        // config record below brings it online.
        did = await arbiter.createArbiter();
        setupState.createDid = did;
      }

      // Bootstrap the fresh (offline) arbiter with the operator-provided
      // policy layers + trusted scopes via resetConfig — the
      // recovery-admin-only hatch works while the arbiter is offboarded, and
      // bringing the config record into existence brings the arbiter online.
      // No record is authored and installPolicy is NOT used: it is
      // append-only and policy-layer-gated, while resetConfig is the
      // designated bootstrap/recovery hatch. The referenced policy records
      // must already exist (published from the Library tab); until they do,
      // the arbiter comes online and then fails closed — recoverable by
      // resetting the config again.
      await arbiter.resetConfig(did, config);

      setupState.step = 'complete';
      setupState.error = undefined;
      setupState.loading = false;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // If createArbiter was rate-limited, the account may already have been
      // created on a prior attempt whose response was lost. Tell the user to
      // retry after the window rather than implying a hard failure.
      if (!setupState.createDid && /rate limit|ErrPermissionDenied/i.test(msg)) {
        setupState.error =
          'The arbiter server is rate-limiting account creation. If a previous attempt ' +
          'succeeded but the response was lost, the account may already exist — retry in ' +
          'a minute to finish setting it up.';
      } else {
        setupState.error = `Failed: ${msg}`;
      }
      setupState.loading = false;
    }
  }
</script>

<div class="max-w-lg mx-auto px-6 py-12 space-y-6">
  <div class="space-y-2">
    <h2 class="text-xl font-semibold text-base-900 dark:text-base-50">Create a New Account</h2>
    <p class="text-sm text-base-600 dark:text-base-400">
      The arbiter server will create a brand-new AT Protocol account on its configured PDS and
      return its DID. You (the signed-in account) become its recovery admin.
    </p>
    <p class="text-xs text-base-500 dark:text-base-500">
      The arbiter stays offline — denying every request — until this step writes its config:
      provide the policy layers and trusted scopes below. You can manage both from the policy
      editor afterwards.
    </p>
  </div>

  <BootstrapConfigInputs bind:policyLayersText bind:trustedScopesText />

  <div class="space-y-4">
    {#if setupState.error}
      <p class="text-sm text-red-500">{setupState.error}</p>
    {/if}
  </div>

  <div class="flex justify-between pt-2">
    <Button variant="ghost" onclick={goBack} disabled={setupState.loading}>Back</Button>
    <Button onclick={createAndFinish} disabled={setupState.loading}>
      {setupState.loading
        ? 'Working…'
        : setupState.createDid
          ? 'Retry Setup'
          : 'Create Account'}
    </Button>
  </div>
</div>