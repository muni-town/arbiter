<script lang="ts">
  import { Button } from '@foxui/core';
  import { setupState, setupClient } from '$lib/setupState.svelte';
  import { isAtprotoDid } from '@atproto/oauth-client-browser';
  import { XrpcResponseError } from '@atproto/lex';
  import { arbiter, parseBootstrapConfig } from '$lib/arbiter';
  import { auth } from '$lib/auth.svelte';
  import BootstrapConfigInputs from './BootstrapConfigInputs.svelte';

  let policyLayersText = $state('');
  let trustedScopesText = $state('');

  function goBack() {
    setupState.step = 'app-password';
  }

  async function finishSetup() {
    setupState.loading = true;
    setupState.error = undefined;

    try {
      if (!isAtprotoDid(auth.did)) throw new Error('Not logged in with valid DID');
      if (!setupState.appPassword) throw new Error('Must provide AppPassword');

      // Parse the operator-provided bootstrap config before provisioning, so
      // a malformed URI never leaves a half-bootstrapped account behind.
      const config = parseBootstrapConfig(policyLayersText, trustedScopesText);

      // Verify the app password works (the session is used for the
      // verification only; the import itself re-proves control via the
      // server).
      if (!setupClient.agent) {
        await setupClient.login(auth.did, setupState.appPassword);
        console.log(`Logged in as ${auth.did}`);
      }

      // Import the existing account as a stewarded arbiter, then bootstrap it
      // with the resetConfig call below.
      //
      // Always attempt provisioning: the server treats a duplicate call over
      // a partially-provisioned row as a retry, and rejects a duplicate over
      // a fully-provisioned one with `ErrArbiterAlreadyExists` (HTTP 409) —
      // treated here as already-provisioned, so a failed bootstrap step can
      // be retried without dead-ending the wizard.
      try {
        await arbiter.createAppPasswordArbiter(auth.did, setupState.appPassword);
        console.log('Created app password arbiter');
      } catch (e) {
        if (!(e instanceof XrpcResponseError) || e.error !== 'ErrArbiterAlreadyExists') throw e;
        console.log('Arbiter already provisioned');
      }

      // Bootstrap the (offline) arbiter with the operator-provided policy
      // layers + trusted scopes via resetConfig — the same uniform path as
      // the create flow, with no app-password repo writes: provisioning
      // wrote the `town.muni.arbiter.recovery/self` record naming this
      // account, so the reset is authorized, and bringing the config record
      // into existence brings the arbiter online. The referenced policy
      // records must already exist (published from the Library tab); until
      // they do, the arbiter comes online and then fails closed —
      // recoverable by resetting the config again.
      await arbiter.resetConfig(auth.did, config);

      setupState.step = 'complete';
      setupState.error = undefined;
      setupState.loading = false;
    } catch (e) {
      setupState.error = `Failed: ${e instanceof Error ? e.message : String(e)}`;
      setupState.loading = false;
    }
  }
</script>

<div class="max-w-lg mx-auto px-6 py-12 space-y-6">
  <div class="space-y-2">
    <h2 class="text-xl font-semibold text-base-900 dark:text-base-50">Finish Setup</h2>
    <p class="text-sm text-base-600 dark:text-base-400">
      Your account will be stewarded by the arbiter server. The arbiter stays offline — denying
      every request — until this step writes its config: provide the policy layers and trusted
      scopes below. You can manage both from the policy editor afterwards.
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
    <Button onclick={finishSetup} disabled={setupState.loading}>
      {setupState.loading ? 'Finalizing…' : 'Complete Setup'}
    </Button>
  </div>
</div>