<script lang="ts">
  import { Button } from '@foxui/core';
  import { setupState, setupClient } from '$lib/setupState.svelte';
  import { isAtprotoDid } from '@atproto/oauth-client-browser';
  import { XrpcResponseError } from '@atproto/lex';
  import { DEFAULT_POLICY_URI } from '$lib/default-policy';
  import { CONFIG_COLLECTION, CONFIG_RKEY, arbiter } from '$lib/arbiter';
  import { auth } from '$lib/auth.svelte';

  function goBack() {
    setupState.step = 'app-password';
  }

  /** The pre-existing default policy URI the bootstrap policy layers reference. */
  function defaultPolicyUri(): string {
    return setupState.defaultPolicyUri ?? DEFAULT_POLICY_URI;
  }

  async function finishSetup() {
    setupState.loading = true;
    setupState.error = undefined;

    try {
      if (!isAtprotoDid(auth.did)) throw new Error('Not logged in with valid DID');
      if (!setupState.appPassword) throw new Error('Must provide AppPassword');

      // Verify the app password works (the session is used for the
      // verification and the bootstrap write below; the import itself
      // re-proves control via the server).
      if (!setupClient.agent) {
        await setupClient.login(auth.did, setupState.appPassword);
        console.log(`Logged in as ${auth.did}`);
      }

      // Import the existing account as a stewarded arbiter, then write the
      // bootstrap config record below.
      //
      // Always attempt provisioning: the server treats a duplicate call over
      // a partially-provisioned row as a retry, and rejects a duplicate over
      // a fully-provisioned one with `ErrArbiterAlreadyExists` (HTTP 409) —
      // treated here as already-provisioned, so a failed bootstrap write can
      // be retried without dead-ending the wizard.
      try {
        await arbiter.createAppPasswordArbiter(auth.did, setupState.appPassword);
        console.log('Created app password arbiter');
      } catch (e) {
        if (!(e instanceof XrpcResponseError) || e.error !== 'ErrArbiterAlreadyExists') throw e;
        console.log('Arbiter already provisioned');
      }

      // Bootstrap the fresh (offline) arbiter: write the initial config
      // record (policy layers = the PRE-EXISTING default policy record, no
      // trusted scopes) directly to the steward's repo via the app-password
      // session — pre-arbiter there is nothing to gate these writes. The
      // arbiter comes online on its own once the config record exists
      // (startup onboarding / Jetstream). No policy record is authored and
      // installPolicy is NOT used: it is append-only and policy-layer-gated.
      // The referenced record must be published somewhere reachable (see
      // DEFAULT_POLICY_URI); until it is, the arbiter fails closed.
      await setupClient.putRecord(CONFIG_COLLECTION, CONFIG_RKEY, {
        $type: CONFIG_COLLECTION,
        trustedScopes: [],
        policyLayers: [defaultPolicyUri()],
      });
      console.log('Published bootstrap config record');

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
      Your account will be stewarded by the arbiter server and brought online with the shared
      default policy. Manage its policy layers and trusted scopes from the policy editor afterwards.
    </p>
  </div>

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