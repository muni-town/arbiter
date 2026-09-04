<script lang="ts">
  import { onMount } from 'svelte';
  import { browser } from '$app/environment';
  import { goto } from '$app/navigation';
  import { resetSetupState, setupState } from '$lib/setupState.svelte';
  import SetupStepIntro from '$lib/components/setup/SetupStepIntro.svelte';
  import SetupStepOAuth from '$lib/components/setup/SetupStepOAuth.svelte';
  import SetupStepChoose from '$lib/components/setup/SetupStepChoose.svelte';
  import SetupStepAppPassword from '$lib/components/setup/SetupStepAppPassword.svelte';
  import SetupStepSelectAdmin from '$lib/components/setup/SetupStepSelectAdmin.svelte';
  import SetupStepCreate from '$lib/components/setup/SetupStepCreate.svelte';
  import SetupStepComplete from '$lib/components/setup/SetupStepComplete.svelte';

  let step = $derived(setupState.step);
  let showFullReset = $state(false);

  // The ordered steps for each mode. The create flow skips app-password and
  // select-admin, so the stepper must not mark them as done.
  const importSteps = ['intro', 'oauth', 'choose', 'app-password', 'select-admin', 'complete'];
  const createSteps = ['intro', 'oauth', 'choose', 'create', 'complete'];
  const steps = $derived(setupState.mode === 'create' ? createSteps : importSteps);
</script>

<div class="min-h-full flex flex-col">
  <!-- Steps indicator -->
  <div
    class="px-6 py-4 border-b border-base-100 dark:border-base-800 flex items-center justify-center gap-4"
  >
    <div class="flex items-center gap-2 text-xs font-medium">
      {#each steps as s, i}
        {@const active = step === s}
        {@const done = steps.indexOf(step) > i}
        <div class="flex items-center gap-2">
          <span
            class="w-6 h-6 rounded-full flex items-center justify-center transition-colors
              {active
              ? 'bg-accent-500 text-white'
              : done
                ? 'bg-green-500 text-white'
                : 'bg-base-200 dark:bg-base-700 text-base-500'}"
          >
            {#if done}
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2.5"
                  d="M5 13l4 4L19 7"
                />
              </svg>
            {:else}
              {i + 1}
            {/if}
          </span>
          <span
            class="hidden sm:inline {active
              ? 'text-base-900 dark:text-base-50 font-semibold'
              : 'text-base-500'}"
          >
            {s === 'intro'
              ? 'Overview'
              : s === 'oauth'
                ? 'Sign In'
                : s === 'choose'
                  ? 'Choose'
                  : s === 'app-password'
                    ? 'App Password'
                    : s === 'select-admin'
                      ? 'Finish'
                      : s === 'create'
                        ? 'Create'
                        : 'Done'}
          </span>
          {#if i < steps.length - 1}
            <span class="w-6 h-px bg-base-300 dark:bg-base-700"></span>
          {/if}
        </div>
      {/each}
    </div>

    {#if step !== 'intro' && step !== 'complete'}
      <button
        onclick={() => {
          showFullReset = true;
        }}
        class="text-xs text-base-500 hover:text-red-500 transition-colors shrink-0"
      >
        Cancel &amp; Reset
      </button>
    {:else}
      <span class="w-8"></span>
    {/if}
  </div>

  <!-- Step content -->
  <div class="flex-1 overflow-auto flex items-start justify-center px-6">
    <div class="w-full max-w-3xl py-8">
      {#if step === 'intro'}
        <SetupStepIntro />
      {:else if step === 'oauth'}
        <SetupStepOAuth />
      {:else if step === 'choose'}
        <SetupStepChoose />
      {:else if step === 'app-password'}
        <SetupStepAppPassword />
      {:else if step === 'select-admin'}
        <SetupStepSelectAdmin />
      {:else if step === 'create'}
        <SetupStepCreate />
      {:else if step === 'complete'}
        <SetupStepComplete />
      {/if}
    </div>
  </div>
</div>

<!-- Full reset confirmation modal -->
{#if showFullReset}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
    <div class="bg-white dark:bg-base-900 rounded-lg p-6 max-w-sm mx-4 shadow-xl">
      <h3 class="text-lg font-semibold text-base-900 dark:text-base-50 mb-2">Reset Setup?</h3>
      <p class="text-sm text-base-600 dark:text-base-400 mb-4">
        This will clear all progress and take you back to the home page.
      </p>
      <div class="flex justify-end gap-2">
        <button
          onclick={() => (showFullReset = false)}
          class="px-4 py-2 text-sm font-medium rounded-lg bg-base-100 dark:bg-base-800 text-base-700 dark:text-base-300 hover:bg-base-200 dark:hover:bg-base-700 transition-colors"
        >
          Keep Going
        </button>
        <button
          onclick={async () => {
            resetSetupState();
            showFullReset = false;
            goto('/');
          }}
          class="px-4 py-2 text-sm font-medium rounded-lg bg-red-500 text-white hover:bg-red-600 transition-colors"
        >
          Reset
        </button>
      </div>
    </div>
  </div>
{/if}
