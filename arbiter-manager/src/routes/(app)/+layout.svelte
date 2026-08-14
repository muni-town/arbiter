<script lang="ts">
  import { onMount } from 'svelte';
  import TopBar from '$lib/components/TopBar.svelte';
  import './app.css';
  import { auth } from '$lib/auth.svelte';
  import { resetSetupState, setupState } from '$lib/setupState.svelte';
  import { goto } from '$app/navigation';

  let ready = $state(false);

  onMount(async () => {
    await auth.init();

    if (setupState.step == 'oauth' && auth.profile) {
      setupState.step = 'choose';
    } else if (!auth.session && setupState.step != 'intro') {
      resetSetupState();
    }

    if (setupState.step != 'intro' && auth.session) {
      await goto('/setup');
    }

    ready = true;
  });

  let { children } = $props();
</script>

{#if !ready}
  <div class="flex items-center justify-center h-screen">
    <div
      class="animate-spin w-6 h-6 border-2 border-accent-500 border-t-transparent rounded-full"
    ></div>
  </div>
{:else}
  <div class="flex flex-col h-screen">
    <TopBar />
    <div class="flex flex-1 justify-center min-w-0">
      {@render children()}
    </div>
  </div>
{/if}
