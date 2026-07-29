<script lang="ts">
  import { Sheet, Button } from '@foxui/core';
  import { AtprotoHandlePopup, type Profile } from '@foxui/all';
  import { managedCommunities } from '$lib/store.svelte';
  import { goto } from '$app/navigation';

  let { open = $bindable() }: { open: boolean } = $props();

  let loading = $state(false);
  let error = $state<string | null>(null);

  async function onSelect(profile: Profile) {
    const did = profile.did;
    if (!did || !did.startsWith('did:')) {
      error = 'Invalid DID from profile';
      return;
    }

    loading = true;
    error = null;

    try {
      // Add to managed communities
      managedCommunities.add(did, profile.handle ?? did);
      goto(`/dashboard/${encodeURIComponent(did)}`);
      open = false;
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
</script>

<Sheet
  bind:open
  title="Lookup Community"
  description="Search for an AT Protocol account to manage."
>
  <div class="flex flex-col gap-4 py-2">
    <div class="flex flex-col gap-2">
      <p class="text-sm text-base-600 dark:text-base-400">
        Type a handle to find the account. It must have an arbiter service record
      </p>
      <AtprotoHandlePopup onselected={onSelect} />
      {#if error}
        <p class="text-sm text-red-500">{error}</p>
      {/if}
    </div>
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={() => (open = false)}>Cancel</Button>
  {/snippet}
</Sheet>