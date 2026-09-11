<script lang="ts">
  import { page } from '$app/state';
  import PolicyLibraryEditor from '$lib/components/PolicyLibraryEditor.svelte';

  const rkey = $derived(page.params.rkey as string);
</script>

<PolicyLibraryEditor initialRkey={rkey} />