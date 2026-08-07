<script lang="ts">
  import { page } from '$app/state';
  import { goto } from '$app/navigation';

  const did = $derived(page.params.did as string);

  $effect(() => {
    if (did) {
      goto(`/dashboard/${encodeURIComponent(did)}/policy`, { replaceState: true });
    }
  });
</script>