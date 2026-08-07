<script lang="ts">
  import { Sheet, Button } from '@foxui/core';
  import { AtprotoHandlePopup, type Profile } from '@foxui/all';
  import { isActorIdentifier } from '@atcute/lexicons/syntax';
  import { arbiter } from '$lib/arbiter';
  import { defaultPolicyWithOwner } from '$lib/default-policy';
  import { actorResolver } from '$lib/resolver';

  let { arbiterDid, open = $bindable(), onReset }: { arbiterDid?: string; open: boolean; onReset?: () => void } = $props();

  let owner: Profile | undefined = $state(undefined);
  let resetting = $state(false);
  let error = $state<string | null>(null);

  async function ownerDid(): Promise<string> {
    if (!owner) throw new Error('Select an owner account');
    if (owner.did) return owner.did;
    if (!owner.handle) throw new Error('Select an owner account');
    if (!isActorIdentifier(owner.handle)) throw new Error('Invalid owner handle');
    const resolved = await actorResolver.resolve(owner.handle);
    return resolved.did;
  }

  async function onConfirm() {
    if (!arbiterDid) return;

    resetting = true;
    error = null;

    try {
      const did = await ownerDid();
      await arbiter.resetPolicy(arbiterDid, defaultPolicyWithOwner(did));
      open = false;
      onReset?.();
    } catch (e) {
      error = arbiter.formatError(e);
    } finally {
      resetting = false;
    }
  }

  function onClose() {
    if (resetting) return;
    open = false;
    owner = undefined;
    error = null;
  }
</script>

<Sheet
  bind:open
  title="Reset Policy"
  description="Choose the owner account and confirm to reset this arbiter's policy to the default."
  onOpenAutoFocus={() => {
    owner = undefined;
    error = null;
  }}
>
  <div class="flex flex-col gap-4 py-2">
    <div class="flex flex-col gap-2">
      <p class="text-sm text-base-600 dark:text-base-400">
        Pick the account that should be granted <strong>Owner</strong> access. The policy will be
        replaced with the default policy where this owner is allowed. This uses the recovery
        endpoint, so it works even when the current policy blocks updates.
      </p>
      <AtprotoHandlePopup onselected={(actor) => (owner = actor)} />
      {#if error}
        <p class="text-sm text-red-500">{error}</p>
      {/if}
    </div>
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={onClose} disabled={resetting}>Cancel</Button>
    <Button onclick={onConfirm} disabled={resetting || !owner}>
      {resetting ? 'Resetting…' : 'Reset Policy'}
    </Button>
  {/snippet}
</Sheet>
