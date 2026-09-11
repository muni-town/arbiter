<script lang="ts">
  import { auth } from '$lib/auth.svelte';
  import { Avatar, Button, ThemeToggle } from '@foxui/core';

  function logout() {
    auth.logout();
  }
</script>

<header
  class="flex items-center justify-between px-4 py-2.5 border-b border-base-200 dark:border-base-800 bg-base-50 dark:bg-base-950 shrink-0"
>
  <div class="flex items-center gap-5">
    <a
      href="/"
      class="text-lg font-semibold tracking-tight text-base-900 dark:text-base-50 no-underline hover:text-accent-600 dark:hover:text-accent-400 transition-colors"
    >
      Arbiter Manager
    </a>
    <Button href="/setup">Setup Org Account</Button>
    {#if auth.session}
      <Button href="/library">Policy Library</Button>
    {/if}
  </div>

  <div class="flex items-center gap-2">
    {#if auth.profile}
      <Avatar src={auth.profile.avatar} />
      <div class="flex items-center gap-2 text-sm text-base-600 dark:text-base-400 mr-2">
        <span class="hidden sm:inline truncate max-w-40">{auth.name}</span>
      </div>

      <ThemeToggle />
      <Button variant="ghost" size="sm" onclick={logout}>Sign Out</Button>
    {:else}
      <ThemeToggle />
      <Button onclick={() => auth.login()}>Sign in with ATProto</Button>
    {/if}
  </div>
</header>
