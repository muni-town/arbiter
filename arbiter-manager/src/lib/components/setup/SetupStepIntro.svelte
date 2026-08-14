<script lang="ts">
  import { Alert, Button } from '@foxui/core';
  import { setupState } from '$lib/setupState.svelte';

  function startSetup() {
    setupState.step = 'oauth';
  }
</script>

<div class="max-w-3xl mx-auto px-6 py-12 space-y-8">
  <!-- Overview heading -->
  <div class="text-center space-y-3">
    <h2 class="text-2xl font-bold text-base-900 dark:text-base-50">
      Set Up Your Community Account
    </h2>
    <p class="text-base text-base-600 dark:text-base-400 max-w-lg mx-auto">
      A community account is an AT Protocol account that's managed by your organization. This wizard
      will guide you through creating a new account or importing an existing one, authorizing an
      arbiter, and granting admin access.
    </p>

    <Alert type="warning">
      <span>
        This is alpha software. We do not recommend using the community setup with non-test accounts
        for the time being.
      </span>
    </Alert>
  </div>

  <!-- Step descriptions -->
  <div class="space-y-4">
    <div
      class="flex gap-4 p-4 rounded-lg bg-base-50 dark:bg-base-900 border border-base-200 dark:border-base-800"
    >
      <div
        class="w-8 h-8 rounded-full bg-accent-100 dark:bg-accent-900 text-accent-600 dark:text-accent-300 flex items-center justify-center text-sm font-bold shrink-0"
      >
        1
      </div>
      <div class="space-y-1">
        <h3 class="font-semibold text-base-900 dark:text-base-50">Create an App Password</h3>
        <p class="text-sm text-base-600 dark:text-base-400 mb-2">
          Log in your AT Protocol PDS (the server that hosts your account) and create an
          <strong>App Password</strong>. <br /><br />The arbiter service will use this to control
          your account after validating all actions against your configured policy.
        </p>
        <p class="text-xs text-base-500 mt-1">
          <a
            href="https://atproto.com/guides/app-passwords"
            target="_blank"
            rel="noopener noreferrer"
            class="text-accent-500 hover:text-accent-600 underline"
          >
            You can create an App Password here if you are setting up a Bluesky account &rarr;
          </a>
        </p>
      </div>
    </div>

    <div
      class="flex gap-4 p-4 rounded-lg bg-base-50 dark:bg-base-900 border border-base-200 dark:border-base-800"
    >
      <div
        class="w-8 h-8 rounded-full bg-accent-100 dark:bg-accent-900 text-accent-600 dark:text-accent-300 flex items-center justify-center text-sm font-bold shrink-0"
      >
        2
      </div>
      <div class="space-y-1">
        <h3 class="font-semibold text-base-900 dark:text-base-50">Sign In To Your Account Here</h3>
        <p class="text-sm text-base-600 dark:text-base-400">
          Sign in with your account using AT Protocol OAuth. This proves you control the account and
          lets the app write the arbiter's initial policy to it.
        </p>
      </div>
    </div>

    <div
      class="flex gap-4 p-4 rounded-lg bg-base-50 dark:bg-base-900 border border-base-200 dark:border-base-800"
    >
      <div
        class="w-8 h-8 rounded-full bg-accent-100 dark:bg-accent-900 text-accent-600 dark:text-accent-300 flex items-center justify-center text-sm font-bold shrink-0"
      >
        3
      </div>
      <div class="space-y-1">
        <h3 class="font-semibold text-base-900 dark:text-base-50">Enter App Password</h3>
        <p class="text-sm text-base-600 dark:text-base-400">
          Type in the App Password you created. It lets the arbiter server execute requests on your
          account's PDS after validating them against your policy.
        </p>
      </div>
    </div>

    <div
      class="flex gap-4 p-4 rounded-lg bg-base-50 dark:bg-base-900 border border-base-200 dark:border-base-800"
    >
      <div
        class="w-8 h-8 rounded-full bg-accent-100 dark:bg-accent-900 text-accent-600 dark:text-accent-300 flex items-center justify-center text-sm font-bold shrink-0"
      >
        4
      </div>
      <div class="space-y-1">
        <h3 class="font-semibold text-base-900 dark:text-base-50">Select an Admin</h3>
        <p class="text-sm text-base-600 dark:text-base-400">
          Choose an account that will have <strong>Owner</strong> access to your community's arbiter.
          This person can manage spaces, members, and policies on behalf of the community account.
        </p>
      </div>
    </div>
  </div>

  <!-- Start button -->
  <div class="text-center pt-4">
    <Button size="lg" onclick={startSetup}>Get Started</Button>
    <p class="text-xs text-base-500 mt-3 pb-8">
      You can cancel at any time. No changes will be made until you confirm.
    </p>
  </div>
</div>
