/**
 * Setup wizard persistent state.
 *
 * Survives page navigation (OAuth redirects) via localStorage.
 * Step transitions are manual — no reactive auto-advance.
 *
 * Uses Svelte 5 runes ($state, $derived, $effect) for reactivity.
 */

import { type } from 'arktype';
import { PdsSetupClient } from './pds-setup-client';

export const STORAGE_KEY = 'arbiter-manager-setup-state';

const setupStepTy = type(
  '"intro" | "oauth" | "choose" | "app-password" | "select-admin" | "complete" | "create"',
);
export type SetupStep = typeof setupStepTy.infer;

const setupModeTy = type('"create" | "import"');
export type SetupMode = typeof setupModeTy.infer;

const setupStateTy = type({
  step: setupStepTy.default('intro'),
  /** Which path the user chose: create a new account or import an existing one. */
  mode: setupModeTy.optional(),
  appPassword: type.string.optional(),
  /** The DID of a newly created (not imported) arbiter account, if any. */
  createDid: type.string.optional(),
  error: type.string.optional(),
  loading: type.boolean.default(false),
});
export type SetupState = typeof setupStateTy.infer;

const initState: SetupState = {
  step: 'intro',
  loading: false,
};
const loaded = JSON.parse(globalThis.localStorage.getItem(STORAGE_KEY) || '{}');
const parsed = setupStateTy(loaded);

export const setupState: SetupState = $state(parsed instanceof type.errors ? initState : parsed);
export const setupClient = new PdsSetupClient();

export const resetSetupState = () => {
  setupState.step = initState.step;
  setupState.mode = undefined;
  setupState.appPassword = undefined;
  setupState.error = undefined;
  setupState.loading = false;
};
// Auto-persist on every change
$effect.root(() => {
  $effect(() => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ ...$state.snapshot(setupState), error: undefined, loading: false }),
    );
  });
});
