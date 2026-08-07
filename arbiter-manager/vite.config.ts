import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import wasm from 'vite-plugin-wasm';
import { defineConfig } from 'vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  base: process.env.BASE_PATH || '/',
  plugins: [tailwindcss(), sveltekit(), wasm()],
  resolve: {
    alias: {
      '/policies': path.resolve(__dirname, '..', 'policies'),
    },
  },
  optimizeDeps: {
    exclude: ['arbiter-core-wasm'],
  },
  server: {
    host: '127.0.0.1',
  },
});
