import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  vitePlugin: {
    inspector: true,
  },
  kit: {
    adapter: adapter({
      fallback: 'index.html',
    }),
    // SvelteKit controls its own asset/path prefix via `paths.base`, not the
    // Vite `base` option. The deploy workflow sets `BASE_PATH` (e.g.
    // `/leaf-0.4/arbiter-manager`) so the app resolves assets from the
    // subpath it is hosted at on GitHub Pages rather than the site root.
    paths: {
      base: process.env.BASE_PATH || '',
    },
  },
};

export default config;
