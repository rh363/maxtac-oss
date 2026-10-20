import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// Test unitari di moduli puri: niente plugin di SvelteKit, alias $lib risolto a mano.
export default defineConfig({
	plugins: [svelte()],
	resolve: { alias: { $lib: fileURLToPath(new URL('./src/lib', import.meta.url)) } },
	test: { include: ['tests/unit/**/*.test.ts'], environment: 'node' }
});
