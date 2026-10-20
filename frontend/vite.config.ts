import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

// In sviluppo `maxtac web --dev` gira su :8080 e qui si fa da proxy per API e login.
const backend = process.env.AUTOFIX_WEB_URL ?? 'http://127.0.0.1:8080';

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			// SPA servita da FastAPI: ogni rotta sconosciuta ricade su index.html
			adapter: adapter({ fallback: 'index.html', strict: true }),
			// convenzione dei progetti dell'utente: import da $lib
			alias: { $lib: 'src/lib' }
		})
	],
	server: {
		proxy: {
			'/api': backend,
			'/auth': backend
		}
	}
});
