import { defineConfig, devices } from '@playwright/test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Due istanze di `maxtac web --dev` su un db demo: una con l'utente che ha il tema
// dell'operatore (alex), una con un utente senza tema (boss). Richiede `npm run build`.
const demo = (user: string, port: number) => {
	const out = join(tmpdir(), `autofix-e2e-${user}`);
	return {
		command:
			`uv run python scripts/seed-demo-db.py --out ${out} --user ${user} && ` +
			`uv run maxtac --config ${out}/config.yaml web --dev --port ${port}`,
		cwd: '..',
		url: `http://127.0.0.1:${port}/healthz`,
		reuseExistingServer: !process.env.CI,
		timeout: 60_000
	};
};

export default defineConfig({
	testDir: 'tests/e2e',
	fullyParallel: true,
	reporter: [['list']],
	use: {
		...devices['Desktop Chrome'],
		locale: 'it-IT',
		timezoneId: 'Europe/Rome',
		trace: 'retain-on-failure'
	},
	webServer: [demo('alex', 8791), demo('boss', 8792)],
	projects: [
		{ name: 'operator', use: { baseURL: 'http://127.0.0.1:8791' } },
		{ name: 'neutral', use: { baseURL: 'http://127.0.0.1:8792' } }
	]
});
