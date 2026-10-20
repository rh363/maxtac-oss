import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Page } from '@playwright/test';

const terms = JSON.parse(
	readFileSync(join(import.meta.dirname, '..', '..', '..', 'web', 'theme-terms.json'), 'utf8')
) as { themed: string[]; bundle_extra: string[] };

export const THEMED = new RegExp([...terms.themed, ...terms.bundle_extra].join('|'), 'i');

/** Raccoglie richieste e violazioni CSP della pagina, da controllare a fine test. */
export function watch(page: Page) {
	const requests: string[] = [];
	const problems: string[] = [];
	page.on('request', (r) => requests.push(r.url()));
	page.on('console', (m) => {
		if (m.type() === 'error') problems.push(m.text());
	});
	page.on('pageerror', (e) => problems.push(e.message));
	return { requests, problems };
}

export async function openFirstRun(page: Page) {
	await page.goto('/runs');
	await page.getByRole('table').getByRole('link').first().click();
	await page.waitForURL(/\/runs\/\d{8}T\d{6}Z$/);
}
