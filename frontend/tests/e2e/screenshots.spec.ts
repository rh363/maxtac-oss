import { test } from '@playwright/test';
import { join } from 'node:path';
import { openFirstRun } from './helpers';

// Screenshot per la documentazione: `SCREENSHOTS=1 npm run test:e2e -- screenshots`.
const out = join(import.meta.dirname, '..', '..', '..', 'docs', 'screenshots');

test.skip(!process.env.SCREENSHOTS, 'solo con SCREENSHOTS=1');

for (const [device, viewport] of [
	['desktop', { width: 1440, height: 1000 }],
	['mobile', { width: 390, height: 844 }]
] as const) {
	test(`screenshot ${device}`, async ({ page }, info) => {
		const theme = info.project.name;
		await page.setViewportSize(viewport);
		await page.goto('/');
		await page.getByRole('table').waitFor();
		await page.screenshot({ path: join(out, `${theme}-dashboard-${device}.png`), fullPage: true });
		await page.goto('/findings');
		await page.getByRole('table').waitFor();
		await page.screenshot({ path: join(out, `${theme}-findings-${device}.png`), fullPage: true });
		await openFirstRun(page);
		await page.screenshot({ path: join(out, `${theme}-run-${device}.png`), fullPage: true });
		await page.getByRole('link', { name: /Aggiorna requests/ }).click();
		await page.getByTestId('diff').waitFor();
		await page.screenshot({ path: join(out, `${theme}-task-${device}.png`), fullPage: true });
	});
}
