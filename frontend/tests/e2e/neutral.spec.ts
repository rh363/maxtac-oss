import { expect, test } from '@playwright/test';
import { THEMED, openFirstRun, watch } from './helpers';

// Utente senza tema assegnato: nessuna traccia del tema alternativo, in nessuna pagina.
test('non vede né carica nulla del tema alternativo', async ({ page }) => {
	const w = watch(page);
	const pages: string[] = [];
	await page.goto('/');
	await expect(page.getByRole('heading', { level: 1, name: 'Panoramica' })).toBeVisible();
	await expect(page.locator('.logo')).toHaveText('Autofix');
	await expect(page.getByTestId('spend-chart')).toBeVisible();
	pages.push(await page.content());

	await page.getByRole('link', { name: 'Finding', exact: true }).click();
	await expect(page.getByRole('heading', { level: 1, name: 'Finding' })).toBeVisible();
	pages.push(await page.content());
	await openFirstRun(page);
	pages.push(await page.content());
	await page.getByRole('link', { name: /Aggiorna requests/ }).click();
	await expect(page.getByTestId('diff')).toContainText('+requests==2.32.3');
	pages.push(await page.content());

	await page.getByRole('navigation').getByRole('link', { name: 'Repository' }).click();
	await expect(page.getByTestId('repos')).toBeVisible();
	pages.push(await page.content());
	await page.getByRole('navigation').getByRole('link', { name: 'Impostazioni' }).click();
	await expect(page.getByTestId('prices')).toBeVisible();
	pages.push(await page.content());

	for (const html of pages) expect(html).not.toMatch(THEMED);
	expect(w.requests.filter((u) => u.includes('/api/theme/'))).toEqual([]);
	expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBeUndefined();
	expect(w.problems).toEqual([]);
});
