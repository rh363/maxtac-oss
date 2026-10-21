import { expect, test } from '@playwright/test';
import { watch } from './helpers';

// Operatore con il tema assegnato: il tema arriva a runtime e ricolora anche i grafici.
test('carica il tema a runtime e lo applica', async ({ page }) => {
	const w = watch(page);
	await page.goto('/');
	await expect(page.locator('.logo')).toHaveText('MaxTac');
	expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('cyberpunk');
	await expect(page.getByText('bounty board')).toBeVisible();
	// etichette funzionali chiare anche nel tema
	await expect(page.getByRole('heading', { name: /Finding per stato/ })).toBeVisible();
	expect(w.requests.some((u) => u.endsWith('/api/theme/cyberpunk/theme.css'))).toBe(true);
	const font = await page.locator('h1').evaluate((el) => getComputedStyle(el).fontFamily);
	expect(font).toContain('Rajdhani');
	expect(w.problems).toEqual([]);
});

test('il grafico della spesa usa i colori del tema', async ({ page }) => {
	await page.goto('/');
	const bar = page.getByTestId('spend-chart').locator('.viz-fix').first();
	await expect(bar).toBeVisible();
	await expect
		.poll(() => bar.evaluate((el) => getComputedStyle(el).fill))
		.toBe('rgb(20, 151, 184)');
});
