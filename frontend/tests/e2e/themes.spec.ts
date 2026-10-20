import { expect, test } from '@playwright/test';
import { THEMED, openFirstRun, watch } from './helpers';

test.describe('utente senza tema', () => {
	// eslint-disable-next-line no-empty-pattern -- Playwright vuole il destructuring
	test.beforeEach(({}, info) => test.skip(info.project.name !== 'neutral'));

	test('non vede né carica nulla del tema alternativo', async ({ page }) => {
		const w = watch(page);
		await page.goto('/');
		await expect(page.getByRole('heading', { level: 1, name: 'Panoramica' })).toBeVisible();
		await expect(page.locator('.logo')).toHaveText('Autofix');

		await page.getByRole('link', { name: 'Finding', exact: true }).click();
		await expect(page.getByRole('heading', { level: 1, name: 'Finding' })).toBeVisible();
		await openFirstRun(page);
		await page.getByRole('link', { name: /Aggiorna requests/ }).click();
		await expect(page.getByTestId('diff')).toContainText('+requests==2.32.3');

		for (const html of [await page.content()]) expect(html).not.toMatch(THEMED);
		expect(w.requests.filter((u) => u.includes('/api/theme/'))).toEqual([]);
		expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBeUndefined();
		expect(w.problems).toEqual([]);
	});
});

test.describe('operatore con tema', () => {
	// eslint-disable-next-line no-empty-pattern -- Playwright vuole il destructuring
	test.beforeEach(({}, info) => test.skip(info.project.name !== 'operator'));

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
});

test('navigazione tra le quattro schermate', async ({ page }) => {
	const w = watch(page);
	await page.goto('/');
	await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
	await expect(page.getByText('alex/ecs2').first()).toBeVisible();

	await page
		.getByRole('navigation')
		.getByRole('link', { name: /Finding/ })
		.click();
	await page.getByLabel('Stato').selectOption('needs_human');
	await expect(page).toHaveURL(/status=needs_human/);
	await expect(page.getByRole('cell', { name: 'core/adapters/orm.py' })).toBeVisible();
	await page.reload();
	await expect(page.getByLabel('Stato')).toHaveValue('needs_human');

	await openFirstRun(page);
	await expect(page.getByRole('heading', { level: 2, name: 'alex/fwagent' })).toBeVisible();
	await expect(page.getByText('scanner gosec: timeout dopo 900s')).toBeVisible();

	await page.getByRole('link', { name: /Aggiorna requests/ }).click();
	await expect(page.getByRole('link', { name: /Apri MR su GitLab/ })).toHaveAttribute(
		'href',
		'https://gitlab.example.it/alex/ecs2/-/merge_requests/128'
	);
	await expect(page.getByText('214 passed in 38.21s')).toBeVisible();
	expect(w.problems).toEqual([]);
});
