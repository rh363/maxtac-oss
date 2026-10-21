import { expect, test } from '@playwright/test';
import { openFirstRun, watch } from './helpers';

// Comuni ai due utenti: stessi dati e stesse etichette funzionali in entrambi i temi.

test('navigazione tra le schermate', async ({ page }) => {
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

test('ricerca testuale nei finding, nell URL', async ({ page }) => {
	const w = watch(page);
	await page.goto('/findings');
	const box = page.getByRole('searchbox', { name: 'Cerca' });
	await box.fill('orm.py');
	await box.press('Enter');
	await expect(page).toHaveURL(/q=orm\.py/);
	await expect(page.getByRole('cell', { name: 'core/adapters/orm.py' })).toBeVisible();
	await expect(page.getByText(/^1 finding su 1$/)).toBeVisible();

	await page.reload();
	await expect(box).toHaveValue('orm.py');
	await page.getByRole('button', { name: 'Azzera la ricerca' }).click();
	await expect(page).not.toHaveURL(/q=/);
	await expect(box).toHaveValue('');
	await page.goto('/findings?q=100%25_nessuno');
	await expect(page.getByText('Nessun finding con questi filtri.', { exact: false })).toBeVisible();
	expect(w.problems).toEqual([]);
});

test('grafico della spesa: legenda, dettaglio del giorno e tabella dei dati', async ({ page }) => {
	const w = watch(page);
	await page.goto('/');
	const chart = page.getByTestId('spend-chart');
	await expect(chart).toBeVisible();
	await expect(page.getByRole('heading', { name: /Spesa giornaliera/ })).toBeVisible();
	for (const name of ['Fix', 'Bug hunting', 'Triage e discovery']) {
		await expect(page.getByRole('listitem').filter({ hasText: name }).first()).toBeVisible();
	}
	await expect(chart.getByText(/^tetto \$3$/)).toBeVisible();

	// passaggio del mouse sull'ultima colonna
	const box = (await chart.boundingBox())!;
	await page.mouse.move(box.x + box.width - 70, box.y + box.height / 2);
	const tip = page.getByRole('status').filter({ hasText: 'Totale' });
	await expect(tip).toBeVisible();
	await page.mouse.move(box.x + 1, box.y + 1);
	await page.mouse.move(0, 0);
	await expect(tip).toBeHidden();

	// tastiera: il fuoco sul grafico e le frecce scorrono i giorni
	await chart.focus();
	await page.keyboard.press('ArrowLeft');
	await expect(tip).toBeVisible();
	await page.keyboard.press('Escape');
	await expect(tip).toBeHidden();

	await page.getByText('Dati del grafico').click();
	await expect(page.locator('details table tbody tr')).toHaveCount(30);
	await expect(page.getByRole('img', { name: /Spesa cumulata del mese/ })).toBeVisible();
	expect(w.problems).toEqual([]);
});

test('iterazioni dell agente nella run e nel task', async ({ page }) => {
	await openFirstRun(page);
	const ecs2 = page
		.locator('section')
		.filter({ has: page.getByRole('heading', { name: 'alex/ecs2' }) });
	await expect(ecs2.getByTestId('iterations').first()).toHaveText('9 passi');
	await page.getByRole('link', { name: /Aggiorna requests/ }).click();
	await page.waitForURL(/\/tasks\//);
	await expect(page.getByTestId('iterations')).toHaveText('9 passi · completato');
});

test('repository attivi e proposte dell autodiscovery, senza scritture', async ({ page }) => {
	const w = watch(page);
	const writes: string[] = [];
	page.on('request', (r) => {
		if (r.method() !== 'GET' && r.url().includes('/api/')) writes.push(r.url());
	});
	await page.goto('/repos');
	const table = page.getByTestId('repos');
	await expect(table.getByRole('row')).toHaveCount(7); // intestazione + 5 dal config + 1 approvato
	const approved = table.getByRole('row').filter({ hasText: 'alex/status-page' });
	await expect(approved.getByText('Autodiscovery')).toBeVisible();
	await expect(approved.getByText(/approvato il/)).toBeVisible();
	await expect(
		table.getByRole('row').filter({ hasText: 'alex/ecs2' }).getByText('config.yaml')
	).toBeVisible();
	// token per repo: il prefisso più specifico vince
	await expect(
		table.getByRole('row').filter({ hasText: 'alex/oidc-admin' }).getByText('oidc-admin', {
			exact: true
		})
	).toBeVisible();
	await expect(
		table.getByRole('row').filter({ hasText: 'alex/fwagent' }).getByText('alex', { exact: true })
	).toBeVisible();

	const proposals = page.getByTestId('proposal');
	await expect(proposals).toHaveCount(5); // 3 in attesa, 1 sostituita, 1 rifiutata
	const legacy = proposals.filter({ hasText: 'alex/legacy-cron' });
	await expect(legacy.getByText("il test command ignora l'exit code (|| true)")).toBeVisible();
	await expect(legacy.getByText('Rossa')).toBeVisible();
	// il nome del comando segue il lessico: maxtac per l'operatore, autofix per gli altri
	const cli = test.info().project.name === 'operator' ? 'maxtac' : 'autofix';
	await expect(legacy.getByText(`${cli} repos approve alex/legacy-cron --force`)).toBeVisible();
	const update = proposals.filter({ hasText: 'alex/status-page' });
	await expect(update.getByTestId('changes')).toContainText('npm run test:ci');
	await expect(
		update.getByText(`${cli} repos approve alex/status-page`, { exact: true })
	).toBeVisible();
	await expect(proposals.filter({ hasText: 'Sostituita' })).toHaveCount(1);
	const rejected = proposals.filter({ hasText: 'Rifiutata' });
	await expect(rejected.getByText(/(autofix|maxtac) repos approve/)).toHaveCount(0);
	expect(writes).toEqual([]);
	expect(w.problems).toEqual([]);
});

test('impostazioni in sola lettura, senza utenti né temi', async ({ page }) => {
	const w = watch(page);
	await page.goto('/settings');
	await expect(page.getByRole('heading', { level: 1, name: 'Impostazioni' })).toBeVisible();
	await expect(page.getByTestId('features')).toContainText('Bug hunting');
	await expect(page.getByTestId('prices').getByRole('row')).toHaveCount(4);
	await expect(page.getByText('claude-sonnet-5-5').first()).toBeVisible();
	const tokens = page.getByTestId('tokens');
	await expect(tokens.getByRole('row')).toHaveCount(3);
	const expiring = tokens.getByRole('row').filter({ hasText: 'oidc-admin' });
	await expect(expiring.getByText('Scade a breve')).toBeVisible();
	await expect(expiring.getByText('project_88_bot_c41e')).toBeVisible();
	const main = (await page.locator('main').textContent()) ?? '';
	expect(main).not.toMatch(/glpat-/);
	expect(main).not.toMatch(/allowed|boss|tema|theme/i);
	expect(w.problems).toEqual([]);
});
