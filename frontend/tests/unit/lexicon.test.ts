import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { NEUTRAL, format, merge } from '$lib/lexicon/lexicon';

const terms = JSON.parse(
	readFileSync(new URL('../../../web/theme-terms.json', import.meta.url), 'utf8')
) as { themed: string[]; bundle_extra: string[] };
const THEMED = new RegExp([...terms.themed, ...terms.bundle_extra].join('|'), 'i');

describe('lessico', () => {
	it('format sostituisce i segnaposto noti e lascia gli altri', () => {
		expect(format('Run del {date}', { date: '20 ott' })).toBe('Run del 20 ott');
		expect(format('{a} e {b}', { a: 1 })).toBe('1 e {b}');
	});
	it('merge accetta solo chiavi esistenti e stringhe', () => {
		const out = merge(NEUTRAL, { brand: 'X', inventata: 'Y', greeting: 3 });
		expect(out.brand).toBe('X');
		expect(out.greeting).toBe(NEUTRAL.greeting);
		expect('inventata' in out).toBe(false);
	});
	it('il lessico neutro non contiene termini del tema alternativo', () => {
		expect(JSON.stringify(NEUTRAL)).not.toMatch(THEMED);
	});
});

describe('t()', async () => {
	const { t, useLabels } = await import('$lib/lexicon/index.svelte');
	it('usa il neutro e poi gli override del tema', () => {
		expect(t('greeting', { user: 'boss' })).toBe('Accesso come boss');
		useLabels({ greeting: 'Ciao {user}' });
		expect(t('greeting', { user: 'alex' })).toBe('Ciao alex');
		useLabels({});
		expect(t('brand')).toBe('Autofix');
	});
});
