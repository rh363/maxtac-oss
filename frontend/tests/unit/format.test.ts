import { describe, expect, it } from 'vitest';
import { ago, duration, money, parseDiff, percent, runDate, safeHttps } from '$lib/format';

describe('money', () => {
	it('usa la virgola e due decimali', () => {
		expect(money(2.18)).toBe('$2,18');
		expect(money(0)).toBe('$0,00');
		expect(money(100)).toBe('$100,00');
	});
	it('sotto il centesimo mostra tre decimali', () => {
		expect(money(0.004)).toBe('$0,004');
	});
	it('arrotonda come toFixed', () => {
		expect(money(0.405)).toMatch(/^\$0,4[01]$/);
	});
});

describe('percent', () => {
	it('limita tra 0 e 100 e gestisce il totale zero', () => {
		expect(percent(73, 100)).toBe(73);
		expect(percent(5, 3)).toBe(100);
		expect(percent(1, 0)).toBe(0);
	});
});

describe('duration e date', () => {
	it('formatta minuti e ore', () => {
		expect(duration('2026-10-20T00:30:00Z', '2026-10-20T01:11:00Z')).toBe('41 min');
		expect(duration('2026-10-20T00:30:00Z', '2026-10-20T02:35:00Z')).toBe('2 h 05 min');
		expect(duration(null, '2026-10-20T01:11:00Z')).toBe('—');
	});
	it('run_id compatto in ISO', () => {
		expect(runDate('20261020T023000Z')).toBe('2026-10-20T02:30:00Z');
		expect(runDate('../etc')).toBeNull();
	});
	it('giorni fa', () => {
		const now = new Date('2026-10-20T12:00:00Z');
		expect(ago(null, now, 'mai')).toBe('mai');
		expect(ago('2026-10-19T10:00:00Z', now, 'mai')).toBe('ieri');
		expect(ago('2026-10-11T10:00:00Z', now, 'mai')).toBe('9 giorni fa');
	});
});

describe('safeHttps', () => {
	it('accetta solo https', () => {
		expect(safeHttps('https://gitlab.example.it/a/-/merge_requests/1')).toBe(
			'https://gitlab.example.it/a/-/merge_requests/1'
		);
		expect(safeHttps('javascript:alert(1)')).toBeNull();
		expect(safeHttps('http://gitlab.example.it')).toBeNull();
		expect(safeHttps('not a url')).toBeNull();
	});
});

describe('parseDiff', () => {
	it('classifica righe e conta file e modifiche', () => {
		const d = parseDiff(
			'--- a/req.txt\n+++ b/req.txt\n@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n--- /dev/null\n+++ b/t.py\n+x\n'
		);
		expect(d.files).toBe(2);
		expect(d.add).toBe(2);
		expect(d.del).toBe(1);
		expect(d.lines.map((l) => l.kind)).toEqual([
			'hunk',
			'hunk',
			'hunk',
			'ctx',
			'del',
			'add',
			'hunk',
			'hunk',
			'add'
		]);
	});
	it('il contenuto resta testo', () => {
		expect(parseDiff('+<img src=x onerror=alert(1)>').lines[0]?.text).toBe(
			'+<img src=x onerror=alert(1)>'
		);
	});
});
