import { describe, expect, it } from 'vitest';
import { dayLabel, labelIndexes, niceAxis, spendParts, stack, topRounded } from '$lib/chart';

describe('asse', () => {
	it('tacche tonde che coprono il massimo', () => {
		expect(niceAxis(3)).toEqual({ max: 3, ticks: [0, 1, 2, 3] });
		expect(niceAxis(2.71)).toEqual({ max: 3, ticks: [0, 1, 2, 3] });
		expect(niceAxis(100)).toEqual({ max: 100, ticks: [0, 25, 50, 75, 100] });
		expect(niceAxis(0.37).max).toBeGreaterThanOrEqual(0.37);
		expect(niceAxis(0)).toEqual({ max: 1, ticks: [0, 1] });
	});
});

describe('colonne impilate', () => {
	const scale = (v: number) => 100 - v * 10; // 0 → 100px, 10 → 0px
	it('somma le categorie minori e lascia il gap tra i segmenti', () => {
		const parts = spendParts({
			date: '2026-10-20',
			triage: 0.5,
			fix: 4,
			hunt: 2,
			discovery: 0.5,
			other: 0,
			total: 7
		});
		expect(parts).toEqual({ fix: 4, hunt: 2, rest: 1 });
		const [fix, hunt, rest] = stack(parts, scale, 100);
		expect(fix).toMatchObject({ key: 'fix', y: 60, h: 40 });
		expect(hunt).toMatchObject({ key: 'hunt', y: 40, h: 18 });
		expect(rest).toMatchObject({ key: 'rest', y: 30, h: 8 });
	});
	it('salta le categorie a zero e disegna almeno 1px', () => {
		const segs = stack({ fix: 0, hunt: 0.01, rest: 0 }, scale, 100);
		expect(segs).toHaveLength(1);
		expect(segs[0]!.h).toBeGreaterThanOrEqual(1);
		expect(stack({ fix: 0, hunt: 0, rest: 0 }, scale, 100)).toEqual([]);
	});
	it('path con angoli arrotondati solo in alto', () => {
		expect(topRounded(0, 10, 20, 50)).toBe('M0,60V14Q0,10 4,10H16Q20,10 20,14V60Z');
		expect(topRounded(0, 10, 20, 2)).toContain('V12');
	});
});

describe('etichette', () => {
	it('data senza scivolamenti di fuso', () => {
		expect(dayLabel('2026-10-01')).toBe('1 ott');
	});
	it('ogni 7 giorni, finendo sull ultimo', () => {
		expect(labelIndexes(30)).toEqual([1, 8, 15, 22, 29]);
		expect(labelIndexes(3)).toEqual([2]);
		expect(labelIndexes(0)).toEqual([]);
	});
});
