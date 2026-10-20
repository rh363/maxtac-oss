import { describe, expect, it } from 'vitest';
import { PAGE_SIZE, parseFilters, toApi, toSearch } from '$lib/filters';

describe('filtri nell URL', () => {
	it('legge solo valori validi', () => {
		const v = parseFilters(
			new URLSearchParams('kind=cve&severity=HIGH&status=mr_open&repo=alex/ecs2&page=3')
		);
		expect(v).toEqual({
			kind: 'cve',
			severity: undefined,
			status: 'mr_open',
			repo: 'alex/ecs2',
			page: 3
		});
		expect(parseFilters(new URLSearchParams('page=-1&kind=x')).page).toBe(1);
	});
	it('scarta repo sconosciuti se la lista è nota', () => {
		const v = parseFilters(new URLSearchParams('repo=evil/x'), ['alex/ecs2']);
		expect(v.repo).toBeUndefined();
	});
	it('andata e ritorno', () => {
		const v = parseFilters(new URLSearchParams('severity=critical&page=2'));
		expect(toSearch(v)).toBe('?severity=critical&page=2');
		expect(toSearch({ page: 1 })).toBe('');
	});
	it('paginazione verso l API', () => {
		expect(toApi({ page: 2, kind: 'sast' })).toEqual({
			kind: 'sast',
			severity: undefined,
			status: undefined,
			repo: undefined,
			limit: PAGE_SIZE,
			offset: PAGE_SIZE
		});
	});
});
