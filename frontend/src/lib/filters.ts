import type { FindingFilters } from './api/client';
import { Kind, Severity, Status } from './api/schemas';

export const PAGE_SIZE = 25;

export interface FindingView {
	kind?: Kind;
	severity?: Severity;
	status?: Status;
	repo?: string;
	page: number; // da 1
}

/** Filtri dall'URL: valori non validi vengono ignorati, non propagati all'API. */
export function parseFilters(
	params: { get(name: string): string | null },
	repos: readonly string[] = []
): FindingView {
	const pick = <T>(
		schema: { safeParse(v: unknown): { success: boolean; data?: T } },
		v: string | null
	) => {
		const r = schema.safeParse(v);
		return r.success ? r.data : undefined;
	};
	const repo = params.get('repo') ?? undefined;
	const page = Number.parseInt(params.get('page') ?? '1', 10);
	return {
		kind: pick<Kind>(Kind, params.get('kind')),
		severity: pick<Severity>(Severity, params.get('severity')),
		status: pick<Status>(Status, params.get('status')),
		repo: repo && (repos.length === 0 || repos.includes(repo)) ? repo : undefined,
		page: Number.isFinite(page) && page > 0 ? page : 1
	};
}

export function toSearch(view: FindingView): string {
	const p = new URLSearchParams();
	if (view.kind) p.set('kind', view.kind);
	if (view.severity) p.set('severity', view.severity);
	if (view.status) p.set('status', view.status);
	if (view.repo) p.set('repo', view.repo);
	if (view.page > 1) p.set('page', String(view.page));
	const s = p.toString();
	return s ? `?${s}` : '';
}

export function toApi(view: FindingView, size = PAGE_SIZE): FindingFilters {
	return {
		kind: view.kind,
		severity: view.severity,
		status: view.status,
		repo: view.repo,
		limit: size,
		offset: (view.page - 1) * size
	};
}
