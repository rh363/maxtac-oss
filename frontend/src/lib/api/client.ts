import type { z } from 'zod';
import {
	DashboardOut,
	FindingPage,
	Me,
	ReposOut,
	SettingsOut,
	SpendSeriesOut,
	RunDetail,
	RunList,
	TaskDetail,
	ThemeLexicon,
	type Kind,
	type Severity,
	type Status
} from './schemas';

export class ApiError extends Error {
	constructor(
		readonly status: number,
		message: string
	) {
		super(message);
	}
}

export interface FindingFilters {
	kind?: Kind;
	severity?: Severity;
	status?: Status;
	repo?: string;
	q?: string;
	limit?: number;
	offset?: number;
}

type Fetch = typeof fetch;

/**
 * Client dell'API della dashboard. Stesso origin: la sessione è un cookie HttpOnly gestito
 * dal backend, qui non passa nessun token. Ogni risposta è validata con Zod.
 */
export class ApiClient {
	private readonly fetch: Fetch;
	private readonly onUnauthorized: () => void;
	private readonly base: string;

	constructor(options: { fetch?: Fetch; onUnauthorized?: () => void; base?: string } = {}) {
		this.fetch = options.fetch ?? ((...a) => globalThis.fetch(...a));
		this.onUnauthorized = options.onUnauthorized ?? (() => window.location.assign('/auth/login'));
		this.base = options.base ?? '';
	}

	me() {
		return this.get('/api/me', Me);
	}

	dashboard() {
		return this.get('/api/dashboard', DashboardOut);
	}

	findings(filters: FindingFilters = {}) {
		const params: Record<string, string> = {};
		for (const [k, v] of Object.entries(filters)) {
			if (v !== undefined && v !== '') params[k] = String(v);
		}
		return this.get('/api/findings', FindingPage, params);
	}

	/** Tutti i finding dei filtri (senza paginazione) come tabella Markdown. */
	async findingsMarkdown(filters: FindingFilters = {}): Promise<string> {
		const params: Record<string, string> = {};
		for (const [k, v] of Object.entries(filters)) {
			if (v !== undefined && v !== '' && k !== 'limit' && k !== 'offset') params[k] = String(v);
		}
		const path = '/api/findings/export.md';
		const resp = await this.fetch(this.url(path, params), {
			method: 'GET',
			credentials: 'same-origin',
			headers: { Accept: 'text/markdown' }
		});
		if (resp.status === 401) {
			this.onUnauthorized();
			throw new ApiError(401, 'login richiesto');
		}
		if (!resp.ok) throw new ApiError(resp.status, `${path}: HTTP ${resp.status}`);
		if (!resp.headers.get('content-type')?.startsWith('text/markdown')) {
			throw new ApiError(resp.status, `${path}: risposta non Markdown`);
		}
		return resp.text();
	}

	spendDaily(days = 30) {
		return this.get('/api/spend/daily', SpendSeriesOut, { days: String(days) });
	}

	repos() {
		return this.get('/api/repos', ReposOut);
	}

	settings() {
		return this.get('/api/settings', SettingsOut);
	}

	runs(limit = 20, offset = 0) {
		return this.get('/api/runs', RunList, { limit: String(limit), offset: String(offset) });
	}

	run(runId: string) {
		return this.get(`/api/runs/${encodeURIComponent(runId)}`, RunDetail);
	}

	task(runId: string, fingerprint: string, repo?: string) {
		const path = `/api/runs/${encodeURIComponent(runId)}/tasks/${encodeURIComponent(fingerprint)}`;
		return this.get(path, TaskDetail, repo ? { repo } : {});
	}

	themeLexicon(theme: string) {
		return this.get(`/api/theme/${encodeURIComponent(theme)}/lexicon.json`, ThemeLexicon);
	}

	async logout() {
		await this.fetch(this.url('/auth/logout'), { method: 'POST', credentials: 'same-origin' });
	}

	private async get<S extends z.ZodType>(
		path: string,
		schema: S,
		params: Record<string, string> = {}
	): Promise<z.infer<S>> {
		const resp = await this.fetch(this.url(path, params), {
			method: 'GET',
			credentials: 'same-origin',
			headers: { Accept: 'application/json' }
		});
		if (resp.status === 401) {
			this.onUnauthorized();
			throw new ApiError(401, 'login richiesto');
		}
		if (!resp.ok) throw new ApiError(resp.status, `${path}: HTTP ${resp.status}`);
		if (!resp.headers.get('content-type')?.startsWith('application/json')) {
			throw new ApiError(resp.status, `${path}: risposta non JSON`);
		}
		return schema.parse(await resp.json());
	}

	private url(path: string, params: Record<string, string> = {}): string {
		const qs = new URLSearchParams(params).toString();
		return `${this.base}${path}${qs ? `?${qs}` : ''}`;
	}
}
