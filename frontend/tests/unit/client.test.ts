import { describe, expect, it, vi } from 'vitest';
import { ZodError } from 'zod';
import { ApiClient, ApiError } from '$lib/api/client';

const json = (body: unknown, status = 200) =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});

function client(resp: Response) {
	const calls: { url: string; init?: RequestInit }[] = [];
	const unauthorized = vi.fn();
	const c = new ApiClient({
		fetch: async (url, init) => {
			calls.push({ url: String(url), init });
			return resp;
		},
		onUnauthorized: unauthorized
	});
	return { c, calls, unauthorized };
}

describe('ApiClient', () => {
	it('valida la risposta e manda il cookie same-origin', async () => {
		const { c, calls } = client(json({ username: 'alex', theme: 'default', extra: 1 }));
		expect(await c.me()).toEqual({ username: 'alex', theme: 'default' });
		expect(calls[0]?.init?.credentials).toBe('same-origin');
	});
	it('rifiuta payload che non rispettano lo schema', async () => {
		const { c } = client(json({ username: 3 }));
		await expect(c.me()).rejects.toBeInstanceOf(ZodError);
	});
	it('su 401 rimanda al login', async () => {
		const { c, unauthorized } = client(json({ detail: 'login richiesto' }, 401));
		await expect(c.dashboard()).rejects.toBeInstanceOf(ApiError);
		expect(unauthorized).toHaveBeenCalledOnce();
	});
	it('errori HTTP e content-type sbagliato', async () => {
		await expect(client(json({}, 404)).c.run('x')).rejects.toMatchObject({ status: 404 });
		const html = new Response('<html>', { headers: { 'content-type': 'text/html' } });
		await expect(client(html).c.me()).rejects.toBeInstanceOf(ApiError);
	});
	it('codifica path e filtri', async () => {
		const { c, calls } = client(json({ items: [], total: 0, limit: 25, offset: 25 }));
		await c.findings({ kind: 'cve', repo: 'alex/ecs2', offset: 25, limit: 25 });
		expect(calls[0]?.url).toBe('/api/findings?kind=cve&repo=alex%2Fecs2&offset=25&limit=25');
		await c.task('20261020T003000Z', '../x', 'alex/ecs2').catch(() => {});
		expect(calls[1]?.url).toBe('/api/runs/20261020T003000Z/tasks/..%2Fx?repo=alex%2Fecs2');
	});
});
