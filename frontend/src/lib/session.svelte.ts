import { api as defaultApi, type ApiClient } from './api';
import { useLabels } from './lexicon/index.svelte';

export const session = $state({
	status: 'loading' as 'loading' | 'ready' | 'error',
	username: '',
	error: ''
});

const THEME_NAME = /^[a-z0-9][a-z0-9-]{0,31}$/;

function loadStylesheet(href: string): Promise<void> {
	return new Promise((resolve, reject) => {
		const link = document.createElement('link');
		link.rel = 'stylesheet';
		link.href = href;
		link.onload = () => resolve();
		link.onerror = () => reject(new Error('foglio di stile del tema non caricato'));
		document.head.appendChild(link);
	});
}

/**
 * Tema dell'utente, caricato solo dopo il login. Il bundle contiene soltanto il tema di
 * default: per un utente senza tema assegnato non viene richiesto nulla.
 */
export async function applyTheme(theme: string, client: ApiClient = defaultApi): Promise<void> {
	if (theme === 'default' || !THEME_NAME.test(theme)) return;
	const [lexicon] = await Promise.all([
		client.themeLexicon(theme),
		loadStylesheet(`/api/theme/${theme}/theme.css`)
	]);
	useLabels(lexicon.ui);
	document.documentElement.dataset.theme = theme;
}

export async function boot(client: ApiClient = defaultApi): Promise<void> {
	try {
		const me = await client.me();
		session.username = me.username;
		try {
			await applyTheme(me.theme, client);
		} catch {
			// tema non disponibile: si resta sul default, la dashboard funziona comunque
		}
		session.status = 'ready';
	} catch (e) {
		session.status = 'error';
		session.error = e instanceof Error ? e.message : String(e);
	}
}
