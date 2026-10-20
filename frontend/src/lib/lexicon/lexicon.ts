import neutral from './neutral.json';

export type LexiconKey = keyof typeof neutral;
export type Labels = Record<LexiconKey, string>;
export type Vars = Record<string, string | number>;

export const NEUTRAL: Labels = neutral;

/** Sostituisce i segnaposto `{nome}`; un segnaposto senza valore resta visibile. */
export function format(template: string, vars: Vars = {}): string {
	return template.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m));
}

/**
 * Applica gli override di un tema alle etichette neutre. Le chiavi sconosciute vengono
 * scartate: un tema può solo cambiare parole che esistono già, non aggiungerne.
 */
export function merge(base: Labels, overrides: Record<string, unknown>): Labels {
	const out: Labels = { ...base };
	for (const [k, v] of Object.entries(overrides)) {
		if (k in base && typeof v === 'string') out[k as LexiconKey] = v;
	}
	return out;
}
