import { NEUTRAL, format, merge, type LexiconKey, type Labels, type Vars } from './lexicon';

export { format, merge, NEUTRAL };
export type { LexiconKey, Labels, Vars };

const state = $state<{ labels: Labels }>({ labels: NEUTRAL });

/** Etichetta corrente (neutra, o del tema caricato a runtime). */
export function t(key: LexiconKey, vars?: Vars): string {
	return format(state.labels[key], vars);
}

/** Etichetta opzionale: stringa vuota se il tema corrente non la definisce. */
export function tag(key: LexiconKey): string {
	return state.labels[key];
}

export function useLabels(overrides: Record<string, unknown>): void {
	state.labels = merge(NEUTRAL, overrides);
}
