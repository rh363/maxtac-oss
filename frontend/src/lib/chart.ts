// Geometria dei grafici della dashboard: funzioni pure, testate in tests/unit/chart.test.ts.
import type { DaySpend } from './api/schemas';

/** Serie del grafico della spesa, dal basso verso l'alto. Triage, discovery e altro insieme. */
export const SPEND_SERIES = ['fix', 'hunt', 'rest'] as const;
export type SpendSeriesKey = (typeof SPEND_SERIES)[number];

export function spendParts(d: DaySpend): Record<SpendSeriesKey, number> {
	return { fix: d.fix, hunt: d.hunt, rest: d.triage + d.discovery + d.other };
}

/** Massimo dell'asse e tacche "tonde" (passo 1, 2 o 5 × 10^n) che lo coprono. */
export function niceAxis(max: number, count = 4): { max: number; ticks: number[] } {
	if (!(max > 0)) return { max: 1, ticks: [0, 1] };
	const raw = max / count;
	const pow = 10 ** Math.floor(Math.log10(raw));
	const step = [1, 2, 2.5, 5, 10].map((m) => m * pow).find((s) => s >= raw) ?? 10 * pow;
	const top = Math.ceil(max / step - 1e-9) * step;
	const ticks: number[] = [];
	for (let v = 0; v <= top + step / 2; v += step) ticks.push(Number(v.toFixed(10)));
	return { max: top, ticks };
}

export interface Segment {
	key: SpendSeriesKey;
	value: number;
	y: number; // in alto
	h: number;
}

/**
 * Segmenti impilati di una colonna in pixel (y verso il basso, `base` = linea dello zero).
 * Tra un segmento e l'altro resta `gap` px di superficie; i segmenti troppo bassi per
 * reggere il gap vengono comunque disegnati con almeno 1px.
 */
export function stack(
	parts: Record<SpendSeriesKey, number>,
	scale: (v: number) => number,
	base: number,
	gap = 2
): Segment[] {
	const out: Segment[] = [];
	let acc = 0;
	for (const key of SPEND_SERIES) {
		const value = parts[key];
		if (!(value > 0)) continue;
		const y0 = scale(acc);
		acc += value;
		const y1 = scale(acc);
		const bottom = out.length === 0 ? y0 : y0 - gap;
		const h = Math.max(1, bottom - y1);
		out.push({ key, value, y: bottom - h, h });
	}
	if (out.length && out[0]!.y + out[0]!.h > base) out[0]!.h = base - out[0]!.y;
	return out;
}

/** Path di un rettangolo con i due angoli in alto arrotondati (estremità dei dati). */
export function topRounded(x: number, y: number, w: number, h: number, r = 4): string {
	const rr = Math.max(0, Math.min(r, w / 2, h));
	return (
		`M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}` +
		`H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`
	);
}

const dayFmt = new Intl.DateTimeFormat('it-IT', {
	day: 'numeric',
	month: 'short',
	timeZone: 'UTC'
});

/** "14 ott" da una data ISO (YYYY-MM-DD), senza scivolare di fuso. */
export function dayLabel(iso: string): string {
	return dayFmt.format(new Date(`${iso}T12:00:00Z`));
}

/** Indici delle date da etichettare sull'asse x: ogni `every` giorni, sempre l'ultima. */
export function labelIndexes(n: number, every = 7): number[] {
	if (n <= 0) return [];
	const out: number[] = [];
	for (let i = (n - 1) % every; i < n; i += every) out.push(i);
	return out;
}
