// Formattazione per la UI (it-IT). Funzioni pure, testate in tests/unit.

/** Importo in dollari con virgola decimale; sotto il centesimo tre decimali ($0,004). */
export function money(usd: number): string {
	const digits = usd > 0 && usd < 0.01 ? 3 : 2;
	const sign = usd < 0 ? '−' : '';
	return `${sign}$${Math.abs(usd).toFixed(digits).replace('.', ',')}`;
}

export function percent(value: number, total: number): number {
	if (!(total > 0)) return 0;
	return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
}

const dateFmt = new Intl.DateTimeFormat('it-IT', { day: 'numeric', month: 'short' });
const timeFmt = new Intl.DateTimeFormat('it-IT', { hour: '2-digit', minute: '2-digit' });

/** "20 ott, 02:30" */
export function when(iso: string | null | undefined): string {
	if (!iso) return '—';
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return '—';
	return `${dateFmt.format(d)}, ${timeFmt.format(d)}`;
}

export function time(iso: string | null | undefined): string {
	if (!iso) return '—';
	const d = new Date(iso);
	return Number.isNaN(d.getTime()) ? '—' : timeFmt.format(d);
}

/** Durata leggibile: "41 min", "1 h 05 min", "40 s". */
export function duration(start: string | null, end: string | null): string {
	if (!start || !end) return '—';
	const s = Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000);
	if (!Number.isFinite(s) || s < 0) return '—';
	if (s < 60) return `${s} s`;
	const m = Math.round(s / 60);
	if (m < 60) return `${m} min`;
	return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, '0')} min`;
}

/** "ieri", "9 giorni fa", "oggi"; `never` se mai. */
export function ago(iso: string | null, now: Date, never: string): string {
	if (!iso) return never;
	const days = Math.floor((now.getTime() - new Date(iso).getTime()) / 86_400_000);
	if (days <= 0) return 'oggi';
	if (days === 1) return 'ieri';
	return `${days} giorni fa`;
}

/** Il run_id della pipeline è un timestamp compatto UTC: 20261020T023000Z. */
export function runDate(runId: string): string | null {
	const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(runId);
	if (!m) return null;
	return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
}

/** Link esterno accettato solo se https: il backend lascia passare solo quelli di GitLab. */
export function safeHttps(url: string | null | undefined): string | null {
	if (!url) return null;
	try {
		return new URL(url).protocol === 'https:' ? url : null;
	} catch {
		return null;
	}
}

export type DiffKind = 'add' | 'del' | 'hunk' | 'ctx';
export interface DiffLine {
	kind: DiffKind;
	text: string;
}

export function parseDiff(diff: string): {
	lines: DiffLine[];
	files: number;
	add: number;
	del: number;
} {
	const lines: DiffLine[] = [];
	const files = new Set<string>();
	let add = 0;
	let del = 0;
	for (const text of diff.replace(/\n$/, '').split('\n')) {
		if (text === '' && lines.length === 0) continue;
		let kind: DiffKind = 'ctx';
		if (text.startsWith('+++ ') || text.startsWith('--- ')) {
			kind = 'hunk';
			const name = text.slice(4).replace(/^[ab]\//, '');
			if (text.startsWith('+++ ') && name !== '/dev/null') files.add(name);
			if (text.startsWith('--- ') && name !== '/dev/null') files.add(name);
		} else if (text.startsWith('@@') || text.startsWith('diff ') || text.startsWith('index ')) {
			kind = 'hunk';
		} else if (text.startsWith('+')) {
			kind = 'add';
			add++;
		} else if (text.startsWith('-')) {
			kind = 'del';
			del++;
		}
		lines.push({ kind, text });
	}
	return { lines, files: files.size, add, del };
}
