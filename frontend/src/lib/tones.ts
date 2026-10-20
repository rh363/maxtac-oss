export type Tone = 'crit' | 'high' | 'med' | 'low' | 'good' | 'bad' | 'warn' | 'idle' | 'info';

export function severityTone(sev: string): Tone {
	return (
		({ critical: 'crit', high: 'high', medium: 'med', low: 'low' } as Record<string, Tone>)[
			sev.toLowerCase()
		] ?? 'idle'
	);
}

export function statusTone(status: string): Tone {
	return (
		(
			{ new: 'info', mr_open: 'good', needs_human: 'warn', ignored: 'idle' } as Record<string, Tone>
		)[status] ?? 'idle'
	);
}

export function outcomeTone(outcome: string): Tone {
	return (
		(
			{
				mr_opened: 'good',
				dry_run: 'info',
				verify_failed: 'bad',
				agent_failed: 'bad',
				error: 'bad',
				needs_human: 'warn',
				budget_exhausted: 'warn',
				ignored: 'idle'
			} as Record<string, Tone>
		)[outcome] ?? 'idle'
	);
}

export const OUTCOMES = [
	'mr_opened',
	'dry_run',
	'verify_failed',
	'agent_failed',
	'needs_human',
	'budget_exhausted',
	'error'
] as const;
