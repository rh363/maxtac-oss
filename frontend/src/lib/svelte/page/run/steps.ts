import type { RepoRun } from '$lib/api';
import type { Tone } from '$lib/tones';

export type StepKey = 'scan' | 'triage' | 'fix' | 'verify' | 'mr';
export interface Step {
	key: StepKey;
	tone: Tone;
	meta: string;
}

const PASSED = new Set(['mr_opened', 'dry_run']);

/** Timeline per repo (scan → triage → fix → verifica → MR) ricavata dal report della run. */
export function repoSteps(r: RepoRun): Step[] {
	const fixes = r.fixes;
	const passed = fixes.filter((f) => PASSED.has(f.outcome)).length;
	const mrs = fixes.filter((f) => f.outcome === 'mr_opened').length;
	const dry = fixes.filter((f) => f.outcome === 'dry_run').length;
	const triaged = fixes.length + r.ignored.length + r.needs_human.length;
	const scanFailed = r.errors.length > 0 && r.findings_total === 0;
	const ratioTone = (ok: number, all: number): Tone =>
		all === 0 ? 'idle' : ok === all ? 'good' : ok === 0 ? 'bad' : 'warn';
	return [
		{
			key: 'scan',
			tone: scanFailed ? 'bad' : 'good',
			meta: `${r.findings_total} · ${r.findings_new} nuovi`
		},
		{
			key: 'triage',
			tone: triaged === 0 ? 'idle' : 'good',
			meta: triaged === 0 ? '—' : `${fixes.length} fix · ${r.ignored.length} ignore`
		},
		{
			key: 'fix',
			tone: fixes.length === 0 ? 'idle' : passed === fixes.length ? 'good' : 'warn',
			meta: String(fixes.length)
		},
		{
			key: 'verify',
			tone: ratioTone(passed, fixes.length),
			meta: fixes.length === 0 ? '—' : `${passed}/${fixes.length}`
		},
		{
			key: 'mr',
			tone: mrs + dry > 0 ? (mrs > 0 ? 'good' : 'info') : 'idle',
			meta: String(mrs + dry)
		}
	];
}
