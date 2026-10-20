// Allineati a web/openapi.json (contratto generato dal backend). Il test
// tests/unit/contract.test.ts fallisce se i campi divergono.
import { z } from 'zod';

const dt = z.string(); // ISO 8601, formattato in UI
const nullableDt = dt.nullable();

export const Me = z.object({ username: z.string(), theme: z.string() });

export const MonthSpendOut = z.object({
	label: z.string(),
	spent_usd: z.number(),
	credits_usd: z.number(),
	projected_usd: z.number()
});

export const NightSpendOut = z.object({
	run_id: z.string().nullable(),
	spent_usd: z.number(),
	cap_usd: z.number()
});

export const OpenMR = z.object({
	project: z.string(),
	kind: z.string(),
	rule: z.string(),
	location: z.string(),
	mr_url: z.string()
});

export const HuntingSlotOut = z.object({
	project: z.string(),
	last_hunted: nullableDt,
	hunt_count: z.number().int(),
	next_up: z.boolean()
});

export const RunSummaryOut = z.object({
	run_id: z.string(),
	started_at: nullableDt,
	finished_at: nullableDt,
	dry_run: z.boolean(),
	spent_usd: z.number(),
	mrs_opened: z.number().int(),
	aborted: z.string().nullable()
});

export const DashboardOut = z.object({
	month: MonthSpendOut,
	night: NightSpendOut,
	open_mrs: z.array(OpenMR),
	findings_by_status: z.record(z.string(), z.number().int()),
	hunting_enabled: z.boolean(),
	hunting: z.array(HuntingSlotOut),
	recent_runs: z.array(RunSummaryOut),
	repos: z.array(z.string()),
	max_mrs_per_night: z.number().int(),
	hunting_per_night: z.number().int(),
	next_run_at: nullableDt
});

export const Severity = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export const Status = z.enum(['new', 'ignored', 'needs_human', 'mr_open']);
export const Kind = z.enum(['cve', 'sast', 'bug']);

export const FindingOut = z.object({
	project: z.string(),
	fingerprint: z.string(),
	kind: z.string(),
	tool: z.string(),
	rule: z.string(),
	location: z.string(),
	severity: Severity,
	status: Status,
	attempts: z.number().int(),
	reason: z.string(),
	mr_url: z.string().nullable(),
	first_seen: dt,
	last_seen: dt
});

export const FindingPage = z.object({
	items: z.array(FindingOut),
	total: z.number().int(),
	limit: z.number().int(),
	offset: z.number().int()
});

export const RunList = z.object({
	items: z.array(RunSummaryOut),
	limit: z.number().int(),
	offset: z.number().int()
});

export const TaskFinding = z.object({
	fingerprint: z.string(),
	kind: z.string(),
	tool: z.string(),
	rule: z.string(),
	location: z.string(),
	line: z.number().int().nullable().default(null),
	severity: z.string()
});

export const TaskOut = z.object({
	fingerprint: z.string(),
	kind: z.string(),
	title: z.string(),
	severity: z.string(),
	findings: z.array(TaskFinding)
});

export const FixOut = z.object({
	task: TaskOut,
	outcome: z.string(),
	cost_usd: z.number(),
	detail: z.string(),
	branch: z.string().nullable().default(null),
	mr_url: z.string().nullable().default(null),
	diff: z.string().default(''),
	test_output: z.string().default(''),
	triage_reason: z.string().default('')
});

export const TriagedOut = z.object({ task: TaskOut, reason: z.string() });

export const RepoRunOut = z.object({
	project: z.string(),
	findings_total: z.number().int(),
	findings_new: z.number().int(),
	skipped_open_mr: z.number().int(),
	hunted: z.boolean(),
	bugs_found: z.number().int(),
	fixes: z.array(FixOut),
	ignored: z.array(TriagedOut),
	needs_human: z.array(TriagedOut),
	errors: z.array(z.string())
});

export const RunDetail = z.object({
	run_id: z.string(),
	dry_run: z.boolean(),
	started_at: nullableDt.default(null),
	finished_at: nullableDt.default(null),
	spent_usd: z.number(),
	night_cap_usd: z.number(),
	aborted: z.string().nullable().default(null),
	mrs_opened: z.number().int(),
	repos: z.array(RepoRunOut)
});

export const TaskDetail = z.object({
	run_id: z.string(),
	project: z.string(),
	task: TaskOut,
	outcome: z.string(),
	cost_usd: z.number().default(0),
	detail: z.string().default(''),
	triage_reason: z.string().default(''),
	branch: z.string().nullable().default(null),
	mr_url: z.string().nullable().default(null),
	diff: z.string().default(''),
	test_output: z.string().default('')
});

/** Pacchetto lessico di un tema: si usano solo gli override `ui`. */
export const ThemeLexicon = z.object({ ui: z.record(z.string(), z.string()).default({}) });

/** Schemi confrontati con components.schemas di web/openapi.json. */
export const CONTRACT = {
	Me,
	MonthSpendOut,
	NightSpendOut,
	OpenMR,
	HuntingSlotOut,
	RunSummaryOut,
	DashboardOut,
	FindingOut,
	FindingPage,
	RunList,
	TaskFinding,
	TaskOut,
	FixOut,
	TriagedOut,
	RepoRunOut,
	RunDetail,
	TaskDetail
} as const;

export type Me = z.infer<typeof Me>;
export type Dashboard = z.infer<typeof DashboardOut>;
export type Finding = z.infer<typeof FindingOut>;
export type FindingPage = z.infer<typeof FindingPage>;
export type RunSummary = z.infer<typeof RunSummaryOut>;
export type RunList = z.infer<typeof RunList>;
export type RunDetail = z.infer<typeof RunDetail>;
export type RepoRun = z.infer<typeof RepoRunOut>;
export type Fix = z.infer<typeof FixOut>;
export type TaskDetail = z.infer<typeof TaskDetail>;
export type Severity = z.infer<typeof Severity>;
export type Status = z.infer<typeof Status>;
export type Kind = z.infer<typeof Kind>;
