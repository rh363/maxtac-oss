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
	triage_reason: z.string().default(''),
	iterations: z.number().int().nullable().default(null),
	agent_stop: z.string().nullable().default(null)
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
	test_output: z.string().default(''),
	iterations: z.number().int().nullable().default(null),
	agent_stop: z.string().nullable().default(null)
});

const date = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);

export const DaySpendOut = z.object({
	date,
	triage: z.number(),
	fix: z.number(),
	hunt: z.number(),
	discovery: z.number(),
	other: z.number(),
	total: z.number()
});

export const MonthPointOut = z.object({ date, cumulative_usd: z.number() });

export const SpendSeriesOut = z.object({
	timezone: z.string(),
	days: z.array(DaySpendOut),
	month: z.array(MonthPointOut),
	cap_usd: z.number(),
	credits_usd: z.number()
});

export const RepoOut = z.object({
	project: z.string(),
	origin: z.enum(['config', 'approved']),
	languages: z.array(z.string()),
	setup_command: z.string().nullable(),
	test_command: z.string(),
	default_branch: z.string().nullable(),
	approved_at: nullableDt,
	last_hunted: nullableDt,
	hunt_count: z.number().int(),
	rotation: z.number().int(),
	next_up: z.boolean(),
	findings_by_status: z.record(z.string(), z.number().int()),
	open_mrs: z.number().int()
});

export const FieldChangeOut = z.object({
	field: z.string(),
	active: z.string().nullable(),
	proposed: z.string().nullable()
});

export const ProposalOut = z.object({
	id: z.number().int().nullable(),
	project: z.string(),
	status: z.enum(['pending', 'superseded', 'rejected']),
	languages: z.array(z.string()),
	setup_command: z.string().nullable(),
	test_command: z.string(),
	default_branch: z.string().nullable(),
	rationale: z.string(),
	baseline_ok: z.boolean().nullable(),
	baseline_output: z.string(),
	duration_s: z.number(),
	cost_usd: z.number(),
	suspicious: z.array(z.string()),
	blockers: z.array(z.string()),
	created_at: dt,
	approve_command: z.string().nullable(),
	changes: z.array(FieldChangeOut)
});

export const ReposOut = z.object({ repos: z.array(RepoOut), proposals: z.array(ProposalOut) });

export const ScheduleOut = z.object({ timezone: z.string(), at: z.string(), next_run_at: dt });
export const FeaturesOut = z.object({ cve: z.boolean(), sast: z.boolean(), hunting: z.boolean() });
export const ModelsOut = z.object({
	triage: z.string(),
	fix: z.string(),
	hunt: z.string(),
	discovery: z.string()
});
export const BudgetOut = z.object({
	monthly_credits_usd: z.number(),
	per_night_usd: z.number(),
	per_task_usd: z.number(),
	triage_per_repo_usd: z.number(),
	hunting_per_night_usd: z.number(),
	discovery_per_repo_usd: z.number()
});
export const LimitsOut = z.object({
	max_mrs_per_night: z.number().int(),
	max_attempts: z.number().int(),
	max_iterations: z.number().int()
});
export const HuntingOut = z.object({
	repos_per_night: z.number().int(),
	lookback_days: z.number().int()
});
export const VCSOut = z.object({ branch_prefix: z.string(), mr_labels: z.array(z.string()) });
export const PriceOut = z.object({
	model: z.string(),
	input: z.number(),
	output: z.number(),
	cache_read: z.number(),
	cache_write: z.number()
});
export const SettingsOut = z.object({
	schedule: ScheduleOut,
	features: FeaturesOut,
	models: ModelsOut,
	budget: BudgetOut,
	limits: LimitsOut,
	hunting: HuntingOut,
	vcs: VCSOut,
	prices: z.array(PriceOut)
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
	TaskDetail,
	DaySpendOut,
	MonthPointOut,
	SpendSeriesOut,
	RepoOut,
	FieldChangeOut,
	ProposalOut,
	ReposOut,
	ScheduleOut,
	FeaturesOut,
	ModelsOut,
	BudgetOut,
	LimitsOut,
	HuntingOut,
	VCSOut,
	PriceOut,
	SettingsOut
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
export type SpendSeries = z.infer<typeof SpendSeriesOut>;
export type DaySpend = z.infer<typeof DaySpendOut>;
export type ReposPage = z.infer<typeof ReposOut>;
export type Repo = z.infer<typeof RepoOut>;
export type Proposal = z.infer<typeof ProposalOut>;
export type Settings = z.infer<typeof SettingsOut>;
