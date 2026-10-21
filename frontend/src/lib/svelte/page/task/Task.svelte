<script lang="ts">
	import { Check, ExternalLink, X } from '@lucide/svelte';
	import { api, type TaskDetail } from '$lib/api';
	import { Async, Badge, PageHeader, SectionTitle } from '$lib/svelte/component';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import { money, safeHttps, stopKey } from '$lib/format';
	import { outcomeTone, severityTone } from '$lib/tones';
	import DiffView from './components/DiffView.svelte';

	let { runId, fingerprint, repo }: { runId: string; fingerprint: string; repo?: string } =
		$props();

	let nonce = $state(0);
	const promise = $derived.by<Promise<TaskDetail>>(() => {
		void nonce;
		return api.task(runId, fingerprint, repo);
	});

	const PASSED = new Set(['mr_opened', 'dry_run']);
	function checks(d: TaskDetail): string[] {
		const out = [t('check.tests')];
		if (d.task.kind === 'bug') out.push(t('check.regression'));
		else out.push(t('check.rescan'));
		out.push(t('check.diff'), t('check.protected'));
		return out;
	}
	const kindLabel = (k: string) =>
		k === 'cve' ? t('kind.cve') : k === 'sast' ? t('kind.sast') : t('kind.bug');
</script>

<Async {promise} retry={() => nonce++}>
	{#snippet children(d: TaskDetail)}
		{@const mr = safeHttps(d.mr_url)}
		{@const passed = PASSED.has(d.outcome)}
		<PageHeader
			title={d.task.title}
			subtitle={t('task.subtitle', { repo: d.project, kind: kindLabel(d.task.kind) })}
		>
			{#snippet actions()}
				{#if mr}
					<!-- link esterno a GitLab, non una rotta della SPA -->
					<!-- eslint-disable svelte/no-navigation-without-resolve -->
					<a
						href={mr}
						rel="noopener noreferrer"
						target="_blank"
						class="btn-primary inline-flex min-h-11 items-center gap-2 px-4 no-underline"
					>
						{t('task.openMr')}
						<ExternalLink size={16} strokeWidth={1.5} aria-hidden="true" />
					</a>
					<!-- eslint-enable svelte/no-navigation-without-resolve -->
				{/if}
			{/snippet}
		</PageHeader>

		<div class="flex flex-wrap items-center gap-2 text-[13px]">
			<Badge tone={outcomeTone(d.outcome)}>{t(`outcome.${d.outcome}` as never)}</Badge>
			{#if d.branch}<span class="mono text-muted break-all">{d.branch}</span>{/if}
			<span class="text-muted">· {t('task.gitlabNeutral')}</span>
		</div>

		<div class="grid grid-cols-[repeat(auto-fit,minmax(min(340px,100%),1fr))] gap-4">
			<section class="card flex flex-col gap-3 p-5">
				<SectionTitle>{t('sec.finding')}</SectionTitle>
				{#each d.task.findings as f (f.fingerprint)}
					<dl class="m-0 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-[13px]">
						<dt class="text-muted">{t('field.rule')}</dt>
						<dd class="mono m-0 break-all">{f.rule}</dd>
						<dt class="text-muted">{t('field.location')}</dt>
						<dd class="mono m-0 break-all">{f.location}{f.line ? `:${f.line}` : ''}</dd>
						<dt class="text-muted">{t('field.severity')}</dt>
						<dd class="m-0">
							<Badge tone={severityTone(f.severity)} mono>{f.severity.toUpperCase()}</Badge>
						</dd>
						<dt class="text-muted">{t('field.tool')}</dt>
						<dd class="mono m-0">{f.tool}</dd>
					</dl>
				{/each}
			</section>
			<section class="card flex flex-col gap-3 p-5">
				<SectionTitle tag={tag('tag.triage')}>{t('sec.triage')}</SectionTitle>
				<p class="m-0 leading-relaxed break-words whitespace-pre-line">
					{d.triage_reason || t('triage.none')}
				</p>
			</section>
			<section class="card flex flex-col gap-3 p-5">
				<SectionTitle tag={tag('tag.change')}>{t('sec.change')}</SectionTitle>
				<p class="m-0 leading-relaxed break-words whitespace-pre-line">
					{d.detail || t('change.none')}
				</p>
			</section>
			<section class="card flex flex-col gap-3 p-5">
				<SectionTitle>{t('sec.verify')}</SectionTitle>
				<ul class="m-0 flex list-none flex-col gap-2 p-0">
					{#if passed}
						{#each checks(d) as c (c)}
							<li class="flex items-center gap-2.5">
								<Check size={18} strokeWidth={2} class="text-ok shrink-0" aria-hidden="true" />
								<span>{c}</span>
							</li>
						{/each}
					{:else}
						<li class="flex items-center gap-2.5">
							<X
								size={18}
								strokeWidth={2}
								class="tone-bad shrink-0 bg-transparent!"
								aria-hidden="true"
							/>
							<span>{t('check.notPassed')}</span>
						</li>
					{/if}
				</ul>
			</section>
		</div>

		<DiffView diff={d.diff} />

		<div class="grid grid-cols-[repeat(auto-fit,minmax(min(340px,100%),1fr))] gap-4">
			<section class="card">
				<div class="border-line bg-surface-alt border-b px-5 py-3.5">
					<SectionTitle class="text-base!">{t('sec.tests')}</SectionTitle>
				</div>
				{#if d.test_output}
					<pre
						class="mono m-0 overflow-x-auto px-5 py-4 text-xs leading-relaxed">{d.test_output}</pre>
				{:else}
					<p class="text-muted m-0 px-5 py-4">{t('tests.empty')}</p>
				{/if}
			</section>
			<section class="card flex flex-col gap-1 p-5">
				<SectionTitle class="mb-2 text-base!">{t('sec.cost')}</SectionTitle>
				{#if d.iterations !== null}
					<div class="border-line flex justify-between gap-3 border-t py-2">
						<span>{t('task.agent')}</span>
						<span class="mono" data-testid="iterations"
							>{t('task.iterations', {
								n: d.iterations,
								stop: t(stopKey(d.agent_stop))
							})}</span
						>
					</div>
				{/if}
				<div class="border-line flex justify-between gap-3 border-t py-2">
					<span class="flex flex-col gap-0.5">
						<span>{t('cost.task')}</span>
						<span class="mono text-muted text-xs">{t('cost.note')}</span>
					</span>
					<span class="mono">{money(d.cost_usd)}</span>
				</div>
				<div class="total flex justify-between gap-3 pt-2.5 font-semibold">
					<span>{t('total')}</span>
					<span class="num h1 text-lg!" title={tag('costTip') || undefined}
						>{money(d.cost_usd)}</span
					>
				</div>
			</section>
		</div>
	{/snippet}
</Async>

<style>
	.total {
		border-top: 2px solid var(--text);
	}
</style>
