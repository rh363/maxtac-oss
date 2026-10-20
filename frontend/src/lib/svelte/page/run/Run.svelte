<script lang="ts">
	import { api, type RunDetail } from '$lib/api';
	import { Async, Badge, PageHeader } from '$lib/svelte/component';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import { duration, money, runDate, when } from '$lib/format';
	import { OUTCOMES, outcomeTone } from '$lib/tones';
	import RepoTimeline from './components/RepoTimeline.svelte';

	let { runId }: { runId: string } = $props();

	let nonce = $state(0);
	const promise = $derived.by<Promise<RunDetail>>(() => {
		void nonce;
		return api.run(runId);
	});
	const reload = () => nonce++;
</script>

<Async {promise} retry={reload}>
	{#snippet children(run: RunDetail)}
		{@const dur = duration(run.started_at, run.finished_at)}
		{@const fresh = run.repos.reduce((a, r) => a + r.findings_new, 0)}
		<PageHeader
			title={t('run.title', { date: when(run.started_at ?? runDate(run.run_id)) })}
			subtitle={t('run.subtitle', { repos: run.repos.length, duration: dur, mrs: run.mrs_opened })}
		/>
		{#if run.aborted}
			<div class="badge tone-warn self-start whitespace-normal!" role="status">
				{t('run.aborted', { reason: run.aborted })}
			</div>
		{/if}
		<div class="grid grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-3">
			{#each [['stats.repos', String(run.repos.length)], ['stats.new', String(fresh)], ['stats.mrs', String(run.mrs_opened)], ['stats.duration', dur], ['stats.spend', money(run.spent_usd)]] as [k, v] (k)}
				<div class="card flex flex-col gap-1 px-4 py-3.5">
					<span class="text-muted text-xs">{t(k as never)}</span>
					<span
						class="num text-[22px]"
						title={k === 'stats.spend' ? tag('costTip') || undefined : undefined}>{v}</span
					>
				</div>
			{/each}
		</div>
		<div class="text-muted flex flex-wrap items-center gap-2 text-xs">
			<span>{t('legend')}</span>
			{#each OUTCOMES as o (o)}<Badge tone={outcomeTone(o)}>{t(`outcome.${o}`)}</Badge>{/each}
		</div>
		{#each run.repos as repo (repo.project)}
			<RepoTimeline runId={run.run_id} {repo} />
		{/each}
	{/snippet}
</Async>
