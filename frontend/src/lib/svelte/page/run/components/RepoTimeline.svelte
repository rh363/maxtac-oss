<script lang="ts">
	import { resolve } from '$app/paths';
	import { ChevronRight } from '@lucide/svelte';
	import type { RepoRun } from '$lib/api';
	import { Badge } from '$lib/svelte/component';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import { money } from '$lib/format';
	import { outcomeTone } from '$lib/tones';
	import { repoSteps } from '../steps';

	let { runId, repo }: { runId: string; repo: RepoRun } = $props();

	const steps = $derived(repoSteps(repo));
	const rows = $derived([
		...repo.fixes.map((f) => ({
			task: f.task,
			outcome: f.outcome,
			detail: f.detail,
			cost: f.cost_usd as number | null
		})),
		...repo.needs_human.map((x) => ({
			task: x.task,
			outcome: 'needs_human',
			detail: x.reason,
			cost: null
		})),
		...repo.ignored.map((x) => ({ task: x.task, outcome: 'ignored', detail: x.reason, cost: null }))
	]);
	const href = (fp: string) =>
		resolve(`/runs/[id]/tasks/[fp]?repo=${encodeURIComponent(repo.project)}`, { id: runId, fp });
</script>

<section class="card">
	<div class="border-line flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4">
		<h2 class="mono m-0 text-base font-semibold">
			{repo.project}
			{#if repo.hunted}<span class="tag">· {t('run.hunted')}</span>{/if}
		</h2>
		<ol aria-label={t('steps.label')} class="m-0 flex list-none flex-wrap items-center gap-1.5 p-0">
			{#each steps as st, i (st.key)}
				<li class="flex items-center gap-1.5">
					<span
						class="badge tone-{st.tone} step h-display inline-flex items-center gap-1.5 px-2.5! py-1!"
					>
						{t(`steps.${st.key}`)}<span class="mono font-normal">{st.meta}</span>
					</span>
					{#if i < steps.length - 1}
						<ChevronRight size={14} strokeWidth={1.5} class="text-muted" aria-hidden="true" />
					{/if}
				</li>
			{/each}
		</ol>
	</div>
	{#if repo.errors.length}
		<div class="border-line border-b px-5 py-3">
			<strong class="text-[13px]">{t('run.errors')}</strong>
			<ul class="mono text-muted m-0 mt-1 list-none p-0 text-xs">
				{#each repo.errors as e, i (i)}<li class="break-words">{e}</li>{/each}
			</ul>
		</div>
	{/if}
	{#if rows.length === 0}
		<p class="text-muted m-0 px-5 py-3">{t('run.noTasks')}</p>
	{:else}
		<div class="overflow-x-auto">
			<table class="w-full min-w-[640px] border-collapse">
				<tbody>
					{#each rows as row, i (`${row.task.fingerprint}-${i}`)}
						<tr class="border-line border-t first:border-t-0">
							<td class="mono text-muted w-14 px-5 py-2.5 text-xs uppercase">{row.task.kind}</td>
							<td class="px-3 py-2.5">
								<a href={href(row.task.fingerprint)} class="link">{row.task.title}</a>
								{#if row.detail}
									<div class="text-muted line-clamp-2 text-xs break-words">{row.detail}</div>
								{/if}
							</td>
							<td class="px-3 py-2.5">
								<Badge tone={outcomeTone(row.outcome)}>{t(`outcome.${row.outcome}` as never)}</Badge
								>
							</td>
							<td
								class="mono px-5 py-2.5 text-right whitespace-nowrap"
								title={tag('costTip') || undefined}>{row.cost === null ? '—' : money(row.cost)}</td
							>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</section>

<style>
	.step {
		clip-path: none;
	}
</style>
