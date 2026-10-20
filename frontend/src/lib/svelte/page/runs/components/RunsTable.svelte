<script lang="ts">
	import { resolve } from '$app/paths';
	import type { RunSummary } from '$lib/api';
	import { Badge } from '$lib/svelte/component';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import { money, runDate, when } from '$lib/format';
	import type { Tone } from '$lib/tones';

	let { runs }: { runs: RunSummary[] } = $props();

	function state(r: RunSummary): { tone: Tone; label: string } {
		if (r.aborted) return { tone: 'warn', label: t('run.state.aborted') };
		if (r.dry_run) return { tone: 'info', label: t('run.state.dry') };
		if (r.mrs_opened > 0) return { tone: 'good', label: t('outcome.mr_opened') };
		return { tone: 'idle', label: t('run.state.ok') };
	}
</script>

{#if runs.length === 0}
	<p class="text-muted m-0 px-5 py-4">{t('empty.runs')}</p>
{:else}
	<div class="overflow-x-auto">
		<table class="w-full min-w-[560px] border-collapse">
			<thead>
				<tr>
					<th class="th px-5 py-2.5">{t('col.when')}</th>
					<th class="th px-3 py-2.5">{t('col.mrs')}</th>
					<th class="th px-3 py-2.5">{t('col.note')}</th>
					<th class="th px-5 py-2.5 text-right!">{t('col.cost')}</th>
				</tr>
			</thead>
			<tbody>
				{#each runs as r (r.run_id)}
					{@const s = state(r)}
					<tr class="border-line border-t">
						<td class="px-5">
							<a
								href={resolve('/runs/[id]', { id: r.run_id })}
								class="link mono inline-flex min-h-11 items-center text-[13px]"
								>{when(r.started_at ?? runDate(r.run_id))}</a
							>
						</td>
						<td class="num px-3 text-[15px]">{r.mrs_opened}</td>
						<td class="px-3"><Badge tone={s.tone} mono>{s.label}</Badge></td>
						<td class="mono px-5 text-right" title={tag('costTip') || undefined}
							>{money(r.spent_usd)}</td
						>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
