<script lang="ts">
	import { TriangleAlert } from '@lucide/svelte';
	import type { Proposal } from '$lib/api';
	import { Badge } from '$lib/svelte/component';
	import { t } from '$lib/lexicon/index.svelte';
	import { money, when } from '$lib/format';
	import type { Tone } from '$lib/tones';
	import CopyCommand from './CopyCommand.svelte';

	let { p }: { p: Proposal } = $props();

	const statusTone: Record<Proposal['status'], Tone> = {
		pending: 'info',
		superseded: 'idle',
		rejected: 'idle'
	};
	const baseline = $derived(
		p.baseline_ok === true
			? { tone: 'good' as Tone, label: t('baseline.ok') }
			: p.baseline_ok === false
				? { tone: 'bad' as Tone, label: t('baseline.fail') }
				: { tone: 'idle' as Tone, label: t('baseline.none') }
	);
	const fieldLabel = (f: string) =>
		f === 'languages'
			? t('field.languages')
			: f === 'setup_command'
				? t('field.setup_command')
				: f === 'test_command'
					? t('field.test_command')
					: f;
</script>

<article class="card flex flex-col gap-3 p-5" data-testid="proposal">
	<header class="flex flex-wrap items-center justify-between gap-2">
		<h3 class="mono m-0 text-base font-semibold">{p.project}</h3>
		<span class="flex flex-wrap items-center gap-2">
			<Badge tone={statusTone[p.status]}>{t(`proposal.${p.status}`)}</Badge>
			<span class="mono text-muted text-xs">{when(p.created_at)}</span>
		</span>
	</header>

	{#if p.suspicious.length}
		<ul class="m-0 flex list-none flex-wrap gap-2 p-0" aria-label={t('proposal.check')}>
			{#each p.suspicious as s (s)}
				<li>
					<Badge tone="warn">
						<span class="inline-flex items-center gap-1.5">
							<TriangleAlert size={14} strokeWidth={1.75} aria-hidden="true" />{s}
						</span>
					</Badge>
				</li>
			{/each}
		</ul>
	{/if}

	<dl class="m-0 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-[13px]">
		<dt class="text-muted">{t('field.languages')}</dt>
		<dd class="m-0">{p.languages.join(', ') || '—'}</dd>
		<dt class="text-muted">{t('field.setup')}</dt>
		<dd class="mono m-0 break-all">{p.setup_command ?? '—'}</dd>
		<dt class="text-muted">{t('field.test')}</dt>
		<dd class="mono m-0 break-all">{p.test_command}</dd>
		<dt class="text-muted">{t('proposal.baseline')}</dt>
		<dd class="m-0 flex flex-wrap items-center gap-2">
			<Badge tone={baseline.tone}>{baseline.label}</Badge>
			<span class="mono text-muted text-xs">{p.duration_s.toFixed(1).replace('.', ',')} s</span>
		</dd>
		<dt class="text-muted">{t('proposal.cost')}</dt>
		<dd class="mono m-0">{money(p.cost_usd)}</dd>
		<dt class="text-muted">{t('proposal.rationale')}</dt>
		<dd class="m-0 break-words">{p.rationale}</dd>
	</dl>

	{#if p.status === 'pending'}
		<div class="flex flex-col gap-1.5 text-[13px]">
			<strong>{t('proposal.changes')}</strong>
			{#if p.changes.length}
				<div class="overflow-x-auto">
					<table class="w-full border-collapse text-[13px]" data-testid="changes">
						<tbody>
							{#each p.changes as c (c.field)}
								<tr class="border-line border-t first:border-t-0">
									<th scope="row" class="th py-1.5 pr-3 align-top">{fieldLabel(c.field)}</th>
									<td class="mono diff-del px-2 py-1.5 break-all">− {c.active ?? '—'}</td>
									<td class="mono diff-add px-2 py-1.5 break-all">+ {c.proposed ?? '—'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else}
				<span class="text-muted">{t('proposal.new')}</span>
			{/if}
		</div>
	{/if}

	{#if p.baseline_output}
		<details class="text-[13px]">
			<summary class="text-link cursor-pointer">{t('proposal.output')}</summary>
			<pre
				class="mono bg-surface-alt m-0 mt-2 max-h-64 overflow-auto p-3 text-xs">{p.baseline_output}</pre>
		</details>
	{/if}

	{#if p.approve_command}
		<div class="border-line flex flex-col gap-1.5 border-t pt-3 text-[13px]">
			<span class="text-muted">{t('proposal.approve')}</span>
			<CopyCommand command={p.approve_command} />
		</div>
	{/if}
</article>
