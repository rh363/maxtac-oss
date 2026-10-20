<script lang="ts">
	import type { Dashboard } from '$lib/api';
	import { SectionTitle } from '$lib/svelte/component';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import { ago } from '$lib/format';

	let {
		enabled,
		perNight,
		slots
	}: { enabled: boolean; perNight: number; slots: Dashboard['hunting'] } = $props();

	const now = new Date();
	const sorted = $derived(
		[...slots].sort((a, b) => Number(b.next_up) - Number(a.next_up) || a.hunt_count - b.hunt_count)
	);
	const sub = $derived(
		[t('hunt.sub', { n: perNight }), tag('tag.hunt')].filter(Boolean).join(' · ')
	);
</script>

<section class="card box-border flex flex-col gap-3 p-5">
	<div class="flex flex-col gap-1">
		<SectionTitle>{t('hunt.title')}</SectionTitle>
		<span class="text-muted text-[13px]">{enabled ? sub : t('hunt.disabled')}</span>
	</div>
	{#each sorted as s (s.project)}
		<div class="border-line flex items-center justify-between gap-2 border-t py-2">
			<span class="mono min-w-0 truncate text-[13px]">{s.project}</span>
			<span class="flex shrink-0 items-center gap-2.5">
				<span class="text-muted text-[13px]">{ago(s.last_hunted, now, t('hunt.never'))}</span>
				{#if enabled && s.next_up}
					<span class="next mono px-2 py-0.5 text-xs font-semibold">{t('hunt.tonight')}</span>
				{/if}
			</span>
		</div>
	{/each}
</section>

<style>
	.next {
		background: var(--primary);
		color: var(--on-primary);
		border-radius: var(--radius);
		text-transform: var(--case);
	}
</style>
