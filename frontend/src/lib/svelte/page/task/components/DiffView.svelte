<script lang="ts">
	import { SectionTitle } from '$lib/svelte/component';
	import { t } from '$lib/lexicon/index.svelte';
	import { parseDiff } from '$lib/format';

	let { diff }: { diff: string } = $props();
	const parsed = $derived(parseDiff(diff));
</script>

<section class="card">
	<div class="border-line bg-surface-alt border-b px-5 py-3.5">
		<SectionTitle class="text-base!">
			{t('sec.diff')}
			{#if diff}
				<span class="tag mono"
					>{t('diff.summary', { files: parsed.files, add: parsed.add, del: parsed.del })}</span
				>
			{/if}
		</SectionTitle>
	</div>
	{#if diff}
		<div class="mono overflow-x-auto py-3 text-[13px] leading-relaxed" data-testid="diff">
			{#each parsed.lines as line, i (i)}
				<div class="diff-{line.kind} px-5 whitespace-pre">{line.text || ' '}</div>
			{/each}
		</div>
	{:else}
		<p class="text-muted m-0 px-5 py-4">{t('diff.empty')}</p>
	{/if}
</section>
