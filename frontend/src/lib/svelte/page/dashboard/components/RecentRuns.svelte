<script lang="ts">
	import { resolve } from '$app/paths';
	import type { RunSummary } from '$lib/api';
	import { SectionTitle } from '$lib/svelte/component';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import RunsTable from '$lib/svelte/page/runs/components/RunsTable.svelte';

	let { runs }: { runs: RunSummary[] } = $props();
</script>

<section class="card box-border flex flex-col">
	<div class="border-line flex items-center justify-between gap-3 border-b px-5 py-4">
		<SectionTitle tag={tag('tag.runs')}>{t('section.runs')}</SectionTitle>
		<a href={resolve('/runs')} class="link text-[13px]">{t('runs.all')}</a>
	</div>
	<RunsTable {runs} />
</section>
