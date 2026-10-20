<script lang="ts">
	import { api, type RunList } from '$lib/api';
	import { Async, PageHeader } from '$lib/svelte/component';
	import { t } from '$lib/lexicon/index.svelte';
	import RunsTable from './components/RunsTable.svelte';

	const SIZE = 20;
	let offset = $state(0);
	let nonce = $state(0);
	const promise = $derived.by<Promise<RunList>>(() => {
		void nonce;
		return api.runs(SIZE, offset);
	});
</script>

<PageHeader title={t('runs.title')} subtitle={t('runs.subtitle')} />

<Async {promise} retry={() => nonce++}>
	{#snippet children(list: RunList)}
		<section class="card">
			<RunsTable runs={list.items} />
		</section>
		<nav class="flex justify-between gap-3">
			<button
				type="button"
				class="field px-4 disabled:opacity-50"
				disabled={offset === 0}
				onclick={() => (offset = Math.max(0, offset - SIZE))}>{t('pager.prev')}</button
			>
			<button
				type="button"
				class="field px-4 disabled:opacity-50"
				disabled={list.items.length < SIZE}
				onclick={() => (offset += SIZE)}>{t('pager.next')}</button
			>
		</nav>
	{/snippet}
</Async>
