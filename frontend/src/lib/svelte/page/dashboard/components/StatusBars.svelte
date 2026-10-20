<script lang="ts">
	import { resolve } from '$app/paths';
	import { SectionTitle } from '$lib/svelte/component';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import { percent } from '$lib/format';

	let { counts }: { counts: Record<string, number> } = $props();

	const order = ['new', 'mr_open', 'needs_human', 'ignored'] as const;
	const total = $derived(order.reduce((a, k) => a + (counts[k] ?? 0), 0));
</script>

<section class="card box-border flex flex-col gap-4 p-5">
	<SectionTitle tag={tag('tag.byStatus')}>{t('section.byStatus')}</SectionTitle>
	{#each order as key (key)}
		{@const n = counts[key] ?? 0}
		<a href={resolve(`/findings?status=${key}`)} class="flex flex-col gap-1.5 no-underline">
			<span class="flex justify-between gap-2">
				<span class="flex items-center gap-2">
					<span aria-hidden="true" class="dot status-{key} size-2.5"></span>{t(`status.${key}`)}
				</span>
				<span class="num text-base">{n}</span>
			</span>
			<span class="bar h-2!">
				<span class="status-{key}" style:width={`${percent(n, total)}%`}></span>
			</span>
		</a>
	{/each}
</section>

<style>
	.dot {
		border-radius: var(--radius);
	}
	.status-new {
		background: var(--bar-new);
	}
	.status-mr_open {
		background: var(--bar-mr_open);
	}
	.status-needs_human {
		background: var(--bar-needs_human);
	}
	.status-ignored {
		background: var(--bar-ignored);
	}
</style>
