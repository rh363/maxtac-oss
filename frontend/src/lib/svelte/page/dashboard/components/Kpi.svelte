<script lang="ts">
	import { tag } from '$lib/lexicon/index.svelte';

	let {
		n,
		label,
		value,
		of,
		sub,
		pct,
		money = false
	}: {
		n: 1 | 2 | 3 | 4;
		label: string;
		value: string;
		of: string;
		sub: string;
		pct?: number;
		money?: boolean;
	} = $props();

	const tip = $derived(money ? tag('costTip') : '');
</script>

<section class="card kpi kpi-{n} box-border flex flex-col gap-2.5 p-5">
	<h2 class="h-display text-muted m-0 text-sm">{label}</h2>
	<div class="flex items-baseline gap-2">
		<span class="num kpi-value text-[34px] leading-none" title={tip || undefined}>{value}</span>
		<span class="mono text-muted text-[13px]">{of}</span>
	</div>
	{#if pct !== undefined}
		<div class="bar" role="img" aria-label={`${pct}%`}>
			<span class="kpi-fill" style:width={`${pct}%`}></span>
		</div>
	{/if}
	<span class="text-muted text-[13px]">{sub}</span>
</section>

<style>
	.kpi {
		border-top-width: 2px;
	}
	.kpi-1 {
		border-top-color: var(--kpi-top-1);
		--kpi: var(--kpi-1);
	}
	.kpi-2 {
		border-top-color: var(--kpi-top-2);
		--kpi: var(--kpi-2);
	}
	.kpi-3 {
		border-top-color: var(--kpi-top-3);
		--kpi: var(--kpi-3);
	}
	.kpi-4 {
		border-top-color: var(--kpi-top-4);
		--kpi: var(--kpi-4);
	}
	.kpi-value {
		color: var(--kpi);
	}
	.kpi-fill {
		background: var(--kpi);
	}
</style>
