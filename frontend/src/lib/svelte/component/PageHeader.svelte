<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		title,
		subtitle = '',
		actions
	}: { title: string; subtitle?: string; actions?: Snippet } = $props();
</script>

<div class="flex flex-wrap items-end justify-between gap-3">
	<div class="flex min-w-0 flex-col gap-1">
		<h1 class="h-display h1 m-0 break-words">{title}</h1>
		{#if subtitle}<span class="text-muted">{subtitle}</span>{/if}
	</div>
	{#if actions}{@render actions()}{/if}
</div>
