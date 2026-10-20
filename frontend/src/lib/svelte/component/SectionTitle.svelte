<script lang="ts">
	import type { Snippet } from 'svelte';

	// `tag` è un sottotitolo secondario facoltativo (vuoto nel tema di default)
	let {
		tag = '',
		level = 2,
		class: klass = '',
		children
	}: { tag?: string; level?: 2 | 3; class?: string; children: Snippet } = $props();
</script>

<svelte:element this={`h${level}`} class="h-display m-0 text-lg {klass}">
	{@render children()}
	{#if tag}<span class="tag">{tag}</span>{/if}
</svelte:element>
