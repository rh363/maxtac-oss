<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { Tone } from '$lib/tones';

	let {
		tone,
		mono = false,
		children
	}: { tone: Tone; mono?: boolean; children: Snippet } = $props();
</script>

<span class="badge tone-{tone}" class:mono>{@render children()}</span>
