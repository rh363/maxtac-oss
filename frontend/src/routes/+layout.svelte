<script lang="ts">
	import '../app.css';
	import type { Snippet } from 'svelte';
	import { boot, session } from '$lib/session.svelte';
	import { Layout } from '$lib/svelte/layout';
	import { t } from '$lib/lexicon/index.svelte';

	let { children }: { children: Snippet } = $props();

	boot();
</script>

{#if session.status === 'ready'}
	<Layout>{@render children()}</Layout>
{:else if session.status === 'error'}
	<main class="mx-auto flex max-w-md flex-col gap-3 p-8" role="alert">
		<strong>{t('error.title')}</strong>
		<span class="mono text-muted text-xs">{session.error}</span>
		<button
			type="button"
			class="btn-primary min-h-11 self-start px-4"
			onclick={() => location.reload()}>{t('error.retry')}</button
		>
	</main>
{:else}
	<p class="text-muted p-8" aria-busy="true">{t('loading')}</p>
{/if}
