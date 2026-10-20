<script lang="ts" generics="T">
	import type { Snippet } from 'svelte';
	import { ApiError } from '$lib/api';
	import { t } from '$lib/lexicon/index.svelte';

	let {
		promise,
		retry,
		children
	}: { promise: Promise<T>; retry?: () => void; children: Snippet<[T]> } = $props();
</script>

{#await promise}
	<p class="text-muted" aria-busy="true">{t('loading')}</p>
{:then value}
	{@render children(value)}
{:catch err}
	<div class="card flex flex-col gap-3 p-5" role="alert">
		<strong
			>{err instanceof ApiError && err.status === 404 ? t('notFound') : t('error.title')}</strong
		>
		<span class="mono text-muted text-xs">{err instanceof Error ? err.message : String(err)}</span>
		{#if retry}
			<button type="button" class="btn-primary min-h-11 self-start px-4" onclick={retry}
				>{t('error.retry')}</button
			>
		{/if}
	</div>
{/await}
