<script lang="ts">
	import { Check, Copy } from '@lucide/svelte';
	import { t } from '$lib/lexicon/index.svelte';

	let { command: raw }: { command: string } = $props();

	// Il server scrive sempre il comando neutro; il nome mostrato segue il lessico dell'utente.
	const command = $derived(raw.replace(/^autofix\b/, t('cli.name')));

	let copied = $state(false);
	let code = $state<HTMLElement>();

	async function copy() {
		try {
			await navigator.clipboard.writeText(command);
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch {
			// clipboard non disponibile: seleziona il testo da copiare a mano
			if (code) window.getSelection()?.selectAllChildren(code);
		}
	}
</script>

<div class="field flex items-center justify-between gap-2 py-1 pr-1 pl-3">
	<code bind:this={code} class="mono min-w-0 text-[13px] break-all">{command}</code>
	<button
		type="button"
		class="text-muted hover:text-ink flex min-h-9 shrink-0 items-center gap-1.5 px-2 text-[13px]"
		onclick={copy}
	>
		{#if copied}
			<Check size={16} strokeWidth={1.5} aria-hidden="true" />{t('copied')}
		{:else}
			<Copy size={16} strokeWidth={1.5} aria-hidden="true" />{t('copy')}
		{/if}
	</button>
</div>
