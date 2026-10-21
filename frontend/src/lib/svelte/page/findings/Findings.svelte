<script lang="ts">
	import { resolve } from '$app/paths';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { ExternalLink, Search, X } from '@lucide/svelte';
	import { api, type FindingPage } from '$lib/api';
	import { Async, Badge, PageHeader } from '$lib/svelte/component';
	import { t } from '$lib/lexicon/index.svelte';
	import {
		MAX_QUERY,
		PAGE_SIZE,
		parseFilters,
		toApi,
		toSearch,
		type FindingView
	} from '$lib/filters';
	import { safeHttps } from '$lib/format';
	import { severityTone, statusTone } from '$lib/tones';

	let repos = $state<string[]>([]);
	$effect(() => {
		api.dashboard().then(
			(d) => (repos = d.repos),
			() => (repos = [])
		);
	});

	const view = $derived(parseFilters(page.url.searchParams));
	let nonce = $state(0);
	const promise = $derived.by<Promise<FindingPage>>(() => {
		void nonce;
		return api.findings(toApi(view));
	});

	// testo in modifica; si applica con Invio o uscendo dal campo
	let draft = $derived(view.q ?? '');

	function search() {
		const q = draft.trim();
		if (q !== (view.q ?? '')) update({ q: q || undefined });
	}

	function update(patch: Partial<FindingView>) {
		const next = { ...view, page: 1, ...patch };
		const q = toSearch(next);
		goto(q ? resolve(`/findings${q}` as `/findings?${string}`) : resolve('/findings'), {
			reset: false
		});
	}

	const filters = $derived([
		{
			key: 'kind',
			label: t('filter.kind'),
			all: t('filter.all'),
			value: view.kind ?? '',
			options: [
				['cve', 'CVE'],
				['sast', 'SAST'],
				['bug', 'Bug']
			]
		},
		{
			key: 'severity',
			label: t('filter.severity'),
			all: t('filter.allF'),
			value: view.severity ?? '',
			options: [
				['critical', 'Critical'],
				['high', 'High'],
				['medium', 'Medium'],
				['low', 'Low'],
				['info', 'Info']
			]
		},
		{
			key: 'status',
			label: t('filter.status'),
			all: t('filter.all'),
			value: view.status ?? '',
			options: (['new', 'mr_open', 'needs_human', 'ignored'] as const).map((s) => [
				s,
				t(`status.${s}`)
			])
		},
		{
			key: 'repo',
			label: t('filter.repo'),
			all: t('filter.all'),
			value: view.repo ?? '',
			options: (view.repo && !repos.includes(view.repo) ? [view.repo, ...repos] : repos).map(
				(r) => [r, r]
			)
		}
	] as const);
</script>

<PageHeader title={t('find.title')} subtitle={t('find.subtitle')} />

<form
	aria-label={t('filters')}
	class="card flex flex-wrap items-end gap-3 p-4"
	role="search"
	onsubmit={(e) => {
		e.preventDefault();
		search();
	}}
>
	<label class="text-muted flex flex-[2_1_260px] flex-col gap-1.5 text-[13px]">
		{t('find.search')}
		<span class="field search flex items-center gap-2 px-2.5">
			<Search size={16} strokeWidth={1.5} aria-hidden="true" />
			<input
				type="search"
				name="q"
				class="text-ink min-w-0 flex-1 bg-transparent text-sm outline-none"
				placeholder={t('find.searchHint')}
				maxlength={MAX_QUERY}
				bind:value={draft}
				onblur={search}
			/>
			{#if view.q}
				<button
					type="button"
					class="text-muted hover:text-ink flex size-8 items-center justify-center"
					aria-label={t('find.searchClear')}
					onclick={() => {
						draft = '';
						update({ q: undefined });
					}}><X size={16} strokeWidth={1.5} aria-hidden="true" /></button
				>
			{/if}
		</span>
	</label>
	{#each filters as f (f.key)}
		<label class="text-muted flex flex-[1_1_150px] flex-col gap-1.5 text-[13px]">
			{f.label}
			<select
				class="field px-2.5 text-sm"
				name={f.key}
				value={f.value}
				onchange={(e) => update({ [f.key]: e.currentTarget.value || undefined })}
			>
				<option value="">{f.all}</option>
				{#each f.options as [value, label] (value)}
					<option {value}>{label}</option>
				{/each}
			</select>
		</label>
	{/each}
</form>

<Async {promise} retry={() => nonce++}>
	{#snippet children(res: FindingPage)}
		<section class="card">
			<div class="border-line text-muted flex justify-between gap-2 border-b px-5 py-3 text-[13px]">
				<span>{t('find.count', { shown: res.items.length, total: res.total })}</span>
				<span class="mono">{t('find.sorted')}</span>
			</div>
			{#if res.items.length === 0}
				<p class="text-muted m-0 px-5 py-4">{t('empty.findings')}</p>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full min-w-[900px] border-collapse">
						<thead>
							<tr>
								<th class="th px-5 py-2.5">{t('col.sev')}</th>
								<th class="th px-3 py-2.5">{t('col.kind')}</th>
								<th class="th px-3 py-2.5">{t('col.rule')}</th>
								<th class="th px-3 py-2.5">{t('col.loc')}</th>
								<th class="th px-3 py-2.5">{t('col.repo')}</th>
								<th class="th px-5 py-2.5">{t('col.status')}</th>
							</tr>
						</thead>
						<tbody>
							{#each res.items as f (`${f.project}:${f.fingerprint}`)}
								{@const mr = safeHttps(f.mr_url)}
								<tr class="border-line border-t align-top">
									<td class="px-5 py-3">
										<Badge tone={severityTone(f.severity)} mono>
											<span class="inline-block min-w-12 text-center"
												>{f.severity.toUpperCase()}</span
											>
										</Badge>
									</td>
									<td class="mono text-muted px-3 py-3 text-xs uppercase">{f.kind}</td>
									<td class="px-3 py-3">
										<span class="mono text-[13px] break-all">{f.rule}</span>
										<div class="text-muted text-xs">{f.tool}</div>
									</td>
									<td class="mono px-3 py-3 text-[13px] break-all">{f.location}</td>
									<td class="mono px-3 py-3 text-[13px]">{f.project}</td>
									<td class="px-5 py-3">
										<span class="flex items-center gap-2">
											<Badge tone={statusTone(f.status)}>{t(`status.${f.status}`)}</Badge>
											{#if mr}
												<!-- link esterno a GitLab, non una rotta della SPA -->
												<!-- eslint-disable svelte/no-navigation-without-resolve -->
												<a
													href={mr}
													rel="noopener noreferrer"
													target="_blank"
													class="text-link"
													aria-label={t('task.openMr')}
													><ExternalLink size={16} strokeWidth={1.5} aria-hidden="true" /></a
												>
												<!-- eslint-enable svelte/no-navigation-without-resolve -->
											{/if}
										</span>
										{#if f.reason && f.status !== 'mr_open'}
											<div class="text-muted mt-1 line-clamp-2 max-w-64 text-xs">{f.reason}</div>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>
		{#if res.total > PAGE_SIZE}
			<nav class="flex items-center justify-between gap-3">
				<button
					type="button"
					class="field px-4 disabled:opacity-50"
					disabled={view.page <= 1}
					onclick={() => update({ page: view.page - 1 })}>{t('pager.prev')}</button
				>
				<span class="mono text-muted text-xs"
					>{view.page} / {Math.max(1, Math.ceil(res.total / PAGE_SIZE))}</span
				>
				<button
					type="button"
					class="field px-4 disabled:opacity-50"
					disabled={view.page * PAGE_SIZE >= res.total}
					onclick={() => update({ page: view.page + 1 })}>{t('pager.next')}</button
				>
			</nav>
		{/if}
	{/snippet}
</Async>

<style>
	.search:focus-within {
		outline: 2px solid var(--link);
		outline-offset: 2px;
	}
	.search input:focus-visible {
		outline: none;
	}
</style>
