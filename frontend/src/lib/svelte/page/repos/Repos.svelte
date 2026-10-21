<script lang="ts">
	import { resolve } from '$app/paths';
	import { api, type ReposPage } from '$lib/api';
	import { Async, Badge, PageHeader, SectionTitle } from '$lib/svelte/component';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import { ago, when } from '$lib/format';
	import { statusTone } from '$lib/tones';
	import ProposalCard from './components/ProposalCard.svelte';

	let nonce = $state(0);
	const promise = $derived.by<Promise<ReposPage>>(() => {
		void nonce;
		return api.repos();
	});
	const now = new Date();
	const STATUSES = ['new', 'mr_open', 'needs_human', 'ignored'] as const;
	const findingsHref = (project: string, status: string) =>
		resolve(
			`/findings?repo=${encodeURIComponent(project)}&status=${status}` as `/findings?${string}`
		);
</script>

<PageHeader title={t('repos.title')} subtitle={t('repos.subtitle')} />

<Async {promise} retry={() => nonce++}>
	{#snippet children(d: ReposPage)}
		<section class="card">
			<div class="border-line border-b px-5 py-4">
				<SectionTitle tag={tag('tag.repos')}>{t('repos.active')}</SectionTitle>
			</div>
			{#if d.repos.length === 0}
				<p class="text-muted m-0 px-5 py-4">{t('empty.repos')}</p>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full min-w-[960px] border-collapse" data-testid="repos">
						<thead>
							<tr>
								<th class="th px-5 py-2.5">{t('col.repo')}</th>
								<th class="th px-3 py-2.5">{t('col.origin')}</th>
								<th class="th px-3 py-2.5">{t('col.commands')}</th>
								<th class="th px-3 py-2.5">{t('col.hunt')}</th>
								<th class="th px-3 py-2.5">{t('col.findings')}</th>
								<th class="th px-5 py-2.5 text-right!">{t('col.openMrs')}</th>
							</tr>
						</thead>
						<tbody>
							{#each d.repos as r (r.project)}
								<tr class="border-line border-t align-top">
									<td class="px-5 py-3">
										<span class="mono text-[13px] font-semibold">{r.project}</span>
										<div class="text-muted text-xs">{r.languages.join(', ')}</div>
									</td>
									<td class="px-3 py-3 text-[13px]">
										<Badge tone={r.origin === 'config' ? 'idle' : 'info'}
											>{t(`origin.${r.origin}`)}</Badge
										>
										{#if r.approved_at}
											<div class="text-muted mt-1 text-xs">
												{t('repos.approvedAt', { date: when(r.approved_at) })}
											</div>
										{/if}
									</td>
									<td class="px-3 py-3">
										<dl
											class="m-0 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-xs"
										>
											<dt class="text-muted">{t('field.setup')}</dt>
											<dd class="mono m-0 break-all">{r.setup_command ?? '—'}</dd>
											<dt class="text-muted">{t('field.test')}</dt>
											<dd class="mono m-0 break-all">{r.test_command}</dd>
											<dt class="text-muted">{t('field.token')}</dt>
											<dd class="mono m-0 break-all">
												{#if r.token}{r.token}{:else}<Badge tone="bad">{t('token.none')}</Badge
													>{/if}
											</dd>
										</dl>
									</td>
									<td class="px-3 py-3 text-[13px]">
										<span class="flex items-center gap-2">
											{t('repos.rotation', { n: r.rotation })}
											{#if r.next_up}<Badge tone="info">{t('hunt.tonight')}</Badge>{/if}
										</span>
										<div class="text-muted text-xs">
											{ago(r.last_hunted, now, t('hunt.never'))}
										</div>
									</td>
									<td class="px-3 py-3">
										<ul class="m-0 flex list-none flex-wrap gap-1.5 p-0">
											{#each STATUSES as s (s)}
												{@const n = r.findings_by_status[s] ?? 0}
												{#if n > 0}
													<li>
														<a href={findingsHref(r.project, s)} class="no-underline">
															<Badge tone={statusTone(s)}>{t(`status.${s}`)} · {n}</Badge>
														</a>
													</li>
												{/if}
											{/each}
										</ul>
									</td>
									<td class="num px-5 py-3 text-right text-base">{r.open_mrs}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>

		<section class="flex flex-col gap-3">
			<div class="flex flex-col gap-1">
				<SectionTitle tag={tag('tag.proposals')}>{t('repos.proposals')}</SectionTitle>
				<span class="text-muted text-[13px]">{t('repos.proposalsSub')}</span>
				<span class="text-muted text-[13px]">{t('proposal.readonly')}</span>
			</div>
			{#if d.proposals.length === 0}
				<p class="card text-muted m-0 px-5 py-4">{t('empty.proposals')}</p>
			{:else}
				<div class="grid grid-cols-[repeat(auto-fill,minmax(min(420px,100%),1fr))] gap-4">
					{#each d.proposals as p (p.id ?? `${p.project}-${p.created_at}`)}
						<ProposalCard {p} />
					{/each}
				</div>
			{/if}
		</section>
	{/snippet}
</Async>
