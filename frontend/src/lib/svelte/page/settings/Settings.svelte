<script lang="ts">
	import { api, type Settings } from '$lib/api';
	import { Async, Badge, PageHeader, SectionTitle } from '$lib/svelte/component';
	import { t } from '$lib/lexicon/index.svelte';
	import { money, when } from '$lib/format';

	let nonce = $state(0);
	const promise = $derived.by<Promise<Settings>>(() => {
		void nonce;
		return api.settings();
	});

	type Row = [label: string, value: string, mono?: boolean];
	const price = (v: number) => `$${v.toFixed(v < 1 ? 3 : 2).replace('.', ',')}`;

	function sections(s: Settings): { title: string; rows: Row[] }[] {
		return [
			{
				title: t('settings.schedule'),
				rows: [
					[t('set.at'), s.schedule.at, true],
					[t('set.timezone'), s.schedule.timezone, true],
					[t('set.next'), when(s.schedule.next_run_at)]
				]
			},
			{
				title: t('settings.models'),
				rows: [
					[t('model.triage'), s.models.triage, true],
					[t('model.fix'), s.models.fix, true],
					[t('model.hunt'), s.models.hunt, true],
					[t('model.discovery'), s.models.discovery, true]
				]
			},
			{
				title: t('settings.budget'),
				rows: [
					[t('budget.monthly'), money(s.budget.monthly_credits_usd)],
					[t('budget.perNight'), money(s.budget.per_night_usd)],
					[t('budget.perTask'), money(s.budget.per_task_usd)],
					[t('budget.triage'), money(s.budget.triage_per_repo_usd)],
					[t('budget.hunting'), money(s.budget.hunting_per_night_usd)],
					[t('budget.discovery'), money(s.budget.discovery_per_repo_usd)]
				]
			},
			{
				title: t('settings.limits'),
				rows: [
					[t('limit.mrs'), String(s.limits.max_mrs_per_night)],
					[t('limit.attempts'), String(s.limits.max_attempts)],
					[t('limit.iterations'), String(s.limits.max_iterations)]
				]
			},
			{
				title: t('settings.hunting'),
				rows: [
					[t('hunting.perNight'), String(s.hunting.repos_per_night)],
					[t('hunting.lookback'), t('days', { n: s.hunting.lookback_days })]
				]
			},
			{
				title: t('settings.vcs'),
				rows: [
					[t('vcs.prefix'), `${s.vcs.branch_prefix}/…`, true],
					[t('vcs.labels'), s.vcs.mr_labels.join(', '), true]
				]
			}
		];
	}
</script>

<PageHeader title={t('settings.title')} subtitle={t('settings.subtitle')} />
<p class="text-muted m-0 text-[13px]">{t('settings.readonly')}</p>

<Async {promise} retry={() => nonce++}>
	{#snippet children(s: Settings)}
		<section class="card flex flex-col gap-3 p-5">
			<SectionTitle>{t('settings.features')}</SectionTitle>
			<ul class="m-0 flex list-none flex-wrap gap-3 p-0" data-testid="features">
				{#each [['feat.cve', s.features.cve], ['feat.sast', s.features.sast], ['feat.hunting', s.features.hunting]] as const as [key, on] (key)}
					<li class="flex items-center gap-2 text-[13px]">
						{t(key)}<Badge tone={on ? 'good' : 'idle'}>{on ? t('on') : t('off')}</Badge>
					</li>
				{/each}
			</ul>
		</section>

		<div class="grid grid-cols-[repeat(auto-fit,minmax(min(320px,100%),1fr))] gap-4">
			{#each sections(s) as sec (sec.title)}
				<section class="card flex flex-col gap-2 p-5">
					<SectionTitle>{sec.title}</SectionTitle>
					<dl class="m-0 flex flex-col">
						{#each sec.rows as [label, value, mono] (label)}
							<div class="border-line flex justify-between gap-4 border-t py-2 text-[13px]">
								<dt class="text-muted">{label}</dt>
								<dd class="m-0 text-right break-all" class:mono>{value}</dd>
							</div>
						{/each}
					</dl>
				</section>
			{/each}
		</div>

		<section class="card">
			<div class="border-line border-b px-5 py-4">
				<SectionTitle>{t('settings.prices')}</SectionTitle>
			</div>
			<div class="overflow-x-auto">
				<table class="w-full min-w-[560px] border-collapse text-[13px]" data-testid="prices">
					<thead>
						<tr>
							<th class="th px-5 py-2.5">{t('price.model')}</th>
							<th class="th px-3 py-2.5 text-right!">{t('price.input')}</th>
							<th class="th px-3 py-2.5 text-right!">{t('price.output')}</th>
							<th class="th px-3 py-2.5 text-right!">{t('price.cacheRead')}</th>
							<th class="th px-5 py-2.5 text-right!">{t('price.cacheWrite')}</th>
						</tr>
					</thead>
					<tbody>
						{#each s.prices as p (p.model)}
							<tr class="border-line mono border-t">
								<td class="px-5 py-2.5">{p.model}</td>
								<td class="px-3 py-2.5 text-right">{price(p.input)}</td>
								<td class="px-3 py-2.5 text-right">{price(p.output)}</td>
								<td class="px-3 py-2.5 text-right">{price(p.cache_read)}</td>
								<td class="px-5 py-2.5 text-right">{price(p.cache_write)}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
	{/snippet}
</Async>
