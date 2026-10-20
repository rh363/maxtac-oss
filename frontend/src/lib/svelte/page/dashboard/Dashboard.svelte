<script lang="ts">
	import { api, type Dashboard } from '$lib/api';
	import { Async, PageHeader } from '$lib/svelte/component';
	import { t } from '$lib/lexicon/index.svelte';
	import { money, percent } from '$lib/format';
	import Kpi from './components/Kpi.svelte';
	import StatusBars from './components/StatusBars.svelte';
	import HuntingRotation from './components/HuntingRotation.svelte';
	import RecentRuns from './components/RecentRuns.svelte';

	let nonce = $state(0);
	const promise = $derived.by<Promise<Dashboard>>(() => {
		void nonce;
		return api.dashboard();
	});
	const reload = () => nonce++;
</script>

<PageHeader title={t('dash.title')} subtitle={t('dash.subtitle')} />

<Async {promise} retry={reload}>
	{#snippet children(d: Dashboard)}
		{@const lastMrs = d.recent_runs[0]?.mrs_opened ?? 0}
		<div class="grid grid-cols-[repeat(auto-fit,minmax(220px,1fr))] gap-4">
			<Kpi
				n={1}
				label={t('kpi.month')}
				value={money(d.month.spent_usd)}
				of={`/ ${money(d.month.credits_usd).replace(/,00$/, '')}`}
				sub={t('kpi.monthSub', { projected: money(d.month.projected_usd) })}
				pct={percent(d.month.spent_usd, d.month.credits_usd)}
				money
			/>
			<Kpi
				n={2}
				label={t('kpi.night')}
				value={money(d.night.spent_usd)}
				of={`/ ${money(d.night.cap_usd)}`}
				sub={t('kpi.nightSub')}
				pct={percent(d.night.spent_usd, d.night.cap_usd)}
				money
			/>
			<Kpi
				n={3}
				label={t('kpi.mrs')}
				value={String(lastMrs)}
				of={`/ ${d.max_mrs_per_night}`}
				sub={t('kpi.mrsSub')}
				pct={percent(lastMrs, d.max_mrs_per_night)}
			/>
			<Kpi
				n={4}
				label={t('kpi.human')}
				value={String(d.findings_by_status['needs_human'] ?? 0)}
				of={t('kpi.humanOf')}
				sub={t('kpi.humanSub')}
			/>
		</div>

		<div class="grid grid-cols-[repeat(auto-fit,minmax(min(320px,100%),1fr))] gap-4">
			<StatusBars counts={d.findings_by_status} />
			<HuntingRotation
				enabled={d.hunting_enabled}
				perNight={d.hunting_per_night}
				slots={d.hunting}
			/>
		</div>

		<RecentRuns runs={d.recent_runs} />
	{/snippet}
</Async>
