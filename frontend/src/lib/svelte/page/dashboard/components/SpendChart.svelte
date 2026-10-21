<script lang="ts">
	import type { SpendSeries } from '$lib/api';
	import { SectionTitle } from '$lib/svelte/component';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import { money } from '$lib/format';
	import {
		SPEND_SERIES,
		dayLabel,
		labelIndexes,
		niceAxis,
		spendParts,
		stack,
		topRounded,
		type SpendSeriesKey
	} from '$lib/chart';

	let { data }: { data: SpendSeries } = $props();

	const H = 220;
	const PAD = { top: 12, right: 64, bottom: 28, left: 44 };
	const MH = 160;

	let width = $state(640);
	let monthWidth = $state(300);
	let active = $state<number | null>(null);

	const label: Record<SpendSeriesKey, string> = $derived({
		fix: t('spend.fix'),
		hunt: t('spend.hunt'),
		rest: t('spend.rest')
	});

	// --- spesa giornaliera, colonne impilate ---
	const peak = $derived(Math.max(data.cap_usd, ...data.days.map((d) => d.total)));
	const axis = $derived(niceAxis(peak));
	const plotW = $derived(Math.max(120, width - PAD.left - PAD.right));
	const plotH = H - PAD.top - PAD.bottom;
	const base = PAD.top + plotH;
	const band = $derived(plotW / Math.max(1, data.days.length));
	const barW = $derived(Math.max(2, Math.min(24, band - 2)));
	const y = (v: number) => base - (v / axis.max) * plotH;
	const xMid = (i: number) => PAD.left + band * i + band / 2;
	const columns = $derived(
		data.days.map((d, i) => ({
			day: d,
			x: xMid(i) - barW / 2,
			segments: stack(spendParts(d), y, base)
		}))
	);
	const xLabels = $derived(labelIndexes(data.days.length));
	const empty = $derived(data.days.every((d) => d.total === 0));
	const current = $derived(active === null ? null : data.days[active]);

	function onKey(e: KeyboardEvent) {
		const n = data.days.length;
		if (!n) return;
		if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
			e.preventDefault();
			const step = e.key === 'ArrowRight' ? 1 : -1;
			active = active === null ? n - 1 : Math.min(n - 1, Math.max(0, active + step));
		} else if (e.key === 'Escape') {
			active = null;
		}
	}

	// --- cumulato del mese contro i crediti ---
	const monthAxis = $derived(niceAxis(data.credits_usd));
	const mPlotW = $derived(Math.max(100, monthWidth - PAD.left - 16));
	const mPlotH = MH - PAD.top - PAD.bottom;
	const mBase = PAD.top + mPlotH;
	// asse x sul mese intero, così la linea mostra anche quanto manca alla fine
	const monthDays = $derived.by(() => {
		const first = data.month[0]?.date;
		if (!first) return 30;
		const [yy, mm] = first.split('-').map(Number) as [number, number];
		return new Date(Date.UTC(yy, mm, 0)).getUTCDate();
	});
	const mx = (i: number) => PAD.left + (mPlotW * i) / Math.max(1, monthDays - 1);
	const my = (v: number) => mBase - (Math.min(v, monthAxis.max) / monthAxis.max) * mPlotH;
	const line = $derived(
		data.month.map((p, i) => `${i ? 'L' : 'M'}${mx(i)},${my(p.cumulative_usd)}`).join('')
	);
	const area = $derived(
		data.month.length ? `${line}L${mx(data.month.length - 1)},${mBase}L${mx(0)},${mBase}Z` : ''
	);
	const last = $derived(data.month.at(-1));
</script>

<section class="card box-border flex flex-col gap-4 p-5">
	<div class="flex flex-wrap items-baseline justify-between gap-2">
		<SectionTitle tag={tag('tag.spend')}>{t('spend.title')}</SectionTitle>
		<span class="text-muted text-[13px]">
			{t('spend.sub', { days: data.days.length, cap: money(data.cap_usd) })}
		</span>
	</div>

	<ul class="text-muted m-0 flex list-none flex-wrap gap-x-5 gap-y-1 p-0 text-[13px]">
		{#each SPEND_SERIES as key (key)}
			<li class="flex items-center gap-2">
				<span aria-hidden="true" class="swatch viz-{key}"></span>{label[key]}
			</li>
		{/each}
	</ul>

	<div class="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
		<!-- spesa per giorno -->
		<div class="relative min-w-0" bind:clientWidth={width}>
			<!-- Il grafico è un'immagine con un livello di esplorazione: frecce e mouse mostrano il
			     dettaglio di un giorno; gli stessi dati sono nella tabella qui sotto. -->
			<!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
			<svg
				role="img"
				aria-label={t('spend.chart')}
				tabindex="0"
				width="100%"
				height={H}
				class="chart block"
				onkeydown={onKey}
				onblur={() => (active = null)}
				onmouseleave={() => (active = null)}
				data-testid="spend-chart"
			>
				{#each axis.ticks as v (v)}
					<line class="grid-line" x1={PAD.left} x2={PAD.left + plotW} y1={y(v)} y2={y(v)} />
					<text class="axis" x={PAD.left - 8} y={y(v)} dy="0.32em" text-anchor="end"
						>{money(v).replace(/,00$/, '')}</text
					>
				{/each}
				{#each columns as col, i (col.day.date)}
					<g class:dim={active !== null && active !== i}>
						{#each col.segments as s, j (s.key)}
							{#if j === col.segments.length - 1}
								<path class="viz-{s.key}" d={topRounded(col.x, s.y, barW, s.h)} />
							{:else}
								<rect class="viz-{s.key}" x={col.x} y={s.y} width={barW} height={s.h} />
							{/if}
						{/each}
					</g>
				{/each}
				<line
					class="ref-line"
					x1={PAD.left}
					x2={PAD.left + plotW}
					y1={y(data.cap_usd)}
					y2={y(data.cap_usd)}
				/>
				<text class="axis ref" x={PAD.left + plotW + 6} y={y(data.cap_usd)} dy="0.32em"
					>{t('spend.cap', { cap: money(data.cap_usd).replace(/,00$/, '') })}</text
				>
				{#each xLabels as i (i)}
					<text class="axis" x={xMid(i)} y={H - 8} text-anchor="middle"
						>{dayLabel(data.days[i]!.date)}</text
					>
				{/each}
				<!-- bersagli del passaggio del mouse: l'intera fascia del giorno -->
				{#each data.days as d, i (d.date)}
					<rect
						role="presentation"
						class="hit"
						x={PAD.left + band * i}
						y={PAD.top}
						width={band}
						height={plotH}
						onmouseenter={() => (active = i)}
					/>
				{/each}
			</svg>
			{#if current && active !== null}
				<div
					class="tip card mono pointer-events-none absolute flex flex-col gap-1 p-2.5 text-xs"
					class:tip-left={active > data.days.length / 2}
					style:left={`${xMid(active)}px`}
					role="status"
				>
					<strong class="text-ink">{dayLabel(current.date)}</strong>
					{#each SPEND_SERIES as key (key)}
						<span class="flex items-center justify-between gap-4">
							<span class="flex items-center gap-1.5">
								<span aria-hidden="true" class="swatch viz-{key}"></span>{label[key]}
							</span>
							<span>{money(spendParts(current)[key])}</span>
						</span>
					{/each}
					<span class="border-line flex justify-between gap-4 border-t pt-1">
						<span>{t('total')}</span><strong class="text-ink">{money(current.total)}</strong>
					</span>
				</div>
			{/if}
			{#if empty}
				<p class="text-muted m-0 text-[13px]">{t('spend.empty')}</p>
			{/if}
		</div>

		<!-- cumulato del mese -->
		<div class="flex min-w-0 flex-col gap-2" bind:clientWidth={monthWidth}>
			<div class="flex flex-wrap items-baseline justify-between gap-2">
				<h3 class="m-0 text-sm font-semibold">{t('spend.month')}</h3>
				{#if last}
					<span class="text-muted text-[13px]"
						>{t('spend.monthSub', {
							spent: money(last.cumulative_usd),
							credits: money(data.credits_usd).replace(/,00$/, '')
						})}</span
					>
				{/if}
			</div>
			<svg role="img" aria-label={t('spend.monthChart')} width="100%" height={MH} class="block">
				{#each monthAxis.ticks as v (v)}
					<line class="grid-line" x1={PAD.left} x2={PAD.left + mPlotW} y1={my(v)} y2={my(v)} />
					<text class="axis" x={PAD.left - 8} y={my(v)} dy="0.32em" text-anchor="end"
						>{money(v).replace(/,00$/, '')}</text
					>
				{/each}
				<line
					class="ref-line"
					x1={PAD.left}
					x2={PAD.left + mPlotW}
					y1={my(data.credits_usd)}
					y2={my(data.credits_usd)}
				/>
				{#if data.month.length}
					<path class="wash" d={area} />
					<path class="month-line" d={line} />
					<circle
						class="end-dot"
						cx={mx(data.month.length - 1)}
						cy={my(last?.cumulative_usd ?? 0)}
						r="4"
					/>
				{/if}
				<text class="axis" x={PAD.left} y={MH - 8}>1</text>
				<text class="axis" x={PAD.left + mPlotW} y={MH - 8} text-anchor="end">{monthDays}</text>
			</svg>
		</div>
	</div>

	<details class="text-[13px]">
		<summary class="text-link cursor-pointer">{t('spend.table')}</summary>
		<div class="mt-2 max-h-72 overflow-auto">
			<table class="mono w-full border-collapse text-xs">
				<thead>
					<tr>
						<th class="th px-2 py-1.5">{t('spend.day')}</th>
						{#each SPEND_SERIES as key (key)}<th class="th px-2 py-1.5 text-right!">{label[key]}</th
							>{/each}
						<th class="th px-2 py-1.5 text-right!">{t('total')}</th>
					</tr>
				</thead>
				<tbody>
					{#each data.days as d (d.date)}
						{@const p = spendParts(d)}
						<tr class="border-line border-t">
							<td class="px-2 py-1">{dayLabel(d.date)}</td>
							{#each SPEND_SERIES as key (key)}<td class="px-2 py-1 text-right">{money(p[key])}</td
								>{/each}
							<td class="px-2 py-1 text-right">{money(d.total)}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	</details>
</section>

<style>
	.chart:focus-visible {
		outline: 2px solid var(--link);
		outline-offset: 2px;
	}
	.swatch {
		display: inline-block;
		width: 10px;
		height: 10px;
		border-radius: 2px;
	}
	.viz-fix {
		fill: var(--viz-fix);
		background: var(--viz-fix);
	}
	.viz-hunt {
		fill: var(--viz-hunt);
		background: var(--viz-hunt);
	}
	.viz-rest {
		fill: var(--viz-rest);
		background: var(--viz-rest);
	}
	.dim {
		opacity: 0.35;
	}
	.grid-line {
		stroke: var(--viz-grid);
		stroke-width: 1;
		shape-rendering: crispEdges;
	}
	.ref-line {
		stroke: var(--viz-ref);
		stroke-width: 1;
		shape-rendering: crispEdges;
	}
	.axis {
		fill: var(--muted);
		font-size: 11px;
		font-family: var(--font);
		font-variant-numeric: tabular-nums;
	}
	.ref {
		fill: var(--text);
	}
	.hit {
		fill: transparent;
	}
	.month-line {
		fill: none;
		stroke: var(--viz-fix);
		stroke-width: 2;
		stroke-linejoin: round;
		stroke-linecap: round;
	}
	.wash {
		fill: var(--viz-fix);
		opacity: 0.1;
	}
	.end-dot {
		fill: var(--viz-fix);
		stroke: var(--surface);
		stroke-width: 2;
	}
	.tip {
		top: 4px;
		min-width: 170px;
		transform: translateX(12px);
		z-index: 1;
	}
	.tip-left {
		transform: translateX(calc(-100% - 12px));
	}
	@media (prefers-reduced-motion: no-preference) {
		.dim {
			transition: opacity 120ms ease-out;
		}
	}
</style>
