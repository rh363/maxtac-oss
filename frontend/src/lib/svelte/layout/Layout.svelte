<script lang="ts">
	import { resolve } from '$app/paths';
	import type { Snippet } from 'svelte';
	import { page } from '$app/state';
	import {
		Clock,
		FolderGit2,
		LayoutDashboard,
		LogOut,
		Settings2,
		TriangleAlert
	} from '@lucide/svelte';
	import { api } from '$lib/api';
	import { time } from '$lib/format';
	import { t, tag } from '$lib/lexicon/index.svelte';
	import { session } from '$lib/session.svelte';

	let { children }: { children: Snippet } = $props();

	let nextRun = $state<string | null | undefined>(undefined);
	$effect(() => {
		api.dashboard().then(
			(d) => (nextRun = d.next_run_at),
			() => (nextRun = null)
		);
	});

	const nav = [
		{ href: resolve('/'), key: 'nav.dashboard', icon: LayoutDashboard },
		{ href: resolve('/findings'), key: 'nav.findings', icon: TriangleAlert },
		{ href: resolve('/runs'), key: 'nav.runs', icon: Clock },
		{ href: resolve('/repos'), key: 'nav.repos', icon: FolderGit2 },
		{ href: resolve('/settings'), key: 'nav.settings', icon: Settings2 }
	] as const;

	function active(href: string, path: string): boolean {
		return href === '/' ? path === '/' : path === href || path.startsWith(`${href}/`);
	}

	const crumbs = $derived.by(() => {
		const parts = page.url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
		const out = [tag('brand')];
		if (parts.length === 0) out.push(t('nav.dashboard'));
		else if (parts[0] === 'findings') out.push(t('nav.findings'));
		else if (parts[0] === 'repos') out.push(t('nav.repos'));
		else if (parts[0] === 'settings') out.push(t('nav.settings'));
		else if (parts[0] === 'runs') {
			out.push(t('nav.runs'));
			if (parts[1]) out.push(parts[1]);
			const repo = page.url.searchParams.get('repo');
			if (parts[2] === 'tasks' && parts[3]) {
				if (repo) out.push(repo);
				out.push(parts[3].slice(0, 8));
			}
		}
		return out.join(' / ');
	});

	const initials = $derived(session.username.slice(0, 2).toUpperCase());

	async function logout() {
		await api.logout();
		window.location.assign('/');
	}
</script>

<div class="bg-bg text-ink flex min-h-screen flex-wrap">
	<aside
		class="bg-side border-line box-border flex flex-[1_1_220px] flex-col gap-6 border-r px-4 py-5 lg:max-w-[260px]
		min-[800px]:sticky min-[800px]:top-0 min-[800px]:h-screen min-[800px]:self-start min-[800px]:overflow-y-auto"
	>
		<a href={resolve('/')} class="flex items-center gap-2.5 px-2 py-1 no-underline">
			<span aria-hidden="true" class="logo-mark size-7 shrink-0"></span>
			<span class="flex flex-col gap-0.5">
				<span class="logo">{t('brand')}</span>
				<span class="mono text-muted text-xs">{t('brandSub')}</span>
			</span>
		</a>
		<nav aria-label={t('nav.label')} class="flex flex-wrap gap-1">
			{#each nav as item (item.href)}
				<a
					href={item.href}
					class="nav-item flex min-h-11 flex-[1_1_180px] items-center gap-2.5 px-3 font-medium no-underline"
					aria-current={active(item.href, page.url.pathname) ? 'page' : undefined}
				>
					<item.icon size={20} strokeWidth={1.5} aria-hidden="true" />
					<span>{t(item.key)}</span>
				</a>
			{/each}
		</nav>
		<div class="card mono text-muted mt-auto flex flex-col gap-1.5 p-3 text-xs">
			{#if nextRun !== undefined}
				<span>{nextRun ? t('nextRun', { time: time(nextRun) }) : t('nextRunNone')}</span>
			{/if}
		</div>
	</aside>

	<div class="flex min-w-0 flex-[999_1_560px] flex-col">
		<header
			class="bg-surface border-line box-border flex min-h-14 flex-wrap items-center justify-between gap-3 border-b px-4 py-2 sm:px-10"
		>
			<span class="mono text-muted min-w-0 truncate text-xs">{crumbs}</span>
			<span class="flex items-center gap-2.5">
				<span class="text-muted">{t('greeting', { user: session.username })}</span>
				<span
					aria-hidden="true"
					class="avatar flex size-8 items-center justify-center text-[13px] font-semibold"
					>{initials}</span
				>
				<button
					type="button"
					class="text-muted hover:text-ink flex size-11 items-center justify-center"
					aria-label={t('signOut')}
					title={t('signOut')}
					onclick={logout}
				>
					<LogOut size={18} strokeWidth={1.5} aria-hidden="true" />
				</button>
			</span>
		</header>
		<main class="box-border flex w-full max-w-[1240px] flex-col gap-6 px-4 pt-8 pb-12 sm:px-10">
			{@render children()}
		</main>
	</div>
</div>
