<script lang="ts">
	import { page } from '$app/state';
	import { Task } from '$lib/svelte/page/task';
</script>

<Task
	runId={page.params.id ?? ''}
	fingerprint={page.params.fp ?? ''}
	repo={page.url.searchParams.get('repo') ?? undefined}
/>
