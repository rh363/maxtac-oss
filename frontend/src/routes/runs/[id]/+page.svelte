<script lang="ts">
	import { page } from '$app/state';
	import { Run } from '$lib/svelte/page/run';
</script>

{#key page.params.id}
	<Run runId={page.params.id ?? ''} />
{/key}
