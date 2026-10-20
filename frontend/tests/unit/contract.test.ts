import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { CONTRACT } from '$lib/api/schemas';

// Il contratto è web/openapi.json (esportato dal backend): gli schemi Zod devono avere
// esattamente gli stessi campi, così un cambio dell'API rompe questo test e non la UI.
const spec = JSON.parse(
	readFileSync(new URL('../../../web/openapi.json', import.meta.url), 'utf8')
) as {
	components: {
		schemas: Record<string, { properties: Record<string, unknown>; required?: string[] }>;
	};
};

describe('contratto con web/openapi.json', () => {
	for (const [name, schema] of Object.entries(CONTRACT)) {
		it(name, () => {
			const remote = spec.components.schemas[name];
			expect(remote, `schema ${name} assente da openapi.json`).toBeDefined();
			expect(Object.keys(schema.shape).sort()).toEqual(Object.keys(remote!.properties).sort());
		});
	}
});
