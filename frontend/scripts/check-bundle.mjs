// Il bundle base deve contenere solo il tema di default: nessun termine, font, colore o nome
// del tema alternativo (che arriva a runtime dall'API, solo a chi lo ha assegnato).
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const terms = JSON.parse(readFileSync(join(root, '..', 'web', 'theme-terms.json'), 'utf8'));
const pattern = new RegExp([...terms.themed, ...terms.bundle_extra].join('|'), 'i');
const build = join(root, 'build');

const TEXT = /\.(html|js|mjs|css|json|svg|txt|map)$/;
const hits = [];
function walk(dir) {
	for (const name of readdirSync(dir)) {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) walk(path);
		else {
			if (pattern.test(name)) hits.push(`${path}: nome del file`);
			if (TEXT.test(name)) {
				const m = pattern.exec(readFileSync(path, 'utf8'));
				if (m) hits.push(`${path}: "${m[0]}"`);
			}
		}
	}
}
walk(build);
if (hits.length) {
	console.error('Termini del tema alternativo nel bundle base:\n' + hits.join('\n'));
	process.exit(1);
}
console.log('check-bundle: nessun termine del tema alternativo nel bundle');
