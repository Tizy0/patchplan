// npm run build: copy the editor into the website folder and write version.json
// (open pages compare it with their own build number and offer the update).
import { readFileSync, writeFileSync, copyFileSync, mkdirSync } from 'node:fs';
const html = readFileSync('patchplan.html', 'utf8');
const m = html.match(/const BUILD = \{ n: (\d+), date: '([^']+)' \}/);
if (!m) throw new Error('const BUILD = { n, date } not found in patchplan.html');
mkdirSync('public', { recursive: true });
copyFileSync('patchplan.html', 'public/index.html');
writeFileSync('public/version.json', JSON.stringify({ build: +m[1], date: m[2] }));
console.log(`build ${m[1]} (${m[2]}) -> public/`);
