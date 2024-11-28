import fs from 'node:fs';
import nmap from './src/index.js';

async function main() {
	const res = await nmap.scan('kansai.soka.ed.jp');
	fs.writeFileSync('output.txt', res);
	console.log('Scan completed');
	const r = await nmap.parseNmapOutput(res);
	fs.writeFileSync('output.json', JSON.stringify(r, null, 4));
}

async function formatResult() {
	const output = fs.readFileSync('output.txt').toString();
	const res = await nmap.parseNmapOutput(output);
	fs.writeFileSync('output.json', JSON.stringify(res, null, 4));
}

main();
//formatResult();
export default { nmap };
