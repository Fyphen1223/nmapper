import fs from 'node:fs';
import nmap from './src/index.js';
import shodanPorts from './src/constants.js';

async function main() {
	const res = await nmap.scan('google.com', [
		'-sS',
		'-A',
		'-p',
		shodanPorts.join(','),
		'-T4',
		'--script=http-headers',
		'--script=http-title',
		'--script=whois-ip',
		'--script=whois-domain',
		'--script=ssl-cert',
		'--script=ip-geolocation-map-google',
		'--script=asn-query',
		'--script=ip-geolocation-maxmind',
	]);
	await fs.writeFileSync('output.json', JSON.stringify(res, null, 4));
	formatResult();
}

async function formatResult() {
	const output = fs.readFileSync('output.txt').toString();
	const res = await nmap.parseNmapOutput(output);
	fs.writeFileSync('./res.json', JSON.stringify(res, null, 4));
}

//main();
formatResult();
export default { nmap };
