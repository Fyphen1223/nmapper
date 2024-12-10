//import fs from 'node:fs';
import nmap from './src/index.js';
//import shodanPorts from './src/constants.js';

/*
async function main() {
	const res = await nmap.scan('google.com', [
		'-sS',
		'-A',
		'-p',
		shodanPorts.join(','),
		'-T4',
		'--script=http-title',
		'--script=whois-ip',
		'--script=whois-domain',
		'--script=ssl-cert',
		'--script=ip-geolocation-map-google',
		'--script=asn-query',
		'--script=ip-geolocation-maxmind',
	]);
	formatResult();
}

async function formatResult() {
	const output = fs.readFileSync('output.txt').toString();
	const res = await nmap.parseNmapOutput(output);
	
}
*/



if (typeof module !== 'undefined' && module.exports) {
    module.exports = { nmap };
}
export { nmap };
