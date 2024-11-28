import fs from 'fs';
import util from 'util';
import child_process from 'child_process';
import shodanPorts from './constants.js';
import { parseStringPromise } from 'xml2js';

const exec = util.promisify(child_process.exec);

async function scan(ip) {
	const res = await exec(
		`sudo nmap ${createArguments([
			ip,
			'-oX',
			'-',
			'-sS',
			'-A',
			'-p',
			shodanPorts.join(','),
		])}`
	);
	fs.writeFileSync('output.txt', res.stdout);
	return res.stdout;
}

function createArguments(list) {
	return list.join(' ');
}

function formatJSON(nmapOutput) {
	let temp = nmapOutput.nmaprun;
	delete temp['$'];
	delete temp['scaninfo'];
	delete temp['verbose'];
	delete temp['debugging'];
	temp['host']['time'] = temp['host']['$'];
	delete temp['host']['$'];
	temp['host']['status'] = temp['host']['status']['$'];
	delete temp['host']['status']['$'];
	temp['host']['address'] = temp['host']['address']['$'];

	temp['host']['hostnames'] = temp['host']['hostnames']['hostname'];
	let hostnames = [];
	temp['host']['hostnames'].map((hostname) => {
		hostnames.push(hostname['$']);
		delete hostname['$'];
	});
	temp['host']['hostnames'] = hostnames;
	temp['host']['uptime'] = temp['host']['uptime']['$'];
	temp['host']['distance'] = temp['host']['distance']['$'];
	temp['host']['tcpsequence'] = temp['host']['tcpsequence']['$'];
	temp['host']['ipidsequence'] = temp['host']['ipidsequence']['$'];
	temp['host']['tcptssequence'] = temp['host']['tcptssequence']['$'];
	temp['host']['trace']['used'] = temp['host']['trace']['$'];
	temp['host']['trace']['hop'] = temp['host']['trace']['hop']['$'];
	delete temp['host']['trace']['$'];
	return temp;
}
async function parseNmapOutput(nmapOutput) {
	const jsonResult = await parseStringPromise(nmapOutput, { explicitArray: false });
	return formatJSON(jsonResult);
}

export default { scan, parseNmapOutput };
