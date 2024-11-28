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

	/*
	temp['host']['hostnames'] = temp['host']['hostnames']['hostname'];
	let hostnames = [];
	if (typeof temp['host']?.['hostnames']?.['hostname']?.['$'] === 'object') {
		hostnames.push(temp['host']['hostnames']['hostname']['$']);
	} else {
		temp['host']['hostnames'].map((hostname) => {
			hostnames.push(hostname['$']);
			delete hostname['$'];
		});
	}

	temp['host']['hostnames'] = hostnames;
	*/
	temp['host']['uptime'] = temp['host']['uptime']['$'];
	temp['host']['distance'] = temp['host']['distance']['$'];
	temp['host']['tcpsequence'] = temp['host']['tcpsequence']['$'];
	temp['host']['ipidsequence'] = temp['host']['ipidsequence']['$'];
	temp['host']['tcptssequence'] = temp['host']['tcptssequence']['$'];
	if (temp['host']['trace']?.['$']) {
		temp['host']['trace']['used'] = temp['host']['trace']['$'];
		delete temp['host']['trace']['$'];
	}
	if (temp['host']['trace']?.['hop']?.['$']) {
		temp['host']['trace']['hop'] = temp['host']['trace']['hop']['$'];
		delete temp['host']['trace']['$'];
	}

	temp['host']['ports']['extraports']['state'] =
		temp['host']['ports']['extraports']['$'];
	delete temp['host']['ports']['extraports']['$'];
	temp['host']['ports']['extraports']['extrareasons'] =
		temp['host']['ports']['extraports']['extrareasons']['$'];
	temp['host']['ports']['port'].forEach((port) => {
		temp['host']['ports']['port'][temp['host']['ports']['port'].indexOf(port)] =
			transformJSON(port);
	});
	temp['host']['os'] = transformOSJSON(temp['host']['os']);

	return temp;
}

function transformJSON(data) {
	function clean(obj) {
		if (Array.isArray(obj)) {
			return obj.map(clean);
		} else if (typeof obj === 'object' && obj !== null) {
			let result = {};
			for (let key in obj) {
				if (key === '$') {
					Object.assign(result, obj[key]); // Expand `$` into parent
				} else if (key === 'elem') {
					if (Array.isArray(obj[key])) {
						obj[key].forEach((subElem) => {
							if (subElem._ && subElem.$ && subElem.$.key) {
								result[subElem.$.key] = subElem._;
							}
						});
					}
				} else if (key === 'table') {
					// Transform `table` to an array of simplified objects
					result[key] = obj[key].map(clean);
				} else {
					result[key] = clean(obj[key]);
				}
			}
			return result;
		}
		return obj; // Return primitive types as-is
	}

	return clean(data);
}

function transformOSJSON(input) {
	function transform(obj) {
		if (Array.isArray(obj)) {
			// Handle array elements recursively
			return obj.map(transform);
		} else if (typeof obj === 'object' && obj !== null) {
			const newObj = {};
			for (const key in obj) {
				if (key === '$') {
					// Merge `$` key's value into the parent object
					Object.assign(newObj, transform(obj[key]));
				} else {
					// Process nested objects
					newObj[key] = transform(obj[key]);
				}
			}
			return newObj;
		}
		return obj; // Return non-object types as-is
	}

	return transform(input);
}
function bringUp$(d) {
	if (d['$']) {
		Object.assign(d, d['$']);
		delete d['$'];
	}
	return d;
}

async function parseNmapOutput(nmapOutput) {
	const jsonResult = await parseStringPromise(nmapOutput, { explicitArray: false });
	return formatJSON(jsonResult);
}

export default { scan, parseNmapOutput, bringUp$ };
