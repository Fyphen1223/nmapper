import fs from 'fs';
import util from 'util';
import child_process from 'child_process';
import shodanPorts from './constants.js';
import { parseStringPromise } from 'xml2js';

const exec = util.promisify(child_process.exec);

async function scan(ip) {
	const res = await exec(
		`${process.platform == 'win32' ? 'nmap' : 'sudo nmap'} ${createArguments([
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

/*
function formatJSON(nmapOutput) {
	let r = nmapOutput.nmaprun;
	delete r['$'];
	delete r['hosthint'];
	delete r['scaninfo'];
	delete r['verbose'];
	delete r['debugging'];
	r['host']['time'] = r['host']['$'];
	delete r['host']['$'];
	r['host']['status'] = r['host']['status']['$'];
	delete r['host']['status']['$'];
	r['host']['address'] = r['host']['address']['$'];

	/*
	r['host']['hostnames'] = r['host']['hostnames']['hostname'];
	let hostnames = [];
	if (typeof r['host']?.['hostnames']?.['hostname']?.['$'] === 'object') {
		hostnames.push(r['host']['hostnames']['hostname']['$']);
	} else {
		r['host']['hostnames'].map((hostname) => {
			hostnames.push(hostname['$']);
			delete hostname['$'];
		});
	}

	r['host']['hostnames'] = hostnames;
	if (r['host']?.['uptime']) {
		r['host']['uptime'] = r['host']['uptime']['$'];
	}
	r['host']['distance'] = r['host']['distance']['$'];
	r['host']['tcpsequence'] = r['host']['tcpsequence']['$'];
	r['host']['ipidsequence'] = r['host']['ipidsequence']['$'];
	r['host']['tcptssequence'] = r['host']['tcptssequence']['$'];
	if (r['host']['trace']?.['$']) {
		r['host']['trace']['used'] = r['host']['trace']['$'];
		delete r['host']['trace']['$'];
	}
	if (r['host']['trace']?.['hop']?.['$']) {
		r['host']['trace']['hop'] = r['host']['trace']['hop']['$'];
		delete r['host']['trace']['$'];
	}

	r['host']['ports']['extraports']['state'] = r['host']['ports']['extraports']['$'];
	delete r['host']['ports']['extraports']['$'];
	r['host']['ports']['extraports']['extrareasons'] =
		r['host']['ports']['extraports']['extrareasons']['$'];
	r['host']['ports']['port'].forEach((port) => {
		r['host']['ports']['port'][r['host']['ports']['port'].indexOf(port)] =
			transformJSON(port);
	});
	r['host']['os'] = transformOSJSON(r['host']['os']);

	return r;
}
*/

function transformJSON(data) {
	let r = data.nmaprun;
	r = mergeDollarKeys(r);
	r = manipulateScript(r);
	r = manipulateElem(r);
	return r;
}

function mergeDollarKeys(data) {
	if (Array.isArray(data)) {
		return data.map(mergeDollarKeys);
	} else if (typeof data === 'object' && data !== null) {
		if ('$' in data) {
			const mergedData = { ...data, ...data['$'] };
			delete mergedData['$'];
			for (const key in mergedData) {
				mergedData[key] = mergeDollarKeys(mergedData[key]);
			}
			return mergedData;
		} else {
			for (const key in data) {
				data[key] = mergeDollarKeys(data[key]);
			}
			return data;
		}
	} else {
		return data;
	}
}

function manipulateScript(script) {
	if (Array.isArray(script)) {
		return script.map(manipulateScript);
	} else if (typeof script === 'object' && script !== null) {
		for (const key in script) {
			script[key] = manipulateScript(script[key]);
		}
		if ('script' in script) {
			if (!Array.isArray(script.script)) {
				script.script = [script.script];
			}
		}
		return script;
	} else {
		return script;
	}
}

function manipulateElem(script) {
	if (Array.isArray(script)) {
		return script.map(manipulateElem);
	} else if (typeof script === 'object' && script !== null) {
		for (const key in script) {
			script[key] = manipulateElem(script[key]);
		}
		if ('elem' in script) {
			console.log(script.elem);
			if (!Array.isArray(script.elem)) {
				script.elem = [script.elem];
			}
			script.elem.forEach((e) => {
				e[e.key] = e['_'];
				delete e['_'];
				delete e['key'];
			});
		}
		return script;
	} else {
		return script;
	}
}

function transformOSJSON(input) {
	console.log(input);
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
	return transformJSON(jsonResult);
}

export default { scan, parseNmapOutput, bringUp$ };
