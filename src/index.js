import util from 'util';
import child_process from 'child_process';
import { parseStringPromise } from 'xml2js';

const exec = util.promisify(child_process.exec);

async function scan(ip, args) {
	const res = await exec(
		`${process.platform == 'win32' ? 'nmap' : 'sudo nmap'} ${createArguments([
			ip,
			'-oX -',
			args,
		])}`
	);
	return await parseNmapOutput(res.stdout);
}

function createArguments(list) {
	const args = list[3].join(' ');
	return `${list[0]} ${list[1]} ${list[2]} ${args}`;
}

function transformJSON(data) {
	let r = data.nmaprun;
	r = mergeDollarKeys(r);
	r = manipulateScript(r);
	r = manipulateElem(r);
	if (r.host.hostnames.hostname && !Array.isArray(r.host.hostnames.hostname)) {
		r.host.hostnames.hostname = [r.host.hostnames.hostname];
	}
	if (r.host.ports.port && !Array.isArray(r.host.ports.port)) {
		r.host.ports.port = [r.host.ports.port];
	}
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
			if (!Array.isArray(script.elem)) {
				script.elem = [script.elem];
			}
			script.elem.forEach((e) => {
				if (typeof e === 'string') {
					return;
				}
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

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { scan, parseNmapOutput, bringUp$ };
} else {
    export default { scan, parseNmapOutput, bringUp$ };
}
