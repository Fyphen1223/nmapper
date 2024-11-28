function transformJSON(data) {
	// Helper function to recursively clean and transform data
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

// Example usage
const input = {
	$: {
		protocol: 'tcp',
		portid: '22',
	},
	state: {
		$: {
			state: 'open',
			reason: 'syn-ack',
			reason_ttl: '47',
		},
	},
	service: {
		$: {
			name: 'ssh',
			product: 'OpenSSH',
			version: '6.6.1p1 Ubuntu 2ubuntu2.13',
			extrainfo: 'Ubuntu Linux; protocol 2.0',
			ostype: 'Linux',
			method: 'probed',
			conf: '10',
		},
		cpe: ['cpe:/a:openbsd:openssh:6.6.1p1', 'cpe:/o:linux:linux_kernel'],
	},
	script: {
		$: {
			id: 'ssh-hostkey',
			output: '\n  1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)\n  2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)\n  256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)\n  256 33:fa:91:0f:e0:e1:7b:1f:6d:05:a2:b0:f1:54:41:56 (ED25519)',
		},
		table: [
			{
				elem: [
					{
						_: 'ssh-dss',
						$: {
							key: 'type',
						},
					},
					{
						_: '1024',
						$: {
							key: 'bits',
						},
					},
					{
						_: 'AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL',
						$: {
							key: 'key',
						},
					},
					{
						_: 'ac00a01a82ffcc5599dc672b34976b75',
						$: {
							key: 'fingerprint',
						},
					},
				],
			},
		],
	},
};

console.log(transformJSON(input));
