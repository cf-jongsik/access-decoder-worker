var extractJWTFromRequest = (request) => request.headers.get('Cf-Access-Jwt-Assertion');
var base64URLDecode = (s) => {
	s = s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
	return new Uint8Array(Array.prototype.map.call(atob(s), (c) => c.charCodeAt(0)));
};
var asciiToUint8Array = (s) => {
	let chars = [];
	for (let i = 0; i < s.length; ++i) {
		chars.push(s.charCodeAt(i));
	}
	return new Uint8Array(chars);
};
var generateValidator =
	({ domain, aud }) =>
	async (request) => {
		const jwt = extractJWTFromRequest(request);
		const parts = jwt.split('.');
		if (parts.length !== 3) {
			throw new Error('JWT does not have three parts.');
		}
		const [header, payload, signature] = parts;
		const textDecoder = new TextDecoder('utf-8');
		const { kid, alg } = JSON.parse(textDecoder.decode(base64URLDecode(header)));
		if (alg !== 'RS256') {
			throw new Error('Unknown JWT type or algorithm.');
		}
		const certsURL = new URL('/cdn-cgi/access/certs', domain);
		const certsResponse = await fetch(certsURL.toString());
		const { keys } = await certsResponse.json();
		if (!keys) {
			throw new Error('Could not fetch signing keys.');
		}
		const jwk = keys.find((key2) => key2.kid === kid);
		if (!jwk) {
			throw new Error('Could not find matching signing key.');
		}
		if (jwk.kty !== 'RSA' || jwk.alg !== 'RS256') {
			throw new Error('Unknown key type of algorithm.');
		}
		const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
		const unroundedSecondsSinceEpoch = Date.now() / 1e3;
		const payloadObj = JSON.parse(textDecoder.decode(base64URLDecode(payload)));
		if (payloadObj.iss && payloadObj.iss !== certsURL.origin) {
			throw new Error('JWT issuer is incorrect.');
		}
		if (payloadObj.aud && !payloadObj.aud.includes(aud)) {
			throw new Error('JWT audience is incorrect.');
		}
		if (payloadObj.exp && Math.floor(unroundedSecondsSinceEpoch) >= payloadObj.exp) {
			throw new Error('JWT has expired.');
		}
		if (payloadObj.nbf && Math.ceil(unroundedSecondsSinceEpoch) < payloadObj.nbf) {
			throw new Error('JWT is not yet valid.');
		}
		const verified = await crypto.subtle.verify(
			'RSASSA-PKCS1-v1_5',
			key,
			base64URLDecode(signature),
			asciiToUint8Array(`${header}.${payload}`)
		);
		if (!verified) {
			throw new Error('Could not verify JWT.');
		}
		return { jwt, payload: payloadObj };
	};

const getIdentity = async ({ jwt, domain }) => {
	const identityURL = new URL('/cdn-cgi/access/get-identity', domain);
	const response = await fetch(identityURL.toString(), {
		headers: { Cookie: `CF_Authorization=${jwt}` },
	});
	if (response.ok) return await response.json();
};

export default {
	async fetch(request, env, ctx) {
		const domain = env.DOMAIN;
		const aud = env.AUD;

		console.log(domain);
		console.log(aud);
		try {
			const validator = generateValidator({ domain, aud });
			const { jwt, payload } = await validator(request);
			const cloudflareaccess = {
				payload,
				getIdentity: () => getIdentity({ jwt, domain }),
			};
			console.log(cloudflareaccess);

			const newRequest = new Request(request);
			newRequest.headers.append('cloudflareaccess', JSON.stringify(cloudflareaccess));
			console.log(newRequest);

			const response = await fetch(newRequest);
			return response;
		} catch {}
		return new Response(null, {
			status: 302,
			headers: {
				Location: env.LOGIN,
			},
		});
	},
};
