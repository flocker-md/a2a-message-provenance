import crypto from 'node:crypto';

// RFC 8785 JCS, hardened to the I-JSON profile PLAN_v2 requires: instead of
// coercing hostile inputs (NaN -> null, 2^53 -> rounded double), we reject
// them. Production implementations should use a vetted RFC 8785 library and
// the same rejection rules; scripts/test-jcs.mjs holds the vectors.
export function canonicalize(value) {
  if (value === undefined) throw new TypeError('undefined is not serializable');
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`non-finite number: ${value}`);
    if (Number.isInteger(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      throw new TypeError(`integer outside I-JSON safe range (use a string): ${value}`);
    }
    return JSON.stringify(value);
  }
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const keys = Object.keys(value).sort(); // UTF-16 code unit order per RFC 8785
  const members = keys.map((k) => {
    if (value[k] === undefined) throw new TypeError(`undefined value at key "${k}"`);
    return `${JSON.stringify(k)}:${canonicalize(value[k])}`;
  });
  return `{${members.join(',')}}`;
}

export const b64url = (buf) => Buffer.from(buf).toString('base64url');
export const b64urlJson = (obj) => b64url(Buffer.from(JSON.stringify(obj), 'utf8'));
export const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest();
export const sha256b64 = (bytes) => b64url(sha256(bytes));

// Compact JWS/JWT (Variant A message provenance token).
export function signCompact(privateKeyJwk, header, claims) {
  const signingInput = `${b64urlJson(header)}.${b64urlJson(claims)}`;
  const key = crypto.createPrivateKey({ key: privateKeyJwk, format: 'jwk' });
  const signature = crypto.sign('sha256', Buffer.from(signingInput, 'ascii'), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${b64url(signature)}`;
}

export function decodeCompact(token) {
  const [h, p, s] = token.split('.');
  const parse = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  return { header: parse(h), claims: parse(p), signingInput: `${h}.${p}`, signature: s };
}

export function verifyCompactSignature(publicKeyJwk, token) {
  const { signingInput, signature } = decodeCompact(token);
  const key = crypto.createPublicKey({ key: publicKeyJwk, format: 'jwk' });
  return crypto.verify(
    'sha256',
    Buffer.from(signingInput, 'ascii'),
    { key, dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature, 'base64url')
  );
}

// Detached JWS signing, §8.4 style — used for Agent Card signatures.
export function signDetached(privateKeyJwk, header, payloadBytes) {
  const protectedB64 = b64urlJson(header);
  const key = crypto.createPrivateKey({ key: privateKeyJwk, format: 'jwk' });
  const signature = crypto.sign('sha256', Buffer.from(`${protectedB64}.${b64url(payloadBytes)}`, 'ascii'), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  return { protected: protectedB64, signature: b64url(signature) };
}

// Detached JWS verification, §8.4 style — used for Agent Card signatures.
export function verifyDetached(publicKeyJwk, protectedB64, payloadBytes, signatureB64) {
  const signingInput = `${protectedB64}.${b64url(payloadBytes)}`;
  const key = crypto.createPublicKey({ key: publicKeyJwk, format: 'jwk' });
  return crypto.verify(
    'sha256',
    Buffer.from(signingInput, 'ascii'),
    { key, dsaEncoding: 'ieee-p1363' },
    Buffer.from(signatureB64, 'base64url')
  );
}

// Strict RFC 4648 §4 base64 (the ProtoJSON wire form for bytes): standard
// alphabet only, correct padding, no whitespace. Node's default decoder
// accepts base64url and ignores whitespace, which makes the on-wire string
// malleable — for a provenance digest the decode must be canonical.
export function strictBase64Decode(s) {
  if (typeof s !== 'string' || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new TypeError('invalid strict base64');
  }
  const bytes = Buffer.from(s, 'base64');
  if (bytes.toString('base64') !== s) throw new TypeError('non-canonical base64 encoding');
  return bytes;
}

// JSON.parse with duplicate-object-key rejection. RFC 8785 assumes I-JSON
// input (unique keys); JSON.parse silently keeps the last duplicate, letting
// one document present different content to the digest and to a lenient
// reader. Detection walks the raw text with a minimal tokenizer.
export function parseJsonStrict(text) {
  const stack = [];
  let i = 0;
  const skipString = () => {
    const start = ++i;
    while (i < text.length) {
      if (text[i] === '\\') i += 2;
      else if (text[i] === '"') return text.slice(start, i++);
      else i++;
    }
    throw new SyntaxError('unterminated string');
  };
  while (i < text.length) {
    const c = text[i];
    if (c === '{') {
      stack.push({ keys: new Set(), expectKey: true });
      i++;
    } else if (c === '}') {
      stack.pop();
      i++;
    } else if (c === '[') {
      stack.push(null);
      i++;
    } else if (c === ']') {
      stack.pop();
      i++;
    } else if (c === '"') {
      const top = stack[stack.length - 1];
      const s = skipString();
      if (top && top.expectKey) {
        if (top.keys.has(s)) throw new SyntaxError(`duplicate object key: "${s}"`);
        top.keys.add(s);
        top.expectKey = false;
      }
    } else if (c === ':') {
      i++;
    } else if (c === ',') {
      const top = stack[stack.length - 1];
      if (top) top.expectKey = true;
      i++;
    } else {
      i++;
    }
  }
  return JSON.parse(text);
}

// RFC 7638 JWK thumbprint for EC keys.
export function jwkThumbprint(jwk) {
  const canonical = canonicalize({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64url(sha256(Buffer.from(canonical, 'utf8')));
}
