import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { jwkThumbprint } from './jcs.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const privateJwk = privateKey.export({ format: 'jwk' });
const publicJwk = publicKey.export({ format: 'jwk' });

const kid = `mock-flocker-${jwkThumbprint(publicJwk).slice(0, 8)}`;

fs.writeFileSync(
  path.join(root, 'keys/mock-signing-key.jwk.json'),
  JSON.stringify({ ...privateJwk, kid, use: 'sig', alg: 'ES256' }, null, 2)
);
fs.writeFileSync(
  path.join(root, 'keys/mock-jwks.json'),
  JSON.stringify({ keys: [{ ...publicJwk, kid, use: 'sig', alg: 'ES256' }] }, null, 2)
);

console.log(`Generated P-256 keypair, kid=${kid}`);
console.log('  keys/mock-signing-key.jwk.json (private — mock only, never commit a real one)');
console.log('  keys/mock-jwks.json (public JWKS the verifier resolves)');
