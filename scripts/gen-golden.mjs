// Deterministic golden-vector generator for cross-language reproducibility.
//
// Emits test-vectors/golden.json from the JS reference implementation
// (scripts/jcs.mjs, scripts/presence.mjs, scripts/sign-message.mjs). The
// vectors let an independent implementation (see python/verify_vectors.py)
// reproduce the §8.4.1 presence processing, the card_digest, and every
// per-part digest byte-for-byte, and verify a JS-signed ES256 token against
// the embedded PUBLIC JWK.
//
// Fully deterministic: FIXED input card, FIXED parts covering all four part
// kinds (text, raw, data, url), and FIXED claims. ES256 signing is randomised
// internally, but the signature still verifies against the embedded public
// key, which is what the cross-check asserts. Re-running only changes the
// token's signature bytes, not any digest.
//
// Not wired into `npm test` — it writes a checked-in artifact on demand.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './jcs.mjs';
import { cardSigningPayload } from './presence.mjs';
import { digestPart, cardDigest, EXT_URI, METADATA_KEY, TOKEN_TYP } from './sign-message.mjs';
import { signCompact } from './jcs.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));

// ---------------------------------------------------------------------------
// FIXED input card. Exercises every presence class:
//   REQUIRED kept at default          -> description: "", skills: []
//   EXPLICIT optional kept at default -> capabilities.streaming: false
//   EXPLICIT optional kept (non-def)  -> capabilities.pushNotifications: true
//   IMPLICIT dropped at default       -> capabilities.extensions[].required:false,
//                                        supportedInterfaces[].tenant: "",
//                                        skills[].examples/inputModes/outputModes
//   IMPLICIT map dropped at default   -> securitySchemes: {} (present, empty)
//   Struct passthrough                -> capabilities.extensions[].params
//   signatures removed entirely       -> signatures: [...]
//   unknown field kept verbatim       -> x-flocker: {...}
// A non-ASCII code point (ü, é, and an emoji) appears in text to prove the
// UTF-8 handling agrees across languages.
// ---------------------------------------------------------------------------
const INPUT_CARD = {
  name: 'Ramen Maxxing',
  description: '',
  supportedInterfaces: [
    {
      url: 'https://flocker.md/a/ramen-maxxing-k4xfr/a2a/v1',
      protocolBinding: 'HTTP+JSON',
      protocolVersion: '1.0',
      tenant: '',
    },
  ],
  provider: { organization: 'FLOCKER', url: 'https://flocker.md/' },
  version: '1.0.0',
  documentationUrl: '',
  capabilities: {
    streaming: false,
    pushNotifications: true,
    extensions: [
      {
        uri: EXT_URI,
        description: 'Attaches a per-message provenance receipt.',
        required: false,
        params: { signsMessages: true, note: 'café ☕' },
      },
    ],
  },
  securitySchemes: {},
  defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain'],
  skills: [
    {
      id: 'showcase',
      name: 'Showcase coordination',
      description: 'Coordinates launch-week showcase slots.',
      tags: ['community', 'ramen'],
      examples: [],
      inputModes: [],
      outputModes: [],
    },
  ],
  signatures: [{ protected: 'ignored', signature: 'ignored' }],
  'x-flocker': { lockLLMProvider: false, theme: 'flocker-cyan' },
};

// ---------------------------------------------------------------------------
// FIXED parts covering all four `src` kinds.
//   text -> exact UTF-8, incl. non-ASCII (ü, é, emoji) to prove code-point handling
//   raw  -> strict RFC 4648 base64 ("Ramen Club" -> UmFtZW4gQ2x1Yg==)
//   data -> JCS of the value (key order + number form must match)
//   url  -> exact UTF-8, with mediaType + filename in the header
// ---------------------------------------------------------------------------
const INPUT_PARTS = [
  {
    text: 'Ramen Maxxing here — café crème, jalapeño ramen, 100% ☕ vibes. Requesting a showcase slot.',
  },
  {
    raw: 'UmFtZW4gQ2x1Yg==', // "Ramen Club"
    mediaType: 'application/octet-stream',
    filename: 'club.bin',
  },
  {
    data: {
      request: 'showcase-slot',
      project: 'flocker.md',
      week: '2026-07-20',
      priority: 1,
      contact: 'https://flocker.md/a/ramen-maxxing-k4xfr',
      nested: { z: 1, a: [3, 2, 1], flag: false },
    },
    mediaType: 'application/json',
  },
  {
    url: 'https://flocker.md/a/ramen-maxxing-k4xfr/.well-known/agent-card.json',
    mediaType: 'application/json',
    filename: 'agent-card.json',
  },
];

const canonicalCardPayload = canonicalize(cardSigningPayload(INPUT_CARD));
const card_digest = cardDigest(INPUT_CARD);
const partDigests = INPUT_PARTS.map(digestPart);

// ---------------------------------------------------------------------------
// FIXED claims -> JS-signed ES256 compact JWS for cross-verification.
// The mock PUBLIC JWK (public key material only) is embedded so a Python
// verifier needs no access to keys/.
// ---------------------------------------------------------------------------
const privateJwk = readJson('keys/mock-signing-key.jwk.json');
const publicJwk = (() => {
  const { d: _omitPrivate, ...pub } = privateJwk; // strip private scalar
  return pub;
})();

const claims = {
  iss: 'https://flocker.md',
  sub: 'https://flocker.md/a/ramen-maxxing-k4xfr/.well-known/agent-card.json',
  aud: 'https://ramenclub.so/agents/showcase-coordinator',
  iat: 1_752_000_000,
  exp: 1_752_000_300,
  jti: 'golden-vector-fixed-jti-0001',
  card_digest,
  msg: 'golden-vector-fixed-message-0001',
  role: 'ROLE_AGENT',
  parts: partDigests,
  media: 'application/json',
  schema: 'https://flocker.md/schemas/showcase-request/v1.json',
};

const header = { alg: 'ES256', typ: TOKEN_TYP, kid: publicJwk.kid };
const token = signCompact(privateJwk, header, claims);

const vectors = {
  description:
    'Deterministic golden vectors for the A2A message-provenance extension. ' +
    'card_payload_canonical, card_digest and parts[].digest are byte-for-byte ' +
    'reproducible from input_card / input_parts by any conformant impl. token ' +
    'is a JS-signed ES256 JWS verifiable against public_jwk.',
  ext_uri: EXT_URI,
  metadata_key: METADATA_KEY,
  token_typ: TOKEN_TYP,
  input_card: INPUT_CARD,
  input_parts: INPUT_PARTS,
  card_payload_canonical: canonicalCardPayload,
  card_digest,
  parts: INPUT_PARTS.map((part, i) => ({ input: part, digest: partDigests[i] })),
  token,
  token_header: header,
  token_claims: claims,
  public_jwk: publicJwk,
};

const outDir = path.join(root, 'test-vectors');
fs.mkdirSync(outDir, { recursive: true });
const outPath = path.join(outDir, 'golden.json');
fs.writeFileSync(outPath, JSON.stringify(vectors, null, 2) + '\n');

console.log(`Golden vectors written to test-vectors/golden.json`);
console.log(`  card canonical : ${canonicalCardPayload}`);
console.log(`  card_digest    : ${card_digest.value}`);
for (const [i, d] of partDigests.entries()) {
  console.log(`  part[${i}] ${d.src.padEnd(4)}  : ${d.value}`);
}
console.log(`  token          : ${token.slice(0, 32)}… (${token.length} chars)`);
