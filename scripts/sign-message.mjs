import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, b64url, sha256b64, signCompact, strictBase64Decode, parseJsonStrict } from './jcs.mjs';
import { cardSigningPayload } from './presence.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));

export const EXT_URI = 'https://flocker.md/a2a/ext/message-provenance/v1';
export const METADATA_KEY = `${EXT_URI}/token`;
export const TOKEN_TYP = 'a2a-msg-provenance+jwt';

// Per-part digest, domain-separated: the hash covers a canonical header
// (src + interpretation-critical siblings) then a NUL then the decoded
// content, so a digest can never be reinterpreted under another part kind,
// media type, or filename. Text/url content hashes exact code points (no
// unicode normalization — documented producer contract). raw uses strict
// RFC 4648 base64 (ProtoJSON wire form).
export function digestPart(part) {
  let src;
  let content;
  if ('text' in part) {
    src = 'text';
    content = Buffer.from(part.text, 'utf8');
  } else if ('raw' in part) {
    src = 'raw';
    content = strictBase64Decode(part.raw);
  } else if ('url' in part) {
    src = 'url';
    content = Buffer.from(part.url, 'utf8');
  } else if ('data' in part) {
    src = 'data';
    content = Buffer.from(canonicalize(part.data), 'utf8');
  } else {
    throw new TypeError('Part has no recognized content member');
  }
  const header = { src };
  if (part.mediaType) header.mediaType = part.mediaType;
  if (part.filename) header.filename = part.filename;
  const input = Buffer.concat([Buffer.from(canonicalize(header), 'utf8'), Buffer.from([0]), content]);
  const entry = { ...header, alg: 'sha-256', value: sha256b64(input) };
  return entry;
}

// SHA-256 over the §8.4 signing payload (presence-processed, signatures
// excluded) — pins the exact card version endorsed at signing time.
export function cardDigest(card) {
  return { alg: 'sha-256', value: sha256b64(Buffer.from(canonicalize(cardSigningPayload(card)), 'utf8')) };
}

const main = process.argv[1] === fileURLToPath(import.meta.url);
if (main) {
  // The card URL IS the agent's canonical identifier (the normative card has
  // no id field), so sub carries it directly. The signer endorses its own
  // CURRENT card, so card_digest is computed over the live card (strict
  // parse) — the tracked mock/agent-card.json is a point-in-time worked
  // example, not the signing input, and would drift from what the verifier
  // fetches.
  const cardUrl = 'https://flocker.md/a/ramen-maxxing-k4xfr/.well-known/agent-card.json';
  const res = await fetch(cardUrl);
  if (!res.ok) {
    throw new Error(`card fetch failed (HTTP ${res.status}) — the sign/verify pipeline needs network access to ${cardUrl}`);
  }
  const card = parseJsonStrict(await res.text());
  const privateJwk = readJson('keys/mock-signing-key.jwk.json');

  const parts = [
    {
      text: 'Ramen Maxxing here. Requesting a slot in the Ramen Club launch-week showcase for a member project.',
    },
    {
      data: {
        request: 'showcase-slot',
        project: 'flocker.md',
        week: '2026-07-20',
        contact: 'https://flocker.md/a/ramen-maxxing-k4xfr',
      },
      mediaType: 'application/json',
    },
  ];

  const message = {
    messageId: crypto.randomUUID(),
    role: 'ROLE_AGENT',
    parts,
    extensions: [EXT_URI],
    metadata: {},
  };

  const iat = Math.floor(Date.now() / 1000);
  const claims = {
    iss: 'https://flocker.md',
    sub: cardUrl,
    aud: 'https://ramenclub.so/agents/showcase-coordinator',
    iat,
    exp: iat + 300,
    jti: b64url(crypto.randomBytes(16)),
    card_digest: cardDigest(card),
    msg: message.messageId,
    role: message.role,
    parts: parts.map(digestPart),
    media: 'application/json',
    schema: 'https://flocker.md/schemas/showcase-request/v1.json',
  };

  const header = { alg: 'ES256', typ: TOKEN_TYP, kid: privateJwk.kid };
  message.metadata[METADATA_KEY] = signCompact(privateJwk, header, claims);

  fs.writeFileSync(path.join(root, 'mock/message.signed.json'), JSON.stringify(message, null, 2));

  console.log('Signed message written to mock/message.signed.json');
  console.log(`  sub (card url): ${cardUrl}`);
  console.log(`  messageId     : ${message.messageId}`);
  console.log(`  card_digest   : ${claims.card_digest.value}`);
  console.log(`  part digests  : ${claims.parts.map((p) => `${p.src}:${p.value.slice(0, 12)}…`).join('  ')}`);
}
