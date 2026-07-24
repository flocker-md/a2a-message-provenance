import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalize,
  b64url,
  decodeCompact,
  verifyCompactSignature,
  verifyDetached,
  signCompact,
  parseJsonStrict,
} from './jcs.mjs';
import { cardSigningPayload } from './presence.mjs';
import { EXT_URI, METADATA_KEY, TOKEN_TYP, digestPart, cardDigest } from './sign-message.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));

// Pinned trust anchors: keys resolve ONLY from here; kid/jku inside tokens
// and cards is never dereferenced on its own authority. Bilateral-v1 model —
// a deployment profile, per PLAN_v3 positioning. Production uses one JWKS
// per issuer for both entries.
const TRUST_ANCHORS = {
  'https://flocker.md': {
    messageJwks: 'mock:keys/mock-jwks.json',
    cardJwks: 'https://flocker.md/api/a2a/agents/.well-known/jwks.json',
  },
};

const FRESHNESS_SKEW_S = 30;

async function resolveJwks(ref) {
  if (ref.startsWith('mock:')) return readJson(ref.slice('mock:'.length));
  return fetch(ref).then((r) => r.json());
}

async function fetchCardStrict(url) {
  const text = await fetch(url).then((r) => r.text());
  return parseJsonStrict(text);
}

function makeReporter(silent) {
  const results = [];
  return {
    results,
    check(ok, label, detail = '') {
      results.push({ ok, label, detail });
      if (!silent) console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`);
      return ok;
    },
    info(label, detail = '') {
      if (!silent) console.log(`  INFO  ${label}${detail ? ` — ${detail}` : ''}`);
    },
  };
}

// Verifies a card's §8.4 JWS: presence-processed payload, pinned jku,
// any-one-of-N signatures suffices (spec's key-rotation rule).
async function verifyCardSignature(card, anchor, check) {
  const sigs = card.signatures ?? [];
  if (!check(sigs.length >= 1, 'card carries at least one §8.4 signature')) return false;
  const payload = Buffer.from(canonicalize(cardSigningPayload(card)), 'utf8');
  for (const sig of sigs) {
    const header = JSON.parse(Buffer.from(sig.protected, 'base64url').toString('utf8'));
    if (header.jku !== anchor.cardJwks) continue;
    const jwks = await resolveJwks(anchor.cardJwks);
    const key = jwks.keys.find((k) => k.kid === header.kid);
    if (key && verifyDetached(key, sig.protected, payload, sig.signature)) {
      check(true, 'card §8.4 JWS verifies (pinned jku, presence-processed payload)', header.kid);
      return true;
    }
  }
  check(false, 'card §8.4 JWS verifies (pinned jku, presence-processed payload)');
  return false;
}

export async function verifyMessage(message, { mode = 'live', expectedAud, jtiCache, cardOverride, silent, anchors } = {}) {
  const { check, info, results } = makeReporter(silent);
  const fail = () => ({ verified: false, results });

  // 1. Token extraction and header discipline.
  const token = message.metadata?.[METADATA_KEY];
  if (!check(typeof token === 'string', 'provenance token present at {URI}/token')) return fail();
  let decoded;
  try {
    decoded = decodeCompact(token);
  } catch {
    check(false, 'token parses as compact JWS');
    return fail();
  }
  const { header, claims } = decoded;
  if (!check(header.typ === TOKEN_TYP, `typ is exactly ${TOKEN_TYP}`, header.typ)) return fail();
  if (!check(header.alg === 'ES256', 'alg is ES256', header.alg)) return fail();

  // 2. Issuer allowlist and pinned key resolution.
  const anchor = (anchors ?? TRUST_ANCHORS)[claims.iss];
  if (!check(!!anchor, 'iss is in the verifier trust-anchor allowlist', claims.iss)) return fail();
  const msgJwks = await resolveJwks(anchor.messageJwks);
  const msgKey = msgJwks.keys.find((k) => k.kid === header.kid);
  if (!check(!!msgKey, 'kid resolves in the PINNED message JWKS', header.kid)) return fail();
  if (!check(verifyCompactSignature(msgKey, token), 'token signature verifies')) return fail();

  // 3. Claim validity. Audit mode verifies long after exp; replay caching is
  // a live-flow concern only.
  const now = Math.floor(Date.now() / 1000);
  check(claims.aud === expectedAud, 'aud names this recipient', claims.aud);
  check(claims.iat <= now + FRESHNESS_SKEW_S, 'iat is not in the future', `now-iat=${now - claims.iat}s`);
  if (mode === 'live') {
    check(now <= claims.exp + FRESHNESS_SKEW_S, 'exp valid (live mode)', `exp-now=${claims.exp - now}s`);
    check(!jtiCache.has(`${claims.aud}|${claims.jti}`), 'jti unseen (replay cache, scoped per aud)');
  } else {
    info('audit mode: exp and replay cache not enforced', `exp was ${claims.exp}`);
  }

  // 4. Message binding: id, role, per-part digests over parsed content.
  check(claims.msg === message.messageId, 'msg binds to messageId');
  check(claims.role === message.role, 'role is signed and matches', message.role);
  if (check(claims.parts.length === message.parts.length, 'signed part count equals received part count')) {
    message.parts.forEach((part, i) => {
      let ok = false;
      let detail = '';
      try {
        const r = digestPart(part);
        const c = claims.parts[i];
        ok = r.src === c.src && r.value === c.value && r.mediaType === c.mediaType && r.filename === c.filename;
        detail = r.value.slice(0, 12) + '…';
      } catch (e) {
        detail = `content rejected: ${e.message}`;
      }
      check(ok, `part[${i}] digest matches (${claims.parts[i].src})`, detail);
    });
  }

  // 5. Card chain: sub IS the card URL (the agent's canonical identifier);
  // origin pinned to iss; §8.4 signature; version pinned by card_digest.
  if (!check(new URL(claims.sub).origin === new URL(claims.iss).origin, 'sub (card URL) origin matches iss', claims.sub))
    return fail();
  const card = cardOverride ?? (await fetchCardStrict(claims.sub));
  await verifyCardSignature(card, anchor, check);
  check(
    cardDigest(card).value === claims.card_digest.value,
    'card_digest matches: message endorsed against THIS card version'
  );

  const verified = results.every((r) => r.ok);
  if (verified && mode === 'live') jtiCache.add(`${claims.aud}|${claims.jti}`);
  return { verified, results };
}

// Inbound gate: strip detection runs on every message, token or not. A
// validated card declaring signsMessages makes an unsigned message from that
// sender a policy violation (the declaration lives inside the §8.4-signed
// card, and verifiers SHOULD pin an observed declaration to resist
// rotate-to-undeclare downgrades — see PLAN_v3).
export async function verifyInbound(message, opts) {
  const hasToken = typeof message.metadata?.[METADATA_KEY] === 'string';
  if (hasToken) return verifyMessage(message, opts);
  const card = opts.cardOverride ?? (opts.senderCardUrl ? await fetchCardStrict(opts.senderCardUrl) : null);
  const declares = (card?.capabilities?.extensions ?? []).some(
    (e) => e.uri === EXT_URI && e.params?.signsMessages === true
  );
  return {
    verified: false,
    stripViolation: declares,
    results: [{ ok: !declares, label: declares ? 'STRIP VIOLATION: sender declares signsMessages, no token' : 'unsigned message from non-declaring sender' }],
  };
}

// ---------------------------------------------------------------------------
const main = process.argv[1] === fileURLToPath(import.meta.url);
if (main) {
  const EXPECTED_AUD = 'https://ramenclub.so/agents/showcase-coordinator';
  const jtiCache = new Set();
  const message = readJson('mock/message.signed.json');
  const privateJwk = readJson('keys/mock-signing-key.jwk.json');
  let suiteFailures = 0;
  const expect = (cond, label) => {
    console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${label}`);
    if (!cond) suiteFailures += 1;
  };
  const quiet = (m, extra = {}) =>
    verifyMessage(m, { expectedAud: EXPECTED_AUD, jtiCache: new Set(), silent: true, ...extra });

  console.log('\n== Positive: full chain (live mode) ==');
  const positive = await verifyMessage(message, { expectedAud: EXPECTED_AUD, jtiCache });
  if (!positive.verified) suiteFailures += 1;

  const { claims: goodClaims } = decodeCompact(message.metadata[METADATA_KEY]);
  const attacker = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const attackerJwk = { ...attacker.privateKey.export({ format: 'jwk' }), kid: 'attacker-key' };
  const resign = (claims, header = { alg: 'ES256', typ: TOKEN_TYP, kid: attackerJwk.kid }, key = attackerJwk) => {
    const m = structuredClone(message);
    m.metadata[METADATA_KEY] = signCompact(key, header, claims);
    return m;
  };

  console.log('== N1a: attacker issuer ==');
  let r = await quiet(resign({ ...goodClaims, iss: 'https://attacker.example', sub: 'https://attacker.example/card.json' }));
  expect(!r.verified, 'rejected: iss not in trust-anchor allowlist');

  console.log('== N1b: allowlisted iss, attacker key ==');
  r = await quiet(resign({ ...goodClaims }));
  expect(!r.verified, 'rejected: attacker kid absent from pinned JWKS');

  console.log('== N1c: valid platform token, off-origin card URL in sub ==');
  r = await quiet(
    resign({ ...goodClaims, sub: 'https://attacker.example/card.json' }, { alg: 'ES256', typ: TOKEN_TYP, kid: privateJwk.kid }, privateJwk)
  );
  expect(!r.verified, 'rejected: sub origin differs from iss');

  console.log('== N2a: tampered part content ==');
  {
    const m = structuredClone(message);
    m.parts[1].data.week = '2026-07-27';
    r = await quiet(m);
    expect(!r.verified, 'rejected: part digest mismatch');
  }

  console.log('== N2b: tampered mediaType (bytes intact) ==');
  {
    const m = structuredClone(message);
    m.parts[1].mediaType = 'text/html';
    r = await quiet(m);
    expect(!r.verified, 'rejected: mediaType is inside the domain-separated digest');
  }

  console.log('== N2c: part kind confusion (text relabeled as url) ==');
  {
    const m = structuredClone(message);
    m.parts[0] = { url: m.parts[0].text };
    r = await quiet(m);
    expect(!r.verified, 'rejected: domain separation makes text/url digests differ');
  }

  console.log('== N3: tampered claims (re-encoded aud) ==');
  {
    const m = structuredClone(message);
    const [h, , s] = m.metadata[METADATA_KEY].split('.');
    const forged = { ...goodClaims, aud: 'https://attacker.example/agent' };
    m.metadata[METADATA_KEY] = `${h}.${b64url(Buffer.from(JSON.stringify(forged), 'utf8'))}.${s}`;
    r = await quiet(m);
    expect(!r.verified, 'rejected: signature fails over modified claims');
  }

  console.log('== N4: cross-context typ confusion ==');
  r = await quiet(resign({ ...goodClaims }, { alg: 'ES256', typ: 'JOSE', kid: privateJwk.kid }, privateJwk));
  expect(!r.verified, 'rejected: typ is not a2a-msg-provenance+jwt');

  console.log('== N5: stripped token, declaring card (via verifyInbound gate) ==');
  {
    const card = readJson('mock/agent-card.json');
    const declaringCard = structuredClone(card);
    declaringCard.capabilities = {
      extensions: [{ uri: EXT_URI, description: 'Message provenance', params: { signsMessages: true } }],
    };
    const stripped = structuredClone(message);
    delete stripped.metadata[METADATA_KEY];
    r = await verifyInbound(stripped, { expectedAud: EXPECTED_AUD, jtiCache, cardOverride: declaringCard, silent: true });
    expect(!r.verified && r.stripViolation === true, 'flagged: strip violation surfaced by the inbound gate');
  }

  console.log('== Modes: expired token — live rejects, audit verifies ==');
  {
    const iat = Math.floor(Date.now() / 1000) - 7200;
    const expired = resign(
      { ...goodClaims, iat, exp: iat + 300 },
      { alg: 'ES256', typ: TOKEN_TYP, kid: privateJwk.kid },
      privateJwk
    );
    r = await quiet(expired, { mode: 'live' });
    expect(!r.verified, 'live mode rejects expired token');
    r = await quiet(expired, { mode: 'audit' });
    expect(r.verified, 'audit mode verifies expired token (full chain, exp not enforced)');
  }

  console.log('== Replay: same token presented twice (live) ==');
  r = await verifyMessage(message, { expectedAud: EXPECTED_AUD, jtiCache, silent: true });
  expect(!r.verified, 'rejected: jti already in replay cache');

  console.log(
    suiteFailures === 0 && positive.verified
      ? '\nAll positive checks and negative cases passed.'
      : `\n${suiteFailures} case(s) FAILED.`
  );
  process.exit(suiteFailures === 0 && positive.verified ? 0 : 1);
}
