import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));

// Pinned copy of https://a2a-protocol.org/latest/spec/a2a.json — the official
// (non-normative, proto-derived) JSON Schema bundle. Definitions carry no
// $id; internal refs use "lf.a2a.v1.{Name}.jsonschema.json", so each
// definition registers under its derived id (display name minus spaces).
const bundle = readJson('schema/vendor/a2a-v1.json');
const WELL_KNOWN = new Set(['Struct', 'Timestamp', 'Value']);
const refId = (name) =>
  (WELL_KNOWN.has(name) ? `google.protobuf.${name}` : `lf.a2a.v1.${name.replaceAll(' ', '')}`) +
  '.jsonschema.json';

const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);
for (const [name, def] of Object.entries(bundle.definitions)) {
  ajv.addSchema(def, refId(name));
}

let failures = 0;
const expect = (cond, label, detail = '') => {
  console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`);
  if (!cond) failures += 1;
};

console.log('== Official A2A schema conformance (pinned bundle) ==');

const validateMessage = ajv.getSchema(refId('Message'));
const message = readJson('mock/message.signed.json');
expect(
  validateMessage(message),
  'mock message validates against the Message definition',
  validateMessage.errors ? JSON.stringify(validateMessage.errors.slice(0, 2)) : ''
);

const validatePart = ajv.getSchema(refId('Part'));
for (const [i, part] of message.parts.entries()) {
  expect(validatePart(part), `part[${i}] validates against the Part definition`, validatePart.errors ? JSON.stringify(validatePart.errors.slice(0, 2)) : '');
}

// Known gap, documented: the production Flocker card predates the v1.0
// AgentCard shape (flocker-pages#39 tracks the upgrade). Reported, not
// gated, until that ships.
const validateCard = ajv.getSchema(refId('Agent Card'));
const card = readJson('mock/agent-card.json');
const cardOk = validateCard(card);
console.log(
  `  ${cardOk ? 'PASS' : 'KNOWN-GAP'}  agent card vs v1.0 AgentCard definition${
    cardOk ? '' : ` — ${validateCard.errors.length} error(s), tracked in flocker-pages#39`
  }`
);

console.log(failures === 0 ? '\nSchema checks passed.' : `\n${failures} schema check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
