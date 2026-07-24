import { canonicalize } from './jcs.mjs';
import { cardSigningPayload } from './presence.mjs';

let failures = 0;
const eq = (card, expected, label) => {
  const got = canonicalize(cardSigningPayload(card));
  const ok = got === expected;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : ` — got ${got}, want ${expected}`}`);
  if (!ok) failures += 1;
};

console.log('== §8.4.1 golden vector (spec worked example) ==');
// Explicit-presence optionals set to their proto defaults MUST survive;
// implicit-presence defaults (extensions: []) MUST be dropped.
eq(
  {
    name: 'Example Agent',
    description: '',
    capabilities: { streaming: false, pushNotifications: false, extensions: [] },
    skills: [],
  },
  '{"capabilities":{"pushNotifications":false,"streaming":false},"description":"","name":"Example Agent","skills":[]}',
  'worked example: "streaming": false and "pushNotifications": false retained byte-exact'
);

console.log('== Presence classes ==');
eq(
  {
    name: '',
    description: '',
    version: '',
    supportedInterfaces: [],
    defaultInputModes: [],
    defaultOutputModes: [],
    skills: [],
    capabilities: {},
  },
  '{"capabilities":{},"defaultInputModes":[],"defaultOutputModes":[],"description":"","name":"","skills":[],"supportedInterfaces":[],"version":""}',
  'REQUIRED fields kept even when default-valued'
);
eq(
  { capabilities: { streaming: false, extendedAgentCard: false }, iconUrl: '', documentationUrl: '' },
  '{"capabilities":{"extendedAgentCard":false,"streaming":false},"documentationUrl":"","iconUrl":""}',
  'EXPLICIT optionals kept whenever physically present, even at defaults'
);
eq(
  {
    name: 'Agent',
    capabilities: { extensions: [] },
    securityRequirements: [],
    securitySchemes: {},
    supportedInterfaces: [
      { url: 'https://x.example/a2a/v1', protocolBinding: 'HTTP+JSON', protocolVersion: '1.0', tenant: '' },
    ],
    skills: [
      {
        id: 's1',
        name: 'Skill',
        description: 'Does things',
        tags: [],
        examples: [],
        inputModes: [],
        outputModes: [],
        securityRequirements: [],
      },
    ],
  },
  '{"capabilities":{},"name":"Agent","skills":[{"description":"Does things","id":"s1","name":"Skill","tags":[]}],"supportedInterfaces":[{"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","url":"https://x.example/a2a/v1"}]}',
  'IMPLICIT defaults dropped recursively (tenant, extensions, skill mode lists)'
);

console.log('== Signing-payload contract ==');
eq(
  { name: 'Agent', signatures: [{ protected: 'x', signature: 'y' }] },
  '{"name":"Agent"}',
  'signatures excluded from signing input (§8.4.1 rule 3)'
);
eq(
  { name: 'Agent', 'x-unknown': { a: 1, empty: '' } },
  '{"name":"Agent","x-unknown":{"a":1,"empty":""}}',
  'unknown fields kept verbatim'
);
eq(
  {
    capabilities: {
      extensions: [
        {
          uri: 'https://flocker.md/a2a/extensions/profile/v1',
          required: false,
          params: { id: 'my-agent', tags: [], flag: false },
        },
      ],
    },
  },
  '{"capabilities":{"extensions":[{"params":{"flag":false,"id":"my-agent","tags":[]},"uri":"https://flocker.md/a2a/extensions/profile/v1"}]}}',
  'extension params (Struct) pass through verbatim; implicit required:false dropped'
);

console.log(failures === 0 ? '\nAll presence vectors passed.' : `\n${failures} vector(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
