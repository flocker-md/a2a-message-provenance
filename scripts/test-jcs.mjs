import { canonicalize, strictBase64Decode, parseJsonStrict, sha256b64 } from './jcs.mjs';

let failures = 0;
const eq = (input, expected, label) => {
  const got = canonicalize(input);
  const ok = got === expected;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : ` — got ${got}, want ${expected}`}`);
  if (!ok) failures += 1;
};
const rejects = (fn, label) => {
  let ok = false;
  try {
    fn();
  } catch {
    ok = true;
  }
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  rejects ${label}`);
  if (!ok) failures += 1;
};

console.log('== RFC 8785 conformance ==');
eq({ b: 2, a: 1 }, '{"a":1,"b":2}', 'key sorting');
eq({ '€': 'e', a: 'a', ö: 'o' }, '{"a":"a","ö":"o","€":"e"}', 'UTF-16 code unit key order');
eq([null, true, false], '[null,true,false]', 'literals');
eq('a\nb', '"a\\nb"', 'string escape: newline');
eq('', '"\\u0007"', 'string escape: control char lowercase hex');
eq(10.0, '10', 'number: 10.0 -> 10');
eq(1e-7, '1e-7', 'number: 1e-7');
eq(0.000001, '0.000001', 'number: 0.000001');
eq(-0, '0', 'number: -0 -> 0');
eq(333333333.3333333, '333333333.3333333', 'number: double round-trip');
eq(Number.MAX_SAFE_INTEGER, '9007199254740991', 'number: 2^53-1 allowed');
eq({ nested: { z: [1, 'two'], a: {} } }, '{"nested":{"a":{},"z":[1,"two"]}}', 'nested structure');

console.log('== I-JSON hardening (must reject, never coerce) ==');
rejects(() => canonicalize(NaN), 'NaN');
rejects(() => canonicalize(Infinity), 'Infinity');
rejects(() => canonicalize(9007199254740992), '2^53 (unsafe integer)');
rejects(() => canonicalize(1e21), '1e21 (integer-valued double past 2^53; Python rfc8785 rejects too)');
rejects(() => canonicalize({ a: undefined }), 'undefined object value');
rejects(() => canonicalize([undefined]), 'undefined array element');
rejects(() => canonicalize({ big: 12345678901234567890 }), 'precision-lossy large integer');

const ok = (fn, label) => {
  let pass = false;
  try {
    pass = fn() === true;
  } catch {
    pass = false;
  }
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}`);
  if (!pass) failures += 1;
};

console.log('== Strict base64 (RFC 4648 §4, canonical only) ==');
ok(() => strictBase64Decode('aGVsbG8=').toString() === 'hello', 'decodes canonical base64');
rejects(() => strictBase64Decode('aGVsbG8'), 'missing padding');
rejects(() => strictBase64Decode('aGVs bG8='), 'embedded whitespace');
rejects(() => strictBase64Decode('aGVsbG-_'), 'base64url alphabet');
rejects(() => strictBase64Decode('aGVsbG9='), 'non-canonical trailing bits');

console.log('== Duplicate-key rejection (I-JSON input discipline) ==');
ok(() => parseJsonStrict('{"a":1,"b":{"c":[1,"x",{"d":2}]}}').b.c[2].d === 2, 'parses valid nested JSON');
rejects(() => parseJsonStrict('{"a":1,"a":2}'), 'duplicate top-level key');
rejects(() => parseJsonStrict('{"a":{"b":1,"b":2}}'), 'duplicate nested key');
ok(() => parseJsonStrict('{"a":{"b":1},"c":{"b":2}}').c.b === 2, 'same key in sibling objects is fine');

console.log('== Text digest contract: exact code points, no normalization ==');
{
  const nfc = 'caf\u00e9';
  const nfd = 'cafe\u0301';
  const differ = sha256b64(Buffer.from(nfc, 'utf8')) !== sha256b64(Buffer.from(nfd, 'utf8'));
  console.log(`  ${differ ? 'PASS' : 'FAIL'}  NFC and NFD forms digest differently (documented producer contract)`);
  if (!differ) failures += 1;
}

console.log(failures === 0 ? '\nAll JCS vectors passed.' : `\n${failures} vector(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
