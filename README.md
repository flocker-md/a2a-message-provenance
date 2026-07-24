# A2A Message Provenance Extension

A community extension for the [Agent2Agent (A2A) protocol](https://github.com/a2aproject/A2A)
that lets a third party cryptographically verify that a message came from the
agent a published, signed A2A Agent Card represents.

A2A signs the Agent *Card* (specification §8.4) — a signed identity document —
but binds no individual *message* to it. This extension adds a per-message,
verify-later provenance receipt: a compact ES256 JWT carried in
`message.metadata` that binds the message content and pins the exact card
*version* it was endorsed against. It is an object-level provenance signal that
**complements** transport authentication and other verification methods; it is
opt-in on both send and receipt and does not exclude or override them.

- **Specification:** [`extensions/message-provenance/v1/spec.md`](extensions/message-provenance/v1/spec.md)
- **Status:** Draft (pre-proposal). Not yet submitted to the A2A project.
- **License:** [Apache-2.0](LICENSE)

## How it works

A supporting agent attaches a detached-from-content JWT
(`typ: a2a-msg-provenance+jwt`) at
`message.metadata["…/message-provenance/v1/token"]`. The token carries:

- `iss` / `sub` — the platform origin and the sender's Agent Card URL (the
  agent's canonical identifier; A2A v1.0 cards have no `id` field).
- `card_digest` — a SHA-256 over the §8.4.1 signing payload of the card,
  pinning the exact endorsed card version.
- `parts` — ordered, domain-separated per-part digests over decoded content, so
  a digest cannot be reinterpreted under another part kind, media type, or
  filename.

Verifiers resolve signing keys only from pre-configured trust anchors
(issuer → pinned JWKS) and never dereference key URLs carried in the token — a
tightened profile of what §8.4.3 already permits. See the spec for the full
claims set, generation, and verification procedures (including `live` vs `audit`
modes and the anti-stripping check).

## Reference implementation

This repository includes a Node reference implementation and conformance test
suite. Node 20+, then:

```bash
npm install                      # ajv, for schema conformance
npm test                         # full pipeline (JCS + presence + schema + sign + verify)
```

Individual stages:

```bash
node scripts/generate-keys.mjs   # mock P-256 keypair + JWKS (stands in for a platform signing key)
node scripts/test-jcs.mjs        # RFC 8785 JCS vectors, I-JSON rejections, strict base64, dup-key rejection
node scripts/test-presence.mjs   # A2A §8.4.1 field-presence (REQUIRED / explicit / implicit) golden vectors
node scripts/test-schema.mjs     # ajv against the pinned official A2A schema bundle (Message / Part)
node scripts/sign-message.mjs    # build a signed provenance token for an example message
node scripts/verify-message.mjs  # pinned-anchor verifier: positive checks + negative / mode cases
```

The verify stage fetches a real, §8.4-signed Agent Card from `flocker.md`
(duplicate-key-strict parse), verifies its signature against the live JWKS over
the presence-processed payload, and matches the signed `card_digest`; only the
message-signing key is mocked. The negative suite covers key substitution,
content and metadata tampering, part-kind confusion, `typ` confusion, token
stripping, expired-token live-vs-audit behavior, and replay.

## Layout

| Path | Contents |
|------|----------|
| `extensions/message-provenance/v1/spec.md` | The extension specification |
| `schema/message-provenance-*.schema.json` | JSON Schemas for the token claims and metadata value |
| `schema/vendor/a2a-v1.json` | Pinned copy of the official A2A JSON Schema bundle (for conformance) |
| `scripts/` | Reference implementation and conformance tests |
| `mock/` | Worked example card and signed message |

## Standards positioning

This extension builds on A2A's own signed-card primitive rather than competing
with it, and is deliberately scoped as one composable verification method among
others. It is published as an open community extension and is seeking
independent co-implementers. Feedback and implementations are welcome.

## Attribution

Authored and maintained by [@hcjmartin](https://github.com/hcjmartin) under
Flocker. Licensed under Apache-2.0.
