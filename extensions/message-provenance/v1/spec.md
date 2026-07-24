# A2A Message Provenance Extension — v1

- **Status:** Draft (pre-proposal). Not yet submitted to the A2A project.
- **Extension URI:** `https://flocker.md/a2a/ext/message-provenance/v1`
- **Version:** 1.0.0-draft
- **License:** Apache License 2.0
- **Depends on:** A2A Protocol v1.0 (specification §8.4 Agent Card Signing, §8.4.1 field presence), RFC 7515 (JWS), RFC 7519 (JWT), RFC 8785 (JCS), RFC 8725 (JWT BCP).

> This is a working draft. Section 9 (Relationship to prior and adjacent work),
> Section 10 (Covered and uncovered fields), Appendix A (§8.4.1 field-behavior
> table), Section 11 (Security Considerations), and Section 12 (Versioning and
> namespace) are stubs pending the tracked issues noted inline. The wire format,
> generation, and verification sections are normative and complete.

## 1. Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in RFC 2119 and RFC 8174 when, and
only when, they appear in all capitals.

## 2. Abstract

This extension defines a per-message, verify-later provenance receipt for the
Agent2Agent (A2A) protocol. A sender attaches a compact, detached-from-content
JSON Web Token to an A2A `Message`; a third party can later verify that the
message was endorsed by the agent that a specific, §8.4-signed Agent Card
version represents. The receipt binds the message content through
domain-separated per-part digests and pins the exact endorsing card version
through a digest over that card's §8.4.1 signing payload.

## 3. Motivation

A2A signs the Agent *Card* (§8.4): a signed identity document. Nothing in the
core protocol binds an individual *message* to that card. Transport
authentication (OAuth, mTLS, HTTP request signing) authenticates the connection
at the moment of the request and terminates at the receiving hop; it produces
no artifact a third party can check afterward, and it does not pin the card
version the sender was representing.

This extension fills that gap with an object-level receipt that:

1. survives forwarding and storage (it travels in the message, not the
   transport);
2. is checkable by a party who was not on the original connection; and
3. names the exact card version endorsed, so a later card mutation cannot
   retroactively change what was attested.

It is intentionally scoped as a **provenance signal**, complementary to
transport authentication and authorization. Verifiers gate policy on it the way
DMARC gates on DKIM/SPF; it is not itself an authentication or authorization
mechanism.

## 4. Relationship to A2A §8.4 (trust-anchor profile)

A2A §8.4.3 already permits a verifier to resolve a card's signing key "from a
trusted key store" rather than by dereferencing the in-card `jku`. This
extension's normative contribution at the key-resolution layer is to **require**
that profile:

- A verifier **MUST** resolve issuer and card signing keys only from a
  pre-configured trust anchor (issuer origin → pinned JWKS).
- A verifier **MUST NOT** dereference a key URL (`jku`, `keyid`, or equivalent)
  taken from the token or from the card being verified.

This is a §8.4 profile, not a replacement, and is honestly scoped as a
bilateral / small-N trust model for v1. A signed trust-list is the documented
migration path for ecosystem scale (see Section 12).

## 5. Extension URI and activation

The extension is identified by the URI
`https://flocker.md/a2a/ext/message-provenance/v1`.

### 5.1 Declaration

A supporting agent **MUST** declare the extension in its Agent Card under
`capabilities.extensions`:

```json
{
  "capabilities": {
    "extensions": [
      {
        "uri": "https://flocker.md/a2a/ext/message-provenance/v1",
        "description": "This agent attaches a per-message cryptographic provenance receipt, bound to this signed card version, to its outbound messages.",
        "required": false,
        "params": { "signsMessages": true }
      }
    ]
  }
}
```

### 5.2 `params` schema

The `params` object conveys the sender's message-signing posture:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `signsMessages` | boolean | yes | `true` asserts that this agent attaches a provenance token to every outbound message. Used by the anti-stripping check in Section 8.3. |

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://flocker.md/a2a/ext/message-provenance/v1/params.schema.json",
  "type": "object",
  "properties": { "signsMessages": { "type": "boolean" } },
  "required": ["signsMessages"],
  "additionalProperties": false
}
```

These `params` describe the sender's own posture only. By design there is no
recipient/consumer param: A2A models no producer-versus-consumer role on an
extension, so whether and how a recipient verifies is local verifier policy
(Section 5.3), not a declared capability.

### 5.3 Activation, negotiation, and `required`

**Data-only by default.** The provenance token is additive metadata — a sender
attaches it without the recipient activating anything. This is consistent with
A2A's rule that extensions "default to being inactive"
(`docs/topics/extensions.md`): activation governs behavior a peer must opt into,
whereas a data-only extension simply contributes a metadata value. A sender that
attaches a token SHOULD list the extension URI in `message.extensions` to mark
the contribution.

**Negotiation.** A client that wants a peer to activate an extension lists its
URI in the `A2A-Extensions` request header; the responding **agent** echoes the
URIs it activated in the response header. This channel is transport-scoped and
per-request, so it is not required by this extension's default (data-only) mode,
and it **MUST NOT** be treated as a substitute for the in-token and in-card
material when reasoning about a message after the fact.

**Recipient side is local policy.** A2A defines no consumer/recipient role on an
extension and no card field for "I verify inbound provenance"; the only
recipient-side signal it defines is the per-request activation echo above.
Accordingly, whether a recipient verifies a token — and what it does on absence
or failure — is local verifier policy (Section 8), not a declared capability.

**Enforcement via native `required`.** A deployment that wants to *require*
inbound provenance does not add a bespoke param — it sets `required: true` on the
extension declaration, invoking A2A's own capability-validation path: a client
that does not satisfy a required extension **MUST** be rejected with
`ExtensionSupportRequiredError` (-32008) (specification §3.3.4). This is the
exclusionary option — it reclassifies the extension from data-only to a profile
extension, gates interaction on support, and shuts out counterparties that do
not implement it. It is available per deployment, is not the default, and does
not override or preclude other verification methods a party may use separately.
*(Positioning expanded in Section 9 / FLO-6.)*

## 6. Token format

The receipt is a compact JWS (RFC 7515) carrying a JWT (RFC 7519) claims set,
stored as a string in the message metadata.

### 6.1 Location

The token **MUST** be stored at:

```
message.metadata["https://flocker.md/a2a/ext/message-provenance/v1/token"]
```

The value **MUST** be a compact-serialization JWS matching
`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`
(`schema/message-provenance-token.schema.json`).

### 6.2 Protected header

The JWS protected header **MUST** be exactly:

| Field | Value | Notes |
|-------|-------|-------|
| `alg` | `ES256` | ECDSA P-256 / SHA-256, IEEE P1363 signature encoding (RFC 7515). |
| `typ` | `a2a-msg-provenance+jwt` | Distinct media type for domain separation from §8.4 card signing (`typ: JOSE`), per RFC 8725. A verifier **MUST** reject any other `typ`. |
| `kid` | key id | **MUST** match an entry in the issuer's pinned JWKS. |

The header **MUST NOT** carry `jku`, `jwk`, `x5u`, or any other key-locator
field; see Section 4.

### 6.3 Claims

Full schema: `schema/message-provenance-claims.schema.json`. REQUIRED claims are
`iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `card_digest`, `msg`, `role`, `parts`.

| Claim | Type | Req | Meaning |
|-------|------|-----|---------|
| `iss` | URI | yes | Platform origin (e.g. `https://flocker.md`). Keys resolve only from this issuer's pinned JWKS. |
| `sub` | URI | yes | Sender's Agent Card URL — the agent's canonical identifier (A2A v1.0 cards have no `id` field). Its origin **MUST** equal `iss`; the verifier fetches and validates this card. |
| `aud` | string | yes | Recipient identifier (card URL, endpoint URL, or agreed name). |
| `iat` | integer | yes | Unix seconds at signing. |
| `exp` | integer | yes | Unix seconds expiry. Enforced in live mode; not gated in audit mode (Section 8.2). |
| `jti` | string | yes | Unique token id; live-mode replay-cache key, scoped per `aud`. |
| `card_digest` | digest | yes | Pins the endorsing card version (Section 7.1). |
| `msg` | string | yes | `messageId` of the enclosing message. |
| `role` | `ROLE_USER` \| `ROLE_AGENT` | yes | The message's role (proto enum JSON form). |
| `parts` | array | yes | Ordered per-part digests; count **MUST** equal the message's part count (Section 7.2). |
| `media` | string | no | Declared media type of the primary payload. |
| `schema` | URI | no | Schema URI under which the recipient should interpret structured parts. |

## 7. Digest construction

### 7.1 `card_digest` — version pinning

```
card_digest.value = b64url( SHA-256( UTF8( JCS( cardSigningPayload(card) ) ) ) )
card_digest.alg   = "sha-256"
```

`cardSigningPayload(card)` is the A2A §8.4.1 signing payload: the card with
`signatures` removed and field-presence pre-processing applied (REQUIRED fields
kept even at default; proto3 explicit-presence `optional` fields kept whenever
present; implicit-presence fields dropped when equal to the proto default),
then RFC 8785 (JCS) canonicalized. The field-behavior table is normative — see
Appendix A. A verifier **MUST** compute this digest over the presence-processed
payload; computing it over the raw card JSON is nonconformant and will diverge
on any card carrying an explicitly-set default-valued optional field.

### 7.2 Per-part digests — domain separation

For each `Part`, in message order, the digest input is:

```
UTF8( JCS( header ) ) || 0x00 || content-bytes
```

where `header = { src, mediaType?, filename? }` and `src` is the Part oneof
member (`text`, `raw`, `url`, `data`). The single NUL byte separates the
canonical header from content so that no digest can be reinterpreted under a
different part kind, media type, or filename.

`content-bytes` by `src`:

| `src` | content-bytes |
|-------|---------------|
| `text` | exact UTF-8 code points of `text`, no Unicode normalization (producer contract) |
| `url` | exact UTF-8 code points of `url`, no normalization |
| `raw` | strict RFC 4648 §4 base64 decode of `raw` (canonical padding, standard alphabet, round-trip equality required) |
| `data` | hardened-JCS bytes of `data` (I-JSON profile; duplicate keys rejected) |

Each `parts[i]` entry is `{ src, alg: "sha-256", value, mediaType?, filename? }`.
The `mediaType`/`filename` in the entry **MUST** equal those fed into the header,
so relabeling breaks verification.

## 8. Procedures

### 8.1 Generation (sender / platform)

1. Construct the A2A `Message` (`messageId`, `role`, ordered `parts`).
2. Fetch the sender's current §8.4-signed Agent Card; compute `card_digest`
   (Section 7.1).
3. Compute ordered per-part digests (Section 7.2).
4. Assemble the claims set (Section 6.3); set `iss` to the platform origin and
   `sub` to the sender card URL (same origin).
5. Sign the claims as a compact JWS with the header of Section 6.2, using a
   dedicated message-signing key (Section 11 / FLO-9).
6. Store the JWS at the metadata key of Section 6.1; declare the extension URI
   in `message.extensions`.

In the blind-signing deployment (Variant A), the platform signs over the digest
material the sending agent submits and never holds message content. Variant B
(per-profile keys published in the card) is deferred — see Section 11 / FLO-9.

### 8.2 Verification (`live` and `audit` modes)

A verifier operates in one of two modes:

- **`live`** — enforces `exp` and a per-`aud` `jti` replay cache. For
  accept-now decisions.
- **`audit`** — validates the full chain (signatures, digests, card version)
  without freshness gating. For later dispute resolution and evidentiary use.

Steps (both modes):

1. Parse the token; reject if `typ` ≠ `a2a-msg-provenance+jwt` (Section 6.2).
2. Reject if `iss` is not in the trust-anchor allowlist. Resolve the issuer
   JWKS from the pinned anchor only (Section 4).
3. Reject if `kid` is absent from the pinned issuer JWKS. Verify the JWS
   signature over the claims.
4. Reject if the origin of `sub` differs from `iss`.
5. Fetch the card from `sub` (duplicate-key-rejecting parse). Verify at least
   one of its §8.4 signatures against the pinned card anchor, over
   `cardSigningPayload(card)`. (Any one of N signatures suffices — §8.4
   key-rotation rule.)
6. Reject if `card_digest` does not equal the digest recomputed over that
   card's signing payload (Section 7.1). This is the version-pinning check.
7. Reject if the received part count ≠ `parts.length`, or if any recomputed
   per-part digest (Section 7.2) differs, or if `msg`/`role` disagree with the
   message.
8. **live only:** reject if `exp` is in the past; reject if `jti` is already in
   the per-`aud` replay cache. Insert `jti` into the cache **only after all
   preceding checks pass**.

### 8.3 Anti-stripping (`verifyInbound`)

A verifier processing an inbound message SHOULD use a single entry point that
handles both the token-present and token-absent cases:

- token present → full verification (Section 8.2).
- token absent → fetch the sender's card; if it carries a signed
  `signsMessages: true` declaration (Section 5.2), **reject** the message as a
  stripped-token violation.

To resist rotate-to-undeclare downgrades (an attacker strips the token, then
mutates the card to drop the declaration), a verifier SHOULD pin an observed
`signsMessages: true` declaration with a TTL. The append-only historical card
index (Section 11 / FLO-9) is the durable answer.

## 9. Relationship to prior and adjacent work — STUB (FLO-6)

> TODO (FLO-6): position against the RFC 9421 identity stack (A2A #1829, #1496
> §6): object-level verify-later receipt vs transport request signature; pinned
> anchors vs self-dereferencing `keyid` URLs; `card_digest` version pinning
> (absent upstream). Map onto the community four-layer vocabulary (wire /
> identity / claims / continuity). Include the terminology disambiguation vs
> #2028 (unsigned actor/delegation chain that also uses "provenance"): ours
> means cryptographic, object-level message provenance.

## 10. Covered and uncovered fields — STUB (FLO-8)

> TODO (FLO-8): normative table of what the token does NOT protect —
> `Part.metadata`, `contextId`, `taskId`, `referenceTaskIds`, `message.metadata`
> siblings, and `tenant` (card and request level) — each with rationale. Plus
> forward-compatibility for a future Agent Card `id` (A2A #1014 / #1079): `sub`
> stays the card URL as the origin binding; a future `id` is surfaced as an
> additive claim, never a substitute for the URL-origin check.

## 11. Security Considerations — STUB (FLO-9)

> TODO (FLO-9): key substitution, token stripping, replay, cross-context reuse,
> and blind-signing (Variant A) non-repudiation liability, each with mitigation.
> Variant B (per-profile keys published in the card) normative sketch. Blind-
> signing MUSTs: dedicated message-signing keys separate from card keys,
> scheduled rotation, published expired private keys after a deniability window,
> rate/abuse controls on the signing endpoint. "Why not a Verifiable Credential
> / RFC 9421 / plain OAuth" rationale appendix.

## 12. Versioning and namespace — STUB (FLO-10)

> TODO (FLO-10): a breaking change MUST mint a new extension URI; graduation
> into the `https://a2a-protocol.org/extensions/{name}/v1` namespace is itself a
> breaking identifier change to plan for. The spec document SHOULD be hosted at
> the extension URI (A2A extensions guidance) — tracked as FLO-12 /
> flocker-pages#41. Neutral-namespace decision (moving off the `flocker.md` host)
> is open.

## Appendix A. §8.4.1 field-behavior table — STUB (FLO-7)

> TODO (FLO-7): machine-readable REQUIRED / EXPLICIT (proto3 `optional`) /
> IMPLICIT presence class for every field in the AgentCard tree, derived from
> `specification/a2a.proto` and matching the reference implementations
> (`scripts/presence.mjs`, flocker-pages `src/lib/a2a/v1/presence.ts`). Include
> the §8.4.1 worked example (`"streaming": false` retained). Verifiers cannot
> compute `card_digest` deterministically without this table.

## Appendix B. References

- A2A Protocol v1.0 — `specification/a2a.proto`, `docs/specification.md` §8.4,
  §8.4.1, §5.7; `docs/topics/extensions.md`;
  `docs/topics/extension-and-binding-governance.md`.
- RFC 7515 (JWS), RFC 7519 (JWT), RFC 7517 (JWK), RFC 8725 (JWT BCP).
- RFC 8785 (JSON Canonicalization Scheme), RFC 7493 (I-JSON), RFC 4648 (base64).
- RFC 2119, RFC 8174 (conformance language).
