# A2A Message Provenance Extension — v1

- **Status:** Draft (pre-proposal). Not yet submitted to the A2A project.
- **Extension URI:** `https://flocker.md/a2a/ext/message-provenance/v1`
- **Version:** 1.0.0-draft
- **License:** Apache License 2.0
- **Depends on:** A2A Protocol v1.0 (specification §8.4 Agent Card Signing, §8.4.1 field presence), RFC 7515 (JWS), RFC 7519 (JWT), RFC 8785 (JCS), RFC 8725 (JWT BCP).

> This is a working draft. Section 9 (Relationship to prior and adjacent work),
> Section 10 (Covered and uncovered fields), Section 11 (Security
> Considerations), and Section 12 (Versioning and namespace) are stubs to be
> completed in a subsequent revision. The wire format, generation, verification,
> and Appendix A (§8.4.1 field-behavior table) sections are normative and
> complete.

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
*(Positioning expanded in Section 9.)*

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
   dedicated message-signing key (Section 11).
6. Store the JWS at the metadata key of Section 6.1; declare the extension URI
   in `message.extensions`.

In the blind-signing deployment (Variant A), the platform signs over the digest
material the sending agent submits and never holds message content. Variant B
(per-profile keys published in the card) is deferred — see Section 11.

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
index (Section 11) is the durable answer.

## 9. Relationship to prior and adjacent work

Several efforts in the A2A ecosystem address agent identity and message
integrity. This extension is designed to compose with them, not to replace
them; a deployment may run any of them alongside this one.

### 9.1 The A2A identity and signing work

Discussion on the A2A repository has organized agent-identity work into roughly
four layers:

- **Wire signature** — signing the transport request itself. The leading
  proposal (issue #1829, and §6 of PR #1496) adopts RFC 9421 HTTP Message
  Signatures with Ed25519 over request components such as `@method`, `@path`,
  and `content-digest`.
- **Identity framework** — how an agent's identity and trust are established
  (PR #1496).
- **Identity claims** — the attributes asserted about an agent (issue #1786).
- **Continuity** — identity persistence across sessions and versions (issue
  #1575).

This extension sits on a different plane from all four: an object-level,
verify-later receipt that binds a specific message to a specific signed card
*version*. Its nearest neighbor is the wire-signature layer, and the contrast
with it is the clearest way to place this work.

### 9.2 Contrast with RFC 9421 transport request signing

| Property | RFC 9421 wire signature (#1829 / #1496 §6) | This extension |
|---|---|---|
| What is signed | The HTTP request — method, path, headers, body digest | The A2A message object — role and per-part content digests |
| Lifetime | The transport hop; verifiable by the receiving endpoint at request time | Travels in the message; verifiable later by a party who was not on the connection |
| Key resolution | A `keyid` / key URL dereferenced by the verifier | Pre-configured trust anchors only; in-token key URLs are never dereferenced (Section 4) |
| Card-version binding | None | `card_digest` pins the exact endorsed card version |

The two are complementary. RFC 9421 authenticates the live request between two
endpoints; this extension produces a durable, third-party-checkable receipt
bound to a card version. A deployment can apply both — the request is signed in
transit and each message additionally carries a provenance receipt.

### 9.3 Terminology: "provenance"

Other proposals use "provenance" for different guarantees. In particular, the
actor/delegation-chain work (issue #2028) records an *attribution* chain — who
acted on whose behalf — without a cryptographic binding of message content. In
this document, "provenance" means a cryptographic, object-level binding of a
message to the signed card version that endorsed it. The two are compatible and
can coexist in one message; they answer different questions.

### 9.4 Other approaches

The rationale for expressing this as a card-anchored JWT receipt rather than a
Verifiable Credential, a plain OAuth token, or a bespoke envelope is given in
Section 11.

## 10. Covered and uncovered fields

> TODO: normative table of what the token does NOT protect —
> `Part.metadata`, `contextId`, `taskId`, `referenceTaskIds`, `message.metadata`
> siblings, and `tenant` (card and request level) — each with rationale. Plus
> forward-compatibility for a future Agent Card `id` (A2A #1014 / #1079): `sub`
> stays the card URL as the origin binding; a future `id` is surfaced as an
> additive claim, never a substitute for the URL-origin check.

## 11. Security Considerations

> TODO: key substitution, token stripping, replay, cross-context reuse,
> and blind-signing (Variant A) non-repudiation liability, each with mitigation.
> Variant B (per-profile keys published in the card) normative sketch. Blind-
> signing MUSTs: dedicated message-signing keys separate from card keys,
> scheduled rotation, published expired private keys after a deniability window,
> rate/abuse controls on the signing endpoint. "Why not a Verifiable Credential
> / RFC 9421 / plain OAuth" rationale appendix.

## 12. Versioning and namespace

> TODO: a breaking change MUST mint a new extension URI; graduation
> into the `https://a2a-protocol.org/extensions/{name}/v1` namespace is itself a
> breaking identifier change to plan for. The spec document SHOULD be hosted at
> the extension URI (A2A extensions guidance), which is a conformance item for a
> conformant deployment. Neutral-namespace decision (moving off the `flocker.md`
> host) is open.

## Appendix A. §8.4.1 field-behavior table (normative)

`card_digest` (Section 7.1) is computed over the JCS of the card's §8.4.1
signing payload. Producing that payload requires knowing, for every field, its
Protocol Buffer presence class — and the core A2A specification ships no
machine-readable form of it. This appendix supplies one, derived from
`specification/a2a.proto` (v1.0). A verifier that does not apply these rules
will compute a divergent `card_digest` for any card carrying an explicitly-set
default-valued field. The reference implementation is `scripts/presence.mjs`.

### A.1 Presence classes and processing rules

Each field has one of three presence classes:

- **REQUIRED** — annotated `google.api.field_behavior = REQUIRED` in the proto.
  Always kept, even when the value equals the proto default.
- **EXPLICIT** — proto3 `optional` scalars, singular message fields, and
  `oneof` variants. Kept whenever the field is physically present in the JSON,
  because presence in the JSON means it was explicitly set — even to a value
  that equals the default (for example `"streaming": false`).
- **IMPLICIT** — plain (non-`optional`) scalars, `repeated`, and `map` fields.
  Omitted when the value equals the proto default.

The proto default is `""` (string), `false` (bool), `0` (number), `[]`
(repeated), or `{}` (message/map). A JSON `null` or absent key is treated as not
present.

Processing (applied before RFC 8785 canonicalization, at both sign and verify
time):

1. Remove the `signatures` field entirely; it is never part of the signing
   input (§8.4.1).
2. For each remaining field, look up its class in the table for the enclosing
   message. Drop IMPLICIT fields whose value equals the proto default; keep
   REQUIRED and EXPLICIT fields.
3. Recurse into message-typed fields (single, `repeated`, or `map`) using the
   referenced message's table.
4. A `google.protobuf.Struct` value (e.g. `AgentExtension.params`) is passed
   through verbatim; its internal keys are not presence-processed.
5. An unknown field (not in the table) is kept verbatim — its presence means it
   was explicitly set, and dropping it would break verification of a card that
   was signed over it.
6. JCS-canonicalize the result.

### A.2 Field tables

Field names below are the ProtoJSON (camelCase) names that appear in card JSON.
"→ Message" indicates recursion into another table; shape is single unless
marked repeated or map.

**AgentCard**

| Field | Class | Recurses into |
|-------|-------|---------------|
| `name` | REQUIRED | |
| `description` | REQUIRED | |
| `supportedInterfaces` | REQUIRED | AgentInterface (repeated) |
| `provider` | EXPLICIT | AgentProvider |
| `version` | REQUIRED | |
| `documentationUrl` | EXPLICIT | |
| `capabilities` | REQUIRED | AgentCapabilities |
| `securitySchemes` | IMPLICIT | SecurityScheme (map) |
| `securityRequirements` | IMPLICIT | SecurityRequirement (repeated) |
| `defaultInputModes` | REQUIRED | |
| `defaultOutputModes` | REQUIRED | |
| `skills` | REQUIRED | AgentSkill (repeated) |
| `signatures` | — | removed before processing (step 1) |
| `iconUrl` | EXPLICIT | |

**AgentInterface**

| Field | Class |
|-------|-------|
| `url` | REQUIRED |
| `protocolBinding` | REQUIRED |
| `tenant` | IMPLICIT |
| `protocolVersion` | REQUIRED |

**AgentProvider**

| Field | Class |
|-------|-------|
| `url` | REQUIRED |
| `organization` | REQUIRED |

**AgentCapabilities**

| Field | Class | Recurses into |
|-------|-------|---------------|
| `streaming` | EXPLICIT | |
| `pushNotifications` | EXPLICIT | |
| `extensions` | IMPLICIT | AgentExtension (repeated) |
| `extendedAgentCard` | EXPLICIT | |

**AgentExtension**

| Field | Class | Notes |
|-------|-------|-------|
| `uri` | IMPLICIT | |
| `description` | IMPLICIT | |
| `required` | IMPLICIT | |
| `params` | EXPLICIT | Struct — passed through verbatim (step 4) |

**AgentSkill**

| Field | Class | Recurses into |
|-------|-------|---------------|
| `id` | REQUIRED | |
| `name` | REQUIRED | |
| `description` | REQUIRED | |
| `tags` | REQUIRED | |
| `examples` | IMPLICIT | |
| `inputModes` | IMPLICIT | |
| `outputModes` | IMPLICIT | |
| `securityRequirements` | IMPLICIT | SecurityRequirement (repeated) |

**SecurityRequirement**

| Field | Class | Recurses into |
|-------|-------|---------------|
| `schemes` | IMPLICIT | StringList (map) |

**StringList**

| Field | Class |
|-------|-------|
| `list` | IMPLICIT |

**SecurityScheme** (a `oneof`; each present variant is an EXPLICIT message field)

| Field | Class | Recurses into |
|-------|-------|---------------|
| `apiKeySecurityScheme` | EXPLICIT | APIKeySecurityScheme |
| `httpAuthSecurityScheme` | EXPLICIT | HTTPAuthSecurityScheme |
| `oauth2SecurityScheme` | EXPLICIT | OAuth2SecurityScheme |
| `openIdConnectSecurityScheme` | EXPLICIT | OpenIdConnectSecurityScheme |
| `mtlsSecurityScheme` | EXPLICIT | MutualTlsSecurityScheme |

**APIKeySecurityScheme**

| Field | Class |
|-------|-------|
| `description` | IMPLICIT |
| `location` | REQUIRED |
| `name` | REQUIRED |

**HTTPAuthSecurityScheme**

| Field | Class |
|-------|-------|
| `description` | IMPLICIT |
| `scheme` | REQUIRED |
| `bearerFormat` | IMPLICIT |

**OAuth2SecurityScheme**

| Field | Class | Recurses into |
|-------|-------|---------------|
| `description` | IMPLICIT | |
| `flows` | REQUIRED | OAuthFlows |
| `oauth2MetadataUrl` | IMPLICIT | |

**OpenIdConnectSecurityScheme**

| Field | Class |
|-------|-------|
| `description` | IMPLICIT |
| `openIdConnectUrl` | REQUIRED |

**MutualTlsSecurityScheme**

| Field | Class |
|-------|-------|
| `description` | IMPLICIT |

**OAuthFlows** (each present variant is an EXPLICIT message field)

| Field | Class | Recurses into |
|-------|-------|---------------|
| `authorizationCode` | EXPLICIT | AuthorizationCodeOAuthFlow |
| `clientCredentials` | EXPLICIT | ClientCredentialsOAuthFlow |
| `deviceCode` | EXPLICIT | DeviceCodeOAuthFlow |
| `implicit` | EXPLICIT | ImplicitOAuthFlow |
| `password` | EXPLICIT | PasswordOAuthFlow |

**AuthorizationCodeOAuthFlow**

| Field | Class |
|-------|-------|
| `authorizationUrl` | REQUIRED |
| `tokenUrl` | REQUIRED |
| `refreshUrl` | IMPLICIT |
| `scopes` | REQUIRED |

**ClientCredentialsOAuthFlow**

| Field | Class |
|-------|-------|
| `tokenUrl` | REQUIRED |
| `refreshUrl` | IMPLICIT |
| `scopes` | REQUIRED |

**DeviceCodeOAuthFlow**

| Field | Class |
|-------|-------|
| `deviceAuthorizationUrl` | REQUIRED |
| `tokenUrl` | REQUIRED |
| `refreshUrl` | IMPLICIT |
| `scopes` | REQUIRED |

**ImplicitOAuthFlow**

| Field | Class |
|-------|-------|
| `authorizationUrl` | IMPLICIT |
| `refreshUrl` | IMPLICIT |
| `scopes` | IMPLICIT |

**PasswordOAuthFlow**

| Field | Class |
|-------|-------|
| `tokenUrl` | IMPLICIT |
| `refreshUrl` | IMPLICIT |
| `scopes` | IMPLICIT |

### A.3 Worked example

An illustrative card fragment that exercises all three classes at their default
values:

```json
{
  "name": "Example Agent",
  "description": "",
  "skills": [],
  "capabilities": {
    "streaming": false,
    "pushNotifications": false,
    "extensions": []
  }
}
```

After §8.4.1 processing and JCS canonicalization:

```json
{"capabilities":{"pushNotifications":false,"streaming":false},"description":"","name":"Example Agent","skills":[]}
```

`name`/`description`/`skills` are REQUIRED, so they are retained even though
`description` and `skills` hold default values. `streaming` and
`pushNotifications` are EXPLICIT and were physically present, so they are
retained despite equalling `false`. `extensions` is IMPLICIT and equals the
empty-array default, so it is dropped. (The fragment omits other REQUIRED
AgentCard fields for brevity; a real card MUST include them.)

## Appendix B. References

- A2A Protocol v1.0 — `specification/a2a.proto`, `docs/specification.md` §8.4,
  §8.4.1, §5.7; `docs/topics/extensions.md`;
  `docs/topics/extension-and-binding-governance.md`.
- RFC 7515 (JWS), RFC 7519 (JWT), RFC 7517 (JWK), RFC 8725 (JWT BCP).
- RFC 8785 (JSON Canonicalization Scheme), RFC 7493 (I-JSON), RFC 4648 (base64).
- RFC 2119, RFC 8174 (conformance language).
