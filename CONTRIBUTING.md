# Contributing

Thanks for your interest in the A2A message-provenance extension. This repository
holds a specification and a reference implementation; both are pre-proposal and
open to revision.

Issues and pull requests are welcome. For anything larger than a fix — a change
to the wire format, claim semantics, digest construction, or the verification
procedure — open an issue first so the approach can be agreed before you invest
time. Independent co-implementers are especially welcome; a second interoperable
implementation is the strongest signal this extension is ready to standardize.

## Setup

Node 20 or newer:

```sh
npm install                      # ajv + ajv-formats, for schema conformance
npm test                         # full pipeline: JCS + presence + schema + sign + verify
```

Individual stages are documented in the [README](README.md#reference-implementation).

## Making a change

- Work on a feature branch and open a PR against `main`.
- `npm test` must pass. New behavior needs a matching vector or negative case in
  the existing style (the suites are table-driven and hermetic apart from the one
  live Agent Card fetch in `verify-message.mjs`).
- Cross-language changes must keep the golden vectors reproducible: regenerate
  with `node scripts/gen-golden.mjs` and confirm `python/verify_vectors.py` still
  round-trips byte-for-byte.
- Comments are one-liners, and only where the code alone would mislead.

## Changing the specification

The spec is normative and versioned by URI. Follow Section 12:

- A backward-compatible addition MAY be made under the existing `…/v1` URI.
- Any change to the wire format, claim semantics, or digest construction MUST be
  published under a new extension URI (for example `…/message-provenance/v2`).
- Keep the spec, the JSON Schemas under `schema/`, and the reference
  implementation in lockstep — a PR that changes one should change the others.

## Security issues

Do not open a public issue or PR for a vulnerability — see [SECURITY.md](SECURITY.md).
