# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting
on this repository:
<https://github.com/flocker-md/a2a-message-provenance/security/advisories/new>.

Do not open a public issue or PR for a security problem.

You should receive an acknowledgement within a few days. Please include the
affected file or specification section and, where relevant, a reproduction.

## Scope

This repository is a specification and a reference implementation. Two kinds of
report belong here:

- **Specification weaknesses** — a way to forge, replay, strip, or misattribute a
  provenance receipt that the verification procedure (spec Section 8) fails to
  reject; a gap in the covered-fields analysis (Section 10); or a domain-separation
  or canonicalization flaw. These are the most valuable reports: a flaw in the
  design affects every implementation.
- **Reference-implementation bugs** — a script under `scripts/` that accepts a
  token it should reject, or diverges from the spec it implements.

The signing keys in this repository are mock and ephemeral (`scripts/generate-keys.mjs`);
the reference implementation is for conformance demonstration, not production use.
The one exception is the live Agent Card fetch in `verify-message.mjs`, which
reads a real, publicly served, §8.4-signed card — public data only.

A vulnerability in the A2A protocol itself belongs upstream at
[a2aproject/A2A](https://github.com/a2aproject/A2A).

## Supported versions

Pre-standardization, only the current draft (`v1.0.0-draft`) receives fixes.
