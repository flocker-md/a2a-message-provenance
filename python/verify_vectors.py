#!/usr/bin/env python3
"""Independent Python cross-check of the A2A message-provenance golden vectors.

Reproduces the JavaScript reference implementation byte-for-byte:

  * §8.4.1 field-presence pre-processing (ported from the normative Appendix A
    field-behavior table),
  * the card_digest (SHA-256 over UTF8(JCS(cardSigningPayload(card)))),
  * the domain-separated per-part digests
    (UTF8(JCS(header)) || 0x00 || content-bytes, §7.2),

and verifies the embedded JS-signed ES256 token against the embedded PUBLIC JWK.

Deliberately independent of the JS impl:
  * JCS comes from the `rfc8785` PyPI package (a vetted RFC 8785 implementation),
    NOT a hand-rolled canonicalizer.
  * ES256 verification uses `cryptography`.

Run:
    python3 -m venv .venv && . .venv/bin/activate
    pip install -r python/requirements.txt
    python python/verify_vectors.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import rfc8785  # RFC 8785 JCS — vetted library, not hand-rolled
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

VECTORS_PATH = Path(__file__).resolve().parent.parent / "test-vectors" / "golden.json"


# ---------------------------------------------------------------------------
# JCS: delegate to the rfc8785 package. jcs_bytes returns the canonical UTF-8
# bytes; jcs_str the string. rfc8785.dumps() returns bytes.
# ---------------------------------------------------------------------------
def jcs_bytes(value: Any) -> bytes:
    return rfc8785.dumps(value)


def jcs_str(value: Any) -> str:
    return jcs_bytes(value).decode("utf-8")


# ---------------------------------------------------------------------------
# base64url WITHOUT padding — matches Node's Buffer.toString('base64url').
# ---------------------------------------------------------------------------
def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sha256_b64url(data: bytes) -> str:
    return b64url_nopad(hashlib.sha256(data).digest())


# ---------------------------------------------------------------------------
# Strict RFC 4648 §4 base64 decode for `raw` parts: standard alphabet only,
# correct padding, no whitespace, canonical round-trip. Mirrors
# strictBase64Decode in scripts/jcs.mjs.
# ---------------------------------------------------------------------------
_STRICT_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def strict_base64_decode(s: str) -> bytes:
    if not isinstance(s, str) or len(s) % 4 != 0 or not _STRICT_B64_RE.match(s):
        raise ValueError("invalid strict base64")
    raw = base64.b64decode(s, validate=True)
    if base64.b64encode(raw).decode("ascii") != s:
        raise ValueError("non-canonical base64 encoding")
    return raw


# ---------------------------------------------------------------------------
# §8.4.1 field-behavior table (normative Appendix A), ported from presence.mjs.
# presence: REQUIRED | EXPLICIT | IMPLICIT
# message:  name of the referenced sub-message table (recursion)
# shape:    single (default) | repeated | map
# struct:   True -> pass value through verbatim (google.protobuf.Struct)
# ---------------------------------------------------------------------------
def R(**kw): return {"presence": "REQUIRED", **kw}
def E(**kw): return {"presence": "EXPLICIT", **kw}
def I(**kw): return {"presence": "IMPLICIT", **kw}


FIELD_BEHAVIOR: dict[str, dict[str, dict]] = {
    "AgentCard": {
        "name": R(),
        "description": R(),
        "supportedInterfaces": R(message="AgentInterface", shape="repeated"),
        "provider": E(message="AgentProvider"),
        "version": R(),
        "documentationUrl": E(),
        "capabilities": R(message="AgentCapabilities"),
        "securitySchemes": I(message="SecurityScheme", shape="map"),
        "securityRequirements": I(message="SecurityRequirement", shape="repeated"),
        "defaultInputModes": R(),
        "defaultOutputModes": R(),
        "skills": R(message="AgentSkill", shape="repeated"),
        "signatures": I(shape="repeated"),
        "iconUrl": E(),
    },
    "AgentInterface": {
        "url": R(),
        "protocolBinding": R(),
        "tenant": I(),
        "protocolVersion": R(),
    },
    "AgentProvider": {
        "url": R(),
        "organization": R(),
    },
    "AgentCapabilities": {
        "streaming": E(),
        "pushNotifications": E(),
        "extensions": I(message="AgentExtension", shape="repeated"),
        "extendedAgentCard": E(),
    },
    "AgentExtension": {
        "uri": I(),
        "description": I(),
        "required": I(),
        "params": E(struct=True),
    },
    "AgentSkill": {
        "id": R(),
        "name": R(),
        "description": R(),
        "tags": R(),
        "examples": I(),
        "inputModes": I(),
        "outputModes": I(),
        "securityRequirements": I(message="SecurityRequirement", shape="repeated"),
    },
    "SecurityRequirement": {
        "schemes": I(message="StringList", shape="map"),
    },
    "StringList": {
        "list": I(),
    },
    "SecurityScheme": {
        "apiKeySecurityScheme": E(message="APIKeySecurityScheme"),
        "httpAuthSecurityScheme": E(message="HTTPAuthSecurityScheme"),
        "oauth2SecurityScheme": E(message="OAuth2SecurityScheme"),
        "openIdConnectSecurityScheme": E(message="OpenIdConnectSecurityScheme"),
        "mtlsSecurityScheme": E(message="MutualTlsSecurityScheme"),
    },
    "APIKeySecurityScheme": {
        "description": I(),
        "location": R(),
        "name": R(),
    },
    "HTTPAuthSecurityScheme": {
        "description": I(),
        "scheme": R(),
        "bearerFormat": I(),
    },
    "OAuth2SecurityScheme": {
        "description": I(),
        "flows": R(message="OAuthFlows"),
        "oauth2MetadataUrl": I(),
    },
    "OpenIdConnectSecurityScheme": {
        "description": I(),
        "openIdConnectUrl": R(),
    },
    "MutualTlsSecurityScheme": {
        "description": I(),
    },
    "OAuthFlows": {
        "authorizationCode": E(message="AuthorizationCodeOAuthFlow"),
        "clientCredentials": E(message="ClientCredentialsOAuthFlow"),
        "deviceCode": E(message="DeviceCodeOAuthFlow"),
        "implicit": E(message="ImplicitOAuthFlow"),
        "password": E(message="PasswordOAuthFlow"),
    },
    "AuthorizationCodeOAuthFlow": {
        "authorizationUrl": R(),
        "tokenUrl": R(),
        "refreshUrl": I(),
        "scopes": R(),
    },
    "ClientCredentialsOAuthFlow": {
        "tokenUrl": R(),
        "refreshUrl": I(),
        "scopes": R(),
    },
    "DeviceCodeOAuthFlow": {
        "deviceAuthorizationUrl": R(),
        "tokenUrl": R(),
        "refreshUrl": I(),
        "scopes": R(),
    },
    "ImplicitOAuthFlow": {
        "authorizationUrl": I(),
        "refreshUrl": I(),
        "scopes": I(),
    },
    "PasswordOAuthFlow": {
        "tokenUrl": I(),
        "refreshUrl": I(),
        "scopes": I(),
    },
}


def _is_plain_object(v: Any) -> bool:
    return isinstance(v, dict)


def _is_proto_default(v: Any) -> bool:
    # Mirrors isProtoDefault in presence.mjs. Note: JS `false === 0` short-circuit
    # is not reproduced here (Python bool is int, but False is the bool default
    # and 0 the number default; both count as default, matching the intent).
    if v is None:
        return True
    if v == "" and isinstance(v, str):
        return True
    if v is False:
        return True
    if v == 0 and isinstance(v, (int, float)) and not isinstance(v, bool):
        return True
    if isinstance(v, list) and len(v) == 0:
        return True
    if isinstance(v, dict) and len(v) == 0:
        return True
    return False


def _process_value(value: Any, rule: dict) -> Any:
    if rule.get("struct") or "message" not in rule:
        return value
    shape = rule.get("shape", "single")
    message = rule["message"]
    if shape == "repeated" and isinstance(value, list):
        return [_process_message(item, message) if _is_plain_object(item) else item for item in value]
    if shape == "map" and isinstance(value, dict):
        return {k: (_process_message(v, message) if _is_plain_object(v) else v) for k, v in value.items()}
    if shape == "single" and isinstance(value, dict):
        return _process_message(value, message)
    return value


def _process_message(obj: dict, message_name: str) -> dict:
    spec = FIELD_BEHAVIOR.get(message_name)
    out: dict[str, Any] = {}
    for key, raw in obj.items():
        if raw is None:
            # JS iterates own enumerable keys; `undefined` values are skipped.
            # JSON has no undefined; treat null as "not present" per Appendix A
            # ("A JSON null or absent key is treated as not present.").
            # For IMPLICIT this is also a proto default and would be dropped;
            # for REQUIRED/EXPLICIT a literal null is unusual — keep parity with
            # JS which would keep an explicit null. Here we mirror the presence
            # rule below rather than special-casing.
            pass
        rule = spec.get(key) if spec else None
        if rule is None:
            out[key] = raw  # unknown field kept verbatim (step 5)
            continue
        value = _process_value(raw, rule)
        if rule["presence"] == "IMPLICIT" and _is_proto_default(value):
            continue
        out[key] = value
    return out


def card_signing_payload(card: dict) -> dict:
    unsigned = {k: v for k, v in card.items() if k != "signatures"}
    return _process_message(unsigned, "AgentCard")


def card_digest(card: dict) -> dict:
    payload = jcs_bytes(card_signing_payload(card))
    return {"alg": "sha-256", "value": sha256_b64url(payload)}


# ---------------------------------------------------------------------------
# §7.2 per-part digest.
# ---------------------------------------------------------------------------
def digest_part(part: dict) -> dict:
    if "text" in part:
        src, content = "text", part["text"].encode("utf-8")
    elif "raw" in part:
        src, content = "raw", strict_base64_decode(part["raw"])
    elif "url" in part:
        src, content = "url", part["url"].encode("utf-8")
    elif "data" in part:
        src, content = "data", jcs_bytes(part["data"])
    else:
        raise ValueError("Part has no recognized content member")

    header: dict[str, Any] = {"src": src}
    if part.get("mediaType"):
        header["mediaType"] = part["mediaType"]
    if part.get("filename"):
        header["filename"] = part["filename"]

    digest_input = jcs_bytes(header) + b"\x00" + content
    entry = {**header, "alg": "sha-256", "value": sha256_b64url(digest_input)}
    return entry


# ---------------------------------------------------------------------------
# ES256 verification of the compact JWS token against the embedded public JWK.
# ---------------------------------------------------------------------------
def verify_es256_token(token: str, public_jwk: dict) -> bool:
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    x = int.from_bytes(b64url_decode(public_jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(public_jwk["y"]), "big")
    public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

    # JWS ES256 signatures are raw R||S (IEEE P1363); convert to DER for cryptography.
    sig = b64url_decode(sig_b64)
    n = len(sig) // 2
    r = int.from_bytes(sig[:n], "big")
    s = int.from_bytes(sig[n:], "big")
    der = encode_dss_signature(r, s)

    try:
        public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------
class Checks:
    def __init__(self) -> None:
        self.failures = 0

    def check(self, label: str, ok: bool, got: Any = None, want: Any = None) -> None:
        mark = "PASS" if ok else "FAIL"
        print(f"  {mark}  {label}")
        if not ok:
            self.failures += 1
            print(f"        got : {got!r}")
            print(f"        want: {want!r}")


def main() -> int:
    if not VECTORS_PATH.exists():
        print(f"ERROR: vectors not found at {VECTORS_PATH}", file=sys.stderr)
        print("Generate them first: node scripts/gen-golden.mjs", file=sys.stderr)
        return 2

    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    checks = Checks()

    print("== §8.4.1 canonical card signing payload ==")
    py_payload = jcs_str(card_signing_payload(vectors["input_card"]))
    checks.check(
        "card_payload_canonical byte-for-byte",
        py_payload == vectors["card_payload_canonical"],
        py_payload,
        vectors["card_payload_canonical"],
    )

    print("== card_digest ==")
    py_card_digest = card_digest(vectors["input_card"])
    checks.check(
        "card_digest matches (alg + value)",
        py_card_digest == vectors["card_digest"],
        py_card_digest,
        vectors["card_digest"],
    )

    print("== per-part digests (§7.2) ==")
    for i, entry in enumerate(vectors["parts"]):
        py_digest = digest_part(entry["input"])
        want = entry["digest"]
        checks.check(
            f"part[{i}] src={want['src']} digest matches",
            py_digest == want,
            py_digest,
            want,
        )

    print("== token ES256 signature (cross-language verify) ==")
    ok = verify_es256_token(vectors["token"], vectors["public_jwk"])
    checks.check("embedded JS-signed token verifies against public JWK", ok)

    # Also confirm the claims the JS side signed embed the same digests we recomputed.
    claims = vectors["token_claims"]
    checks.check(
        "token claims card_digest == recomputed card_digest",
        claims["card_digest"] == py_card_digest,
        claims["card_digest"],
        py_card_digest,
    )
    py_parts = [digest_part(entry["input"]) for entry in vectors["parts"]]
    checks.check(
        "token claims parts == recomputed part digests",
        claims["parts"] == py_parts,
        claims["parts"],
        py_parts,
    )

    print()
    if checks.failures == 0:
        print("ALL CHECKS PASSED — Python reproduced the canonical payload, "
              "every digest, and verified the JS-signed token.")
        return 0
    print(f"{checks.failures} CHECK(S) FAILED.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
