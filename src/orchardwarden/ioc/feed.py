"""Signed IOC feed bundles (Ed25519). Prototype of the plan's feed integrity control.

Envelope format (JSON):
  {"key_id": "...", "signed_at": "...", "payload": "<canonical JSON string>", "signature": "<base64>"}
The signature covers the exact UTF-8 bytes of the payload string, so no canonicalisation
ambiguity exists between signer and verifier.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class FeedError(Exception):
    pass


def generate_keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_b = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_b = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv_b, pub_b


def sign_bundle(bundle: dict, private_key: bytes, key_id: str) -> dict:
    payload = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    sig = Ed25519PrivateKey.from_private_bytes(private_key).sign(payload.encode("utf-8"))
    return {
        "key_id": key_id,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
        "signature": base64.b64encode(sig).decode("ascii"),
    }


def verify_envelope(envelope: dict, pinned_keys: dict[str, bytes]) -> dict:
    """Return the bundle dict if the signature verifies against a pinned key."""
    try:
        key_id = envelope["key_id"]
        payload = envelope["payload"]
        sig = base64.b64decode(envelope["signature"])
    except (KeyError, ValueError) as exc:
        raise FeedError("malformed feed envelope") from exc
    pub = pinned_keys.get(key_id)
    if pub is None:
        raise FeedError("unknown signing key id: " + str(key_id))
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload.encode("utf-8"))
    except InvalidSignature as exc:
        raise FeedError("signature verification failed") from exc
    return json.loads(payload)


def load_pinned_keys(path: Path) -> dict[str, bytes]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: base64.b64decode(v) for k, v in raw.items()}
