"""Ed25519 identities, domain certificates and signatures.

Trust model
-----------
* The mesh has one **governance authority** key. Its public key is the only
  thing a verifier must obtain out of band (``trust/authority.pub``).
* Every department (a *domain* in data-mesh terms) owns an Ed25519 key pair.
  The authority issues it a **domain certificate** binding the domain name to
  its public key.
* Domains sign manifests and log entries with their own key. A verifier checks
  the certificate against the pinned authority key, then the payload against
  the certificate's key.

Every signature covers ``context || 0x00 || canonical_json(body)`` so a
signature made for one kind of document can never be replayed as another.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_json, sha256_hex

CTX_CERTIFICATE = "proofmesh/domain-certificate/v1"
CTX_MANIFEST = "proofmesh/manifest/v1"
CTX_REGISTRATION = "proofmesh/product-registration/v1"
CTX_EVENT = "proofmesh/event/v1"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def key_id_for(public_key_b64: str) -> str:
    """Short, stable fingerprint of a public key."""
    return sha256_hex(_unb64(public_key_b64))[:16]


def signing_payload(context: str, body: Any) -> bytes:
    return context.encode("ascii") + b"\x00" + canonical_json(body)


class SigningKey:
    """An Ed25519 private key plus convenience helpers."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.public_key_b64 = _b64(raw)
        self.key_id = key_id_for(self.public_key_b64)

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: Path) -> "SigningKey":
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 private key")
        return cls(key)

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = self._sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)

    def sign(self, context: str, body: Any) -> str:
        return _b64(self._sk.sign(signing_payload(context, body)))


def verify_signature(public_key_b64: str, context: str, body: Any, signature_b64: str) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(_unb64(public_key_b64))
        pk.verify(_unb64(signature_b64), signing_payload(context, body))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --------------------------------------------------------------------------
# Domain certificates
# --------------------------------------------------------------------------

def issue_certificate(
    authority: SigningKey, domain: str, public_key_b64: str, issued_at: str
) -> dict:
    body = {
        "type": "proofmesh/domain-certificate",
        "domain": domain,
        "public_key": public_key_b64,
        "key_id": key_id_for(public_key_b64),
        "issuer_key_id": authority.key_id,
        "issued_at": issued_at,
    }
    return {"certificate": body, "signature": authority.sign(CTX_CERTIFICATE, body)}


def check_certificate(envelope: dict, authority_public_key_b64: str) -> tuple[bool, str]:
    """Return ``(ok, reason)`` for a domain certificate envelope."""
    try:
        body = envelope["certificate"]
        sig = envelope["signature"]
    except (KeyError, TypeError):
        return False, "malformed certificate envelope"
    if body.get("type") != "proofmesh/domain-certificate":
        return False, "not a domain certificate"
    if body.get("issuer_key_id") != key_id_for(authority_public_key_b64):
        return False, "certificate was not issued by the trusted mesh authority"
    if body.get("key_id") != key_id_for(body.get("public_key", "")):
        return False, "certificate key_id does not match its public key"
    if not verify_signature(authority_public_key_b64, CTX_CERTIFICATE, body, sig):
        return False, "authority signature on certificate is invalid"
    return True, f"certificate for '{body['domain']}' issued by mesh authority {body['issuer_key_id']}"
