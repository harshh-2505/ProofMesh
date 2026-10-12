"""Canonical encoding and hashing.

Everything ProofMesh signs or hashes is first turned into *canonical JSON*:
keys sorted, no insignificant whitespace, UTF-8, no NaN/Infinity. Two parties
that hold the same logical document therefore always compute the same bytes,
the same hash and can check the same signature.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

HASH_ALGORITHM = "sha256"


def canonical_json(obj: Any) -> bytes:
    """Serialise ``obj`` deterministically."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    """Content identifier of a JSON document: sha256 of its canonical form."""
    return sha256_hex(canonical_json(obj))


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
