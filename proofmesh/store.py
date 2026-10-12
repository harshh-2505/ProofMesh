"""Content-addressed chunk store.

Chunks live at ``objects/<first two hex chars>/<remaining hex>``. The file name
*is* the SHA-256 of the contents, so a stored object can always be checked by
re-hashing it. The store deliberately does not verify on read: verification
is the job of :mod:`proofmesh.verify`, which reports exactly what is wrong
instead of failing on the first bad byte.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .chunking import chunk_hash


class MissingChunk(KeyError):
    pass


class ChunkStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, cid: str) -> Path:
        if len(cid) != 64 or any(c not in "0123456789abcdef" for c in cid):
            raise ValueError(f"invalid chunk id {cid!r}")
        return self.root / cid[:2] / cid[2:]

    def put(self, data: bytes) -> str:
        cid = chunk_hash(data)
        dest = self.path(cid)
        if dest.exists() and chunk_hash(dest.read_bytes()) == cid:
            return cid  # deduplicated (a corrupted copy is overwritten below)
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, dest)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return cid

    def get(self, cid: str) -> bytes:
        try:
            return self.path(cid).read_bytes()
        except FileNotFoundError:
            raise MissingChunk(cid) from None

    def exists(self, cid: str) -> bool:
        return self.path(cid).exists()
