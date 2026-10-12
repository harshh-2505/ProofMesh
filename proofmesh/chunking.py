"""Content-defined chunking (FastCDC) and fixed-size chunking.

A dataset is split into chunks, and each chunk is identified by the SHA-256 of
its bytes (a *content-addressed chunk*). With content-defined chunking the cut
points depend on the bytes themselves (a rolling "gear" hash over roughly the
last 64 bytes), so inserting or deleting a few bytes only changes the chunks
around the edit instead of shifting every later chunk boundary. That keeps
tamper reports precise and lets unchanged chunks be deduplicated between
versions.

The implementation follows FastCDC (Xia et al., USENIX ATC '16) with
normalised chunking: a stricter mask before the target average size and a
looser one after it, which pulls chunk sizes towards the average.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Iterator

_MASK64 = (1 << 64) - 1

# 256 pseudo-random 64-bit values, derived deterministically so that every
# ProofMesh node computes identical cut points for identical bytes.
_GEAR = tuple(
    int.from_bytes(hashlib.sha256(b"proofmesh-gear-%d" % i).digest()[:8], "big")
    for i in range(256)
)


@dataclass(frozen=True)
class ChunkingParams:
    algorithm: str = "fastcdc"  # "fastcdc" or "fixed"
    min_size: int = 2048
    avg_size: int = 8192
    max_size: int = 65536

    def __post_init__(self) -> None:
        if self.algorithm not in ("fastcdc", "fixed"):
            raise ValueError(f"unknown chunking algorithm {self.algorithm!r}")
        if self.algorithm == "fastcdc":
            if self.avg_size & (self.avg_size - 1) or self.avg_size < 64:
                raise ValueError("avg_size must be a power of two >= 64")
            if not (0 < self.min_size <= self.avg_size <= self.max_size):
                raise ValueError("require 0 < min_size <= avg_size <= max_size")
        elif self.avg_size <= 0:
            raise ValueError("fixed chunk size must be positive")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ChunkingParams":
        return cls(**{k: d[k] for k in ("algorithm", "min_size", "avg_size", "max_size")})


DEFAULT_PARAMS = ChunkingParams()


def _masks(avg_size: int) -> tuple[int, int]:
    bits = avg_size.bit_length() - 1
    # Use the *high* bits of the gear hash: with a shift-left rolling hash they
    # depend on the most bytes, so they are the best mixed.
    strict = ((1 << (bits + 1)) - 1) << (64 - (bits + 1))
    loose = ((1 << (bits - 1)) - 1) << (64 - (bits - 1))
    return strict, loose


def _fastcdc_cut(data: memoryview, start: int, p: ChunkingParams, strict: int, loose: int) -> int:
    """Return the end offset (exclusive) of the chunk beginning at ``start``."""
    remaining = len(data) - start
    if remaining <= p.min_size:
        return len(data)
    stop = start + min(remaining, p.max_size)
    normal = start + min(remaining, p.avg_size)
    gear = _GEAR
    h = 0
    i = start + p.min_size
    while i < normal:
        h = ((h << 1) + gear[data[i]]) & _MASK64
        if not h & strict:
            return i + 1
        i += 1
    while i < stop:
        h = ((h << 1) + gear[data[i]]) & _MASK64
        if not h & loose:
            return i + 1
        i += 1
    return stop


def iter_chunks(data: bytes, params: ChunkingParams = DEFAULT_PARAMS) -> Iterator[tuple[int, bytes]]:
    """Yield ``(offset, chunk_bytes)`` covering ``data`` exactly once, in order."""
    view = memoryview(data)
    n = len(view)
    if params.algorithm == "fixed":
        for off in range(0, n, params.avg_size):
            yield off, bytes(view[off : off + params.avg_size])
        return
    strict, loose = _masks(params.avg_size)
    off = 0
    while off < n:
        end = _fastcdc_cut(view, off, params, strict, loose)
        yield off, bytes(view[off:end])
        off = end


def chunk_hash(chunk: bytes) -> str:
    return hashlib.sha256(chunk).hexdigest()
