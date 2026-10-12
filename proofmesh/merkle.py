"""Merkle trees over content-addressed chunks (RFC 6962 / RFC 9162 layout).

* Leaf hash:     ``SHA256(0x00 || chunk_id)`` where ``chunk_id = SHA256(chunk)``
* Interior hash: ``SHA256(0x01 || left || right)``
* A tree of ``n`` leaves is split at the largest power of two below ``n``.

The 0x00/0x01 prefixes provide domain separation, so an interior node can
never be passed off as a leaf (second-preimage attack). Signing the single
root commits the producer to every chunk; an inclusion proof of
``O(log n)`` hashes lets a consumer check one chunk against that signed root
without downloading the rest.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

_LEAF = b"\x00"
_NODE = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def leaf_hash(chunk_id_hex: str) -> bytes:
    return hashlib.sha256(_LEAF + bytes.fromhex(chunk_id_hex)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than ``n`` (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class MerkleTree:
    """Merkle tree over an ordered list of chunk ids, with memoised subtrees."""

    def __init__(self, chunk_ids: list[str]):
        self.chunk_ids = list(chunk_ids)
        self._leaves = [leaf_hash(c) for c in self.chunk_ids]
        self._memo: dict[tuple[int, int], bytes] = {}

    def __len__(self) -> int:
        return len(self._leaves)

    def subtree(self, lo: int, hi: int) -> bytes:
        """Hash of the subtree covering leaves ``[lo, hi)``."""
        key = (lo, hi)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        n = hi - lo
        if n == 1:
            h = self._leaves[lo]
        else:
            k = _split(n)
            h = node_hash(self.subtree(lo, lo + k), self.subtree(lo + k, hi))
        self._memo[key] = h
        return h

    @property
    def root(self) -> str:
        if not self._leaves:
            return EMPTY_ROOT
        return self.subtree(0, len(self._leaves)).hex()

    def inclusion_proof(self, index: int) -> list[str]:
        """Audit path for leaf ``index`` (RFC 9162 §2.1.3.1), leaf-to-root order."""
        n = len(self._leaves)
        if not 0 <= index < n:
            raise IndexError(f"leaf {index} out of range for tree of size {n}")
        path: list[str] = []

        def walk(m: int, lo: int, hi: int) -> None:
            size = hi - lo
            if size == 1:
                return
            k = _split(size)
            if m < k:
                walk(m, lo, lo + k)
                path.append(self.subtree(lo + k, hi).hex())
            else:
                walk(m - k, lo + k, hi)
                path.append(self.subtree(lo, lo + k).hex())

        walk(index, 0, n)
        return path


def merkle_root(chunk_ids: list[str]) -> str:
    return MerkleTree(chunk_ids).root


def verify_inclusion(chunk_id: str, index: int, tree_size: int, proof: list[str], root_hex: str) -> bool:
    """Check an inclusion proof (RFC 9162 §2.1.3.2)."""
    if not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(chunk_id)
    try:
        for p_hex in proof:
            p = bytes.fromhex(p_hex)
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                r = node_hash(p, r)
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
            else:
                r = node_hash(r, p)
            fn >>= 1
            sn >>= 1
    except ValueError:
        return False
    return sn == 0 and r.hex() == root_hex


@dataclass
class Localization:
    """Result of comparing two equally-sized Merkle trees top-down."""

    changed_leaves: list[int] = field(default_factory=list)
    comparisons: int = 0
    leaves: int = 0


def localize_changes(expected: MerkleTree, actual: MerkleTree) -> Localization:
    """Find differing leaves by descending only into subtrees whose hashes differ.

    With ``k`` modified chunks out of ``n`` this costs ``O(k log n)`` hash
    comparisons instead of ``n``: the property that makes Merkle trees useful
    for auditing very large datasets.
    """
    if len(expected) != len(actual):
        raise ValueError("trees must have the same number of leaves")
    result = Localization(leaves=len(expected))
    if not len(expected):
        return result

    def descend(lo: int, hi: int) -> None:
        result.comparisons += 1
        if expected.subtree(lo, hi) == actual.subtree(lo, hi):
            return
        if hi - lo == 1:
            result.changed_leaves.append(lo)
            return
        k = _split(hi - lo)
        descend(lo, lo + k)
        descend(lo + k, hi)

    descend(0, len(expected))
    return result
