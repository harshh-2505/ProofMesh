import random

import pytest

from proofmesh.chunking import ChunkingParams, chunk_hash, iter_chunks

P = ChunkingParams("fastcdc", 256, 1024, 4096)


def data(n=200_000, seed=1):
    return random.Random(seed).randbytes(n)


def test_chunks_cover_input_exactly():
    d = data()
    pieces = list(iter_chunks(d, P))
    assert b"".join(c for _, c in pieces) == d
    off = 0
    for o, c in pieces:
        assert o == off
        off += len(c)


def test_chunk_sizes_respect_bounds():
    pieces = list(iter_chunks(data(), P))
    for _, c in pieces[:-1]:
        assert P.min_size < len(c) <= P.max_size
    avg = sum(len(c) for _, c in pieces) / len(pieces)
    assert 0.5 * P.avg_size < avg < 2.5 * P.avg_size


def test_deterministic():
    d = data()
    assert [chunk_hash(c) for _, c in iter_chunks(d, P)] == [chunk_hash(c) for _, c in iter_chunks(d, P)]


def test_content_defined_boundaries_survive_insertion():
    d = data()
    edited = d[:5000] + b"INSERTED BYTES" + d[5000:]
    before = {chunk_hash(c) for _, c in iter_chunks(d, P)}
    after = [chunk_hash(c) for _, c in iter_chunks(edited, P)]
    new = [h for h in after if h not in before]
    assert len(new) <= 3, "an insertion should only disturb the chunks around it"

    fixed = ChunkingParams("fixed", 1024, 1024, 1024)
    before_f = {chunk_hash(c) for _, c in iter_chunks(d, fixed)}
    after_f = [chunk_hash(c) for _, c in iter_chunks(edited, fixed)]
    assert sum(h not in before_f for h in after_f) > len(after_f) * 0.9  # fixed-size shifts everything


def test_small_and_empty_inputs():
    assert list(iter_chunks(b"", P)) == []
    assert list(iter_chunks(b"abc", P)) == [(0, b"abc")]


def test_invalid_params():
    with pytest.raises(ValueError):
        ChunkingParams("fastcdc", 100, 1000, 4000)  # avg not a power of two
    with pytest.raises(ValueError):
        ChunkingParams("fastcdc", 2048, 1024, 4096)
    with pytest.raises(ValueError):
        ChunkingParams("rabin", 1, 1024, 2048)
