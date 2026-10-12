import hashlib

import pytest

from proofmesh.merkle import EMPTY_ROOT, MerkleTree, leaf_hash, localize_changes, merkle_root, node_hash, verify_inclusion


def ids(n, salt=b""):
    return [hashlib.sha256(salt + i.to_bytes(4, "big")).hexdigest() for i in range(n)]


def test_empty_and_single():
    assert merkle_root([]) == EMPTY_ROOT
    one = ids(1)
    assert merkle_root(one) == leaf_hash(one[0]).hex()


def test_rfc6962_shape():
    a, b, c = ids(3)
    expected = node_hash(node_hash(leaf_hash(a), leaf_hash(b)), leaf_hash(c)).hex()
    assert merkle_root([a, b, c]) == expected


def test_root_changes_with_any_leaf_or_order():
    leaves = ids(10)
    root = merkle_root(leaves)
    for i in range(10):
        changed = list(leaves)
        changed[i] = hashlib.sha256(b"evil").hexdigest()
        assert merkle_root(changed) != root
    assert merkle_root(list(reversed(leaves))) != root


def test_leaf_and_node_are_domain_separated():
    a, b = ids(2)
    # An interior node must never equal the leaf hash of its own concatenation.
    assert node_hash(leaf_hash(a), leaf_hash(b)) != leaf_hash((leaf_hash(a) + leaf_hash(b)).hex()[:64])


@pytest.mark.parametrize("n", list(range(1, 34)) + [100, 257])
def test_inclusion_proofs_verify_for_every_leaf(n):
    leaves = ids(n)
    tree = MerkleTree(leaves)
    for i in range(n):
        assert verify_inclusion(leaves[i], i, n, tree.inclusion_proof(i), tree.root)


def test_inclusion_proof_rejects_wrong_data_index_or_root():
    leaves = ids(21)
    tree = MerkleTree(leaves)
    proof = tree.inclusion_proof(7)
    assert not verify_inclusion(leaves[8], 7, 21, proof, tree.root)
    assert not verify_inclusion(leaves[7], 8, 21, proof, tree.root)
    # The tree size is authenticated by the signed manifest (chunk_count); a size
    # that implies a different path shape must fail.
    assert not verify_inclusion(leaves[7], 7, 64, proof, tree.root)
    assert not verify_inclusion(leaves[7], 7, 8, proof, tree.root)
    assert not verify_inclusion(leaves[7], 7, 21, proof, merkle_root(ids(21, b"x")))
    bad = list(proof)
    bad[0] = "00" * 32
    assert not verify_inclusion(leaves[7], 7, 21, bad, tree.root)
    assert not verify_inclusion(leaves[7], 7, 21, proof[:-1], tree.root)


def test_localize_changes_is_logarithmic():
    n = 1024
    expected = ids(n)
    actual = list(expected)
    actual[613] = hashlib.sha256(b"tampered").hexdigest()
    loc = localize_changes(MerkleTree(expected), MerkleTree(actual))
    assert loc.changed_leaves == [613]
    assert loc.comparisons <= 2 * 10 + 1  # ~2 log2(n), not n


def test_localize_multiple_changes():
    expected = ids(50)
    actual = list(expected)
    for i in (0, 17, 49):
        actual[i] = hashlib.sha256(b"x%d" % i).hexdigest()
    loc = localize_changes(MerkleTree(expected), MerkleTree(actual))
    assert loc.changed_leaves == [0, 17, 49]
