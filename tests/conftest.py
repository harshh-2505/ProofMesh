import pytest

from proofmesh import ProofMesh
from proofmesh import demo


@pytest.fixture
def mesh(tmp_path):
    m = ProofMesh.init(tmp_path / "node", chunking=demo.DEMO_CHUNKING)
    yield m
    m.close()


@pytest.fixture
def scenario(mesh):
    """The demo mesh: finance -> operations -> executive, plus an independent HR source."""
    manifests = demo.build_scenario(mesh)
    return mesh, manifests
