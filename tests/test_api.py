import pytest
from fastapi.testclient import TestClient

from proofmesh import api


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PROOFMESH_ROOT", str(tmp_path / "node"))
    monkeypatch.setenv("PROOFMESH_DEMO", "1")
    api.state.mesh = None
    with TestClient(api.app) as c:
        yield c
    if api.state.mesh:
        api.state.mesh.close()
        api.state.mesh = None


def test_ui_and_overview(client):
    assert "ProofMesh" in client.get("/").text
    ov = client.get("/api/overview").json()
    assert ov["demo_mode"] and ov["counts"]["VERIFIED"] == 6
    g = client.get("/api/lineage").json()
    assert len(g["nodes"]) == 6 and len(g["edges"]) == 5


def test_tamper_flow(client):
    assert client.get("/api/products/finance.transactions/data").status_code == 200
    t = client.post("/api/demo/tamper").json()
    rep = client.get("/api/products/finance.transactions/verify").json()
    assert rep["status"] == "TAMPERED"
    assert rep["content"]["tampered_chunks"][0]["index"] == t["chunk_index"]
    assert len(rep["affected_downstream"]) == 4
    r = client.get("/api/products/executive.cost-per-head/data")
    assert r.status_code == 409 and r.json()["report"]["status"] == "TAINTED"
    ov = client.get("/api/overview").json()
    assert ov["counts"] == {"VERIFIED": 1, "TAINTED": 4, "TAMPERED": 1, "INVALID": 0}
    client.post("/api/demo/cover-tracks")
    assert client.get("/api/products/finance.transactions/verify").json()["status"] == "INVALID"
    client.post("/api/demo/reset")
    assert client.get("/api/overview").json()["counts"]["VERIFIED"] == 6


def test_register_publish_derive(client):
    assert client.post("/api/domains", json={"name": "sales"}).status_code == 201
    contract = {"schema": {"format": "csv", "columns": [{"name": "region", "required": True},
                                                       {"name": "revenue", "type": "decimal"}]},
                "permitted_purposes": ["financial-reporting"]}
    assert client.post("/api/products", json={"product_id": "sales.revenue", "owner": "sales",
                                              "contract": contract}).status_code == 201
    r = client.post("/api/products/sales.revenue/versions?filename=rev.csv",
                    content=b"region,revenue\nEMEA,10.5\nAPAC,20\n",
                    headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 201, r.text
    assert r.json()["manifest"]["product"]["version"] == 1
    bad = client.post("/api/products/sales.revenue/versions", content=b"region,revenue\n,x\n")
    assert bad.status_code == 422
    client.post("/api/products", json={"product_id": "sales.big", "owner": "sales", "contract": contract})
    d = client.post("/api/products/sales.big/derive", json={
        "inputs": ["sales.revenue"], "transform": "filter_rows",
        "params": {"column": "revenue", "op": "gt", "value": 15}, "purpose": "financial-reporting"})
    assert d.status_code == 201, d.text
    data = client.get("/api/products/sales.big/data").content
    assert data == b"region,revenue\nAPAC,20\n"
    denied = client.post("/api/products/sales.big/derive", json={
        "inputs": ["sales.revenue"], "transform": "filter_rows",
        "params": {"column": "revenue", "op": "gt", "value": 15}, "purpose": "marketing"})
    assert denied.status_code == 403
    assert client.get("/api/products/nope.nothing").status_code == 404
    proof = client.get("/api/products/sales.revenue/proof/0").json()
    assert proof["verified"]
    check = client.post("/api/products/sales.revenue/verify-file", content=b"region,revenue\nEMEA,10.5\nAPAC,21\n").json()
    assert not check["matches"]


def test_demo_endpoints_disabled_without_flag(client, monkeypatch):
    monkeypatch.delenv("PROOFMESH_DEMO")
    assert client.post("/api/demo/tamper").status_code == 404
