import pytest
from fastapi.testclient import TestClient

from proofmesh import api, demo, lab


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PROOFMESH_ROOT", str(tmp_path / "node"))
    monkeypatch.delenv("PROOFMESH_MODE", raising=False)
    lab.LAB_ROOT = tmp_path / "lab"
    api.node.mesh = None
    with TestClient(api.app) as c:
        yield c
    if api.node.mesh:
        api.node.mesh.close()
        api.node.mesh = None


def admin_headers(tmp_path):
    return {"Authorization": "Bearer " + (tmp_path / "node" / "keys" / "admin.token").read_text().strip()}


def test_ui_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "ProofMesh" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/../api.py").status_code == 404
    assert client.get("/api/health").json()["ok"]


def test_lab_endpoints(client):
    cat = client.get("/api/lab/catalog").json()
    assert len(cat["attacks"]) == 16
    clean = client.post("/api/lab/run", json={"attacks": []}).json()
    assert clean["ok"]
    hit = client.post("/api/lab/run", json={"attacks": [{"id": "edit", "params": {"txn": "TX-000100"}}]}).json()
    fin = next(n for n in hit["graph"]["nodes"] if n["product_id"] == "finance.transactions")
    assert fin["status"] == "TAMPERED"
    rep = hit["reports"][fin["id"]]
    assert len(rep["affected_downstream"]) == 4
    assert client.post("/api/lab/run", json={"attacks": [{"id": "nope"}]}).status_code == 400

    csv = client.get("/api/lab/data/finance.transactions")
    assert csv.status_code == 200 and csv.content.startswith(b"txn_id,")
    ok = client.post("/api/lab/verify-copy/finance.transactions", content=csv.content).json()
    assert ok["matches"]
    bad = client.post("/api/lab/verify-copy/finance.transactions",
                      content=csv.content.replace(b"USD\n", b"EUR\n", 1)).json()
    assert not bad["matches"] and bad["changed_lines"]

    assert not client.get("/api/lab/policy", params={"consumer": "marketing", "purpose": "ad-targeting"}).json()["allowed"]
    b = client.get("/api/lab/bundle/executive.cost-per-head")
    assert client.post("/api/lab/verify-bundle", content=b.content).json()["ok"]
    assert client.post("/api/lab/verify-bundle", content=b"{not json").status_code == 400
    assert client.get("/api/lab/proof/finance.transactions/4").json()["verified"]
    assert client.post("/api/lab/verify-copy/finance.transactions", content=b"x" * (6 * 1024 * 1024)).status_code == 413


def test_node_requires_tokens(client, tmp_path):
    assert client.post("/api/node/domains", json={"name": "sales"}).status_code == 401
    client.get("/api/node/overview")  # creates the node
    admin = admin_headers(tmp_path)
    r = client.post("/api/node/domains", json={"name": "sales"}, headers=admin)
    assert r.status_code == 201
    sales = {"Authorization": f"Bearer {r.json()['token']}"}
    other = {"Authorization": f"Bearer {client.post('/api/node/domains', json={'name': 'audit'}, headers=admin).json()['token']}"}
    assert client.post("/api/node/domains", json={"name": "x1"}, headers=sales).status_code == 403

    contract = {"schema": {"format": "csv", "columns": [{"name": "region", "required": True},
                                                       {"name": "revenue", "type": "decimal"}]},
                "access_policy": {"readers": ["sales"]}, "permitted_purposes": ["financial-reporting"]}
    assert client.post("/api/node/products", json={"product_id": "sales.revenue", "owner": "sales",
                                                   "contract": contract}, headers=other).status_code == 403
    assert client.post("/api/node/products", json={"product_id": "sales.revenue", "owner": "sales",
                                                   "contract": contract}, headers=sales).status_code == 201
    body = b"region,revenue\nEMEA,10.5\nAPAC,20\n"
    assert client.post("/api/node/products/sales.revenue/versions", content=body).status_code == 401
    assert client.post("/api/node/products/sales.revenue/versions", content=body, headers=other).status_code == 403
    r = client.post("/api/node/products/sales.revenue/versions?filename=rev.csv", content=body, headers=sales)
    assert r.status_code == 201, r.text
    assert client.post("/api/node/products/sales.revenue/versions", content=b"region,revenue\n,x\n",
                       headers=sales).status_code == 422

    assert client.get("/api/node/products/sales.revenue/verify").json()["status"] == "VERIFIED"
    assert client.get("/api/node/products/sales.revenue/data").status_code == 401
    assert client.get("/api/node/products/sales.revenue/data", headers=other).status_code == 403
    assert client.get("/api/node/products/sales.revenue/data", headers=sales).content == body
    assert client.get("/api/node/checkpoint", headers=admin).json()["checkpoint"]["seq"] > 0
    assert client.post("/api/node/domains/sales/revoke", json={"reason": "test"}, headers=admin).status_code == 200
    assert client.get("/api/node/products/sales.revenue/verify").json()["status"] == "VERIFIED"


def test_lab_only_mode(client, monkeypatch):
    monkeypatch.setenv("PROOFMESH_MODE", "lab")
    assert client.get("/api/node/overview").status_code == 404
    assert client.get("/api/lab/catalog").status_code == 200
