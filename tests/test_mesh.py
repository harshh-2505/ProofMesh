"""Registering, publishing, deriving and contract enforcement."""

import pytest

from proofmesh import ContractError, IntegrityError, PolicyViolation, ProofMeshError, Verifier, demo


def test_publish_roundtrip(scenario):
    mesh, m = scenario
    env = m["finance.transactions"]
    body = env["manifest"]
    assert body["content"]["chunk_count"] > 20
    assert body["signer"]["domain"] == "finance"
    assert mesh.read("finance.transactions") == demo.transactions_csv()
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert rep["status"] == "VERIFIED", rep["summary"]
    assert all(c["ok"] for c in rep["checks"])


def test_everything_verifies_and_replays(scenario):
    mesh, _ = scenario
    v = Verifier(mesh, replay=True)
    for p in mesh.products():
        if mesh.db.manifest_row(p["product_id"]) is None:
            continue
        rep = v.verify_product(p["product_id"])
        assert rep["status"] == "VERIFIED", (p["product_id"], rep["summary"])
        if rep["inputs"]:
            assert any(c["name"] == "replay" and c["ok"] for c in rep["checks"])


def test_derived_content_is_correct(scenario):
    mesh, _ = scenario
    rows = mesh.read("executive.cost-per-head").decode().splitlines()
    assert rows[0] == "department,total_spend,headcount,spend_per_head"
    assert len(rows) == 7
    dept, total, head, per = rows[1].split(",")
    from decimal import Decimal
    assert Decimal(per) == (Decimal(total) / Decimal(head)).quantize(Decimal("0.01"))


def test_product_namespace_and_ownership(mesh):
    mesh.register_domain("finance")
    mesh.register_domain("hr")
    with pytest.raises(ProofMeshError):
        mesh.register_product("hr.payroll", "finance", {})
    with pytest.raises(ProofMeshError):
        mesh.register_domain("finance")
    mesh.register_product("finance.raw", "finance", {})
    with pytest.raises(PolicyViolation):
        mesh.publish("finance.raw", b"data", actor="hr")


def test_contract_blocks_bad_data(scenario):
    mesh, _ = scenario
    bad = demo.transactions_csv().replace(b",USD\n", b",EUR\n", 1)
    with pytest.raises(ContractError, match="currency-usd"):
        mesh.publish("finance.transactions", bad)
    with pytest.raises(ContractError, match="missing columns"):
        mesh.publish("finance.transactions", b"txn_id,amount\nTX-000001,1\n")


def test_purpose_and_reader_enforcement(scenario):
    mesh, _ = scenario
    with pytest.raises(PolicyViolation, match="ad-targeting"):
        mesh.derive("marketing.vendor-targets", ["finance.transactions"], "select_columns",
                    {"columns": ["vendor"]}, purpose="ad-targeting")
    # HR headcount is readable only by executive, operations and finance.
    with pytest.raises(PolicyViolation, match="not an authorised reader"):
        mesh.derive("marketing.vendor-targets", ["hr.headcount"], "select_columns",
                    {"columns": ["department"]}, purpose="financial-reporting")


def test_derived_product_cannot_widen_purposes(scenario):
    mesh, _ = scenario
    mesh.register_product("operations.anything", "operations", {
        "schema": {"format": "csv", "columns": [{"name": "vendor"}]},
        "permitted_purposes": ["spend-analysis", "ad-targeting"]})
    with pytest.raises(PolicyViolation, match="ad-targeting"):
        mesh.derive("operations.anything", ["finance.transactions"], "select_columns",
                    {"columns": ["vendor"]}, purpose="spend-analysis")


def test_versions_chain_and_pinning(scenario):
    mesh, _ = scenario
    v2 = mesh.publish("finance.transactions", demo.transactions_csv(seed=99))
    assert v2["manifest"]["product"]["version"] == 2
    assert v2["manifest"]["previous_manifest"] == mesh.envelope("finance.transactions", 1)["manifest_id"]
    v = Verifier(mesh)
    assert v.verify_product("finance.transactions", 2)["status"] == "VERIFIED"
    old = v.verify_product("finance.transactions", 1)
    assert old["status"] == "VERIFIED" and old["newer_version"] == 2
    # Reports derived from v1 stay pinned to v1 and remain valid.
    rep = v.verify_product("operations.vendor-spend")
    assert rep["status"] == "VERIFIED"
    assert rep["inputs"][0]["version"] == 1


def test_unchanged_chunks_are_deduplicated(scenario):
    mesh, _ = scenario
    data = demo.transactions_csv()
    edited = data.replace(b"TX-002999,", b"TX-002999,", 1) + b"TX-003001,2026-09-30,HR,Acme Cloud,Cloud,10.00,USD\n"
    v1 = mesh.envelope("finance.transactions")["manifest"]["content"]["chunks"]
    v2 = mesh.publish("finance.transactions", edited)["manifest"]["content"]["chunks"]
    shared = {c["id"] for c in v1} & {c["id"] for c in v2}
    assert len(shared) >= len(v1) - 2


def test_external_derivation(scenario):
    mesh, _ = scenario
    mesh.register_product("operations.it-vendors", "operations", {
        "schema": {"format": "csv", "columns": [{"name": "vendor", "required": True}]},
        "permitted_purposes": ["spend-analysis"]})
    env = mesh.derive_external("operations.it-vendors", ["finance.transactions@1"],
                               b"vendor\nAcme Cloud\nContoso Software\n", name="notebook:it-vendors",
                               description="Hand-curated in a notebook", purpose="spend-analysis",
                               code=b"print('hello')")
    t = env["manifest"]["lineage"]["transformation"]
    assert t["kind"] == "external" and len(t["code_hash"]) == 64
    rep = Verifier(mesh, replay=True).verify_product("operations.it-vendors")
    assert rep["status"] == "VERIFIED"


def test_inclusion_proof(scenario):
    from proofmesh.merkle import verify_inclusion
    mesh, _ = scenario
    p = mesh.inclusion_proof("finance.transactions", 5)
    assert verify_inclusion(p["chunk"]["id"], 5, p["tree_size"], p["proof"], p["merkle_root"])
    assert len(p["proof"]) <= 6


def test_evidence_bundle(scenario):
    mesh, _ = scenario
    b = mesh.export_bundle("executive.cost-per-head")
    names = sorted(a["manifest"]["product"]["id"] for a in b["ancestors"])
    assert names == ["executive.department-costs", "finance.transactions", "hr.headcount", "operations.department-spend"]
