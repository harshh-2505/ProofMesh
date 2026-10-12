"""The core promise: any modification is detected and its blast radius reported."""

import json

import pytest

from proofmesh import IntegrityError, Verifier, audit, demo, verify_event_log, verify_file
from proofmesh.canonical import digest
from proofmesh.crypto import CTX_MANIFEST, SigningKey, issue_certificate

DOWNSTREAM = {"operations.vendor-spend", "operations.department-spend",
              "executive.department-costs", "executive.cost-per-head"}


def statuses(mesh):
    return {r["product_id"]: r["status"] for r in audit(mesh)["reports"]}


def test_secret_edit_is_detected_and_localised(scenario):
    mesh, m = scenario
    t = demo.secretly_tamper(mesh)
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert rep["status"] == "TAMPERED"
    bad = rep["content"]["tampered_chunks"]
    assert [b["index"] for b in bad] == [t["chunk_index"]]
    assert rep["content"]["actual_root"] != rep["content"]["expected_root"]
    assert rep["content"]["localization"]["changed_leaves"] == [t["chunk_index"]]
    lo, hi = bad[0]["lines"]
    assert lo <= 1338 <= hi  # TX-001337 sits on CSV line 1338 (header is line 1)
    # The signature is still valid: Finance genuinely published the original.
    assert next(c for c in rep["checks"] if c["name"] == "manifest signature")["ok"]


def test_blast_radius_is_exact(scenario):
    mesh, _ = scenario
    demo.secretly_tamper(mesh)
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert {d["product_id"] for d in rep["affected_downstream"]} == DOWNSTREAM
    deepest = next(d for d in rep["affected_downstream"] if d["product_id"] == "executive.cost-per-head")
    assert deepest["path"] == ["finance.transactions@1", "operations.department-spend@1",
                               "executive.department-costs@1", "executive.cost-per-head@1"]
    s = statuses(mesh)
    assert s["hr.headcount"] == "VERIFIED"
    assert s["finance.transactions"] == "TAMPERED"
    assert all(s[p] == "TAINTED" for p in DOWNSTREAM)


def test_consumers_are_protected(scenario):
    mesh, _ = scenario
    demo.secretly_tamper(mesh)
    with pytest.raises(IntegrityError):
        mesh.read("finance.transactions")
    with pytest.raises(IntegrityError, match="TAINTED"):
        mesh.read("executive.cost-per-head")
    with pytest.raises(IntegrityError, match="refusing to derive"):
        mesh.derive("operations.vendor-spend", ["finance.transactions"], "aggregate",
                    {"group_by": ["vendor"], "metrics": [{"fn": "count", "as": "transactions"}]},
                    purpose="spend-analysis")
    assert mesh.read("finance.transactions", verify=False)  # explicit opt-out still possible


def test_single_bit_flip_in_derived_product(scenario):
    mesh, _ = scenario
    env = mesh.envelope("executive.department-costs")
    path = mesh.store.path(env["manifest"]["content"]["chunks"][0]["id"])
    blob = bytearray(path.read_bytes())
    blob[40] ^= 0x01
    path.write_bytes(bytes(blob))
    s = statuses(mesh)
    assert s["executive.department-costs"] == "TAMPERED"
    assert s["executive.cost-per-head"] == "TAINTED"
    assert s["finance.transactions"] == "VERIFIED"
    assert s["operations.department-spend"] == "VERIFIED"


def test_deleted_chunk(scenario):
    mesh, _ = scenario
    env = mesh.envelope("finance.transactions")
    mesh.store.path(env["manifest"]["content"]["chunks"][3]["id"]).unlink()
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert rep["status"] == "TAMPERED"
    assert rep["content"]["tampered_chunks"][0]["problem"] == "missing"


def test_rewriting_the_manifest_is_detected(scenario):
    mesh, _ = scenario
    demo.secretly_tamper(mesh)
    demo.cover_tracks(mesh)
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert rep["status"] == "INVALID"
    failed = {c["name"] for c in rep["checks"] if not c["ok"]}
    assert {"record integrity", "manifest signature"} <= failed
    assert {d["product_id"] for d in rep["affected_downstream"]} == DOWNSTREAM


def test_resigning_with_a_rogue_key_is_detected(scenario):
    """An attacker re-hashes everything *and* re-signs with a key they control."""
    mesh, _ = scenario
    demo.secretly_tamper(mesh)
    row = mesh.db.manifest_row("finance.transactions")
    env = json.loads(row["envelope"])
    body = env["manifest"]
    rogue_authority, rogue = SigningKey.generate(), SigningKey.generate()
    for c in body["content"]["chunks"]:
        c["id"] = mesh.store.put(mesh.store.path(c["id"]).read_bytes())
    from proofmesh.merkle import merkle_root
    body["content"]["merkle_root"] = merkle_root([c["id"] for c in body["content"]["chunks"]])
    body["signer"]["key_id"] = rogue.key_id
    new_env = {"manifest_id": row["manifest_id"], "manifest": body, "signature": rogue.sign(CTX_MANIFEST, body),
               "certificate": issue_certificate(rogue_authority, "finance", rogue.public_key_b64, "2026-01-01T00:00:00Z")}
    mesh.db.execute("UPDATE manifests SET envelope = ? WHERE manifest_id = ?", (json.dumps(new_env), row["manifest_id"]))
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert rep["status"] == "INVALID"
    cert = next(c for c in rep["checks"] if c["name"] == "signer certificate")
    assert not cert["ok"] and "trusted mesh authority" in cert["detail"]


def test_other_domain_cannot_sign_for_finance(scenario):
    """Operations has a valid certificate, but is not a writer of finance.transactions."""
    mesh, _ = scenario
    row = mesh.db.manifest_row("finance.transactions")
    env = json.loads(row["envelope"])
    body = env["manifest"]
    ops_key = mesh._domain_key("operations")
    body["signer"] = {"domain": "operations", "key_id": ops_key.key_id}
    new_id = digest(body)
    forged = {"manifest_id": new_id, "manifest": body, "signature": ops_key.sign(CTX_MANIFEST, body),
              "certificate": mesh.domain("operations")["certificate"]}
    mesh.db.execute("UPDATE manifests SET manifest_id = ?, envelope = ? WHERE manifest_id = ?",
                    (new_id, json.dumps(forged), row["manifest_id"]))
    rep = Verifier(mesh).verify_manifest(new_id)
    assert rep["status"] == "INVALID"
    assert not next(c for c in rep["checks"] if c["name"] == "authorised publisher")["ok"]


def test_contract_drift_is_detected(scenario):
    """Someone loosens the registered contract in the database to allow a new purpose."""
    mesh, _ = scenario
    p = mesh.db.get_product("finance.transactions")
    reg = p["registration"]
    reg["registration"]["contract"]["permitted_purposes"].append("ad-targeting")
    mesh.db.execute("UPDATE products SET registration = ? WHERE product_id = ?",
                    (json.dumps(reg), "finance.transactions"))
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert rep["status"] == "INVALID"
    assert not next(c for c in rep["checks"] if c["name"] == "product registration")["ok"]


def test_hiding_lineage_edges_does_not_hide_impact(scenario):
    mesh, _ = scenario
    src = mesh.envelope("finance.transactions")["manifest_id"]
    mesh.db.execute("DELETE FROM lineage_edges WHERE input_manifest_id = ?", (src,))
    demo.secretly_tamper(mesh)
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert {d["product_id"] for d in rep["affected_downstream"]} == DOWNSTREAM
    ops = Verifier(mesh).verify_product("operations.vendor-spend")
    idx = next(c for c in ops["checks"] if c["name"] == "lineage index")
    assert not idx["ok"] and idx["severity"] == "warning"


def test_replay_catches_a_forged_derivation(scenario):
    """Operations signs a report whose numbers do not come from the declared transformation."""
    mesh, m = scenario
    honest = m["operations.vendor-spend"]["manifest"]
    fake = mesh.read("operations.vendor-spend").replace(b"Acme Cloud,", b"Acme Cloud,1", 1)
    out = mesh.product("operations.vendor-spend")
    env = mesh._record(out, fake, actor="operations", filename=None, media_type=None,
                       inputs=honest["lineage"]["inputs"],
                       transformation={**honest["lineage"]["transformation"], "id": "forged"})
    assert Verifier(mesh).verify_manifest(env["manifest_id"])["status"] == "VERIFIED"  # signatures alone can't tell
    rep = Verifier(mesh, replay=True).verify_manifest(env["manifest_id"])
    assert rep["status"] == "INVALID"
    assert not next(c for c in rep["checks"] if c["name"] == "replay")["ok"]


def test_audit_log_tampering(scenario):
    mesh, _ = scenario
    assert verify_event_log(mesh)["ok"]
    mesh.db.execute("UPDATE events SET payload = ? WHERE seq = 5", (json.dumps({"product_id": "x"}),))
    res = verify_event_log(mesh)
    assert not res["ok"] and any("entry 5" in p for p in res["problems"])


def test_audit_log_deletion(scenario):
    mesh, _ = scenario
    mesh.db.execute("DELETE FROM events WHERE seq = 3")
    assert not verify_event_log(mesh)["ok"]


def test_verify_received_copy(scenario):
    mesh, _ = scenario
    original = demo.transactions_csv()
    assert verify_file(mesh, "finance.transactions", original)["matches"]
    edited = original.replace(b"TX-000500,", b"TX-000501,", 1)
    res = verify_file(mesh, "finance.transactions", edited)
    assert not res["matches"]
    assert len(res["unexpected_regions"]) == 1
    region = res["unexpected_regions"][0]
    pos = original.index(b"TX-000500,")
    assert region["offset"] <= pos < region["offset"] + region["size"]
    inserted = original[:1000] + b"X" * 50 + original[1000:]
    assert len(verify_file(mesh, "finance.transactions", inserted)["unexpected_regions"]) <= 2


def test_store_heals_on_republish(scenario):
    mesh, _ = scenario
    demo.secretly_tamper(mesh)
    # Republishing the original bytes rewrites the corrupted chunk object.
    from proofmesh.chunking import iter_chunks
    for _, c in iter_chunks(demo.transactions_csv(), mesh.chunking):
        mesh.store.put(c)
    assert Verifier(mesh).verify_product("finance.transactions")["status"] == "VERIFIED"


def test_full_demo(tmp_path):
    lines = []
    r = demo.run(tmp_path / "demo", write=lines.append, color=False)
    assert r["baseline"]["VERIFIED"] == 6
    assert r["policy_denied"] and "ad-targeting" in r["policy_denied"]
    assert r["source_report"]["status"] == "TAMPERED"
    assert set(r["affected"]) == DOWNSTREAM
    assert r["unaffected"] == ["hr.headcount"]
    assert r["board_report"]["status"] == "TAINTED"
    assert r["cover_tracks_report"]["status"] == "INVALID"
    text = "\n".join(lines)
    assert "Merkle" in text and "executive.cost-per-head" in text
