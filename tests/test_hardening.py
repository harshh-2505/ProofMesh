"""Loopholes closed after the MVP: trust pinning, key lifecycle, log anchoring, rollback, offline bundles."""

import json

import pytest

from proofmesh import ProofMesh, Verifier, audit, demo, verify_bundle, verify_event_log
from proofmesh.crypto import SigningKey, key_id_for


def check(rep, name):
    return next(c for c in rep["checks"] if c["name"] == name)


def test_trust_anchor_pinning(tmp_path, scenario):
    mesh, _ = scenario
    anchor = mesh.node_authority_key
    pinned = ProofMesh(mesh.root, trust_anchor=key_id_for(anchor))
    assert Verifier(pinned).verify_product("finance.transactions")["status"] == "VERIFIED"
    assert pinned.trust_status()["pinned"]
    # The node's trust root is replaced behind the verifier's back.
    (mesh.root / "trust" / "authority.pub").write_text(SigningKey.generate().public_key_b64)
    swapped = ProofMesh(mesh.root, trust_anchor=anchor)
    rep = Verifier(swapped).verify_product("hr.headcount")
    assert rep["status"] == "INVALID"
    assert not check(rep, "trust anchor")["ok"]
    unpinned = ProofMesh(mesh.root)
    assert not unpinned.trust_status()["pinned"]


def test_trust_anchor_from_environment(scenario, monkeypatch):
    mesh, _ = scenario
    monkeypatch.setenv("PROOFMESH_TRUST_ANCHOR", "0000000000000000")
    rep = Verifier(ProofMesh(mesh.root)).verify_product("hr.headcount")
    assert rep["status"] == "INVALID"


def test_every_manifest_is_anchored_in_the_log(scenario):
    mesh, m = scenario
    body = m["finance.transactions"]["manifest"]
    assert body["log_anchor"]["seq"] >= 1
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert check(rep, "audit log record")["ok"] and check(rep, "log anchor")["ok"]


def test_manifest_inserted_without_log_record(scenario):
    mesh, _ = scenario
    mesh.db.execute("DELETE FROM events WHERE kind = 'product.published' AND payload LIKE '%hr.headcount%'")
    rep = Verifier(mesh).verify_product("hr.headcount")
    assert rep["status"] == "INVALID"
    assert not check(rep, "audit log record")["ok"]


def test_erased_product_is_reported(scenario):
    mesh, _ = scenario
    mid = mesh.envelope("executive.cost-per-head")["manifest_id"]
    mesh.db.execute("DELETE FROM manifests WHERE manifest_id = ?", (mid,))
    res = audit(mesh)
    assert not res["ok"]
    assert [e["product_id"] for e in res["erased"]] == ["executive.cost-per-head"]


def test_rollback_is_detected(scenario):
    mesh, _ = scenario
    v2 = mesh.publish("finance.transactions", demo.transactions_csv(seed=3))
    assert Verifier(mesh).verify_product("finance.transactions")["status"] == "VERIFIED"
    mesh.db.execute("DELETE FROM manifests WHERE manifest_id = ?", (v2["manifest_id"],))
    rep = Verifier(mesh).verify_product("finance.transactions")
    assert rep["version"] == 1 and rep["status"] == "INVALID"
    assert "version 2" in check(rep, "rollback protection")["detail"]


def test_key_rotation_keeps_old_signatures_valid(scenario):
    mesh, _ = scenario
    old = mesh.domain("finance")["key_id"]
    new = mesh.rotate_domain_key("finance")["key_id"]
    assert old != new
    v2 = mesh.publish("finance.transactions", demo.transactions_csv(seed=5))
    assert v2["manifest"]["signer"]["key_id"] == new
    v = Verifier(mesh)
    assert v.verify_product("finance.transactions", 1)["status"] == "VERIFIED"
    assert v.verify_product("finance.transactions", 2)["status"] == "VERIFIED"
    assert verify_event_log(mesh)["ok"]


def test_revoked_key_cannot_sign_new_data(scenario):
    mesh, _ = scenario
    stolen = mesh._domain_key("finance")
    mesh.revoke_domain_key("finance", reason="laptop stolen")
    assert mesh.domain("finance")["key_id"] != stolen.key_id  # rotated automatically
    v = Verifier(mesh)
    assert v.verify_product("finance.transactions", 1)["status"] == "VERIFIED"  # signed before revocation
    env = mesh._record(mesh.product("finance.transactions"), demo.transactions_csv(seed=9), actor="finance",
                       filename=None, media_type=None, inputs=[], transformation=None, key=stolen)
    rep = Verifier(mesh).verify_manifest(env["manifest_id"])
    assert rep["status"] == "INVALID"
    assert "revoked" in check(rep, "signing key status")["detail"]
    assert not verify_event_log(mesh)["ok"]
    # The legitimate new key still works.
    fresh = mesh.publish("finance.transactions", demo.transactions_csv(seed=10))
    good = Verifier(mesh).verify_manifest(fresh["manifest_id"])
    assert good["status"] == "VERIFIED", [c for c in good["checks"] if not c["ok"]]


def test_fake_revocation_row_is_ignored(scenario):
    mesh, _ = scenario
    key_id = mesh.domain("hr")["key_id"]
    fake = {"revocation": {"type": "proofmesh/key-revocation", "key_id": key_id, "log_seq": 1}, "signature": "AAAA"}
    mesh.db.execute("UPDATE keys SET revocation = ? WHERE key_id = ?", (json.dumps(fake), key_id))
    assert Verifier(mesh).verify_product("hr.headcount")["status"] == "VERIFIED"


def test_checkpoint_detects_truncation(scenario):
    mesh, _ = scenario
    cp = mesh.checkpoint()
    assert verify_event_log(mesh, cp)["checkpoint"]["ok"]
    mesh.publish("hr.headcount", demo.headcount_csv().replace(b"Sales,81", b"Sales,82"))
    assert verify_event_log(mesh, cp)["ok"]  # the log grew; it still extends the checkpoint
    last = mesh.db.last_event()["seq"]
    mesh.db.execute("DELETE FROM events WHERE seq >= ?", (cp["checkpoint"]["seq"],))
    res = verify_event_log(mesh, cp)
    assert not res["ok"] and not res["checkpoint"]["ok"]
    forged = {**cp, "checkpoint": {**cp["checkpoint"], "seq": 1}}
    assert not verify_event_log(mesh, forged)["checkpoint"]["ok"]


def test_offline_bundle_verification(scenario):
    mesh, _ = scenario
    b = json.loads(json.dumps(mesh.export_bundle("executive.cost-per-head")))
    anchor = mesh.node_authority_key
    data = mesh.read("executive.cost-per-head")
    res = verify_bundle(b, anchor, data)
    assert res["ok"] and res["data"]["matches"] and len(res["manifests"]) == 5
    assert verify_bundle(b, SigningKey.generate().public_key_b64)["status"] == "INVALID"
    assert verify_bundle(b, anchor, data + b"x")["status"] == "TAMPERED"
    tampered = json.loads(json.dumps(b))
    fin = next(a for a in tampered["ancestors"] if a["manifest"]["product"]["id"] == "finance.transactions")
    fin["manifest"]["content"]["chunks"][0]["size"] += 1
    res = verify_bundle(tampered, anchor)
    assert res["status"] == "TAINTED"
    assert any(m["product_id"] == "finance.transactions" and m["status"] == "INVALID" for m in res["manifests"])


def test_encrypted_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("PROOFMESH_KEY_PASSPHRASE", "correct horse battery staple")
    mesh = ProofMesh.init(tmp_path / "n")
    mesh.register_domain("finance")
    assert b"ENCRYPTED" in (tmp_path / "n" / "keys" / "domains" / "finance.pem").read_bytes()
    monkeypatch.delenv("PROOFMESH_KEY_PASSPHRASE")
    with pytest.raises(ValueError, match="PROOFMESH_KEY_PASSPHRASE"):
        mesh._domain_key("finance")


def test_api_tokens(mesh):
    mesh.register_domain("finance")
    admin = (mesh.root / "keys" / "admin.token").read_text().strip()
    assert mesh.authenticate(admin) == "admin"
    tok = mesh.issue_token("finance")
    assert mesh.authenticate(tok) == "finance"
    assert mesh.authenticate("pm_finance_guess") is None
    assert tok not in (mesh.root / "registry.db").read_bytes().decode("latin-1")


def test_filenames_are_sanitised(mesh):
    mesh.register_domain("finance")
    mesh.register_product("finance.raw", "finance", {})
    env = mesh.publish("finance.raw", b"x", filename='../../etc/"passwd"\r\nX-Evil: 1')
    assert env["manifest"]["content"]["filename"] == "etc_passwd_X-Evil_1"


def test_csv_shape_problems(mesh):
    from proofmesh.contract import evaluate, normalize_contract
    c = normalize_contract({"schema": {"format": "csv", "columns": [{"name": "a"}, {"name": "b"}]}}, "x")
    assert not evaluate(b"a,b,a\n1,2,3\n", {**c, "schema": {**c["schema"], "allow_extra_columns": True}})["passed"]
    assert not evaluate(b"a,b\n1,2,3\n", c)["passed"]
    assert not evaluate(b"a,b\n1\n", c)["passed"]
