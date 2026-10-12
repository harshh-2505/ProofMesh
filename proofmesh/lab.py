"""The attack lab: a stateless, reproducible sandbox for the live site.

Every lab request starts from the same pristine mesh (the demo scenario, built
with deterministic keys and a fixed clock so every server instance produces
byte-identical manifests), copies it to a private scratch directory, applies
the attacks the visitor chose, verifies everything with a *pinned* trust
anchor and replay enabled, and returns a complete snapshot. Nothing persists
between requests, which is what makes it safe to run on serverless hosting.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from . import __version__, demo
from .canonical import digest
from .contract import PolicyViolation
from .crypto import CTX_MANIFEST, SigningKey, issue_certificate, key_id_for
from .lineage import lineage_graph
from .merkle import MerkleTree, verify_inclusion
from .mesh import IntegrityError, ProofMesh
from .verify import Verifier, verify_bundle, verify_event_log, verify_file

SEED = b"proofmesh-public-attack-lab/v1"
LAB_ROOT = Path(os.environ.get("PROOFMESH_LAB_DIR", Path(tempfile.gettempdir()) / "proofmesh-lab"))
MAX_ATTACKS = 8
_lock = threading.Lock()


def _clock_factory() -> Callable[[], str]:
    start = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
    state = {"n": 0}

    def clock() -> str:
        state["n"] += 1
        return (start + timedelta(seconds=37 * state["n"])).isoformat().replace("+00:00", "Z")

    return clock


def _base_dir() -> Path:
    return LAB_ROOT / f"base-{__version__}"


def ensure_base() -> Path:
    """Build the pristine mesh once per server instance."""
    base = _base_dir()
    if (base / "ready").exists():
        return base
    with _lock:
        if (base / "ready").exists():
            return base
        LAB_ROOT.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(dir=LAB_ROOT, prefix="build-"))
        mesh = ProofMesh.init(work / "node", chunking=demo.DEMO_CHUNKING, clock=_clock_factory(), key_seed=SEED)
        demo.build_scenario(mesh)
        checkpoint = mesh.checkpoint()
        (work / "node" / "checkpoint.json").write_text(json.dumps(checkpoint))
        mesh.close()
        if base.exists():
            shutil.rmtree(base)
        os.replace(work / "node", base)
        shutil.rmtree(work, ignore_errors=True)
        (base / "ready").write_text("ok")
    return base


def trust_anchor() -> str:
    """The lab's authority key, as a verifier would have pinned it out of band."""
    return SigningKey.from_seed(SEED + b"/authority").public_key_b64


class Sandbox:
    """A throwaway copy of the pristine mesh."""

    def __enter__(self) -> "Sandbox":
        base = ensure_base()
        self.dir = Path(tempfile.mkdtemp(dir=LAB_ROOT, prefix="run-"))
        shutil.copytree(base, self.dir / "node", ignore=shutil.ignore_patterns("ready", "*-wal", "*-shm"))
        self.mesh = ProofMesh(self.dir / "node", clock=_clock_factory(), trust_anchor=trust_anchor())
        # Continue the deterministic clock after the base build.
        for _ in range(200):
            self.mesh.clock()
        self.checkpoint = json.loads((self.dir / "node" / "checkpoint.json").read_text())
        return self

    def __exit__(self, *exc) -> None:
        self.mesh.close()
        shutil.rmtree(self.dir, ignore_errors=True)


# ------------------------------------------------------------------ attacks

@dataclass(frozen=True)
class Attack:
    id: str
    title: str
    attacker: str
    summary: str
    defence: str
    fn: Callable[[ProofMesh, dict], str]
    params: tuple = ()


def _envelope_row(mesh: ProofMesh, product_id: str) -> tuple[dict, dict]:
    row = dict(mesh.db.manifest_row(product_id))
    return row, json.loads(row["envelope"])


def _save_envelope(mesh: ProofMesh, manifest_id: str, env: dict) -> None:
    mesh.db.execute("UPDATE manifests SET envelope = ? WHERE manifest_id = ?", (json.dumps(env), manifest_id))


def a_edit(mesh: ProofMesh, p: dict) -> str:
    txn = str(p.get("txn") or demo.TAMPER_TXN).strip().upper()
    amount = p.get("amount")
    if amount is not None:
        amount = f"{float(amount):.2f}"
    t = demo.secretly_tamper(mesh, txn_id=txn, new_amount=amount)
    return (f"Changed {t['txn_id']} from {t['old_amount']} to {t['new_amount']} directly in chunk object "
            f"{t['chunk_id'][:12]}…, keeping its timestamps.")


def a_flip(mesh: ProofMesh, p: dict) -> str:
    env = mesh.envelope("executive.department-costs")
    chunk = env["manifest"]["content"]["chunks"][0]
    path = mesh.store.path(chunk["id"])
    blob = bytearray(path.read_bytes())
    pos = int(p.get("byte", 77)) % len(blob)
    blob[pos] ^= 0x04
    path.write_bytes(bytes(blob))
    return f"Flipped one bit at byte {pos} of the executive department-costs report."


def a_delete_chunk(mesh: ProofMesh, p: dict) -> str:
    env = mesh.envelope("finance.transactions")
    chunks = env["manifest"]["content"]["chunks"]
    idx = int(p.get("index", 9)) % len(chunks)
    mesh.store.path(chunks[idx]["id"]).unlink(missing_ok=True)
    return f"Deleted chunk #{idx} of finance.transactions from storage."


def a_rewrite_manifest(mesh: ProofMesh, p: dict) -> str:
    note = a_edit(mesh, p)
    demo.cover_tracks(mesh)
    return note + " Then rewrote the stored manifest so its chunk hashes and Merkle root match the edit."


def a_rogue_resign(mesh: ProofMesh, p: dict) -> str:
    a_edit(mesh, p)
    row, env = _envelope_row(mesh, "finance.transactions")
    body = env["manifest"]
    for c in body["content"]["chunks"]:
        c["id"] = mesh.store.put(mesh.store.path(c["id"]).read_bytes())
    body["content"]["merkle_root"] = MerkleTree([c["id"] for c in body["content"]["chunks"]]).root
    rogue_authority, rogue = SigningKey.from_seed(b"rogue-ca"), SigningKey.from_seed(b"rogue-finance")
    body["signer"]["key_id"] = rogue.key_id
    _save_envelope(mesh, row["manifest_id"], {
        "manifest_id": row["manifest_id"], "manifest": body, "signature": rogue.sign(CTX_MANIFEST, body),
        "certificate": issue_certificate(rogue_authority, "finance", rogue.public_key_b64, body["created_at"])})
    return ("Edited a transaction, rebuilt the Merkle root and re-signed the manifest with a key and certificate "
            "from a certificate authority the attacker controls.")


def a_replace_trust_root(mesh: ProofMesh, p: dict) -> str:
    """Swap the node's own trust anchor so forged signatures chain to an attacker CA."""
    a_edit(mesh, p)
    rogue_ca = SigningKey.from_seed(b"rogue-root")
    (mesh.root / "trust" / "authority.pub").write_text(rogue_ca.public_key_b64 + "\n")
    mesh.node_authority_key = rogue_ca.public_key_b64
    # Re-certify every domain key under the rogue CA, then re-sign the edited manifest.
    rogue_fin = SigningKey.from_seed(b"rogue-finance-2")
    for d in mesh.db.list_domains():
        cert = issue_certificate(rogue_ca, d["name"], d["public_key"], d["registered_at"])
        mesh.db.execute("UPDATE domains SET certificate = ? WHERE name = ?", (json.dumps(cert), d["name"]))
        mesh.db.execute("UPDATE keys SET certificate = ? WHERE key_id = ?", (json.dumps(cert), d["key_id"]))
    row, env = _envelope_row(mesh, "finance.transactions")
    body = env["manifest"]
    for c in body["content"]["chunks"]:
        c["id"] = mesh.store.put(mesh.store.path(c["id"]).read_bytes())
    body["content"]["merkle_root"] = MerkleTree([c["id"] for c in body["content"]["chunks"]]).root
    body["signer"]["key_id"] = rogue_fin.key_id
    _save_envelope(mesh, row["manifest_id"], {
        "manifest_id": row["manifest_id"], "manifest": body, "signature": rogue_fin.sign(CTX_MANIFEST, body),
        "certificate": issue_certificate(rogue_ca, "finance", rogue_fin.public_key_b64, body["created_at"])})
    return ("Replaced the node's trust/authority.pub with an attacker CA, re-certified every department under it, "
            "edited a transaction and re-signed Finance's manifest with a forged Finance key.")


def a_impersonate(mesh: ProofMesh, p: dict) -> str:
    row, env = _envelope_row(mesh, "finance.transactions")
    body = env["manifest"]
    ops = mesh._domain_key("operations")
    body["signer"] = {"domain": "operations", "key_id": ops.key_id}
    new_id = digest(body)
    forged = {"manifest_id": new_id, "manifest": body, "signature": ops.sign(CTX_MANIFEST, body),
              "certificate": mesh.domain("operations")["certificate"]}
    mesh.db.execute("UPDATE manifests SET manifest_id = ?, envelope = ? WHERE manifest_id = ?",
                    (new_id, json.dumps(forged), row["manifest_id"]))
    return "Operations re-signed Finance's dataset with its own valid key, posing as the publisher."


def a_loosen_contract(mesh: ProofMesh, p: dict) -> str:
    prod = mesh.db.get_product("finance.transactions")
    reg = prod["registration"]
    reg["registration"]["contract"]["permitted_purposes"].append("ad-targeting")
    reg["registration"]["contract"]["access_policy"]["readers"] = ["*"]
    mesh.db.execute("UPDATE products SET registration = ? WHERE product_id = ?",
                    (json.dumps(reg), "finance.transactions"))
    return "Edited Finance's registered data contract in the database to allow 'ad-targeting'."


def a_hide_lineage(mesh: ProofMesh, p: dict) -> str:
    note = a_edit(mesh, p)
    src = mesh.envelope("finance.transactions")["manifest_id"]
    mesh.db.execute("DELETE FROM lineage_edges WHERE input_manifest_id = ?", (src,))
    mesh.db.execute("DELETE FROM transformations")
    return note + " Then deleted the lineage index rows so the reports built on it look unrelated."


def a_forge_report(mesh: ProofMesh, p: dict) -> str:
    honest = mesh.envelope("operations.vendor-spend")["manifest"]
    data = mesh.read("operations.vendor-spend", verify=False).decode().splitlines()
    vendor, total, count = data[1].split(",")
    data[1] = f"{vendor},{float(total) / 2:.2f},{count}"
    fake = ("\n".join(data) + "\n").encode()
    t = dict(honest["lineage"]["transformation"])
    t["executed_at"] = mesh.clock()
    t["id"] = digest({k: v for k, v in t.items() if k != "id"})
    mesh._record(mesh.product("operations.vendor-spend"), fake, actor="operations", filename=None,
                 media_type=None, inputs=honest["lineage"]["inputs"], transformation=t)
    return (f"Operations published version 2 of its vendor report, halving {vendor}'s spend, while claiming it is "
            "the same 'aggregate' of verified Finance data. Every signature on it is genuine.")


def a_erase_report(mesh: ProofMesh, p: dict) -> str:
    mid = mesh.envelope("executive.cost-per-head")["manifest_id"]
    mesh.db.execute("DELETE FROM lineage_edges WHERE output_manifest_id = ?", (mid,))
    mesh.db.execute("DELETE FROM transformations WHERE output_manifest_id = ?", (mid,))
    mesh.db.execute("DELETE FROM manifests WHERE manifest_id = ?", (mid,))
    return "Deleted the board's cost-per-head report from the registry to hide that it ever existed."


def a_rollback(mesh: ProofMesh, p: dict) -> str:
    corrected = demo.transactions_csv() + b"TX-003001,2026-09-30,Finance,Acme Cloud,Cloud,120.00,USD\n"
    v2 = mesh.publish("finance.transactions", corrected)
    mesh.db.execute("DELETE FROM manifests WHERE manifest_id = ?", (v2["manifest_id"],))
    return ("Finance published a corrected version 2. The attacker deleted it so consumers keep receiving "
            "version 1 (a rollback).")


def a_tamper_log(mesh: ProofMesh, p: dict) -> str:
    row = mesh.db.one("SELECT seq, payload FROM events WHERE kind = 'domain.registered' AND payload LIKE '%marketing%'")
    payload = json.loads(row["payload"])
    payload["domain"] = "marketing-admin"
    mesh.db.execute("UPDATE events SET payload = ? WHERE seq = ?", (json.dumps(payload), row["seq"]))
    return f"Rewrote audit-log entry #{row['seq']} to change a domain registration."


def a_truncate_log(mesh: ProofMesh, p: dict) -> str:
    last = mesh.db.last_event()["seq"]
    n = 2
    mesh.db.execute("DELETE FROM events WHERE seq > ?", (last - n,))
    return f"Deleted the last {n} audit-log entries, which recorded the two executive reports."


def a_stolen_key(mesh: ProofMesh, p: dict) -> str:
    stolen = mesh._domain_key("finance")
    mesh.revoke_domain_key("finance", reason="laptop stolen")
    lines = demo.transactions_csv().decode().splitlines()
    parts = lines[777].split(",")
    parts[5] = "1.00"
    lines[777] = ",".join(parts)
    mesh._record(mesh.product("finance.transactions"), ("\n".join(lines) + "\n").encode(), actor="finance",
                 filename=None, media_type=None, inputs=[], transformation=None, key=stolen)
    return ("Finance reported its key stolen and it was revoked. The thief then published version 2 of the ledger "
            "with the stolen key, writing off TX-000777.")


def a_policy_bypass(mesh: ProofMesh, p: dict) -> str:
    src = mesh.envelope("finance.transactions")
    body = src["manifest"]
    data = mesh.read("finance.transactions", verify=False)
    from .transforms import get as get_transform

    t = get_transform("select_columns")
    out = t.fn([data], {"columns": ["vendor"]})
    record = {"kind": "registered", "name": t.name, "description": t.description, "code_hash": t.code_hash,
              "params": {"columns": ["vendor"]}, "purpose": "ad-targeting", "executed_by": "marketing",
              "executed_at": mesh.clock(), "inputs_verified": True}
    record["id"] = digest(record)
    inputs = [{"product_id": "finance.transactions", "version": body["product"]["version"],
               "manifest_id": src["manifest_id"], "merkle_root": body["content"]["merkle_root"],
               "owner_domain": "finance"}]
    mesh._record(mesh.product("marketing.vendor-targets"), out, actor="marketing", filename=None,
                 media_type=None, inputs=inputs, transformation=record)
    return ("Marketing skipped ProofMesh's policy gate and published an ad-targeting list derived from Finance data, "
            "signed with its own valid key.")


ATTACKS: dict[str, Attack] = {a.id: a for a in [
    Attack("edit", "Silent edit", "Insider with storage access",
           "Change one transaction amount directly in the chunk store, keeping file size and timestamps.",
           "Chunk re-hash and Merkle root comparison", a_edit, ("txn", "amount")),
    Attack("bitflip", "One-bit flip", "Disk fault or insider",
           "Flip a single bit inside a derived executive report.",
           "Chunk re-hash", a_flip),
    Attack("delete-chunk", "Missing chunk", "Storage loss or sabotage",
           "Delete one content-addressed chunk of the Finance ledger.",
           "Content check: the chunk is missing", a_delete_chunk),
    Attack("rewrite-manifest", "Cover-up rewrite", "Insider with database access",
           "Edit a transaction, then rewrite the stored manifest so its hashes match the edited bytes.",
           "Manifest id and Finance's signature", a_rewrite_manifest, ("txn", "amount")),
    Attack("rogue-ca", "Rogue certificate", "Attacker with their own CA",
           "Edit the data and re-sign the manifest with a key certified by an attacker's own authority.",
           "Certificate chain to the pinned mesh authority", a_rogue_resign, ("txn", "amount")),
    Attack("trust-root", "Swap the trust root", "Attacker who owns the server",
           "Replace the node's authority.pub, re-certify every department under it and re-sign forged data.",
           "Pinned trust anchor held by the verifier", a_replace_trust_root, ("txn", "amount")),
    Attack("impersonate", "Impersonation", "Another department",
           "Operations re-signs Finance's dataset with its own perfectly valid key.",
           "Signed product registration lists Finance as the only writer", a_impersonate),
    Attack("loosen-contract", "Loosen the contract", "Database administrator",
           "Quietly add 'ad-targeting' to Finance's permitted purposes in the registry.",
           "Owner-signed product registration", a_loosen_contract),
    Attack("hide-lineage", "Hide the lineage", "Insider covering the blast radius",
           "Edit the data, then delete lineage index rows so dependent reports look unrelated.",
           "Impact analysis reads signed manifests, not the index", a_hide_lineage, ("txn", "amount")),
    Attack("forge-report", "Forged derivation", "Department publishing bad numbers",
           "Publish a report with altered numbers while claiming it came from a verified transformation.",
           "Replay: re-running the declared transformation", a_forge_report),
    Attack("erase-report", "Erase a report", "Insider hiding evidence",
           "Delete the board report so nobody knows it relied on Finance data.",
           "Hash-chained, signed audit log", a_erase_report),
    Attack("rollback", "Rollback", "Insider serving stale data",
           "Delete Finance's corrected version 2 so consumers keep getting version 1.",
           "Audit log records every published version", a_rollback),
    Attack("tamper-log", "Rewrite history", "Database administrator",
           "Edit an entry in the audit log.",
           "Hash chain and per-entry signatures", a_tamper_log),
    Attack("truncate-log", "Truncate the log", "Database administrator",
           "Delete the newest audit-log entries.",
           "Manifest log records and the signed checkpoint", a_truncate_log),
    Attack("stolen-key", "Stolen key", "Thief with a revoked key",
           "Use Finance's key after it was reported stolen and revoked.",
           "Revocation ordered by the audit log, not timestamps", a_stolen_key),
    Attack("policy-bypass", "Policy bypass", "Department ignoring its contract",
           "Marketing publishes an ad-targeting list built from Finance data, which Finance forbids.",
           "Purpose re-checked against the signed contract", a_policy_bypass),
]}


def catalog() -> list[dict]:
    return [{"id": a.id, "title": a.title, "attacker": a.attacker, "summary": a.summary,
             "defence": a.defence, "params": list(a.params)} for a in ATTACKS.values()]


# ----------------------------------------------------------------- snapshot

def _manifest_view(env: dict) -> dict:
    b = env["manifest"]
    t = b["lineage"].get("transformation")
    return {
        "manifest_id": env["manifest_id"],
        "product": b["product"],
        "signer": b["signer"],
        "created_at": b["created_at"],
        "log_anchor": b.get("log_anchor"),
        "content": {k: b["content"][k] for k in ("filename", "media_type", "size", "content_hash", "chunk_count",
                                                  "merkle_root", "chunking")}
        | {"chunks": [{"index": c["index"], "offset": c["offset"], "size": c["size"], "id": c["id"]}
                      for c in b["content"]["chunks"]]},
        "contract": {"permitted_purposes": b["contract"]["permitted_purposes"],
                     "readers": b["contract"]["access_policy"]["readers"],
                     "writers": b["contract"]["access_policy"]["writers"],
                     "classification": b["contract"].get("classification"),
                     "columns": [c["name"] for c in b["contract"]["schema"].get("columns", [])],
                     "rules": [r["id"] for r in b["contract"]["quality_rules"]]},
        "quality": {"rows": b["quality"].get("rows"), "passed": b["quality"].get("passed")},
        "lineage": {"inputs": b["lineage"]["inputs"],
                    "transformation": {k: t.get(k) for k in ("kind", "name", "purpose", "executed_by", "code_hash", "params")}
                    if t else None},
    }


def snapshot(sb: Sandbox, applied: list[dict] | None = None) -> dict:
    started = time.perf_counter()
    mesh = sb.mesh
    v = Verifier(mesh, replay=True)
    log = verify_event_log(mesh, sb.checkpoint)
    graph = lineage_graph(mesh, with_status=False)
    reports, manifests = {}, {}
    for node in graph["nodes"]:
        rep = v.verify_manifest(node["id"])
        node["status"], node["summary"] = rep["status"], rep["summary"]
        reports[node["id"]] = rep
        manifests[node["id"]] = _manifest_view(mesh.db.get_envelope(node["id"]))
    # Products the log says exist but the registry lost: show them as ghosts.
    known = {n["id"] for n in graph["nodes"]}
    for mid, e in v._publish_events.items():
        if mid in known:
            continue
        p = e["payload"]
        graph["nodes"].append({"id": mid, "product_id": p.get("product_id"), "name": p.get("product_id"),
                               "version": p.get("version"), "owner_domain": e["actor"], "latest": True,
                               "status": "ERASED", "merkle_root": p.get("merkle_root"), "chunk_count": None,
                               "summary": f"recorded at audit-log entry #{e['seq']} but missing from the registry",
                               "log_seq": e["seq"]})
        for src in p.get("inputs") or []:
            if src in known:
                graph["edges"].append({"source": src, "target": mid, "transformation": None, "purpose": None})
    counts = {s: 0 for s in ("VERIFIED", "TAINTED", "TAMPERED", "INVALID", "ERASED")}
    for n in graph["nodes"]:
        counts[n["status"]] += 1
    events = mesh.db.events()
    return {
        "version": __version__,
        "applied": applied or [],
        "trust": v.trust,
        "counts": counts,
        "ok": all(n["status"] == "VERIFIED" for n in graph["nodes"]) and log["ok"] and v.trust["ok"],
        "graph": graph,
        "reports": reports,
        "manifests": manifests,
        "event_log": {k: log[k] for k in ("ok", "entries", "head", "problems", "bad_seqs", "checkpoint")},
        "events": [{k: e[k] for k in ("seq", "ts", "actor", "key_id", "kind", "payload", "entry_hash")}
                   for e in events],
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
    }


def run(attacks: list[dict]) -> dict:
    if len(attacks) > MAX_ATTACKS:
        raise ValueError(f"at most {MAX_ATTACKS} attacks per run")
    applied = []
    with Sandbox() as sb:
        for spec in attacks:
            attack = ATTACKS.get(spec.get("id", ""))
            if attack is None:
                raise ValueError(f"unknown attack {spec.get('id')!r}")
            params = {k: spec.get("params", {}).get(k) for k in attack.params if spec.get("params", {}).get(k) not in (None, "")}
            try:
                effect = attack.fn(sb.mesh, params)
            except (LookupError, ValueError, IntegrityError) as exc:
                effect = f"Attack could not be applied: {exc}"
            applied.append({"id": attack.id, "title": attack.title, "effect": effect, "defence": attack.defence})
        return snapshot(sb, applied)


def pristine_data(product_id: str) -> tuple[bytes, dict]:
    with Sandbox() as sb:
        env = sb.mesh.envelope(product_id)
        return sb.mesh.read(product_id), env["manifest"]["content"]


def check_copy(product_id: str, data: bytes) -> dict:
    with Sandbox() as sb:
        res = verify_file(sb.mesh, product_id, data)
        if not res["matches"] and product_id.endswith(".transactions"):
            original = sb.mesh.read(product_id).decode().splitlines()
            received = data.decode("utf-8", "replace").splitlines()
            changed = [{"line": i + 1, "expected": a, "received": b}
                       for i, (a, b) in enumerate(zip(original, received)) if a != b][:10]
            res["changed_lines"] = changed
            res["line_count"] = {"expected": len(original), "received": len(received)}
        return res


def try_derivation(consumer: str, purpose: str, source: str = "finance.transactions") -> dict:
    """Ask the policy engine whether ``consumer`` may use ``source`` for ``purpose``."""
    targets = {"marketing": "marketing.vendor-targets", "operations": "operations.vendor-spend",
               "executive": "executive.department-costs", "hr": None, "finance": None}
    with Sandbox() as sb:
        mesh = sb.mesh
        body = mesh.envelope(source)["manifest"]
        contract = body["contract"]
        from .contract import can_read, purpose_allowed

        reasons = []
        if not can_read(contract, consumer):
            reasons.append(f"'{consumer}' is not an authorised reader of {source}")
        if not purpose_allowed(contract, purpose):
            reasons.append(f"purpose '{purpose}' is not in {source}'s permitted purposes "
                           f"({', '.join(contract['permitted_purposes'])})")
        target = targets.get(consumer)
        if not reasons and target:
            out = mesh.product(target)
            from .contract import purposes_within

            bad = purposes_within(out["contract"]["permitted_purposes"], [contract])
            if bad:
                reasons.append(f"{target} would offer purposes {source} forbids: {', '.join(bad)}")
        return {"consumer": consumer, "purpose": purpose, "source": source, "allowed": not reasons,
                "reasons": reasons, "permitted_purposes": contract["permitted_purposes"],
                "readers": contract["access_policy"]["readers"]}


def bundle(product_id: str) -> dict:
    with Sandbox() as sb:
        return sb.mesh.export_bundle(product_id)


def check_bundle(b: dict, data: bytes | None = None) -> dict:
    return verify_bundle(b, trust_anchor(), data)


def proof(product_id: str, index: int) -> dict:
    with Sandbox() as sb:
        p = sb.mesh.inclusion_proof(product_id, index)
    p["verified"] = verify_inclusion(p["chunk"]["id"], index, p["tree_size"], p["proof"], p["merkle_root"])
    return p


__all__ = ["ATTACKS", "catalog", "run", "pristine_data", "check_copy", "try_derivation", "bundle",
           "check_bundle", "proof", "trust_anchor", "ensure_base", "PolicyViolation", "key_id_for"]
