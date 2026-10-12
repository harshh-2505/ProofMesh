"""End-to-end demonstration scenario.

1. Finance publishes a verified transactions dataset; HR publishes headcount.
2. Operations derives spend reports from it; the Executive Office joins one
   of those with HR headcount and computes cost per head.
3. Marketing tries to use finance data for a purpose the contract forbids.
4. An insider *secretly* edits one transaction directly in storage.
5. ProofMesh detects the modification with the Merkle tree, pinpoints the
   chunk and CSV lines, and lists every downstream product that inherited it,
   while the unrelated HR product stays verified.
6. The insider tries to cover their tracks by rewriting the manifest; the
   signature check catches that too.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Callable

from .chunking import ChunkingParams
from .contract import PolicyViolation
from .mesh import IntegrityError, ProofMesh
from .merkle import MerkleTree
from .verify import Verifier, audit

DEMO_CHUNKING = ChunkingParams("fastcdc", min_size=1024, avg_size=4096, max_size=16384)

DEPARTMENTS = ["Engineering", "Finance", "HR", "Marketing", "Operations", "Sales"]
VENDORS = ["Acme Cloud", "Brightline Consulting", "Contoso Software", "Delta Airlines", "Evergreen Facilities",
           "Fabrikam Hardware", "Globex Logistics", "Initech Services", "Northwind Travel", "Umbrella Security"]
CATEGORIES = {"Acme Cloud": "Cloud", "Brightline Consulting": "Consulting", "Contoso Software": "Software",
              "Delta Airlines": "Travel", "Evergreen Facilities": "Facilities", "Fabrikam Hardware": "Hardware",
              "Globex Logistics": "Logistics", "Initech Services": "Consulting", "Northwind Travel": "Travel",
              "Umbrella Security": "Software"}

TAMPER_TXN = "TX-001337"

FINANCE_CONTRACT = {
    "description": "Every approved Q3 2026 vendor transaction, from the general ledger.",
    "schema": {"format": "csv", "columns": [
        {"name": "txn_id", "type": "string", "required": True},
        {"name": "date", "type": "date", "required": True},
        {"name": "department", "type": "string", "required": True},
        {"name": "vendor", "type": "string", "required": True},
        {"name": "category", "type": "string", "required": True},
        {"name": "amount", "type": "decimal", "required": True},
        {"name": "currency", "type": "string", "required": True},
    ]},
    "quality_rules": [
        {"id": "txn-id-format", "type": "regex", "column": "txn_id", "pattern": r"TX-\d{6}"},
        {"id": "txn-id-unique", "type": "unique", "column": "txn_id"},
        {"id": "amount-positive", "type": "range", "column": "amount", "min": 0.01, "max": 1000000},
        {"id": "currency-usd", "type": "allowed_values", "column": "currency", "values": ["USD"]},
        {"id": "department-known", "type": "allowed_values", "column": "department", "values": DEPARTMENTS},
        {"id": "non-empty", "type": "row_count", "min": 1},
    ],
    "access_policy": {"readers": ["*"], "writers": ["finance"]},
    "permitted_purposes": ["audit", "financial-reporting", "spend-analysis"],
    "classification": "confidential",
}

HR_CONTRACT = {
    "schema": {"format": "csv", "columns": [
        {"name": "department", "type": "string", "required": True},
        {"name": "headcount", "type": "integer", "required": True},
    ]},
    "quality_rules": [
        {"id": "department-unique", "type": "unique", "column": "department"},
        {"id": "headcount-positive", "type": "range", "column": "headcount", "min": 1},
    ],
    "access_policy": {"readers": ["executive", "operations", "finance"]},
    "permitted_purposes": ["financial-reporting", "workforce-planning"],
}


def _report_contract(columns: list[tuple[str, str]], purposes: list[str], readers=("*",)) -> dict:
    return {
        "schema": {"format": "csv", "columns": [{"name": n, "type": t, "required": True} for n, t in columns]},
        "quality_rules": [{"id": "non-empty", "type": "row_count", "min": 1}],
        "access_policy": {"readers": list(readers)},
        "permitted_purposes": purposes,
    }


def transactions_csv(rows: int = 3000, seed: int = 7) -> bytes:
    rng = random.Random(seed)
    start = date(2026, 7, 1)
    lines = ["txn_id,date,department,vendor,category,amount,currency"]
    for i in range(1, rows + 1):
        vendor = rng.choice(VENDORS)
        amount = Decimal(rng.randint(5_000, 2_000_000)) / 100
        d = start + timedelta(days=rng.randint(0, 91))
        lines.append(f"TX-{i:06d},{d.isoformat()},{rng.choice(DEPARTMENTS)},{vendor},{CATEGORIES[vendor]},{amount:.2f},USD")
    return ("\n".join(lines) + "\n").encode()


def headcount_csv() -> bytes:
    counts = {"Engineering": 142, "Finance": 23, "HR": 11, "Marketing": 37, "Operations": 58, "Sales": 81}
    return ("department,headcount\n" + "".join(f"{d},{n}\n" for d, n in counts.items())).encode()


def build_scenario(mesh: ProofMesh) -> dict:
    """Register the domains and products and run the derivations. Returns the manifests."""
    for name, desc in [("finance", "Corporate Finance"), ("hr", "People & HR"),
                       ("operations", "Business Operations"), ("executive", "Executive Office"),
                       ("marketing", "Marketing")]:
        mesh.register_domain(name, desc)

    mesh.register_product("finance.transactions", "finance", FINANCE_CONTRACT,
                          name="Q3 2026 vendor transactions", description=FINANCE_CONTRACT["description"])
    mesh.register_product("hr.headcount", "hr", HR_CONTRACT, name="Headcount by department",
                          description="Active employees per department at quarter end.")
    mesh.register_product("operations.vendor-spend", "operations",
                          _report_contract([("vendor", "string"), ("total_spend", "decimal"), ("transactions", "integer")],
                                           ["spend-analysis", "financial-reporting"]),
                          name="Spend by vendor", description="Quarterly spend aggregated per vendor.")
    mesh.register_product("operations.department-spend", "operations",
                          _report_contract([("department", "string"), ("total_spend", "decimal")],
                                           ["financial-reporting"]),
                          name="Spend by department", description="Quarterly spend aggregated per department.")
    mesh.register_product("executive.department-costs", "executive",
                          _report_contract([("department", "string"), ("total_spend", "decimal"), ("headcount", "integer")],
                                           ["financial-reporting"], readers=("executive",)),
                          name="Department costs", description="Department spend joined with headcount.")
    mesh.register_product("executive.cost-per-head", "executive",
                          _report_contract([("department", "string"), ("total_spend", "decimal"),
                                            ("headcount", "integer"), ("spend_per_head", "decimal")],
                                           ["financial-reporting"], readers=("executive",)),
                          name="Board report: spend per head", description="Board pack metric.")
    mesh.register_product("marketing.vendor-targets", "marketing",
                          _report_contract([("vendor", "string")], ["ad-targeting"]),
                          name="Vendor ad targets", description="Vendors to target with ads.")

    m = {}
    m["finance.transactions"] = mesh.publish("finance.transactions", transactions_csv(),
                                             filename="q3-2026-transactions.csv")
    m["hr.headcount"] = mesh.publish("hr.headcount", headcount_csv(), filename="headcount-2026-09-30.csv")
    m["operations.vendor-spend"] = mesh.derive(
        "operations.vendor-spend", ["finance.transactions"], "aggregate",
        {"group_by": ["vendor"], "metrics": [{"fn": "sum", "column": "amount", "as": "total_spend"},
                                              {"fn": "count", "as": "transactions"}]},
        purpose="spend-analysis")
    m["operations.department-spend"] = mesh.derive(
        "operations.department-spend", ["finance.transactions"], "aggregate",
        {"group_by": ["department"], "metrics": [{"fn": "sum", "column": "amount", "as": "total_spend"}]},
        purpose="financial-reporting")
    m["executive.department-costs"] = mesh.derive(
        "executive.department-costs", ["operations.department-spend", "hr.headcount"], "join",
        {"left_on": "department", "how": "inner"}, purpose="financial-reporting")
    m["executive.cost-per-head"] = mesh.derive(
        "executive.cost-per-head", ["executive.department-costs"], "compute",
        {"left": "total_spend", "op": "/", "right": "headcount", "as": "spend_per_head"},
        purpose="financial-reporting")
    return m


def secretly_tamper(mesh: ProofMesh, product_id: str = "finance.transactions", txn_id: str = TAMPER_TXN) -> dict:
    """Insider attack: edit one transaction's amount directly in the chunk store.

    Bypasses ProofMesh completely, keeps the file size identical and restores
    the file's timestamps so nothing looks touched at the filesystem level.
    """
    env = mesh.envelope(product_id)
    for c in env["manifest"]["content"]["chunks"]:
        path = mesh.store.path(c["id"])
        blob = path.read_bytes()
        marker = f"\n{txn_id},".encode()
        pos = blob.find(marker)
        if pos < 0:
            continue
        line_end = blob.index(b"\n", pos + 1)
        line = blob[pos + 1:line_end].decode()
        fields = line.split(",")
        old = fields[5]
        new = ("9" + old[1:]) if old[0] != "9" else ("1" + old[1:])  # same length, still a valid amount
        fields[5] = new
        new_blob = blob[:pos + 1] + ",".join(fields).encode() + blob[line_end:]
        st = path.stat()
        os.chmod(path, 0o644)
        path.write_bytes(new_blob)
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        return {"product_id": product_id, "txn_id": txn_id, "old_amount": old, "new_amount": new,
                "chunk_index": c["index"], "chunk_id": c["id"], "object": str(path)}
    raise LookupError(f"{txn_id} not found in {product_id}")


def cover_tracks(mesh: ProofMesh, product_id: str = "finance.transactions") -> dict:
    """Second-stage attack: rewrite the stored manifest so its hashes match the tampered bytes."""
    row = mesh.db.manifest_row(product_id)
    env = json.loads(row["envelope"])
    body = env["manifest"]
    data = b""
    for c in body["content"]["chunks"]:
        blob = mesh.store.path(c["id"]).read_bytes()
        c["id"] = mesh.store.put(blob)  # file the edited bytes under their new content address
        data += blob
    body["content"]["merkle_root"] = MerkleTree([c["id"] for c in body["content"]["chunks"]]).root
    body["content"]["content_hash"] = hashlib.sha256(data).hexdigest()
    # The attacker cannot re-sign without Finance's private key, so the old signature stays.
    mesh.db.execute("UPDATE manifests SET envelope = ? WHERE manifest_id = ?", (json.dumps(env), row["manifest_id"]))
    return {"product_id": product_id, "forged_root": body["content"]["merkle_root"]}


# ---------------------------------------------------------------- narration

class _Out:
    def __init__(self, write: Callable[[str], None], color: bool):
        self.write = write
        self.color = color

    def c(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def h(self, text: str) -> None:
        self.write("")
        self.write(self.c(f"━━ {text} ", "1;36") + self.c("━" * max(0, 72 - len(text)), "36"))

    def status(self, s: str) -> str:
        return self.c(f"{s:<8}", {"VERIFIED": "1;32", "TAINTED": "1;33", "TAMPERED": "1;31", "INVALID": "1;35"}[s])


def run(root: Path | str, *, write: Callable[[str], None] = print, color: bool = True,
        fresh: bool = True, cover: bool = True) -> dict:
    root = Path(root)
    if fresh and root.exists():
        shutil.rmtree(root)
    o = _Out(write, color)
    result: dict = {"root": str(root)}

    o.h("1. Set up the mesh")
    mesh = ProofMesh.init(root, chunking=DEMO_CHUNKING)
    m = build_scenario(mesh)
    for d in mesh.db.list_domains():
        o.write(f"  domain {d['name']:<11} key {d['key_id']}  certified by mesh authority")

    o.h("2. Finance publishes; other departments derive reports")
    for pid, env in m.items():
        body = env["manifest"]
        t = body["lineage"]["transformation"]
        src = (" ← " + " + ".join(f"{i['product_id']}@{i['version']}" for i in body["lineage"]["inputs"])
               + f"  [{t['name']} for '{t['purpose']}']") if t else ""
        o.write(f"  {pid}@{body['product']['version']}  {body['content']['chunk_count']:>3} chunks  "
                f"root {body['content']['merkle_root'][:12]}…  signed by {body['signer']['domain']}{src}")

    o.h("3. Contracts are enforced")
    try:
        mesh.derive("marketing.vendor-targets", ["finance.transactions"], "select_columns",
                    {"columns": ["vendor"]}, purpose="ad-targeting")
        result["policy_denied"] = None
    except PolicyViolation as exc:
        result["policy_denied"] = str(exc)
        o.write("  marketing tried to use finance.transactions for 'ad-targeting':")
        o.write("  " + o.c("DENIED", "1;31") + f"  {exc}")

    o.h("4. Baseline: verify everything")
    before = audit(mesh)
    for rep in before["reports"]:
        o.write(f"  {o.status(rep['status'])} {rep['product_id']}@{rep['version']}")
    o.write(f"  audit log: {before['event_log']['entries']} hash-chained, signed entries "
            f"{'intact' if before['event_log']['ok'] else 'BROKEN'}")
    result["baseline"] = before["counts"]

    o.h("5. An insider secretly edits the source data in storage")
    t = secretly_tamper(mesh)
    result["tamper"] = t
    o.write(f"  {t['txn_id']} amount changed {t['old_amount']} → {t['new_amount']} inside chunk object "
            f"{t['chunk_id'][:12]}… (same size, timestamps restored)")

    o.h("6. Ask ProofMesh to verify finance.transactions")
    v = Verifier(mesh)
    rep = v.verify_product("finance.transactions")
    result["source_report"] = rep
    o.write(f"  {o.status(rep['status'])} finance.transactions@{rep['version']}")
    content = rep["content"]
    o.write(f"  signed Merkle root     {content['expected_root']}")
    o.write(f"  recomputed Merkle root {content['actual_root']}")
    for p in content["tampered_chunks"]:
        o.write(f"  ✗ chunk #{p['index']} {p['problem']}: bytes {p['offset']}–{p['offset'] + p['size'] - 1}"
                + (f", CSV lines {p['lines'][0]}–{p['lines'][1]}" if p.get("lines") else ""))
    loc = content["localization"]
    o.write(f"  located by descending the Merkle tree: {loc['comparisons']} subtree comparisons "
            f"for {loc['leaves']} chunks")
    o.write(f"  manifest signature still valid → Finance really published the original; the stored bytes changed")

    o.h("7. Blast radius: every downstream product derived from the tampered data")
    for d in rep["affected_downstream"]:
        o.write(f"  {o.c('⚠', '1;33')} {d['product_id']}@{d['version']} (owner: {d['owner_domain']})  via "
                + " → ".join(d["path"]))
    unaffected = [r for r in audit(mesh)["reports"] if r["status"] == "VERIFIED"]
    for r in unaffected:
        o.write(f"  {o.c('✓', '1;32')} {r['product_id']}@{r['version']} unaffected")
    result["affected"] = [d["product_id"] for d in rep["affected_downstream"]]
    result["unaffected"] = [r["product_id"] for r in unaffected]

    o.h("8. Consumers verifying the board report see the problem too")
    board = Verifier(mesh).verify_product("executive.cost-per-head")
    result["board_report"] = board
    o.write(f"  {o.status(board['status'])} executive.cost-per-head: {board['summary']}")
    for a in board["compromised_ancestors"]:
        o.write(f"    compromised ancestor: {' → '.join(reversed(a['path']))} ({a['status']})")
    try:
        mesh.read("executive.cost-per-head")
    except IntegrityError as exc:
        o.write("  " + o.c("BLOCKED", "1;31") + f" reading it: {exc}")
    try:
        mesh.derive("operations.vendor-spend", ["finance.transactions"], "aggregate",
                    {"group_by": ["vendor"], "metrics": [{"fn": "sum", "column": "amount", "as": "total_spend"},
                                                          {"fn": "count", "as": "transactions"}]},
                    purpose="spend-analysis")
    except IntegrityError as exc:
        o.write("  " + o.c("BLOCKED", "1;31") + f" new derivation: {exc}")

    if cover:
        o.h("9. The insider rewrites the manifest to match the edited bytes")
        cover_tracks(mesh)
        rep2 = Verifier(mesh).verify_product("finance.transactions")
        result["cover_tracks_report"] = rep2
        o.write(f"  {o.status(rep2['status'])} finance.transactions: {rep2['summary']}")
        o.write(f"  downstream still flagged: {', '.join(d['product_id'] for d in rep2['affected_downstream'])}")

    final = audit(mesh)
    result["final_counts"] = final["counts"]
    o.h("Result")
    o.write("  " + ", ".join(f"{k}: {v}" for k, v in final["counts"].items()))
    o.write(f"  node directory: {root}")
    mesh.close()
    return result
