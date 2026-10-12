"""Verification engine.

``Verifier.verify_manifest`` checks one product version and, recursively, its
entire upstream history:

1. **Record integrity**: the stored manifest hashes to its id.
2. **Identity**: the signer's certificate chains to the pinned mesh authority.
3. **Signature**: the manifest is signed by that certificate's key.
4. **Ownership & contract**: the product registration is signed by its owner,
   the signer is an authorised writer, and the manifest carries the registered
   contract unchanged.
5. **Version chain**: version ``n`` points at version ``n-1`` of the product.
6. **Content**: every chunk is re-read and re-hashed; the Merkle root is
   recomputed and compared to the signed root; modified chunks are localised
   by descending the two trees.
7. **Lineage**: every input exists, matches the Merkle root recorded at
   derivation time, is itself verified (recursively) and permitted the
   declared purpose.
8. **Lineage index**: the SQL lineage index agrees with the signed manifests.
9. **Replay** (optional): registered transformations are re-executed and must
   reproduce the signed output exactly.

Statuses, worst first:

* ``INVALID``  – the manifest or its provenance claims are forged/broken.
* ``TAMPERED`` – the manifest is authentic but the stored bytes changed.
* ``TAINTED``  – this product is intact but something upstream is not.
* ``VERIFIED`` – everything checks out.

When a version is ``INVALID`` or ``TAMPERED`` the report lists every
downstream product version derived from it, directly or transitively, using
the lineage claims inside *signed* manifests (so deleting rows from the
lineage index cannot hide a dependant).
"""

from __future__ import annotations

from collections import deque
from typing import Any

from . import transforms
from .canonical import digest, sha256_hex
from .chunking import ChunkingParams, chunk_hash, iter_chunks
from .contract import evaluate, purpose_allowed, can_read
from .crypto import CTX_EVENT, CTX_MANIFEST, CTX_REGISTRATION, check_certificate, verify_signature
from .merkle import MerkleTree, localize_changes
from .store import MissingChunk

STATUS_ORDER = ["VERIFIED", "TAINTED", "TAMPERED", "INVALID"]
MISSING_CHUNK = "0" * 64


def worst(*statuses: str) -> str:
    return max(statuses, key=STATUS_ORDER.index)


class _Report:
    def __init__(self, manifest_id: str):
        self.data: dict[str, Any] = {
            "manifest_id": manifest_id,
            "product_id": None,
            "version": None,
            "owner_domain": None,
            "status": "VERIFIED",
            "summary": "",
            "checks": [],
            "content": None,
            "inputs": [],
            "compromised_ancestors": [],
            "affected_downstream": [],
            "newer_version": None,
        }

    def check(self, name: str, ok: bool, detail: str, fail_status: str = "INVALID",
              severity: str | None = None) -> bool:
        sev = severity or ("info" if ok else ("warning" if fail_status == "VERIFIED" else "critical"))
        self.data["checks"].append({"name": name, "ok": ok, "severity": sev, "detail": detail})
        if not ok:
            self.data["status"] = worst(self.data["status"], fail_status)
        return ok


class Verifier:
    def __init__(self, mesh, *, replay: bool = False):
        self.mesh = mesh
        self.db = mesh.db
        self.replay = replay
        self._cache: dict[str, dict] = {}
        self._in_progress: set[str] = set()
        self._children: dict[str, list[str]] | None = None

    # ---------------------------------------------------------------- public
    def verify_product(self, product_id: str, version: int | None = None) -> dict:
        row = self.mesh._resolve((product_id, version) if version is not None else product_id)
        return self.verify_manifest(row["manifest_id"])

    def verify_manifest(self, manifest_id: str) -> dict:
        if manifest_id in self._cache:
            return self._cache[manifest_id]
        if manifest_id in self._in_progress:  # a cycle can only come from forged records
            r = _Report(manifest_id)
            r.check("lineage acyclic", False, "lineage graph contains a cycle")
            return self._finish(r)
        self._in_progress.add(manifest_id)
        try:
            report = self._verify(manifest_id)
        finally:
            self._in_progress.discard(manifest_id)
        self._cache[manifest_id] = report
        return report

    # -------------------------------------------------------------- internals
    def _verify(self, manifest_id: str) -> dict:
        r = _Report(manifest_id)
        row = self.db.one("SELECT * FROM manifests WHERE manifest_id = ?", (manifest_id,))
        if row is None:
            r.check("manifest exists", False, f"no manifest {manifest_id[:16]}… in the registry")
            return self._finish(r)
        env = self.db.get_envelope(manifest_id)
        body = env.get("manifest", {})
        product = body.get("product", {})
        r.data.update(product_id=product.get("id", row["product_id"]),
                      version=product.get("version", row["version"]),
                      owner_domain=product.get("owner_domain"))

        # 1. record integrity
        recomputed = digest(body)
        r.check("record integrity",
                recomputed == manifest_id == env.get("manifest_id")
                and row["product_id"] == product.get("id") and row["version"] == product.get("version"),
                "manifest content hashes to its id and matches its registry row"
                if recomputed == manifest_id else
                f"manifest content hashes to {recomputed[:16]}…, not its id {manifest_id[:16]}…: the record was edited")

        # 2-3. identity and signature
        signer = body.get("signer", {})
        cert_env = env.get("certificate") or {}
        cert_ok, cert_detail = check_certificate(cert_env, self.mesh.authority_public_key)
        cert = cert_env.get("certificate", {}) if isinstance(cert_env, dict) else {}
        if cert_ok and (cert.get("domain") != signer.get("domain") or cert.get("key_id") != signer.get("key_id")):
            cert_ok, cert_detail = False, "certificate does not belong to the declared signer"
        r.check("signer certificate", cert_ok, cert_detail)
        sig_ok = cert_ok and verify_signature(cert["public_key"], CTX_MANIFEST, body, env.get("signature", ""))
        r.check("manifest signature", sig_ok,
                f"Ed25519 signature by '{signer.get('domain')}' (key {signer.get('key_id')}) is valid"
                if sig_ok else "signature does not match the manifest content")

        # 4. ownership & contract
        self._check_registration(r, body, signer)

        # 5. version chain
        self._check_version_chain(r, body)

        # 6. content
        self._check_content(r, body)

        # 7. lineage
        self._check_lineage(r, body)

        # 8. lineage index
        self._check_index(r, manifest_id, body)

        # 9. replay
        if self.replay:
            self._check_replay(r, body)

        newest = self.db.manifest_row(r.data["product_id"])
        if newest is not None and newest["version"] > (r.data["version"] or 0):
            r.data["newer_version"] = newest["version"]

        return self._finish(r)

    def _finish(self, r: _Report) -> dict:
        d = r.data
        status = d["status"]
        if status in ("INVALID", "TAMPERED"):
            d["affected_downstream"] = self.downstream(d["manifest_id"])
        failed = [c for c in d["checks"] if not c["ok"] and c["severity"] == "critical"]
        if status == "VERIFIED":
            d["summary"] = "signature, content and complete upstream history verified"
        elif status == "TAINTED":
            names = ", ".join(f"{a['product_id']}@{a['version']}" for a in d["compromised_ancestors"]) or "an input"
            d["summary"] = f"content intact, but derived from compromised data: {names}"
        else:
            d["summary"] = "; ".join(f"{c['name']}: {c['detail']}" for c in failed[:3])
        return d

    def _check_registration(self, r: _Report, body: dict, signer: dict) -> None:
        pid = body.get("product", {}).get("id")
        product = self.db.get_product(pid) if pid else None
        if product is None:
            r.check("product registration", False, f"product '{pid}' is not registered")
            return
        reg_env = product["registration"]
        reg = reg_env.get("registration", {})
        owner = self.db.get_domain(reg.get("owner_domain", ""))
        ok = False
        if owner is not None:
            owner_cert_ok, _ = check_certificate(owner["certificate"], self.mesh.authority_public_key)
            ok = owner_cert_ok and verify_signature(
                owner["certificate"]["certificate"]["public_key"], CTX_REGISTRATION, reg, reg_env.get("signature", ""))
        r.check("product registration", ok and reg.get("product_id") == pid,
                f"registration of '{pid}' is signed by its owner '{reg.get('owner_domain')}'"
                if ok else "product registration is not validly signed by its owner")
        if not ok:
            return
        r.check("product ownership", body["product"].get("owner_domain") == reg["owner_domain"],
                f"manifest names owner '{body['product'].get('owner_domain')}', registration says '{reg['owner_domain']}'")
        writers = reg["contract"]["access_policy"]["writers"]
        r.check("authorised publisher", signer.get("domain") in writers,
                f"'{signer.get('domain')}' is an authorised writer" if signer.get("domain") in writers
                else f"'{signer.get('domain')}' is not among the product's writers {writers}")
        same = digest(reg["contract"]) == body.get("contract_hash") == digest(body.get("contract"))
        r.check("data contract", same,
                f"manifest carries the registered contract ({body.get('contract_hash', '')[:12]}…)" if same
                else "the contract in the manifest differs from the one the owner registered")

    def _check_version_chain(self, r: _Report, body: dict) -> None:
        version = body.get("product", {}).get("version")
        prev_id = body.get("previous_manifest")
        if version == 1:
            r.check("version chain", prev_id is None, "first version" if prev_id is None
                    else "version 1 must not reference a previous manifest")
            return
        prev = self.db.get_envelope(prev_id) if prev_id else None
        ok = (prev is not None and prev["manifest"]["product"]["id"] == body["product"]["id"]
              and prev["manifest"]["product"]["version"] == version - 1 and digest(prev["manifest"]) == prev_id)
        r.check("version chain", ok, f"links to version {version - 1} ({(prev_id or '')[:12]}…)" if ok
                else f"version {version} does not link to an intact version {version - 1}")

    def _check_content(self, r: _Report, body: dict) -> None:
        content = body.get("content", {})
        chunks = content.get("chunks", [])
        expected_ids = [c["id"] for c in chunks]
        expected = MerkleTree(expected_ids)
        r.check("chunk list commits to signed Merkle root", expected.root == content.get("merkle_root"),
                f"{len(chunks)} chunk hashes reproduce root {expected.root[:16]}…"
                if expected.root == content.get("merkle_root") else
                "the chunk list does not hash to the signed Merkle root")

        actual_ids, blobs, problems = [], [], []
        for c in chunks:
            try:
                blob = self.mesh.store.get(c["id"])
            except MissingChunk:
                actual_ids.append(MISSING_CHUNK)
                blobs.append(None)
                problems.append({**c, "problem": "missing", "actual_id": None})
                continue
            aid = chunk_hash(blob)
            actual_ids.append(aid)
            blobs.append(blob)
            if aid != c["id"] or len(blob) != c["size"]:
                problems.append({**c, "problem": "modified", "actual_id": aid, "actual_size": len(blob)})
        actual = MerkleTree(actual_ids)
        loc = localize_changes(expected, actual)

        is_csv = body.get("contract", {}).get("schema", {}).get("format") == "csv"
        if is_csv and problems:
            line = 1
            starts = []
            for blob, c in zip(blobs, chunks):
                starts.append(line)
                line += blob.count(b"\n") if blob is not None else 0
            for p in problems:
                i = p["index"]
                blob = blobs[i]
                first = starts[i]
                last = first + (blob.count(b"\n") if blob is not None else 0)
                p["lines"] = [first, last]

        info = {
            "size": content.get("size"),
            "chunk_count": len(chunks),
            "expected_root": content.get("merkle_root"),
            "actual_root": actual.root,
            "tampered_chunks": problems,
            "localization": {"comparisons": loc.comparisons, "leaves": loc.leaves,
                             "changed_leaves": loc.changed_leaves},
        }
        r.data["content"] = info
        if problems:
            descr = ", ".join(
                f"chunk #{p['index']} (bytes {p['offset']}–{p['offset'] + p['size'] - 1}"
                + (f", lines {p['lines'][0]}–{p['lines'][1]}" if p.get("lines") else "") + f") {p['problem']}"
                for p in problems[:5])
            r.check("content integrity", False,
                    f"recomputed Merkle root {actual.root[:16]}… ≠ signed root {expected.root[:16]}…; "
                    f"{len(problems)} of {len(chunks)} chunks altered: {descr}; located with "
                    f"{loc.comparisons} subtree comparisons", fail_status="TAMPERED")
            return
        data = b"".join(blobs)
        whole_ok = sha256_hex(data) == content.get("content_hash") and len(data) == content.get("size")
        r.check("content integrity", whole_ok,
                f"all {len(chunks)} chunks re-hashed; Merkle root {actual.root[:16]}… matches the signed root"
                if whole_ok else "chunks are intact but do not reassemble into the signed content hash",
                fail_status="TAMPERED")
        if whole_ok and body.get("contract"):
            q = evaluate(data, body["contract"])
            r.check("contract quality rules", q["passed"],
                    f"schema and {len(q['rules'])} quality rule(s) hold" if q["passed"]
                    else "data no longer satisfies its contract", fail_status="TAMPERED")

    def _check_lineage(self, r: _Report, body: dict) -> None:
        lineage = body.get("lineage") or {}
        inputs = lineage.get("inputs") or []
        t = lineage.get("transformation")
        if not inputs:
            r.check("lineage", t is None, "source product (no upstream inputs)" if t is None
                    else "a transformation is recorded but it has no inputs")
            return
        if t is None:
            r.check("lineage", False, "derived product has no transformation record")
        purpose = (t or {}).get("purpose", "")
        actor = body.get("signer", {}).get("domain", "")
        for ref in inputs:
            mid = ref.get("manifest_id", "")
            label = f"{ref.get('product_id')}@{ref.get('version')}"
            env = self.db.get_envelope(mid)
            if env is None:
                r.check(f"input {label}", False, "input manifest is missing from the registry", fail_status="TAINTED")
                r.data["inputs"].append({**ref, "status": "MISSING"})
                r.data["compromised_ancestors"].append({**ref, "status": "MISSING", "path": [label]})
                continue
            ib = env["manifest"]
            pinned = (ib["content"]["merkle_root"] == ref.get("merkle_root")
                      and ib["product"]["id"] == ref.get("product_id")
                      and ib["product"]["version"] == ref.get("version"))
            r.check(f"input {label} pinned", pinned,
                    f"input matches Merkle root {ref.get('merkle_root', '')[:12]}… recorded at derivation"
                    if pinned else "input no longer matches the version recorded at derivation time",
                    fail_status="TAINTED")
            allowed = purpose_allowed(ib["contract"], purpose) and can_read(ib["contract"], actor)
            r.check(f"input {label} policy", allowed,
                    f"'{actor}' may read it for purpose '{purpose}'" if allowed
                    else f"'{actor}' was not permitted to use it for purpose '{purpose}'")
            sub = self.verify_manifest(mid)
            r.data["inputs"].append({**ref, "status": sub["status"]})
            if sub["status"] != "VERIFIED":
                r.check(f"input {label} history", False, f"upstream is {sub['status']}", fail_status="TAINTED")
                if sub["status"] in ("INVALID", "TAMPERED"):
                    r.data["compromised_ancestors"].append({**ref, "status": sub["status"], "path": [label]})
                for anc in sub["compromised_ancestors"]:
                    r.data["compromised_ancestors"].append({**anc, "path": [label] + anc["path"]})
            else:
                r.check(f"input {label} history", True, "upstream history verified")

    def _check_index(self, r: _Report, manifest_id: str, body: dict) -> None:
        signed_inputs = sorted(i["manifest_id"] for i in (body.get("lineage") or {}).get("inputs") or [])
        indexed = sorted(self.db.inputs_of(manifest_id))
        t = (body.get("lineage") or {}).get("transformation")
        row = self.db.transformation_for(manifest_id)
        t_ok = (t is None and row is None) or (
            t is not None and row is not None and row["transformation_id"] == t.get("id")
            and row["params"] == t.get("params") and row["code_hash"] == t.get("code_hash"))
        ok = signed_inputs == indexed and t_ok
        r.check("lineage index", ok, "lineage index agrees with the signed manifest" if ok
                else "lineage index rows differ from the signed manifest (index was altered; "
                     "impact analysis uses the signed manifests)", fail_status="VERIFIED", severity="warning" if not ok else "info")

    def _check_replay(self, r: _Report, body: dict) -> None:
        t = (body.get("lineage") or {}).get("transformation")
        if not t:
            return
        if t.get("kind") != "registered":
            r.check("replay", True, "external transformation: attested by signature, not replayable", severity="info")
            return
        if r.data["status"] != "VERIFIED":
            r.check("replay", True, "skipped: inputs or content did not verify", severity="info")
            return
        try:
            tr = transforms.get(t["name"])
        except KeyError:
            r.check("replay", False, f"transformation '{t['name']}' is not available on this node",
                    fail_status="VERIFIED", severity="warning")
            return
        if tr.code_hash != t.get("code_hash"):
            r.check("replay", False, "transformation code changed since derivation; cannot replay faithfully",
                    fail_status="VERIFIED", severity="warning")
            return
        payloads = [self.mesh._materialize(self.db.get_envelope(i["manifest_id"])["manifest"])
                    for i in body["lineage"]["inputs"]]
        output = tr.fn(payloads, t["params"])
        params = ChunkingParams.from_dict(body["content"]["chunking"])
        root = MerkleTree([chunk_hash(c) for _, c in iter_chunks(output, params)]).root
        ok = root == body["content"]["merkle_root"]
        r.check("replay", ok, f"re-running '{t['name']}' reproduces the signed output exactly" if ok
                else f"re-running '{t['name']}' produces different data (root {root[:16]}…): "
                     "the output does not match its declared derivation")

    # ---------------------------------------------------------- impact graph
    def _graph(self) -> dict[str, list[str]]:
        """input manifest -> [output manifests], built from self-consistent manifests."""
        if self._children is None:
            children: dict[str, list[str]] = {}
            for row in self.db.iter_manifest_rows():
                env = self.db.get_envelope(row["manifest_id"])
                body = env["manifest"]
                if digest(body) != row["manifest_id"]:
                    continue
                for inp in (body.get("lineage") or {}).get("inputs") or []:
                    children.setdefault(inp["manifest_id"], []).append(row["manifest_id"])
            self._children = children
        return self._children

    def downstream(self, manifest_id: str) -> list[dict]:
        """Every product version derived (transitively) from ``manifest_id``, breadth first."""
        graph = self._graph()
        out, seen = [], {manifest_id}
        start = self.db.get_envelope(manifest_id)
        start_label = (f"{start['manifest']['product']['id']}@{start['manifest']['product']['version']}"
                       if start else manifest_id[:12])
        queue = deque([(manifest_id, [start_label])])
        while queue:
            mid, path = queue.popleft()
            for child in sorted(graph.get(mid, [])):
                if child in seen:
                    continue
                seen.add(child)
                body = self.db.get_envelope(child)["manifest"]
                label = f"{body['product']['id']}@{body['product']['version']}"
                t = body["lineage"].get("transformation") or {}
                out.append({
                    "product_id": body["product"]["id"],
                    "version": body["product"]["version"],
                    "manifest_id": child,
                    "owner_domain": body["product"]["owner_domain"],
                    "depth": len(path),
                    "path": path + [label],
                    "transformation": t.get("name"),
                    "purpose": t.get("purpose"),
                })
                queue.append((child, path + [label]))
        return out


# ------------------------------------------------------------------ helpers

def audit(mesh, *, replay: bool = False, latest_only: bool = False) -> dict:
    """Verify every product version in the mesh and summarise the blast radius."""
    v = Verifier(mesh, replay=replay)
    rows = list(mesh.db.iter_manifest_rows())
    if latest_only:
        latest: dict[str, Any] = {}
        for row in rows:
            if row["product_id"] not in latest or row["version"] > latest[row["product_id"]]["version"]:
                latest[row["product_id"]] = row
        rows = list(latest.values())
    reports = [v.verify_manifest(row["manifest_id"]) for row in rows]
    counts = {s: 0 for s in STATUS_ORDER}
    for rep in reports:
        counts[rep["status"]] += 1
    compromised = [
        {"product_id": rep["product_id"], "version": rep["version"], "manifest_id": rep["manifest_id"],
         "status": rep["status"], "summary": rep["summary"],
         "affected_downstream": rep["affected_downstream"]}
        for rep in reports if rep["status"] in ("INVALID", "TAMPERED")
    ]
    log = verify_event_log(mesh)
    return {
        "ok": not compromised and counts["TAINTED"] == 0 and log["ok"],
        "counts": counts,
        "compromised": compromised,
        "reports": reports,
        "event_log": log,
    }


def verify_event_log(mesh) -> dict:
    """Check the hash chain and signatures of the append-only audit log."""
    prev = "0" * 64
    problems = []
    events = mesh.db.events()
    for i, ev in enumerate(events, start=1):
        entry = {k: ev[k] for k in ("seq", "ts", "actor", "kind", "payload", "prev_hash")}
        if ev["seq"] != i:
            problems.append(f"entry {ev['seq']}: expected sequence number {i} (entries removed or reordered)")
        if ev["prev_hash"] != prev:
            problems.append(f"entry {ev['seq']}: does not link to the previous entry")
        if digest(entry) != ev["entry_hash"]:
            problems.append(f"entry {ev['seq']}: content was modified")
        if ev["actor"] == "authority":
            pk = mesh.authority_public_key
        else:
            d = mesh.db.get_domain(ev["actor"])
            ok, _ = check_certificate(d["certificate"], mesh.authority_public_key) if d else (False, "")
            pk = d["certificate"]["certificate"]["public_key"] if ok else None
        if pk is None or not verify_signature(pk, CTX_EVENT, entry, ev["signature"]):
            problems.append(f"entry {ev['seq']}: signature by '{ev['actor']}' is invalid")
        prev = ev["entry_hash"]
    return {"ok": not problems, "entries": len(events), "head": prev, "problems": problems}


def verify_file(mesh, product_id: str, data: bytes, version: int | None = None) -> dict:
    """Check a copy of a product that a consumer received out of band."""
    env = mesh.envelope(product_id, version)
    body = env["manifest"]
    manifest_report = Verifier(mesh).verify_manifest(env["manifest_id"])
    params = ChunkingParams.from_dict(body["content"]["chunking"])
    pieces = list(iter_chunks(data, params))
    actual_ids = [chunk_hash(c) for _, c in pieces]
    expected_ids = [c["id"] for c in body["content"]["chunks"]]
    root = MerkleTree(actual_ids).root
    match = root == body["content"]["merkle_root"]
    expected_set, actual_set = set(expected_ids), set(actual_ids)
    changed = [{"offset": off, "size": len(c), "id": cid}
               for (off, c), cid in zip(pieces, actual_ids) if cid not in expected_set]
    removed = [c for c in body["content"]["chunks"] if c["id"] not in actual_set]
    return {
        "product_id": product_id,
        "version": body["product"]["version"],
        "manifest_id": env["manifest_id"],
        "manifest_status": manifest_report["status"],
        # The copy is genuine when it reproduces the root of an *authentic* manifest,
        # even if this node's own stored chunks were later tampered with.
        "matches": match and manifest_report["status"] != "INVALID",
        "expected_root": body["content"]["merkle_root"],
        "actual_root": root,
        "size": len(data),
        "expected_size": body["content"]["size"],
        "unexpected_regions": changed,
        "missing_chunks": removed,
    }
