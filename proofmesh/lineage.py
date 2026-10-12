"""Lineage graph views built from signed manifests."""

from __future__ import annotations

from .verify import Verifier


def lineage_graph(mesh, *, with_status: bool = True, latest_only: bool = False) -> dict:
    """Nodes are product versions, edges point from an input to the product derived from it."""
    verifier = Verifier(mesh) if with_status else None
    rows = list(mesh.db.iter_manifest_rows())
    latest = {}
    for row in rows:
        if row["product_id"] not in latest or row["version"] > latest[row["product_id"]]:
            latest[row["product_id"]] = row["version"]
    nodes, edges = [], []
    keep = set()
    for row in rows:
        if latest_only and row["version"] != latest[row["product_id"]]:
            continue
        keep.add(row["manifest_id"])
    for row in rows:
        if row["manifest_id"] not in keep:
            continue
        body = mesh.db.get_envelope(row["manifest_id"])["manifest"]
        t = body["lineage"].get("transformation") or {}
        node = {
            "id": row["manifest_id"],
            "product_id": body["product"]["id"],
            "name": body["product"]["name"],
            "version": body["product"]["version"],
            "owner_domain": body["product"]["owner_domain"],
            "latest": body["product"]["version"] == latest[row["product_id"]],
            "merkle_root": body["content"]["merkle_root"],
            "chunk_count": body["content"]["chunk_count"],
            "size": body["content"]["size"],
            "created_at": body["created_at"],
            "transformation": t.get("name"),
            "purpose": t.get("purpose"),
        }
        if verifier:
            rep = verifier.verify_manifest(row["manifest_id"])
            node["status"] = rep["status"]
            node["summary"] = rep["summary"]
        nodes.append(node)
        for inp in body["lineage"]["inputs"]:
            if inp["manifest_id"] in keep:
                edges.append({"source": inp["manifest_id"], "target": row["manifest_id"],
                              "transformation": t.get("name"), "purpose": t.get("purpose")})
    return {"nodes": nodes, "edges": edges}


def upstream(mesh, manifest_id: str) -> list[dict]:
    """Every ancestor of a product version, nearest first."""
    out, seen, frontier = [], {manifest_id}, [(manifest_id, 0)]
    while frontier:
        mid, depth = frontier.pop(0)
        env = mesh.db.get_envelope(mid)
        if env is None:
            continue
        for inp in env["manifest"]["lineage"]["inputs"]:
            if inp["manifest_id"] in seen:
                continue
            seen.add(inp["manifest_id"])
            out.append({**inp, "depth": depth + 1})
            frontier.append((inp["manifest_id"], depth + 1))
    return out
