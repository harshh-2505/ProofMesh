"""Command line interface: ``proofmesh <command>``.

The node directory comes from ``--root`` or ``$PROOFMESH_ROOT`` (default
``./.proofmesh``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, demo, transforms
from .chunking import ChunkingParams
from .contract import ContractError, PolicyViolation
from .lineage import lineage_graph, upstream
from .merkle import verify_inclusion
from .mesh import IntegrityError, ProofMesh, ProofMeshError
from .verify import Verifier, audit, verify_event_log, verify_file

COLORS = {"VERIFIED": "32", "TAINTED": "33", "TAMPERED": "31", "INVALID": "35"}


def _color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


def _status(s: str) -> str:
    return _color(s, "1;" + COLORS.get(s, "0"))


def _mesh(args) -> ProofMesh:
    return ProofMesh(args.root)


def _dump(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=False))


def _parse_param(kv: str):
    key, _, value = kv.partition("=")
    try:
        return key, json.loads(value)
    except json.JSONDecodeError:
        return key, value


def print_report(rep: dict, verbose: bool = False) -> None:
    print(f"{_status(rep['status'])}  {rep['product_id']}@{rep['version']}  ({rep['manifest_id'][:16]}…)")
    print(f"  {rep['summary']}")
    for c in rep["checks"]:
        if verbose or not c["ok"]:
            mark = _color("✓", "32") if c["ok"] else _color("✗", "31" if c["severity"] == "critical" else "33")
            print(f"  {mark} {c['name']}: {c['detail']}")
    content = rep.get("content") or {}
    for p in content.get("tampered_chunks", []):
        lines = f", lines {p['lines'][0]}–{p['lines'][1]}" if p.get("lines") else ""
        print(f"  ✗ chunk #{p['index']} {p['problem']}: bytes {p['offset']}–{p['offset'] + p['size'] - 1}{lines}")
    for a in rep.get("compromised_ancestors", []):
        print(f"  ⚠ compromised ancestor {a['product_id']}@{a['version']} ({a['status']}) via {' → '.join(a['path'])}")
    if rep.get("affected_downstream"):
        print(f"  Affected downstream products ({len(rep['affected_downstream'])}):")
        for d in rep["affected_downstream"]:
            print(f"    - {d['product_id']}@{d['version']} (owner {d['owner_domain']}): {' → '.join(d['path'])}")
    if rep.get("newer_version"):
        print(f"  note: version {rep['newer_version']} of this product exists")


# ---------------------------------------------------------------- commands

def cmd_init(args):
    params = ChunkingParams(args.chunking, args.min_chunk, args.avg_chunk, args.max_chunk)
    mesh = ProofMesh.init(args.root, chunking=params)
    print(f"Initialised ProofMesh node at {mesh.root}")
    print(f"Trust anchor (share with verifiers): {mesh.root / 'trust' / 'authority.pub'}")


def cmd_domain_add(args):
    d = _mesh(args).register_domain(args.name, args.description)
    print(f"Registered domain '{d['name']}' with key {d['key_id']} (certified by the mesh authority)")


def cmd_domain_list(args):
    for d in _mesh(args).db.list_domains():
        print(f"{d['name']:<16} key {d['key_id']}  {d['description']}")


def cmd_product_register(args):
    contract = json.loads(Path(args.contract).read_text()) if args.contract else {}
    p = _mesh(args).register_product(args.product_id, args.owner, contract, name=args.name,
                                      description=args.description)
    print(f"Registered data product '{p['product_id']}' owned by '{p['owner_domain']}'")


def cmd_product_list(args):
    mesh = _mesh(args)
    v = Verifier(mesh)
    for p in mesh.products():
        row = mesh.db.manifest_row(p["product_id"])
        if row is None:
            print(f"{'—':<8}  {p['product_id']:<34} (no versions)")
            continue
        rep = v.verify_manifest(row["manifest_id"])
        print(f"{_status(rep['status']):<8}  {p['product_id']:<34} v{row['version']}  owner {p['owner_domain']}")


def cmd_publish(args):
    path = Path(args.file)
    env = _mesh(args).publish(args.product_id, path.read_bytes(), actor=args.as_domain, filename=path.name)
    b = env["manifest"]
    print(f"Published {b['product']['id']}@{b['product']['version']}: {b['content']['chunk_count']} chunks, "
          f"Merkle root {b['content']['merkle_root']}")
    print(f"Manifest {env['manifest_id']} signed by '{b['signer']['domain']}'")


def cmd_derive(args):
    mesh = _mesh(args)
    params = dict(_parse_param(p) for p in args.param)
    if args.params_json:
        params.update(json.loads(args.params_json))
    if args.from_file:
        code = Path(args.code).read_bytes() if args.code else None
        env = mesh.derive_external(args.output, args.input, Path(args.from_file).read_bytes(),
                                   name=args.transform, description=args.description or "", purpose=args.purpose,
                                   code=code, params=params, actor=args.as_domain,
                                   filename=Path(args.from_file).name)
    else:
        env = mesh.derive(args.output, args.input, args.transform, params, purpose=args.purpose,
                          actor=args.as_domain)
    b = env["manifest"]
    srcs = ", ".join(f"{i['product_id']}@{i['version']}" for i in b["lineage"]["inputs"])
    print(f"Derived {b['product']['id']}@{b['product']['version']} from {srcs} via "
          f"'{b['lineage']['transformation']['name']}' (Merkle root {b['content']['merkle_root'][:16]}…)")


def cmd_verify(args):
    mesh = _mesh(args)
    rep = Verifier(mesh, replay=args.replay).verify_product(args.product_id, args.version)
    if args.json:
        _dump(rep)
    else:
        print_report(rep, verbose=args.verbose)
    return 0 if rep["status"] == "VERIFIED" else 2


def cmd_verify_file(args):
    res = verify_file(_mesh(args), args.product_id, Path(args.file).read_bytes(), args.version)
    if args.json:
        _dump(res)
    else:
        verdict = _color("MATCHES", "1;32") if res["matches"] else _color("DOES NOT MATCH", "1;31")
        print(f"{verdict} {res['product_id']}@{res['version']} (signed root {res['expected_root'][:16]}…, "
              f"file root {res['actual_root'][:16]}…)")
        for r in res["unexpected_regions"]:
            print(f"  ✗ unexpected bytes at {r['offset']}–{r['offset'] + r['size'] - 1}")
    return 0 if res["matches"] else 2


def cmd_audit(args):
    mesh = _mesh(args)
    res = audit(mesh, replay=args.replay, latest_only=args.latest)
    if args.json:
        _dump(res)
        return 0 if res["ok"] else 2
    for rep in res["reports"]:
        print(f"{_status(rep['status']):<8}  {rep['product_id']}@{rep['version']}  {rep['summary']}")
    print("\n" + ", ".join(f"{k}: {v}" for k, v in res["counts"].items()))
    for c in res["compromised"]:
        print(f"\n{_status(c['status'])} {c['product_id']}@{c['version']} affects "
              f"{len(c['affected_downstream'])} downstream product version(s):")
        for d in c["affected_downstream"]:
            print(f"  - {d['product_id']}@{d['version']} ({d['owner_domain']})")
    log = res["event_log"]
    print(f"\nAudit log: {log['entries']} entries, {'intact' if log['ok'] else 'BROKEN: ' + '; '.join(log['problems'])}")
    return 0 if res["ok"] else 2


def cmd_lineage(args):
    mesh = _mesh(args)
    if args.product_id:
        env = mesh.envelope(args.product_id, args.version)
        v = Verifier(mesh)
        print(f"{args.product_id}@{env['manifest']['product']['version']}")
        print("  upstream:")
        for u in upstream(mesh, env["manifest_id"]) or [{"product_id": "(none: source product)", "version": "", "depth": 1}]:
            print(f"    {'  ' * (u['depth'] - 1)}{u['product_id']}@{u['version']}")
        print("  downstream:")
        for d in v.downstream(env["manifest_id"]) or [{"product_id": "(none)", "version": "", "depth": 1}]:
            print(f"    {'  ' * (d['depth'] - 1)}{d['product_id']}@{d['version']}")
        return
    g = lineage_graph(mesh)
    if args.json:
        _dump(g)
        return
    by_id = {n["id"]: n for n in g["nodes"]}
    for e in g["edges"]:
        s, t = by_id[e["source"]], by_id[e["target"]]
        print(f"{s['product_id']}@{s['version']} --[{e['transformation']} / {e['purpose']}]--> "
              f"{t['product_id']}@{t['version']}")


def cmd_show(args):
    _dump(_mesh(args).envelope(args.product_id, args.version))


def cmd_export(args):
    mesh = _mesh(args)
    data = mesh.read(args.product_id, args.version)
    Path(args.out).write_bytes(data)
    print(f"Verified and wrote {len(data)} bytes to {args.out}")


def cmd_bundle(args):
    bundle = _mesh(args).export_bundle(args.product_id, args.version)
    Path(args.out).write_text(json.dumps(bundle, indent=2))
    print(f"Wrote evidence bundle ({1 + len(bundle['ancestors'])} manifests) to {args.out}")


def cmd_prove(args):
    proof = _mesh(args).inclusion_proof(args.product_id, args.index, args.version)
    ok = verify_inclusion(proof["chunk"]["id"], args.index, proof["tree_size"], proof["proof"], proof["merkle_root"])
    proof["verified"] = ok
    _dump(proof)


def cmd_log(args):
    mesh = _mesh(args)
    res = verify_event_log(mesh)
    for ev in mesh.db.events(limit=args.limit):
        print(f"#{ev['seq']:<4} {ev['ts']}  {ev['actor']:<11} {ev['kind']:<20} {json.dumps(ev['payload'])[:90]}")
    print(f"\nChain head {res['head'][:16]}…: {'intact' if res['ok'] else 'BROKEN'}")
    for p in res["problems"]:
        print(f"  ✗ {p}")
    return 0 if res["ok"] else 2


def cmd_transforms(args):
    for t in sorted(transforms.REGISTRY.values(), key=lambda t: t.name):
        print(f"{t.name:<15} code {t.code_hash[:12]}…  {t.description}")


def cmd_demo(args):
    demo.run(args.root if args.root_given else "./proofmesh-demo", color=sys.stdout.isatty(),
             cover=not args.no_cover_tracks)


def cmd_serve(args):
    import uvicorn

    os.environ["PROOFMESH_ROOT"] = str(args.root)
    if args.demo:
        os.environ["PROOFMESH_DEMO"] = "1"
    uvicorn.run("proofmesh.api:app", host=args.host, port=args.port, log_level="info")


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="proofmesh", description="A cryptographically verifiable data mesh.")
    p.add_argument("--version", action="version", version=f"proofmesh {__version__}")
    p.add_argument("--root", default=None, help="node directory (default $PROOFMESH_ROOT or ./.proofmesh)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create a new ProofMesh node")
    s.add_argument("--chunking", choices=["fastcdc", "fixed"], default="fastcdc")
    s.add_argument("--min-chunk", type=int, default=2048)
    s.add_argument("--avg-chunk", type=int, default=8192)
    s.add_argument("--max-chunk", type=int, default=65536)
    s.set_defaults(fn=cmd_init)

    dom = sub.add_parser("domain", help="manage domains (departments)").add_subparsers(dest="sub", required=True)
    s = dom.add_parser("add")
    s.add_argument("name")
    s.add_argument("--description", default="")
    s.set_defaults(fn=cmd_domain_add)
    dom.add_parser("list").set_defaults(fn=cmd_domain_list)

    prod = sub.add_parser("product", help="manage data products").add_subparsers(dest="sub", required=True)
    s = prod.add_parser("register")
    s.add_argument("product_id", help="<domain>.<name>")
    s.add_argument("--owner", required=True)
    s.add_argument("--contract", help="path to a contract JSON file")
    s.add_argument("--name")
    s.add_argument("--description", default="")
    s.set_defaults(fn=cmd_product_register)
    prod.add_parser("list").set_defaults(fn=cmd_product_list)

    s = sub.add_parser("publish", help="publish a new version of a product from a file")
    s.add_argument("product_id")
    s.add_argument("file")
    s.add_argument("--as", dest="as_domain")
    s.set_defaults(fn=cmd_publish)

    s = sub.add_parser("derive", help="create a product from other products")
    s.add_argument("output")
    s.add_argument("--input", "-i", action="append", required=True, help="product or product@version")
    s.add_argument("--transform", "-t", required=True,
                   help="registered transformation, or a name for --from-file")
    s.add_argument("--param", "-p", action="append", default=[], help="key=value (value parsed as JSON)")
    s.add_argument("--params-json")
    s.add_argument("--purpose", required=True)
    s.add_argument("--as", dest="as_domain")
    s.add_argument("--from-file", help="record an external transformation that produced this file")
    s.add_argument("--code", help="script that produced --from-file (its hash is recorded)")
    s.add_argument("--description")
    s.set_defaults(fn=cmd_derive)

    s = sub.add_parser("verify", help="verify a product version and its full history")
    s.add_argument("product_id")
    s.add_argument("--version", type=int)
    s.add_argument("--replay", action="store_true", help="re-run registered transformations")
    s.add_argument("--json", action="store_true")
    s.add_argument("--verbose", "-v", action="store_true")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("verify-file", help="check a received copy of a product against its manifest")
    s.add_argument("product_id")
    s.add_argument("file")
    s.add_argument("--version", type=int)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_verify_file)

    s = sub.add_parser("audit", help="verify every product version in the mesh")
    s.add_argument("--replay", action="store_true")
    s.add_argument("--latest", action="store_true", help="only the latest version of each product")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("lineage", help="show the lineage graph, or one product's up/downstream")
    s.add_argument("product_id", nargs="?")
    s.add_argument("--version", type=int)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_lineage)

    s = sub.add_parser("show", help="print a signed manifest")
    s.add_argument("product_id")
    s.add_argument("--version", type=int)
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("export", help="verify, then write a product's data to a file")
    s.add_argument("product_id")
    s.add_argument("out")
    s.add_argument("--version", type=int)
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("bundle", help="export a self-contained evidence bundle (manifest + ancestors)")
    s.add_argument("product_id")
    s.add_argument("out")
    s.add_argument("--version", type=int)
    s.set_defaults(fn=cmd_bundle)

    s = sub.add_parser("prove", help="Merkle inclusion proof for one chunk")
    s.add_argument("product_id")
    s.add_argument("index", type=int)
    s.add_argument("--version", type=int)
    s.set_defaults(fn=cmd_prove)

    s = sub.add_parser("log", help="show and verify the hash-chained audit log")
    s.add_argument("--limit", type=int, default=30)
    s.set_defaults(fn=cmd_log)

    sub.add_parser("transforms", help="list registered transformations").set_defaults(fn=cmd_transforms)

    s = sub.add_parser("demo", help="run the end-to-end tamper-detection demonstration")
    s.add_argument("--no-cover-tracks", action="store_true")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("serve", help="run the REST API and web UI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--demo", action="store_true", help="enable demo endpoints (seed scenario, simulate tampering)")
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.root_given = args.root is not None or "PROOFMESH_ROOT" in os.environ
    args.root = Path(args.root or os.environ.get("PROOFMESH_ROOT", ".proofmesh"))
    try:
        return args.fn(args) or 0
    except (ProofMeshError, ContractError, PolicyViolation, IntegrityError, LookupError, ValueError) as exc:
        msg = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        print(_color("error: ", "1;31") + str(msg), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
