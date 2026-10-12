"""HTTP API and web UI (FastAPI).

Two surfaces share one app:

* ``/api/lab/*``: the stateless attack lab behind the public site. Every
  request runs in a throwaway copy of the demo mesh, so it is safe on
  serverless hosting and needs no credentials.
* ``/api/node/*``: a real, stateful ProofMesh node rooted at
  ``$PROOFMESH_ROOT``. Reads that only reveal signed metadata are public;
  anything that writes, or returns a product's data, needs a bearer token
  (``proofmesh token issue <domain>``; the admin token is created by
  ``proofmesh init``). Disabled when ``PROOFMESH_MODE=lab``.

Run locally with ``proofmesh serve``.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from . import __version__, lab, transforms
from .contract import ContractError, PolicyViolation, can_read
from .lineage import lineage_graph
from .merkle import verify_inclusion
from .mesh import IntegrityError, NotFound, ProofMesh, ProofMeshError
from .verify import Verifier, audit, verify_event_log, verify_file

WEB = Path(__file__).parent / "web"
MAX_BODY = int(os.environ.get("PROOFMESH_MAX_UPLOAD", 25 * 1024 * 1024))
LAB_MAX_BODY = 5 * 1024 * 1024
STATIC = {"index.html": "text/html", "app.js": "text/javascript", "app.css": "text/css",
          "favicon.svg": "image/svg+xml", "og.png": "image/png"}

app = FastAPI(title="ProofMesh", version=__version__,
              description="A cryptographically verifiable data mesh: signed data products, Merkle-tree "
                          "integrity, lineage and downstream impact analysis.")


def _mode() -> str:
    return os.environ.get("PROOFMESH_MODE", "full")


@app.middleware("http")
async def _limits_and_headers(request: Request, call_next):
    length = request.headers.get("content-length")
    limit = LAB_MAX_BODY if request.url.path.startswith("/api/lab") else MAX_BODY
    if length and length.isdigit() and int(length) > limit:
        return JSONResponse(status_code=413, content={"error": f"request body larger than {limit} bytes"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
    return response


@app.exception_handler(ProofMeshError)
@app.exception_handler(ContractError)
@app.exception_handler(PolicyViolation)
@app.exception_handler(KeyError)
@app.exception_handler(ValueError)
async def _errors(_: Request, exc: Exception):
    if isinstance(exc, IntegrityError):
        return JSONResponse(status_code=409, content={"error": str(exc), "report": exc.report})
    if isinstance(exc, (NotFound, KeyError)):
        code = 404
    elif isinstance(exc, PolicyViolation):
        code = 403
    elif isinstance(exc, ContractError):
        code = 422
    else:
        code = 400
    msg = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
    return JSONResponse(status_code=code, content={"error": str(msg)})


async def _body(request: Request, limit: int) -> bytes:
    data = bytearray()
    async for part in request.stream():
        data.extend(part)
        if len(data) > limit:
            raise HTTPException(413, f"request body larger than {limit} bytes")
    return bytes(data)


# ---------------------------------------------------------------- web UI

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(WEB / "index.html", media_type="text/html")


@app.get("/assets/{name}", include_in_schema=False)
def asset(name: str):
    if name not in STATIC or not (WEB / name).exists():
        raise HTTPException(404, "not found")
    return FileResponse(WEB / name, media_type=STATIC[name], headers={"Cache-Control": "public, max-age=300"})


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__, "mode": _mode()}


# ------------------------------------------------------------------- lab

class AttackSpec(BaseModel):
    id: str
    params: dict[str, Any] = Field(default_factory=dict)


class LabRun(BaseModel):
    attacks: list[AttackSpec] = Field(default_factory=list)


@app.get("/api/lab/catalog")
def lab_catalog():
    return {"attacks": lab.catalog(), "trust_anchor": lab.trust_anchor(),
            "transforms": [{"name": t.name, "description": t.description}
                           for t in sorted(transforms.REGISTRY.values(), key=lambda t: t.name)]}


@app.post("/api/lab/run")
def lab_run(body: LabRun):
    return lab.run([a.model_dump() for a in body.attacks])


@app.get("/api/lab/run")
def lab_run_link(attacks: str = ""):
    """Shareable form: ``/api/lab/run?attacks=edit,trust-root`` (default parameters)."""
    return lab.run([{"id": a.strip()} for a in attacks.split(",") if a.strip()])


@app.get("/api/lab/data/{product_id}")
def lab_data(product_id: str):
    data, content = lab.pristine_data(product_id)
    return Response(data, media_type=content["media_type"], headers={
        "Content-Disposition": f'attachment; filename="{content["filename"]}"',
        "X-ProofMesh-Merkle-Root": content["merkle_root"]})


@app.post("/api/lab/verify-copy/{product_id}")
async def lab_verify_copy(product_id: str, request: Request):
    return lab.check_copy(product_id, await _body(request, LAB_MAX_BODY))


@app.get("/api/lab/policy")
def lab_policy(consumer: str, purpose: str, source: str = "finance.transactions"):
    return lab.try_derivation(consumer, purpose, source)


@app.get("/api/lab/bundle/{product_id}")
def lab_bundle(product_id: str):
    return JSONResponse(lab.bundle(product_id), headers={
        "Content-Disposition": f'attachment; filename="{product_id}.evidence.json"'})


@app.post("/api/lab/verify-bundle")
async def lab_verify_bundle(request: Request):
    raw = await _body(request, LAB_MAX_BODY)
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"not a JSON evidence bundle: {exc}") from None
    return lab.check_bundle(bundle)


@app.get("/api/lab/proof/{product_id}/{index}")
def lab_proof(product_id: str, index: int):
    return lab.proof(product_id, index)


# ------------------------------------------------------------------ node

class _Node:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.mesh: ProofMesh | None = None

    def get(self) -> ProofMesh:
        if _mode() == "lab":
            raise HTTPException(404, "this deployment only runs the stateless attack lab")
        if self.mesh is None:
            root = Path(os.environ.get("PROOFMESH_ROOT", ".proofmesh"))
            if not (root / "proofmesh.json").exists():
                ProofMesh.init(root).close()
            self.mesh = ProofMesh(root)
        return self.mesh


node = _Node()


def principal(authorization: str | None = Header(default=None)) -> str | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    with node.lock:
        return node.get().authenticate(authorization.split(" ", 1)[1].strip())


def require(who: str | None, *allowed: str) -> str:
    if who is None:
        raise HTTPException(401, "send 'Authorization: Bearer <token>' (see `proofmesh token issue`)")
    if allowed and who not in allowed and who != "admin":
        raise HTTPException(403, f"token for '{who}' may not do this")
    return who


class DomainIn(BaseModel):
    name: str
    description: str = ""


class ProductIn(BaseModel):
    product_id: str
    owner: str
    contract: dict[str, Any] = Field(default_factory=dict)
    name: str | None = None
    description: str = ""


class DeriveIn(BaseModel):
    inputs: list[str]
    transform: str
    params: dict[str, Any] = Field(default_factory=dict)
    purpose: str


class RevokeIn(BaseModel):
    reason: str
    key_id: str | None = None


@app.get("/api/node/overview")
def node_overview():
    with node.lock:
        mesh = node.get()
        res = audit(mesh)
        return {"version": __version__, "trust": res["trust"], "counts": res["counts"],
                "compromised": res["compromised"], "erased": res["erased"],
                "event_log": {k: res["event_log"][k] for k in ("ok", "entries", "head", "problems")},
                "domains": [{k: d[k] for k in ("name", "description", "key_id", "registered_at")}
                            for d in mesh.db.list_domains()],
                "products": [{"product_id": p["product_id"], "name": p["name"], "owner_domain": p["owner_domain"],
                              "versions": len(mesh.db.versions(p["product_id"]))} for p in mesh.products()]}


@app.post("/api/node/domains", status_code=201)
def node_add_domain(body: DomainIn, who: str | None = Depends(principal)):
    require(who, "admin")
    with node.lock:
        mesh = node.get()
        d = mesh.register_domain(body.name, body.description)
        return {"name": d["name"], "key_id": d["key_id"], "token": mesh.issue_token(d["name"])}


@app.post("/api/node/domains/{name}/rotate")
def node_rotate(name: str, who: str | None = Depends(principal)):
    require(who, "admin")
    with node.lock:
        return {"key_id": node.get().rotate_domain_key(name)["key_id"]}


@app.post("/api/node/domains/{name}/revoke")
def node_revoke(name: str, body: RevokeIn, who: str | None = Depends(principal)):
    require(who, "admin")
    with node.lock:
        k = node.get().revoke_domain_key(name, body.reason, body.key_id)
        return {"revoked": k["key_id"], "revocation": k["revocation"]}


@app.get("/api/node/products")
def node_products():
    with node.lock:
        return [{k: p[k] for k in ("product_id", "name", "owner_domain", "description", "contract")}
                for p in node.get().products()]


@app.post("/api/node/products", status_code=201)
def node_add_product(body: ProductIn, who: str | None = Depends(principal)):
    require(who, body.owner)
    with node.lock:
        p = node.get().register_product(body.product_id, body.owner, body.contract, name=body.name,
                                        description=body.description)
        return {k: p[k] for k in ("product_id", "name", "owner_domain", "contract")}


@app.post("/api/node/products/{product_id}/versions", status_code=201)
async def node_publish(product_id: str, request: Request, filename: str | None = None,
                       who: str | None = Depends(principal)):
    require(who)
    data = await _body(request, MAX_BODY)
    with node.lock:
        mesh = node.get()
        actor = mesh.product(product_id)["owner_domain"] if who == "admin" else who
        return mesh.publish(product_id, data, actor=actor, filename=filename)


@app.post("/api/node/products/{product_id}/derive", status_code=201)
def node_derive(product_id: str, body: DeriveIn, who: str | None = Depends(principal)):
    require(who)
    with node.lock:
        mesh = node.get()
        actor = mesh.product(product_id)["owner_domain"] if who == "admin" else who
        return mesh.derive(product_id, body.inputs, body.transform, body.params, body.purpose, actor)


@app.get("/api/node/products/{product_id}/manifest")
def node_manifest(product_id: str, version: int | None = None):
    with node.lock:
        return node.get().envelope(product_id, version)


@app.get("/api/node/products/{product_id}/verify")
def node_verify(product_id: str, version: int | None = None, replay: bool = False):
    with node.lock:
        return Verifier(node.get(), replay=replay).verify_product(product_id, version)


@app.get("/api/node/products/{product_id}/data")
def node_data(product_id: str, version: int | None = None, who: str | None = Depends(principal)):
    require(who)
    with node.lock:
        mesh = node.get()
        env = mesh.envelope(product_id, version)
        if who != "admin" and not can_read(env["manifest"]["contract"], who):
            raise PolicyViolation(f"'{who}' is not an authorised reader of '{product_id}'")
        payload = mesh.read(product_id, version)
    c = env["manifest"]["content"]
    return Response(payload, media_type=c["media_type"], headers={
        "Content-Disposition": f'attachment; filename="{c["filename"]}"',
        "X-ProofMesh-Manifest": env["manifest_id"], "X-ProofMesh-Merkle-Root": c["merkle_root"]})


@app.post("/api/node/products/{product_id}/verify-file")
async def node_verify_file(product_id: str, request: Request, version: int | None = None):
    payload = await _body(request, MAX_BODY)
    with node.lock:
        return verify_file(node.get(), product_id, payload, version)


@app.get("/api/node/products/{product_id}/proof/{index}")
def node_proof(product_id: str, index: int, version: int | None = None):
    with node.lock:
        p = node.get().inclusion_proof(product_id, index, version)
    p["verified"] = verify_inclusion(p["chunk"]["id"], index, p["tree_size"], p["proof"], p["merkle_root"])
    return p


@app.get("/api/node/products/{product_id}/bundle")
def node_bundle(product_id: str, version: int | None = None):
    with node.lock:
        return node.get().export_bundle(product_id, version)


@app.get("/api/node/lineage")
def node_lineage():
    with node.lock:
        return lineage_graph(node.get())


@app.get("/api/node/audit")
def node_audit(replay: bool = False):
    with node.lock:
        return audit(node.get(), replay=replay)


@app.get("/api/node/log")
def node_log(limit: int = 100):
    with node.lock:
        mesh = node.get()
        return {"verification": verify_event_log(mesh), "events": mesh.db.events(limit=limit)}


@app.get("/api/node/checkpoint")
def node_checkpoint(who: str | None = Depends(principal)):
    require(who, "admin")
    with node.lock:
        return node.get().checkpoint()


@app.get("/robots.txt", include_in_schema=False)
def robots():
    return PlainTextResponse("User-agent: *\nAllow: /\n")
