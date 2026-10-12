"""REST API and web UI (FastAPI).

Run with ``proofmesh serve`` (add ``--demo`` for the demo endpoints), or::

    PROOFMESH_ROOT=./node uvicorn proofmesh.api:app

Acting domains are named in the request (``actor``). This MVP node is
custodial and trusts its callers; a production deployment would authenticate
each department and keep its signing key on its own node.
"""

from __future__ import annotations

import os
import shutil
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from . import __version__, demo, transforms
from .contract import ContractError, PolicyViolation
from .lineage import lineage_graph
from .merkle import verify_inclusion
from .mesh import IntegrityError, NotFound, ProofMesh, ProofMeshError
from .verify import Verifier, audit, verify_event_log, verify_file

WEB = Path(__file__).parent / "web"


class _State:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.mesh: ProofMesh | None = None

    @property
    def root(self) -> Path:
        return Path(os.environ.get("PROOFMESH_ROOT", ".proofmesh"))

    @property
    def demo(self) -> bool:
        return os.environ.get("PROOFMESH_DEMO") == "1"

    def get(self) -> ProofMesh:
        if self.mesh is None:
            if not (self.root / "proofmesh.json").exists():
                if self.demo:
                    self.reset_demo()
                else:
                    ProofMesh.init(self.root).close()
            if self.mesh is None:
                self.mesh = ProofMesh(self.root)
        return self.mesh

    def reset_demo(self) -> None:
        if self.mesh is not None:
            self.mesh.close()
            self.mesh = None
        if self.root.exists():
            shutil.rmtree(self.root)
        mesh = ProofMesh.init(self.root, chunking=demo.DEMO_CHUNKING)
        demo.build_scenario(mesh)
        self.mesh = mesh


state = _State()
app = FastAPI(title="ProofMesh", version=__version__,
              description="A cryptographically verifiable data mesh: signed manifests, Merkle-tree "
                          "integrity, lineage and downstream impact analysis.")


@app.exception_handler(ProofMeshError)
@app.exception_handler(ContractError)
@app.exception_handler(PolicyViolation)
@app.exception_handler(KeyError)
async def _errors(_: Request, exc: Exception):
    if isinstance(exc, (NotFound, KeyError)):
        code = 404
    elif isinstance(exc, PolicyViolation):
        code = 403
    elif isinstance(exc, ContractError):
        code = 422
    elif isinstance(exc, IntegrityError):
        return JSONResponse(status_code=409, content={"error": str(exc), "report": exc.report})
    else:
        code = 400
    msg = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
    return JSONResponse(status_code=code, content={"error": str(msg)})


def _mesh() -> ProofMesh:
    return state.get()


# ------------------------------------------------------------------ models

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
    actor: str | None = None


# ------------------------------------------------------------------ routes

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(WEB / "index.html")


@app.get("/api/overview")
def overview():
    with state.lock:
        mesh = _mesh()
        res = audit(mesh, latest_only=False)
        return {
            "version": __version__,
            "demo_mode": state.demo,
            "authority_key": mesh.authority_public_key,
            "chunking": mesh.chunking.to_dict(),
            "domains": [{k: d[k] for k in ("name", "description", "key_id", "registered_at")}
                        for d in mesh.db.list_domains()],
            "products": [{"product_id": p["product_id"], "name": p["name"], "owner_domain": p["owner_domain"],
                          "description": p["description"],
                          "versions": len(mesh.db.versions(p["product_id"]))} for p in mesh.products()],
            "counts": res["counts"],
            "compromised": res["compromised"],
            "event_log": res["event_log"],
        }


@app.get("/api/domains")
def domains():
    with state.lock:
        return [{k: d[k] for k in ("name", "description", "key_id", "public_key", "registered_at", "certificate")}
                for d in _mesh().db.list_domains()]


@app.post("/api/domains", status_code=201)
def add_domain(body: DomainIn):
    with state.lock:
        d = _mesh().register_domain(body.name, body.description)
        return {k: d[k] for k in ("name", "description", "key_id", "public_key", "registered_at")}


@app.get("/api/products")
def products():
    with state.lock:
        return _mesh().products()


@app.post("/api/products", status_code=201)
def add_product(body: ProductIn):
    with state.lock:
        return _mesh().register_product(body.product_id, body.owner, body.contract, name=body.name,
                                        description=body.description)


@app.get("/api/products/{product_id}")
def product(product_id: str):
    with state.lock:
        mesh = _mesh()
        p = mesh.product(product_id)
        p["versions"] = [dict(r) for r in mesh.db.versions(product_id)]
        return p


@app.post("/api/products/{product_id}/versions", status_code=201)
async def publish(product_id: str, request: Request, filename: str | None = None, actor: str | None = None):
    """Publish raw request body bytes as a new version (``Content-Type: application/octet-stream``)."""
    data = await request.body()
    with state.lock:
        return _mesh().publish(product_id, data, actor=actor, filename=filename)


@app.post("/api/products/{product_id}/derive", status_code=201)
def derive(product_id: str, body: DeriveIn):
    with state.lock:
        return _mesh().derive(product_id, body.inputs, body.transform, body.params, body.purpose, body.actor)


@app.get("/api/products/{product_id}/manifest")
def manifest(product_id: str, version: int | None = None):
    with state.lock:
        return _mesh().envelope(product_id, version)


@app.get("/api/products/{product_id}/verify")
def verify(product_id: str, version: int | None = None, replay: bool = False):
    with state.lock:
        return Verifier(_mesh(), replay=replay).verify_product(product_id, version)


@app.get("/api/products/{product_id}/data")
def data(product_id: str, version: int | None = None):
    with state.lock:
        mesh = _mesh()
        env = mesh.envelope(product_id, version)
        payload = mesh.read(product_id, version)
    c = env["manifest"]["content"]
    return Response(payload, media_type=c["media_type"], headers={
        "Content-Disposition": f'attachment; filename="{c["filename"]}"',
        "X-ProofMesh-Manifest": env["manifest_id"],
        "X-ProofMesh-Merkle-Root": c["merkle_root"],
    })


@app.post("/api/products/{product_id}/verify-file")
async def verify_upload(product_id: str, request: Request, version: int | None = None):
    payload = await request.body()
    with state.lock:
        return verify_file(_mesh(), product_id, payload, version)


@app.get("/api/products/{product_id}/proof/{index}")
def proof(product_id: str, index: int, version: int | None = None):
    with state.lock:
        p = _mesh().inclusion_proof(product_id, index, version)
    p["verified"] = verify_inclusion(p["chunk"]["id"], index, p["tree_size"], p["proof"], p["merkle_root"])
    return p


@app.get("/api/products/{product_id}/bundle")
def bundle(product_id: str, version: int | None = None):
    with state.lock:
        return _mesh().export_bundle(product_id, version)


@app.get("/api/lineage")
def lineage(latest_only: bool = False):
    with state.lock:
        return lineage_graph(_mesh(), latest_only=latest_only)


@app.get("/api/audit")
def audit_all(replay: bool = False, latest_only: bool = False):
    with state.lock:
        return audit(_mesh(), replay=replay, latest_only=latest_only)


@app.get("/api/log")
def log(limit: int = 100):
    with state.lock:
        mesh = _mesh()
        return {"verification": verify_event_log(mesh), "events": mesh.db.events(limit=limit)}


@app.get("/api/transforms")
def list_transforms():
    return [{"name": t.name, "description": t.description, "arity": t.arity, "code_hash": t.code_hash}
            for t in sorted(transforms.REGISTRY.values(), key=lambda t: t.name)]


# --------------------------------------------------------------- demo mode

def _require_demo() -> None:
    if not state.demo:
        raise HTTPException(404, "demo endpoints are disabled (start with `proofmesh serve --demo`)")


@app.post("/api/demo/reset")
def demo_reset():
    _require_demo()
    with state.lock:
        state.reset_demo()
        return {"ok": True}


@app.post("/api/demo/tamper")
def demo_tamper(txn_id: str = demo.TAMPER_TXN):
    _require_demo()
    with state.lock:
        return demo.secretly_tamper(_mesh(), txn_id=txn_id)


@app.post("/api/demo/cover-tracks")
def demo_cover_tracks():
    _require_demo()
    with state.lock:
        return demo.cover_tracks(_mesh())
