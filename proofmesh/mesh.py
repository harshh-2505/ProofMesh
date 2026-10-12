"""The ProofMesh node: register domains and products, publish, derive, read.

Directory layout of a mesh rooted at ``ROOT``::

    ROOT/proofmesh.json          node configuration (chunking parameters)
    ROOT/registry.db             SQLite index (domains, products, manifests, lineage, log)
    ROOT/objects/                content-addressed chunk store
    ROOT/trust/authority.pub     the mesh authority public key (the trust anchor)
    ROOT/keys/authority.pem      authority private key
    ROOT/keys/domains/<d>.pem    each domain's private key

In this reference node one machine holds every domain's key, standing in for
each department's own key store or HSM. Keys are encrypted at rest when
``PROOFMESH_KEY_PASSPHRASE`` is set. Nothing in the verification path depends
on the private keys: verifiers need only the authority public key, and should
*pin* it (``trust_anchor=`` or ``PROOFMESH_TRUST_ANCHOR``) rather than trust the
copy in ``trust/authority.pub`` that sits next to the data it protects.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Callable, Iterable

from . import transforms
from .canonical import digest, sha256_hex, utc_now
from .chunking import ChunkingParams, iter_chunks
from .contract import (
    ContractError,
    PolicyViolation,
    can_read,
    can_write,
    evaluate,
    normalize_contract,
    purpose_allowed,
    purposes_within,
    summarize_quality,
)
from .crypto import (
    CTX_CHECKPOINT,
    CTX_EVENT,
    CTX_MANIFEST,
    CTX_REGISTRATION,
    CTX_REVOCATION,
    SigningKey,
    issue_certificate,
    key_id_for,
)
from .db import Database
from .merkle import MerkleTree
from .store import ChunkStore

DOMAIN_RE = re.compile(r"^[a-z][a-z0-9-]{1,39}$")
PRODUCT_RE = re.compile(r"^[a-z][a-z0-9-]{1,39}\.[a-z0-9][a-z0-9.-]{0,79}$")
GENESIS = "0" * 64
FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _passphrase() -> bytes | None:
    value = os.environ.get("PROOFMESH_KEY_PASSPHRASE")
    return value.encode() if value else None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class ProofMeshError(Exception):
    pass


class NotFound(ProofMeshError, LookupError):
    pass


class IntegrityError(ProofMeshError):
    """Raised when an operation would rely on data that failed verification."""

    def __init__(self, message: str, report: dict | None = None):
        super().__init__(message)
        self.report = report


class ProofMesh:
    def __init__(self, root: Path | str, clock: Callable[[], str] = utc_now, *,
                 trust_anchor: str | None = None, key_seed: bytes | None = None):
        """Open a node.

        ``trust_anchor`` pins the mesh authority: either its base64 public key or
        its 16-hex-digit key id. It defaults to ``$PROOFMESH_TRUST_ANCHOR``.
        Without a pin, verification trusts ``trust/authority.pub`` and says so.
        """
        self.root = Path(root)
        if not (self.root / "proofmesh.json").exists():
            raise NotFound(f"no ProofMesh node at {self.root} (run `proofmesh init`)")
        self.config = json.loads((self.root / "proofmesh.json").read_text())
        self.chunking = ChunkingParams.from_dict(self.config["chunking"])
        self.db = Database(self.root / "registry.db")
        self.store = ChunkStore(self.root / "objects")
        self.node_authority_key = (self.root / "trust" / "authority.pub").read_text().strip()
        self.trust_anchor = trust_anchor or os.environ.get("PROOFMESH_TRUST_ANCHOR") or None
        self.clock = clock
        self._key_seed = key_seed

    @property
    def authority_public_key(self) -> str:
        """The authority key verification uses: the pinned one when a full key is pinned."""
        if self.trust_anchor and len(self.trust_anchor) > 16:
            return self.trust_anchor
        return self.node_authority_key

    def trust_status(self) -> dict:
        """Whether the node's authority key matches the verifier's pinned trust anchor."""
        node_id = key_id_for(self.node_authority_key)
        if not self.trust_anchor:
            return {"pinned": False, "ok": True, "authority_key_id": node_id,
                    "detail": f"trusting the node's own authority key {node_id} (not pinned)"}
        pinned_id = self.trust_anchor if len(self.trust_anchor) <= 16 else key_id_for(self.trust_anchor)
        ok = pinned_id == node_id
        return {"pinned": True, "ok": ok, "authority_key_id": node_id, "pinned_key_id": pinned_id,
                "detail": f"node authority {node_id} matches the pinned trust anchor" if ok else
                f"node authority {node_id} is NOT the pinned trust anchor {pinned_id}: "
                "the node's trust root was replaced"}

    # ------------------------------------------------------------------ setup
    @classmethod
    def init(cls, root: Path | str, chunking: ChunkingParams | None = None,
             clock: Callable[[], str] = utc_now, *, key_seed: bytes | None = None) -> "ProofMesh":
        """Create a node. ``key_seed`` makes every key deterministic (demos and tests only)."""
        root = Path(root)
        if (root / "proofmesh.json").exists():
            raise ProofMeshError(f"{root} already contains a ProofMesh node")
        root.mkdir(parents=True, exist_ok=True)
        authority = SigningKey.from_seed(key_seed + b"/authority") if key_seed else SigningKey.generate()
        authority.save(root / "keys" / "authority.pem", _passphrase())
        (root / "trust").mkdir(exist_ok=True)
        (root / "trust" / "authority.pub").write_text(authority.public_key_b64 + "\n")
        params = chunking or ChunkingParams()
        (root / "proofmesh.json").write_text(json.dumps(
            {"spec_version": 1, "chunking": params.to_dict(), "created_at": clock()}, indent=2) + "\n")
        mesh = cls(root, clock=clock, key_seed=key_seed)
        now = clock()
        mesh.db.execute("INSERT INTO keys (key_id, owner, public_key, certificate, created_at) VALUES (?,?,?,?,?)",
                        (authority.key_id, "authority", authority.public_key_b64, None, now))
        mesh._log("authority", "mesh.initialized", {
            "authority_key_id": authority.key_id, "chunking": params.to_dict()})
        admin = mesh.issue_token("admin")
        token_path = root / "keys" / "admin.token"
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(admin + "\n")
        return mesh

    def close(self) -> None:
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------------- keys
    def _authority_key(self) -> SigningKey:
        return SigningKey.load(self.root / "keys" / "authority.pem", _passphrase())

    def _domain_key(self, domain: str) -> SigningKey:
        path = self.root / "keys" / "domains" / f"{domain}.pem"
        if not path.exists():
            raise NotFound(f"no private key for domain '{domain}' on this node")
        return SigningKey.load(path, _passphrase())

    def _new_key(self, label: str) -> SigningKey:
        if self._key_seed:
            return SigningKey.from_seed(self._key_seed + b"/" + label.encode())
        return SigningKey.generate()

    # ----------------------------------------------------------------- tokens
    def issue_token(self, principal: str) -> str:
        """Create an API token for a domain (or ``admin``). Only its hash is stored."""
        if principal != "admin":
            self.domain(principal)
        token = f"pm_{principal}_{secrets.token_urlsafe(24)}"
        self.db.execute("INSERT INTO api_tokens (token_hash, principal, created_at) VALUES (?,?,?)",
                        (hash_token(token), principal, self.clock()))
        return token

    def authenticate(self, token: str | None) -> str | None:
        """Return the principal (domain name or ``admin``) a token belongs to."""
        if not token:
            return None
        row = self.db.one("SELECT principal FROM api_tokens WHERE token_hash = ?", (hash_token(token),))
        return row["principal"] if row else None

    def _key_for(self, actor: str) -> SigningKey:
        return self._authority_key() if actor == "authority" else self._domain_key(actor)

    # -------------------------------------------------------------- audit log
    def _log(self, actor: str, kind: str, payload: dict, *, key: SigningKey | None = None) -> dict:
        last = self.db.last_event()
        key = key or self._key_for(actor)
        entry = {
            "seq": (last["seq"] + 1) if last else 1,
            "ts": self.clock(),
            "actor": actor,
            "key_id": key.key_id,
            "kind": kind,
            "payload": payload,
            "prev_hash": last["entry_hash"] if last else GENESIS,
        }
        entry_hash = digest(entry)
        signature = key.sign(CTX_EVENT, entry)
        self.db.execute(
            "INSERT INTO events (seq, ts, actor, key_id, kind, payload, prev_hash, entry_hash, signature) VALUES (?,?,?,?,?,?,?,?,?)",
            (entry["seq"], entry["ts"], actor, key.key_id, kind, json.dumps(payload, sort_keys=True),
             entry["prev_hash"], entry_hash, signature),
        )
        return {**entry, "entry_hash": entry_hash}

    # ---------------------------------------------------------------- domains
    def register_domain(self, name: str, description: str = "") -> dict:
        if not DOMAIN_RE.match(name):
            raise ProofMeshError("domain names are 2-40 chars of a-z, 0-9 and '-', starting with a letter")
        if name == "authority":
            raise ProofMeshError("'authority' is reserved")
        if self.db.get_domain(name):
            raise ProofMeshError(f"domain '{name}' already exists")
        key = self._new_key(f"domain/{name}/1")
        key.save(self.root / "keys" / "domains" / f"{name}.pem", _passphrase())
        now = self.clock()
        cert = issue_certificate(self._authority_key(), name, key.public_key_b64, now)
        with self.db.transaction():
            self.db.execute(
                "INSERT INTO domains (name, description, public_key, key_id, certificate, registered_at) VALUES (?,?,?,?,?,?)",
                (name, description, key.public_key_b64, key.key_id, json.dumps(cert), now),
            )
            self.db.execute("INSERT INTO keys (key_id, owner, public_key, certificate, created_at) VALUES (?,?,?,?,?)",
                            (key.key_id, name, key.public_key_b64, json.dumps(cert), now))
            self._log("authority", "domain.registered", {"domain": name, "key_id": key.key_id})
        return self.db.get_domain(name)

    def rotate_domain_key(self, name: str) -> dict:
        """Issue a domain a fresh key. Signatures made with the old key stay valid."""
        old = self.domain(name)
        generation = len(self.db.keys_of(name)) + 1
        key = self._new_key(f"domain/{name}/{generation}")
        now = self.clock()
        cert = issue_certificate(self._authority_key(), name, key.public_key_b64, now)
        with self.db.transaction():
            self.db.execute("UPDATE domains SET public_key = ?, key_id = ?, certificate = ? WHERE name = ?",
                            (key.public_key_b64, key.key_id, json.dumps(cert), name))
            self.db.execute("INSERT INTO keys (key_id, owner, public_key, certificate, created_at) VALUES (?,?,?,?,?)",
                            (key.key_id, name, key.public_key_b64, json.dumps(cert), now))
            self._log("authority", "domain.key_rotated",
                      {"domain": name, "old_key_id": old["key_id"], "new_key_id": key.key_id})
        key.save(self.root / "keys" / "domains" / f"{name}.pem", _passphrase())
        return self.db.get_domain(name)

    def revoke_domain_key(self, name: str, reason: str, key_id: str | None = None) -> dict:
        """Revoke a (compromised) domain key and rotate to a new one.

        The revocation is an authority-signed statement recorded in the audit
        log. Anything signed with the key and recorded *after* that log entry is
        rejected; earlier signatures stay valid. Ordering comes from the
        hash-chained log, not from timestamps an attacker could backdate.
        """
        current = self.domain(name)
        key_id = key_id or current["key_id"]
        key = self.db.get_key(key_id)
        if key is None or key["owner"] != name:
            raise NotFound(f"domain '{name}' has no key {key_id}")
        if key["revocation"]:
            raise ProofMeshError(f"key {key_id} is already revoked")
        with self.db.transaction():
            event = self._log("authority", "key.revoked", {"domain": name, "key_id": key_id, "reason": reason})
            statement = {"type": "proofmesh/key-revocation", "domain": name, "key_id": key_id,
                         "reason": reason, "log_seq": event["seq"], "revoked_at": event["ts"]}
            revocation = {"revocation": statement, "signature": self._authority_key().sign(CTX_REVOCATION, statement)}
            self.db.execute("UPDATE keys SET revocation = ? WHERE key_id = ?", (json.dumps(revocation), key_id))
        if key_id == current["key_id"]:
            self.rotate_domain_key(name)
        return self.db.get_key(key_id)

    def checkpoint(self) -> dict:
        """An authority-signed statement of the current audit-log head.

        Store it somewhere the node cannot rewrite (a git repo, a ticket, an
        email). ``verify_event_log(mesh, checkpoint)`` then proves the log still
        extends it, which catches truncation or a rewritten history.
        """
        last = self.db.last_event()
        body = {"type": "proofmesh/log-checkpoint", "seq": last["seq"], "entry_hash": last["entry_hash"],
                "authority_key_id": key_id_for(self.node_authority_key), "created_at": self.clock()}
        return {"checkpoint": body, "signature": self._authority_key().sign(CTX_CHECKPOINT, body)}

    def domain(self, name: str) -> dict:
        d = self.db.get_domain(name)
        if d is None:
            raise NotFound(f"unknown domain '{name}'")
        return d

    # --------------------------------------------------------------- products
    def register_product(self, product_id: str, owner: str, contract: dict, name: str | None = None,
                         description: str = "") -> dict:
        self.domain(owner)
        if not PRODUCT_RE.match(product_id):
            raise ProofMeshError("product ids look like '<domain>.<name>', e.g. 'finance.transactions'")
        if product_id.split(".", 1)[0] != owner:
            raise ProofMeshError(f"product '{product_id}' must live in its owner's namespace '{owner}.'")
        if self.db.get_product(product_id):
            raise ProofMeshError(f"product '{product_id}' already exists")
        contract = normalize_contract(contract, owner)
        now = self.clock()
        registration = {
            "type": "proofmesh/product-registration",
            "product_id": product_id,
            "name": name or product_id,
            "owner_domain": owner,
            "description": description,
            "contract": contract,
            "registered_at": now,
        }
        key = self._domain_key(owner)
        envelope = {"registration": registration, "signature": key.sign(CTX_REGISTRATION, registration),
                    "signer_key_id": key.key_id}
        with self.db.transaction():
            self.db.execute(
                "INSERT INTO products (product_id, name, owner_domain, description, registration, registered_at) VALUES (?,?,?,?,?,?)",
                (product_id, registration["name"], owner, description, json.dumps(envelope), now),
            )
            self._log(owner, "product.registered", {"product_id": product_id, "contract_hash": digest(contract)})
        return self.product(product_id)

    def product(self, product_id: str) -> dict:
        p = self.db.get_product(product_id)
        if p is None:
            raise NotFound(f"unknown data product '{product_id}'")
        p["contract"] = p["registration"]["registration"]["contract"]
        return p

    def products(self) -> list[dict]:
        return [self.product(p["product_id"]) for p in self.db.list_products()]

    # ---------------------------------------------------------------- publish
    def publish(self, product_id: str, data: bytes, *, actor: str | None = None,
                filename: str | None = None, media_type: str | None = None) -> dict:
        """Chunk, hash, check the contract, sign and record a new product version."""
        product = self.product(product_id)
        actor = actor or product["owner_domain"]
        if not can_write(product["contract"], actor):
            raise PolicyViolation(f"domain '{actor}' may not publish '{product_id}'")
        return self._record(product, data, actor=actor, filename=filename, media_type=media_type,
                            inputs=[], transformation=None)

    def _record(self, product: dict, data: bytes, *, actor: str, filename: str | None,
                media_type: str | None, inputs: list[dict], transformation: dict | None,
                key: SigningKey | None = None) -> dict:
        contract = product["contract"]
        quality = evaluate(data, contract)
        if not quality["passed"]:
            raise ContractError(f"data violates the contract of '{product['product_id']}': {summarize_quality(quality)}")

        chunks = []
        for index, (offset, chunk) in enumerate(iter_chunks(data, self.chunking)):
            cid = self.store.put(chunk)
            chunks.append({"index": index, "offset": offset, "size": len(chunk), "id": cid})
        tree = MerkleTree([c["id"] for c in chunks])

        prev = self.db.manifest_row(product["product_id"])
        version = (prev["version"] + 1) if prev else 1
        key = key or self._domain_key(actor)
        signer_domain = self.domain(actor)
        is_csv = contract["schema"]["format"] == "csv"
        if filename:
            filename = FILENAME_RE.sub("_", filename).strip("._")[:120] or None
        head = self.db.last_event()
        body = {
            "type": "proofmesh/manifest",
            "spec_version": 1,
            "product": {
                "id": product["product_id"],
                "name": product["name"],
                "owner_domain": product["owner_domain"],
                "description": product["description"],
                "version": version,
            },
            "previous_manifest": prev["manifest_id"] if prev else None,
            "contract": contract,
            "contract_hash": digest(contract),
            "content": {
                "filename": filename or f"{product['product_id']}.v{version}{'.csv' if is_csv else ''}",
                "media_type": media_type or ("text/csv" if is_csv else "application/octet-stream"),
                "size": len(data),
                "content_hash": sha256_hex(data),
                "hash_algorithm": "sha256",
                "chunking": self.chunking.to_dict(),
                "chunk_count": len(chunks),
                "chunks": chunks,
                "merkle_root": tree.root,
            },
            "quality": quality,
            "lineage": {"inputs": inputs, "transformation": transformation},
            "signer": {"domain": actor, "key_id": key.key_id},
            # Commits the manifest to the audit log as it stood: a manifest
            # cannot later be slipped in "before" an event it never saw.
            "log_anchor": {"seq": head["seq"], "entry_hash": head["entry_hash"]},
            "created_at": self.clock(),
        }
        manifest_id = digest(body)
        envelope = {
            "manifest_id": manifest_id,
            "manifest": body,
            "signature": key.sign(CTX_MANIFEST, body),
            "certificate": (signer_domain["certificate"] if signer_domain["key_id"] == key.key_id
                            else (self.db.get_key(key.key_id) or {}).get("certificate")),
        }
        with self.db.transaction():
            if self.db.last_event()["seq"] != head["seq"]:
                raise ProofMeshError("the audit log moved while publishing; retry")
            self.db.execute(
                "INSERT INTO manifests (manifest_id, product_id, version, envelope, created_at) VALUES (?,?,?,?,?)",
                (manifest_id, product["product_id"], version, json.dumps(envelope), body["created_at"]),
            )
            for inp in inputs:
                self.db.execute(
                    "INSERT INTO lineage_edges (input_manifest_id, output_manifest_id) VALUES (?,?)",
                    (inp["manifest_id"], manifest_id),
                )
            if transformation:
                self.db.execute(
                    "INSERT INTO transformations (transformation_id, output_manifest_id, name, kind, code_hash, params, purpose, executed_by, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (transformation["id"], manifest_id, transformation["name"], transformation["kind"],
                     transformation.get("code_hash"), json.dumps(transformation["params"], sort_keys=True),
                     transformation["purpose"], transformation["executed_by"], body["created_at"]),
                )
            self._log(actor, "product.derived" if inputs else "product.published", key=key, payload={
                "product_id": product["product_id"],
                "version": version,
                "manifest_id": manifest_id,
                "merkle_root": tree.root,
                "inputs": [i["manifest_id"] for i in inputs],
            })
        return envelope

    # ----------------------------------------------------------------- derive
    def _resolve(self, ref: str | tuple[str, int]) -> dict:
        """Resolve ``'product'``, ``'product@3'`` or ``(product, 3)`` to a manifest row."""
        if isinstance(ref, tuple):
            pid, version = ref
        elif "@" in ref:
            pid, v = ref.rsplit("@", 1)
            version = int(v)
        else:
            pid, version = ref, None
        row = self.db.manifest_row(pid, version)
        if row is None:
            what = f"version {version} of '{pid}'" if version else f"any published version of '{pid}'"
            raise NotFound(f"there is no {what}")
        return dict(row)

    def _prepare_derivation(self, output_product_id: str, input_refs: Iterable, purpose: str,
                            actor: str | None) -> tuple[dict, str, list[dict], list[bytes]]:
        out = self.product(output_product_id)
        actor = actor or out["owner_domain"]
        if not can_write(out["contract"], actor):
            raise PolicyViolation(f"domain '{actor}' may not publish '{output_product_id}'")
        if not purpose:
            raise PolicyViolation("a derivation must declare its purpose")
        input_refs = list(input_refs)
        if not input_refs:
            raise ProofMeshError("a derivation needs at least one input")

        from .verify import Verifier  # local import: verify depends on mesh

        verifier = Verifier(self)
        refs, payloads, contracts = [], [], []
        for ref in input_refs:
            row = self._resolve(ref)
            report = verifier.verify_manifest(row["manifest_id"])
            if report["status"] != "VERIFIED":
                raise IntegrityError(
                    f"refusing to derive from {row['product_id']}@{row['version']}: {report['status']} ({report['summary']})",
                    report)
            body = self.db.get_envelope(row["manifest_id"])["manifest"]
            contract = body["contract"]
            if not can_read(contract, actor):
                raise PolicyViolation(f"domain '{actor}' is not an authorised reader of '{row['product_id']}'")
            if not purpose_allowed(contract, purpose):
                raise PolicyViolation(
                    f"purpose '{purpose}' is not permitted by the contract of '{row['product_id']}' "
                    f"(permitted: {', '.join(contract['permitted_purposes'])})")
            contracts.append(contract)
            refs.append({
                "product_id": row["product_id"],
                "version": row["version"],
                "manifest_id": row["manifest_id"],
                "merkle_root": body["content"]["merkle_root"],
                "owner_domain": body["product"]["owner_domain"],
            })
            payloads.append(self._materialize(body))
        bad = purposes_within(out["contract"]["permitted_purposes"], contracts)
        if bad:
            raise PolicyViolation(
                f"'{output_product_id}' would permit purposes its inputs do not allow: {', '.join(sorted(set(bad)))}")
        return out, actor, refs, payloads

    def derive(self, output_product_id: str, inputs: Iterable, transform: str, params: dict,
               purpose: str, actor: str | None = None) -> dict:
        """Run a registered transformation over verified inputs and publish the result."""
        t = transforms.get(transform)
        out, actor, refs, payloads = self._prepare_derivation(output_product_id, inputs, purpose, actor)
        if t.arity and len(payloads) != t.arity:
            raise ProofMeshError(f"transformation '{transform}' takes {t.arity} input(s), got {len(payloads)}")
        data = t.fn(payloads, params)
        record = {
            "kind": "registered",
            "name": t.name,
            "description": t.description,
            "code_hash": t.code_hash,
            "params": params,
            "purpose": purpose,
            "executed_by": actor,
            "executed_at": self.clock(),
            "inputs_verified": True,
        }
        record["id"] = digest(record)
        return self._record(out, data, actor=actor, filename=None, media_type=None,
                            inputs=refs, transformation=record)

    def derive_external(self, output_product_id: str, inputs: Iterable, data: bytes, *, name: str,
                        description: str, purpose: str, code: bytes | None = None,
                        params: dict | None = None, actor: str | None = None,
                        filename: str | None = None) -> dict:
        """Record a transformation that ran outside ProofMesh (e.g. a notebook or Spark job)."""
        out, actor, refs, _ = self._prepare_derivation(output_product_id, inputs, purpose, actor)
        record = {
            "kind": "external",
            "name": name,
            "description": description,
            "code_hash": sha256_hex(code) if code is not None else None,
            "params": params or {},
            "purpose": purpose,
            "executed_by": actor,
            "executed_at": self.clock(),
            "inputs_verified": True,
        }
        record["id"] = digest(record)
        return self._record(out, data, actor=actor, filename=filename, media_type=None,
                            inputs=refs, transformation=record)

    # ------------------------------------------------------------------- read
    def _materialize(self, body: dict) -> bytes:
        return b"".join(self.store.get(c["id"]) for c in body["content"]["chunks"])

    def envelope(self, product_id: str, version: int | None = None) -> dict:
        row = self._resolve((product_id, version) if version is not None else product_id)
        return self.db.get_envelope(row["manifest_id"])

    def read(self, product_id: str, version: int | None = None, *, verify: bool = True) -> bytes:
        """Return a product's bytes, refusing if the full history does not verify."""
        env = self.envelope(product_id, version)
        if verify:
            from .verify import Verifier

            report = Verifier(self).verify_manifest(env["manifest_id"])
            if report["status"] != "VERIFIED":
                raise IntegrityError(f"{product_id}@{env['manifest']['product']['version']} is {report['status']}: "
                                     f"{report['summary']}", report)
        return self._materialize(env["manifest"])

    def inclusion_proof(self, product_id: str, index: int, version: int | None = None) -> dict:
        env = self.envelope(product_id, version)
        content = env["manifest"]["content"]
        tree = MerkleTree([c["id"] for c in content["chunks"]])
        chunk = content["chunks"][index]
        return {
            "product_id": product_id,
            "version": env["manifest"]["product"]["version"],
            "manifest_id": env["manifest_id"],
            "chunk": chunk,
            "tree_size": len(tree),
            "proof": tree.inclusion_proof(index),
            "merkle_root": content["merkle_root"],
        }

    def export_bundle(self, product_id: str, version: int | None = None) -> dict:
        """Self-contained evidence: the manifest envelope plus every ancestor's envelope."""
        env = self.envelope(product_id, version)
        ancestors: dict[str, dict] = {}
        stack = [i["manifest_id"] for i in env["manifest"]["lineage"]["inputs"]]
        while stack:
            mid = stack.pop()
            if mid in ancestors:
                continue
            anc = self.db.get_envelope(mid)
            if anc is None:
                continue
            ancestors[mid] = anc
            stack.extend(i["manifest_id"] for i in anc["manifest"]["lineage"]["inputs"])
        products = {env["manifest"]["product"]["id"]} | {a["manifest"]["product"]["id"] for a in ancestors.values()}
        registrations = {}
        for pid in sorted(products):
            p = self.db.get_product(pid)
            if p is None:
                continue
            reg = p["registration"]
            key = self.db.get_key(reg.get("signer_key_id", ""))
            registrations[pid] = {**reg, "certificate": key["certificate"] if key else None}
        return {
            "type": "proofmesh/evidence-bundle",
            "authority_key_id": key_id_for(self.node_authority_key),
            "manifest": env,
            "ancestors": list(ancestors.values()),
            "registrations": registrations,
        }
