"""SQLite registry: domains, products, manifests, lineage index and audit log.

The database is a *convenience index*, not a source of trust. Every fact that
matters is also covered by a signature (manifests, certificates, log entries),
so a verifier can detect a row that was edited behind ProofMesh's back.

The audit log is append-only and hash-chained: each entry commits to the hash
of the previous one and is signed by the domain that performed the action.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    name          TEXT PRIMARY KEY,
    description   TEXT NOT NULL DEFAULT '',
    public_key    TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    certificate   TEXT NOT NULL,
    registered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
    product_id    TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    owner_domain  TEXT NOT NULL REFERENCES domains(name),
    description   TEXT NOT NULL DEFAULT '',
    registration  TEXT NOT NULL,
    registered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS manifests (
    manifest_id   TEXT PRIMARY KEY,
    product_id    TEXT NOT NULL REFERENCES products(product_id),
    version       INTEGER NOT NULL,
    envelope      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    UNIQUE (product_id, version)
);
CREATE TABLE IF NOT EXISTS lineage_edges (
    input_manifest_id  TEXT NOT NULL,
    output_manifest_id TEXT NOT NULL,
    PRIMARY KEY (input_manifest_id, output_manifest_id)
);
CREATE INDEX IF NOT EXISTS lineage_by_output ON lineage_edges(output_manifest_id);
CREATE TABLE IF NOT EXISTS transformations (
    transformation_id  TEXT PRIMARY KEY,
    output_manifest_id TEXT NOT NULL UNIQUE,
    name               TEXT NOT NULL,
    kind               TEXT NOT NULL,
    code_hash          TEXT,
    params             TEXT NOT NULL,
    purpose            TEXT NOT NULL,
    executed_by        TEXT NOT NULL,
    created_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    kind       TEXT NOT NULL,
    payload    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    signature  TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # -- transactions --------------------------------------------------------
    def transaction(self):
        return _Tx(self.conn)

    def execute(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, args)

    def one(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, args).fetchall()

    # -- domains -------------------------------------------------------------
    def get_domain(self, name: str) -> dict | None:
        row = self.one("SELECT * FROM domains WHERE name = ?", (name,))
        if row is None:
            return None
        d = dict(row)
        d["certificate"] = json.loads(d["certificate"])
        return d

    def list_domains(self) -> list[dict]:
        out = []
        for row in self.all("SELECT * FROM domains ORDER BY name"):
            d = dict(row)
            d["certificate"] = json.loads(d["certificate"])
            out.append(d)
        return out

    # -- products ------------------------------------------------------------
    def get_product(self, product_id: str) -> dict | None:
        row = self.one("SELECT * FROM products WHERE product_id = ?", (product_id,))
        if row is None:
            return None
        d = dict(row)
        d["registration"] = json.loads(d["registration"])
        return d

    def list_products(self) -> list[dict]:
        out = []
        for row in self.all("SELECT * FROM products ORDER BY product_id"):
            d = dict(row)
            d["registration"] = json.loads(d["registration"])
            out.append(d)
        return out

    # -- manifests -----------------------------------------------------------
    def get_envelope(self, manifest_id: str) -> dict | None:
        row = self.one("SELECT envelope FROM manifests WHERE manifest_id = ?", (manifest_id,))
        return json.loads(row["envelope"]) if row else None

    def manifest_row(self, product_id: str, version: int | None = None) -> sqlite3.Row | None:
        if version is None:
            return self.one(
                "SELECT * FROM manifests WHERE product_id = ? ORDER BY version DESC LIMIT 1", (product_id,)
            )
        return self.one("SELECT * FROM manifests WHERE product_id = ? AND version = ?", (product_id, version))

    def iter_manifest_rows(self) -> Iterator[sqlite3.Row]:
        yield from self.all("SELECT * FROM manifests ORDER BY rowid")

    def versions(self, product_id: str) -> list[sqlite3.Row]:
        return self.all(
            "SELECT manifest_id, version, created_at FROM manifests WHERE product_id = ? ORDER BY version",
            (product_id,),
        )

    # -- lineage index -------------------------------------------------------
    def inputs_of(self, manifest_id: str) -> list[str]:
        return [r[0] for r in self.all(
            "SELECT input_manifest_id FROM lineage_edges WHERE output_manifest_id = ? ORDER BY input_manifest_id",
            (manifest_id,))]

    def outputs_of(self, manifest_id: str) -> list[str]:
        return [r[0] for r in self.all(
            "SELECT output_manifest_id FROM lineage_edges WHERE input_manifest_id = ? ORDER BY output_manifest_id",
            (manifest_id,))]

    def transformation_for(self, manifest_id: str) -> dict | None:
        row = self.one("SELECT * FROM transformations WHERE output_manifest_id = ?", (manifest_id,))
        if row is None:
            return None
        d = dict(row)
        d["params"] = json.loads(d["params"])
        return d

    # -- events --------------------------------------------------------------
    def last_event(self) -> sqlite3.Row | None:
        return self.one("SELECT * FROM events ORDER BY seq DESC LIMIT 1")

    def events(self, limit: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM events ORDER BY seq"
        rows = self.all(sql)
        if limit is not None:
            rows = rows[-limit:]
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d["payload"])
            out.append(d)
        return out


class _Tx:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def __enter__(self):
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        self.conn.execute("ROLLBACK" if exc_type else "COMMIT")
        return False
