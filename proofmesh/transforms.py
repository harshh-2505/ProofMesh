"""Registered, deterministic transformations.

A transformation that runs through ProofMesh is recorded in the output's
signed manifest together with the SHA-256 of its source code and its exact
parameters. Because the built-in transformations are deterministic (stable
row order, exact ``Decimal`` arithmetic, fixed CSV dialect), a verifier can
*replay* a derivation and check it reproduces the signed output byte for byte.

Transformations performed outside ProofMesh can still be recorded (see
``ProofMesh.derive_external``); they are attested by the deriving domain's
signature but cannot be replayed.
"""

from __future__ import annotations

import csv
import hashlib
import inspect
import io
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Callable

from .contract import read_csv

TransformFn = Callable[[list[bytes], dict], bytes]


@dataclass(frozen=True)
class Transform:
    name: str
    fn: TransformFn
    description: str
    arity: int  # number of inputs; 0 = any number >= 1

    @property
    def code_hash(self) -> str:
        return hashlib.sha256(inspect.getsource(self.fn).encode("utf-8")).hexdigest()


REGISTRY: dict[str, Transform] = {}


def register(name: str, description: str, arity: int = 1):
    def deco(fn: TransformFn) -> TransformFn:
        REGISTRY[name] = Transform(name, fn, description, arity)
        return fn
    return deco


def get(name: str) -> Transform:
    try:
        return REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown transformation {name!r}; available: {', '.join(sorted(REGISTRY))}") from None


def _write_csv(header: list[str], rows: list[dict]) -> bytes:
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=header, lineterminator="\n", extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode("utf-8")


def _compare(value: str, op: str, target) -> bool:
    if op == "in":
        return value in [str(t) for t in target]
    if op in ("eq", "ne"):
        a: object = value
        b: object = str(target)
        try:
            a, b = Decimal(value), Decimal(str(target))
        except (InvalidOperation, ValueError):
            pass
        return (a == b) if op == "eq" else (a != b)
    try:
        a_num, b_num = Decimal(value), Decimal(str(target))
    except (InvalidOperation, ValueError):
        return False
    return {"gt": a_num > b_num, "ge": a_num >= b_num, "lt": a_num < b_num, "le": a_num <= b_num}[op]


@register("filter_rows", "Keep rows where <column> <op> <value> (ops: eq ne gt ge lt le in).")
def filter_rows(inputs: list[bytes], params: dict) -> bytes:
    header, rows = read_csv(inputs[0])
    col, op, value = params["column"], params["op"], params["value"]
    if op not in ("eq", "ne", "gt", "ge", "lt", "le", "in"):
        raise ValueError(f"unsupported op {op!r}")
    if col not in header:
        raise ValueError(f"unknown column {col!r}")
    return _write_csv(header, [r for r in rows if _compare(r[col], op, value)])


@register("select_columns", "Project the listed columns, in the given order.")
def select_columns(inputs: list[bytes], params: dict) -> bytes:
    header, rows = read_csv(inputs[0])
    cols = list(params["columns"])
    unknown = [c for c in cols if c not in header]
    if unknown:
        raise ValueError(f"unknown columns: {unknown}")
    return _write_csv(cols, rows)


@register("aggregate", "Group by columns and compute sum/count/avg/min/max metrics.")
def aggregate(inputs: list[bytes], params: dict) -> bytes:
    header, rows = read_csv(inputs[0])
    group_by = list(params["group_by"])
    metrics = list(params["metrics"])
    places = Decimal(1).scaleb(-int(params.get("decimals", 2)))
    for c in group_by + [m["column"] for m in metrics if m["fn"] != "count"]:
        if c not in header:
            raise ValueError(f"unknown column {c!r}")
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(r[c] for c in group_by), []).append(r)
    out_rows = []
    for key in sorted(groups):
        members = groups[key]
        row = dict(zip(group_by, key))
        for m in metrics:
            fn, alias = m["fn"], m.get("as") or f"{m['fn']}_{m.get('column', 'rows')}"
            if fn == "count":
                row[alias] = str(len(members))
                continue
            vals = [Decimal(r[m["column"]]) for r in members if r[m["column"]] != ""]
            if fn == "sum":
                v = sum(vals, Decimal(0))
            elif fn == "avg":
                v = (sum(vals, Decimal(0)) / len(vals)) if vals else Decimal(0)
            elif fn == "min":
                v = min(vals) if vals else Decimal(0)
            elif fn == "max":
                v = max(vals) if vals else Decimal(0)
            else:
                raise ValueError(f"unsupported metric {fn!r}")
            row[alias] = str(v.quantize(places))
        out_rows.append(row)
    out_header = group_by + [m.get("as") or f"{m['fn']}_{m.get('column', 'rows')}" for m in metrics]
    return _write_csv(out_header, out_rows)


@register("join", "Inner/left join of two CSV inputs on key columns.", arity=2)
def join(inputs: list[bytes], params: dict) -> bytes:
    lh, lrows = read_csv(inputs[0])
    rh, rrows = read_csv(inputs[1])
    left_on, right_on = params["left_on"], params.get("right_on", params["left_on"])
    how = params.get("how", "inner")
    if how not in ("inner", "left"):
        raise ValueError("how must be 'inner' or 'left'")
    index: dict[str, list[dict]] = {}
    for r in rrows:
        index.setdefault(r[right_on], []).append(r)
    r_extra = [c for c in rh if c != right_on and c not in lh]
    out = []
    for lr in lrows:
        matches = index.get(lr[left_on], [])
        if not matches and how == "left":
            out.append({**lr, **{c: "" for c in r_extra}})
        for rr in matches:
            out.append({**lr, **{c: rr[c] for c in r_extra}})
    return _write_csv(lh + r_extra, out)


@register("compute", "Add a column = <left> <op> <right> where operands are columns or numbers (ops: + - * /).")
def compute(inputs: list[bytes], params: dict) -> bytes:
    header, rows = read_csv(inputs[0])
    places = Decimal(1).scaleb(-int(params.get("decimals", 2)))
    op = params["op"]

    def operand(row: dict, ref) -> Decimal:
        return Decimal(row[ref]) if isinstance(ref, str) and ref in header else Decimal(str(ref))

    out = []
    for r in rows:
        a, b = operand(r, params["left"]), operand(r, params["right"])
        if op == "+":
            v = a + b
        elif op == "-":
            v = a - b
        elif op == "*":
            v = a * b
        elif op == "/":
            v = a / b if b else Decimal(0)
        else:
            raise ValueError(f"unsupported op {op!r}")
        out.append({**r, params["as"]: str(v.quantize(places))})
    return _write_csv(header + [params["as"]], out)
