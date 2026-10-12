"""Data contracts: schema, quality rules, access policy and permitted purposes.

A contract is a plain JSON document, embedded verbatim in every signed
manifest of the product so that the producer's promises travel with the data.

Example::

    {
      "schema": {"format": "csv", "columns": [
          {"name": "txn_id", "type": "string", "required": true},
          {"name": "amount", "type": "decimal", "required": true}]},
      "quality_rules": [
          {"id": "txn-unique", "type": "unique", "column": "txn_id"},
          {"id": "amount-positive", "type": "range", "column": "amount", "min": 0}],
      "access_policy": {"readers": ["*"], "writers": ["finance"]},
      "permitted_purposes": ["financial-reporting", "audit"],
      "classification": "internal"
    }

Supported column types: ``string``, ``integer``, ``decimal``, ``date``
(ISO ``YYYY-MM-DD``), ``boolean``. Supported rule types: ``not_null``,
``unique``, ``range``, ``allowed_values``, ``regex``, ``row_count``.
Rules have severity ``error`` (blocks publishing) or ``warn`` (recorded).
"""

from __future__ import annotations

import csv
import io
import re
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any, Callable

COLUMN_TYPES = ("string", "integer", "decimal", "date", "boolean")
RULE_TYPES = ("not_null", "unique", "range", "allowed_values", "regex", "row_count")
MAX_EXAMPLES = 5


class ContractError(ValueError):
    """The contract document itself is malformed."""


class PolicyViolation(PermissionError):
    """An operation is not allowed by a product's access policy or purposes."""


# --------------------------------------------------------------------------
# Contract structure
# --------------------------------------------------------------------------

def normalize_contract(contract: dict, owner_domain: str) -> dict:
    """Validate a contract and fill in defaults. Returns a new dict."""
    if not isinstance(contract, dict):
        raise ContractError("contract must be a JSON object")
    c = dict(contract)
    schema = dict(c.get("schema") or {"format": "binary"})
    fmt = schema.get("format", "binary")
    if fmt not in ("csv", "binary"):
        raise ContractError(f"unsupported schema format {fmt!r}")
    schema["format"] = fmt
    if fmt == "csv":
        cols = schema.get("columns")
        if not cols or not isinstance(cols, list):
            raise ContractError("csv schema needs a non-empty 'columns' list")
        seen = set()
        norm_cols = []
        for col in cols:
            name = col.get("name")
            if not name or name in seen:
                raise ContractError(f"column names must be unique and non-empty (got {name!r})")
            seen.add(name)
            ctype = col.get("type", "string")
            if ctype not in COLUMN_TYPES:
                raise ContractError(f"column {name!r}: unknown type {ctype!r}")
            norm_cols.append({"name": name, "type": ctype, "required": bool(col.get("required", False)),
                              **({"description": col["description"]} if col.get("description") else {})})
        schema["columns"] = norm_cols
        schema["allow_extra_columns"] = bool(schema.get("allow_extra_columns", False))
    c["schema"] = schema

    rules = []
    for i, rule in enumerate(c.get("quality_rules") or []):
        rtype = rule.get("type")
        if rtype not in RULE_TYPES:
            raise ContractError(f"quality rule #{i}: unknown type {rtype!r}")
        if rtype != "row_count":
            if fmt != "csv":
                raise ContractError(f"quality rule {rtype!r} needs a csv schema")
            if rule.get("column") not in {col["name"] for col in schema["columns"]}:
                raise ContractError(f"quality rule #{i}: unknown column {rule.get('column')!r}")
        if rtype == "regex":
            try:
                re.compile(rule["pattern"])
            except (KeyError, re.error) as exc:
                raise ContractError(f"quality rule #{i}: bad regex: {exc}") from None
        if rtype == "allowed_values" and not isinstance(rule.get("values"), list):
            raise ContractError(f"quality rule #{i}: 'values' list required")
        severity = rule.get("severity", "error")
        if severity not in ("error", "warn"):
            raise ContractError(f"quality rule #{i}: severity must be 'error' or 'warn'")
        rules.append({**rule, "id": rule.get("id") or f"{rtype}:{rule.get('column', '*')}", "severity": severity})
    c["quality_rules"] = rules

    policy = dict(c.get("access_policy") or {})
    policy["readers"] = list(policy.get("readers") or ["*"])
    policy["writers"] = list(policy.get("writers") or [owner_domain])
    if owner_domain not in policy["writers"]:
        policy["writers"].insert(0, owner_domain)
    c["access_policy"] = policy

    purposes = c.get("permitted_purposes")
    if purposes is None:
        purposes = ["*"]
    if not isinstance(purposes, list) or not all(isinstance(p, str) and p for p in purposes):
        raise ContractError("permitted_purposes must be a list of non-empty strings")
    c["permitted_purposes"] = sorted(set(purposes))
    c.setdefault("classification", "internal")
    return c


def can_read(contract: dict, domain: str) -> bool:
    readers = contract["access_policy"]["readers"]
    return "*" in readers or domain in readers


def can_write(contract: dict, domain: str) -> bool:
    return domain in contract["access_policy"]["writers"]


def purpose_allowed(contract: dict, purpose: str) -> bool:
    allowed = contract["permitted_purposes"]
    return "*" in allowed or purpose in allowed


def purposes_within(output_purposes: list[str], input_contracts: list[dict]) -> list[str]:
    """Purposes a derived product claims that some input does not permit.

    Purpose restrictions are *sticky*: data derived from a product cannot be
    offered for a purpose the original producer never allowed.
    """
    bad = []
    for p in output_purposes:
        for c in input_contracts:
            allowed = c["permitted_purposes"]
            if "*" in allowed:
                continue
            if p == "*" or p not in allowed:
                bad.append(p)
                break
    return bad


# --------------------------------------------------------------------------
# Data evaluation
# --------------------------------------------------------------------------

def _parse_bool(v: str) -> bool:
    if v.lower() in ("true", "false", "1", "0", "yes", "no"):
        return True
    raise ValueError(v)


_TYPE_CHECKS: dict[str, Callable[[str], Any]] = {
    "string": str,
    "integer": int,
    "decimal": Decimal,
    "date": date.fromisoformat,
    "boolean": _parse_bool,
}


def _conforms(value: str, ctype: str) -> bool:
    try:
        _TYPE_CHECKS[ctype](value)
        return True
    except (ValueError, InvalidOperation, ArithmeticError):
        return False


def _number(value: str) -> Decimal | None:
    try:
        return Decimal(value)
    except (InvalidOperation, ValueError):
        return None


def read_csv(data: bytes) -> tuple[list[str], list[dict[str, str]]]:
    text = data.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    rows = list(reader)
    return list(reader.fieldnames or []), rows


def evaluate(data: bytes, contract: dict) -> dict:
    """Check ``data`` against the contract's schema and quality rules.

    Returns a JSON-serialisable *quality report*; ``report["passed"]`` is
    False when the schema is violated or an ``error``-severity rule fails.
    Row numbers in examples are 1-based data rows (header excluded).
    """
    schema = contract["schema"]
    report: dict[str, Any] = {"format": schema["format"], "rows": None, "schema": None, "rules": []}
    rows: list[dict[str, str]] = []

    if schema["format"] == "csv":
        try:
            header, rows = read_csv(data)
        except (UnicodeDecodeError, csv.Error) as exc:
            report["schema"] = {"passed": False, "problems": [f"unreadable CSV: {exc}"]}
            report["passed"] = False
            return report
        report["rows"] = len(rows)
        problems = []
        declared = [c["name"] for c in schema["columns"]]
        missing = [c for c in declared if c not in header]
        extra = [c for c in header if c not in declared]
        if missing:
            problems.append(f"missing columns: {', '.join(missing)}")
        if extra and not schema.get("allow_extra_columns"):
            problems.append(f"undeclared columns: {', '.join(extra)}")
        for col in schema["columns"]:
            if col["name"] in missing:
                continue
            bad_type, bad_required = [], []
            for i, row in enumerate(rows, start=1):
                v = row.get(col["name"])
                if v is None or v == "":
                    if col["required"]:
                        bad_required.append(i)
                    continue
                if not _conforms(v, col["type"]):
                    bad_type.append(i)
            if bad_required:
                problems.append(f"column '{col['name']}' is required but empty in {len(bad_required)} row(s), e.g. rows {bad_required[:MAX_EXAMPLES]}")
            if bad_type:
                problems.append(f"column '{col['name']}' is not {col['type']} in {len(bad_type)} row(s), e.g. rows {bad_type[:MAX_EXAMPLES]}")
        report["schema"] = {"passed": not problems, "problems": problems}

    for rule in contract["quality_rules"]:
        violations = _check_rule(rule, rows, report["rows"])
        report["rules"].append({
            "id": rule["id"],
            "type": rule["type"],
            "column": rule.get("column"),
            "severity": rule["severity"],
            "passed": not violations,
            "violations": len(violations),
            "examples": violations[:MAX_EXAMPLES],
        })

    schema_ok = report["schema"] is None or report["schema"]["passed"]
    report["passed"] = schema_ok and all(r["passed"] for r in report["rules"] if r["severity"] == "error")
    return report


def _check_rule(rule: dict, rows: list[dict[str, str]], row_count: int | None) -> list:
    rtype = rule["type"]
    if rtype == "row_count":
        n = row_count or 0
        lo, hi = rule.get("min"), rule.get("max")
        if (lo is not None and n < lo) or (hi is not None and n > hi):
            return [f"row count {n} outside [{lo}, {hi}]"]
        return []
    col = rule["column"]
    out: list[int] = []
    if rtype == "not_null":
        out = [i for i, r in enumerate(rows, 1) if not r.get(col)]
    elif rtype == "unique":
        seen: set[str] = set()
        for i, r in enumerate(rows, 1):
            v = r.get(col)
            if v in seen:
                out.append(i)
            seen.add(v)
    elif rtype == "range":
        lo = Decimal(str(rule["min"])) if rule.get("min") is not None else None
        hi = Decimal(str(rule["max"])) if rule.get("max") is not None else None
        for i, r in enumerate(rows, 1):
            v = r.get(col)
            if not v:
                continue
            num = _number(v)
            if num is None or (lo is not None and num < lo) or (hi is not None and num > hi):
                out.append(i)
    elif rtype == "allowed_values":
        allowed = set(map(str, rule["values"]))
        out = [i for i, r in enumerate(rows, 1) if r.get(col) and r.get(col) not in allowed]
    elif rtype == "regex":
        pat = re.compile(rule["pattern"])
        out = [i for i, r in enumerate(rows, 1) if r.get(col) and not pat.fullmatch(r.get(col))]
    return out


def summarize_quality(report: dict) -> str:
    if report.get("schema") and not report["schema"]["passed"]:
        return "; ".join(report["schema"]["problems"])
    failed = [r for r in report["rules"] if not r["passed"]]
    if not failed:
        return "all checks passed"
    return "; ".join(f"{r['id']} ({r['severity']}): {r['violations']} violation(s)" for r in failed)
