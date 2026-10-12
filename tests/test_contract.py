import pytest

from proofmesh.contract import ContractError, evaluate, normalize_contract, purposes_within

C = normalize_contract({
    "schema": {"format": "csv", "columns": [
        {"name": "id", "type": "string", "required": True},
        {"name": "amount", "type": "decimal"},
        {"name": "day", "type": "date"}]},
    "quality_rules": [
        {"type": "unique", "column": "id"},
        {"type": "range", "column": "amount", "min": 0},
        {"type": "regex", "column": "id", "pattern": r"A\d+", "severity": "warn"}],
    "permitted_purposes": ["audit"],
}, "finance")


def test_defaults():
    assert C["access_policy"] == {"readers": ["*"], "writers": ["finance"]}
    assert C["quality_rules"][0]["id"] == "unique:id"


def test_valid_data_passes():
    r = evaluate(b"id,amount,day\nA1,1.50,2026-01-01\nA2,,2026-01-02\n", C)
    assert r["passed"] and r["rows"] == 2


def test_schema_violations():
    assert not evaluate(b"id,amount\nA1,1\n", C)["passed"]  # missing column
    assert not evaluate(b"id,amount,day,x\nA1,1,2026-01-01,1\n", C)["passed"]  # extra column
    r = evaluate(b"id,amount,day\nA1,abc,2026-13-01\n,1,2026-01-01\n", C)
    assert not r["passed"]
    assert len(r["schema"]["problems"]) == 3


def test_rule_severity():
    r = evaluate(b"id,amount,day\nB1,1,2026-01-01\n", C)  # regex is only a warning
    assert r["passed"]
    assert [x["passed"] for x in r["rules"]] == [True, True, False]
    r = evaluate(b"id,amount,day\nA1,1,2026-01-01\nA1,-1,2026-01-01\n", C)
    assert not r["passed"]
    assert r["rules"][0]["examples"] == [2] and r["rules"][1]["examples"] == [2]


def test_bad_contracts():
    with pytest.raises(ContractError):
        normalize_contract({"schema": {"format": "csv", "columns": []}}, "x")
    with pytest.raises(ContractError):
        normalize_contract({"schema": {"format": "csv", "columns": [{"name": "a", "type": "money"}]}}, "x")
    with pytest.raises(ContractError):
        normalize_contract({"schema": {"format": "csv", "columns": [{"name": "a"}]},
                            "quality_rules": [{"type": "unique", "column": "b"}]}, "x")


def test_purposes_are_sticky():
    a = {"permitted_purposes": ["audit", "reporting"]}
    b = {"permitted_purposes": ["reporting"]}
    star = {"permitted_purposes": ["*"]}
    assert purposes_within(["reporting"], [a, b]) == []
    assert purposes_within(["audit"], [a, b]) == ["audit"]
    assert purposes_within(["*"], [a]) == ["*"]
    assert purposes_within(["anything"], [star]) == []
