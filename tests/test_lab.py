import pytest

from proofmesh import lab

EXPECT = {
    "edit": ("finance.transactions", "TAMPERED"),
    "bitflip": ("executive.department-costs", "TAMPERED"),
    "delete-chunk": ("finance.transactions", "TAMPERED"),
    "rewrite-manifest": ("finance.transactions", "INVALID"),
    "rogue-ca": ("finance.transactions", "INVALID"),
    "trust-root": ("hr.headcount", "INVALID"),
    "loosen-contract": ("finance.transactions", "INVALID"),
    "hide-lineage": ("executive.cost-per-head", "TAINTED"),
    "forge-report": ("operations.vendor-spend", "INVALID"),
    "erase-report": ("executive.cost-per-head", "ERASED"),
    "rollback": ("finance.transactions", "INVALID"),
    "truncate-log": ("executive.cost-per-head", "INVALID"),
    "stolen-key": ("finance.transactions", "INVALID"),
    "policy-bypass": ("marketing.vendor-targets", "INVALID"),
}


@pytest.fixture(scope="module", autouse=True)
def lab_dir(tmp_path_factory):
    lab.LAB_ROOT = tmp_path_factory.mktemp("lab")
    yield


def statuses(snap):
    """product -> worst status across its versions (ERASED ghosts reported separately)."""
    order = ["VERIFIED", "TAINTED", "TAMPERED", "INVALID"]
    out = {}
    for n in snap["graph"]["nodes"]:
        if n["status"] == "ERASED":
            out.setdefault(n["product_id"] + "#erased", "ERASED")
            out.setdefault(n["product_id"], "ERASED")
            continue
        prev = out.get(n["product_id"], "VERIFIED")
        out[n["product_id"]] = max(prev if prev != "ERASED" else "VERIFIED", n["status"], key=order.index)
    return out


def test_clean_lab_is_verified_and_deterministic():
    a, b = lab.run([]), lab.run([])
    assert a["ok"] and a["counts"]["VERIFIED"] == 6
    assert a["trust"]["pinned"] and a["trust"]["ok"]
    assert [n["id"] for n in a["graph"]["nodes"]] == [n["id"] for n in b["graph"]["nodes"]]


@pytest.mark.parametrize("attack", sorted(lab.ATTACKS))
def test_every_attack_is_detected(attack):
    snap = lab.run([{"id": attack}])
    assert not snap["ok"], f"{attack} went undetected"
    if attack in EXPECT:
        product, status = EXPECT[attack]
        assert statuses(snap)[product] == status


def test_attack_parameters_and_combinations():
    snap = lab.run([{"id": "edit", "params": {"txn": "TX-000010", "amount": "1"}}, {"id": "bitflip"}])
    assert "TX-000010" in snap["applied"][0]["effect"] and "1.00" in snap["applied"][0]["effect"]
    s = statuses(snap)
    assert s["finance.transactions"] == "TAMPERED" and s["executive.department-costs"] == "TAMPERED"
    assert s["hr.headcount"] == "VERIFIED"
    bad = lab.run([{"id": "edit", "params": {"txn": "TX-999999"}}])
    assert "could not be applied" in bad["applied"][0]["effect"]
    with pytest.raises(ValueError):
        lab.run([{"id": "nope"}])
    with pytest.raises(ValueError):
        lab.run([{"id": "edit"}] * 9)


def test_tools():
    data, content = lab.pristine_data("finance.transactions")
    assert lab.check_copy("finance.transactions", data)["matches"]
    res = lab.check_copy("finance.transactions", data.replace(b"TX-000500,2026", b"TX-000500,2025", 1))
    assert not res["matches"] and res["changed_lines"][0]["line"] == 501
    assert lab.try_derivation("operations", "spend-analysis")["allowed"]
    denied = lab.try_derivation("marketing", "ad-targeting")
    assert not denied["allowed"] and "ad-targeting" in denied["reasons"][0]
    b = lab.bundle("executive.cost-per-head")
    assert lab.check_bundle(b)["ok"]
    assert lab.proof("finance.transactions", 3)["verified"]
