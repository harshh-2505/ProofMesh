import json

from proofmesh import demo
from proofmesh.cli import main


def test_cli_end_to_end(tmp_path, capsys):
    root = str(tmp_path / "node")
    run = lambda *a: main(["--root", root, *a])
    assert run("init", "--min-chunk", "1024", "--avg-chunk", "4096", "--max-chunk", "16384") == 0
    assert run("domain", "add", "finance") == 0
    assert run("domain", "add", "operations") == 0
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps(demo.FINANCE_CONTRACT))
    assert run("product", "register", "finance.transactions", "--owner", "finance", "--contract", str(contract)) == 0
    report_contract = tmp_path / "report.json"
    report_contract.write_text(json.dumps({"schema": {"format": "csv", "columns": [
        {"name": "vendor"}, {"name": "total", "type": "decimal"}]}, "permitted_purposes": ["spend-analysis"]}))
    assert run("product", "register", "operations.vendors", "--owner", "operations", "--contract", str(report_contract)) == 0
    data = tmp_path / "tx.csv"
    data.write_bytes(demo.transactions_csv(500))
    assert run("publish", "finance.transactions", str(data)) == 0
    assert run("derive", "operations.vendors", "-i", "finance.transactions", "-t", "aggregate",
               "-p", 'group_by=["vendor"]', "-p", 'metrics=[{"fn":"sum","column":"amount","as":"total"}]',
               "--purpose", "spend-analysis") == 0
    assert run("verify", "operations.vendors", "--replay") == 0
    assert run("verify-file", "finance.transactions", str(data)) == 0
    assert run("audit") == 0
    assert run("log") == 0
    out = tmp_path / "out.csv"
    assert run("export", "operations.vendors", str(out)) == 0 and out.read_bytes().startswith(b"vendor,total")

    from proofmesh import ProofMesh
    with ProofMesh(root) as mesh:
        demo.secretly_tamper(mesh, txn_id="TX-000250")
    capsys.readouterr()
    assert run("verify", "finance.transactions") == 2
    text = capsys.readouterr().out
    assert "TAMPERED" in text and "operations.vendors@1" in text
    assert run("verify", "operations.vendors") == 2
    assert run("export", "operations.vendors", str(out)) == 1
    assert run("audit", "--json") == 2
