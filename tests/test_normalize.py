import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanners" / "normalize"))

import normalize as n  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def by_rule(findings, rule_id):
    return [f for f in findings if f["rule_id"] == rule_id]


def test_semgrep_sarif_parsed_and_paths_normalized():
    out = n.dedupe_exact(n.parse_sarif(FIX / "semgrep.sarif", "semgrep"))
    files = {f["location"]["file"] for f in out}
    assert files == {"apps/vulnshop-api/app/routes/search.py", "apps/vulnshop-api/app/auth.py"}


def test_duplicate_results_collapse_to_one_finding():
    raw = n.parse_sarif(FIX / "semgrep.sarif", "semgrep")
    assert len(raw) == 3
    sqli = by_rule(n.dedupe_exact(raw), "python.flask.security.sql-injection")
    assert len(sqli) == 1
    # First occurrence wins, so the snippet survives
    assert "SELECT" in sqli[0]["evidence"]["snippet"]


def test_semgrep_cwe_and_severity_mapping():
    out = n.parse_sarif(FIX / "semgrep.sarif", "semgrep")
    sqli = by_rule(out, "python.flask.security.sql-injection")[0]
    md5 = by_rule(out, "python.lang.security.audit.insecure-hash")[0]
    assert sqli["cwe"] == ["CWE-89"]
    assert sqli["severity_norm"] == "HIGH"      # semgrep error is capped at HIGH
    assert md5["severity_norm"] == "MEDIUM"
    assert sqli["cve"] == []


def test_trivy_vulns_and_misconfigs():
    out = n.parse_trivy(FIX / "trivy.json")
    flask = by_rule(out, "CVE-2023-30861")[0]
    assert flask["cve"] == ["CVE-2023-30861"]
    assert flask["package"] == {"name": "flask", "version": "2.2.2", "fixed_version": "2.2.5"}
    assert flask["severity_norm"] == "HIGH"

    ghsa = by_rule(out, "GHSA-xxxx-yyyy-zzzz")[0]
    assert ghsa["cve"] == []                      # GHSA is not a CVE; never invent one
    assert ghsa["package"]["fixed_version"] is None
    assert ghsa["severity_norm"] == "INFO"

    ksv = by_rule(out, "KSV017")[0]
    assert ksv["location"] == {"file": "infra/k8s/deployment.yaml", "line": 21}


def test_gitleaks_is_always_high():
    out = n.parse_sarif(FIX / "gitleaks.sarif", "gitleaks")
    assert out[0]["severity_norm"] == "HIGH"
    assert "snippet" not in out[0]["evidence"]    # gitleaks runs with --redact


def test_finding_id_is_stable_and_16_hex():
    a = n.make_finding_id("semgrep", "r", "a.py", 1, None)
    assert a == n.make_finding_id("semgrep", "r", "a.py", 1, None)
    assert len(a) == 16 and int(a, 16) >= 0
    assert a != n.make_finding_id("semgrep", "r", "a.py", 2, None)


def test_raw_ref_points_into_source():
    out = n.parse_trivy(FIX / "trivy.json", ref="artifacts/scans/trivy.json")
    assert by_rule(out, "KSV017")[0]["evidence"]["raw_ref"] == \
        "artifacts/scans/trivy.json#/Results/1/Misconfigurations/0"


def test_unmapped_severity_falls_back_with_warning(capsys):
    assert n.normalize_severity("semgrep", "BOGUS") == "MEDIUM"
    assert "unmapped severity" in capsys.readouterr().err


def test_schema_rejects_bad_finding():
    good = n.parse_trivy(FIX / "trivy.json")[0]
    bad = {**good, "severity_norm": "SEVERE"}
    with pytest.raises(ValueError, match="schema validation failed"):
        n.validate([bad])


def test_cli_end_to_end_is_valid_and_deterministic(tmp_path):
    args = ["--semgrep", str(FIX / "semgrep.sarif"), "--gitleaks", str(FIX / "gitleaks.sarif"),
            "--trivy", str(FIX / "trivy.json")]
    o1, o2 = tmp_path / "a.json", tmp_path / "b.json"
    assert n.main(args + ["-o", str(o1)]) == 0
    assert n.main(args + ["-o", str(o2)]) == 0
    assert o1.read_bytes() == o2.read_bytes()
    findings = json.loads(o1.read_text())
    assert len(findings) == 6                     # 2 semgrep + 1 gitleaks + 3 trivy
    assert len({f["finding_id"] for f in findings}) == 6
