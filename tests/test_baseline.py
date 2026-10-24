import copy
import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanners" / "normalize"))
sys.path.insert(0, str(ROOT / "scanners" / "baseline"))

import baseline as b  # noqa: E402
import normalize as n  # noqa: E402

TODAY = dt.date(2026, 10, 22)


def finding(rule="r.sqli", file="app/search.py", line=10, sev="HIGH", tool="semgrep", pkg=None):
    return {
        "schema_version": "1.0.0",
        "finding_id": n.make_finding_id(tool, rule, file, line, pkg),
        "tool": tool, "rule_id": rule, "severity_raw": sev, "severity_norm": sev,
        "cwe": [], "cve": [],
        "location": {"file": file, "line": line},
        "package": {"name": pkg, "version": None, "fixed_version": None},
        "evidence": {"raw_ref": "x"},
        "baseline": {"is_new": True, "first_seen_commit": None},
    }


def run_check(findings, base, repo, fail_on="HIGH"):
    findings = copy.deepcopy(findings)
    stats = b.apply_baseline(findings, base, "c2")
    anns = b.scan_annotations(repo, TODAY, 90)
    b.attach_exceptions(findings, anns)
    return findings, b.evaluate_gate(findings, anns, fail_on, stats)


# ------------------------------------------------------------------ baseline matching

def test_everything_new_without_baseline(tmp_path):
    fs, rep = run_check([finding()], b.load_baseline(tmp_path / "none.json"), tmp_path)
    assert fs[0]["baseline"] == {"is_new": True, "first_seen_commit": "c2"}
    assert rep["result"] == "fail" and rep["counts"]["blocking"] == 1


def test_baselined_finding_does_not_block(tmp_path):
    base = b.build_baseline([finding()], "c1")
    fs, rep = run_check([finding()], base, tmp_path)
    assert fs[0]["baseline"] == {"is_new": False, "first_seen_commit": "c1"}
    assert rep["result"] == "pass"


def test_line_shift_is_not_new(tmp_path):
    """Inserting lines above a known finding changes finding_id but must not make it new."""
    base = b.build_baseline([finding(line=10)], "c1")
    fs, rep = run_check([finding(line=14)], base, tmp_path)
    assert fs[0]["finding_id"] != base["entries"][0]["finding_id"]
    assert fs[0]["baseline"]["is_new"] is False
    assert rep["result"] == "pass"


def test_extra_occurrence_of_known_rule_is_new(tmp_path):
    base = b.build_baseline([finding(line=10)], "c1")
    fs, rep = run_check([finding(line=10), finding(line=50)], base, tmp_path)
    by_line = {f["location"]["line"]: f["baseline"]["is_new"] for f in fs}
    assert by_line == {10: False, 50: True}     # exact match claims the old slot first
    assert rep["counts"]["new"] == 1 and rep["result"] == "fail"


def test_same_rule_other_file_is_new(tmp_path):
    base = b.build_baseline([finding(file="app/a.py")], "c1")
    fs, _ = run_check([finding(file="app/b.py")], base, tmp_path)
    assert fs[0]["baseline"]["is_new"] is True


def test_fixed_findings_are_counted(tmp_path):
    base = b.build_baseline([finding(line=10), finding(rule="r.xss", line=20)], "c1")
    _, rep = run_check([finding(line=10)], base, tmp_path)
    assert rep["counts"]["fixed_since_baseline"] == 1


def test_severity_threshold(tmp_path):
    _, rep = run_check([finding(sev="MEDIUM")], b.load_baseline(tmp_path / "none.json"), tmp_path)
    assert rep["result"] == "pass" and rep["counts"]["new"] == 1
    _, rep = run_check([finding(sev="MEDIUM")], b.load_baseline(tmp_path / "none.json"),
                       tmp_path, fail_on="MEDIUM")
    assert rep["result"] == "fail"


def test_rebaseline_preserves_first_seen(tmp_path):
    first = b.build_baseline([finding()], "c1")
    second = b.build_baseline([finding(), finding(rule="r.xss")], "c5", previous=first)
    seen = {e["rule_id"]: e["first_seen_commit"] for e in second["entries"]}
    assert seen == {"r.sqli": "c1", "r.xss": "c5"}


def test_dependency_version_bump_keeps_match(tmp_path):
    dep = finding(tool="trivy", rule="CVE-2023-30861", file="requirements.txt", line=0, pkg="flask")
    base = b.build_baseline([dep], "c1")
    fs, _ = run_check([dep], base, tmp_path)
    assert fs[0]["baseline"]["is_new"] is False


# ------------------------------------------------------------------ exceptions

def write(repo, rel, text):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_valid_exception_on_line_above_unblocks(tmp_path):
    lines = ["x = 1"] * 8 + ["# security-exception: r.sqli expires:2026-11-30 owner:r2", "db.execute(q)"]
    write(tmp_path, "app/search.py", "\n".join(lines))
    fs, rep = run_check([finding(line=10)], b.load_baseline(tmp_path / "none.json"), tmp_path)
    assert fs[0]["baseline"]["exception"] == {"id": "r.sqli", "expires": "2026-11-30", "owner": "r2"}
    assert rep["result"] == "pass" and rep["counts"]["excepted"] == 1


def test_exception_far_from_finding_does_not_apply(tmp_path):
    write(tmp_path, "app/search.py", "# security-exception: r.sqli expires:2026-11-30 owner:r2\n" + "x\n" * 20)
    _, rep = run_check([finding(line=10)], b.load_baseline(tmp_path / "none.json"), tmp_path)
    assert rep["result"] == "fail"
    assert rep["counts"]["exceptions_stale"] == 1


def test_expired_exception_fails_even_on_known_finding(tmp_path):
    write(tmp_path, "app/search.py", "\n" * 8 + "# security-exception: r.sqli expires:2026-10-01 owner:r2\nq\n")
    base = b.build_baseline([finding(line=10)], "c1")
    _, rep = run_check([finding(line=10)], base, tmp_path)
    assert rep["result"] == "fail"
    assert rep["counts"]["exceptions_expired"] == 1 and rep["counts"]["blocking"] == 0


def test_malformed_and_too_long_exceptions_fail(tmp_path):
    write(tmp_path, "a.py", "# security-exception: r.sqli owner:r2\n")
    write(tmp_path, "b.py", "# security-exception: r.sqli expires:2026-02-30 owner:r2\n")
    write(tmp_path, "c.py", "# security-exception: r.sqli expires:2027-12-31 owner:r2\n")
    anns = b.scan_annotations(tmp_path, TODAY, 90)
    assert sorted(a["status"] for a in anns) == ["malformed", "malformed", "too_long"]
    _, rep = run_check([], b.load_baseline(tmp_path / "none.json"), tmp_path)
    assert rep["result"] == "fail" and rep["counts"]["exceptions_invalid"] == 3


def test_manifest_exception_applies_anywhere_in_file(tmp_path):
    write(tmp_path, "requirements.txt",
          "flask==2.2.2\n# security-exception: CVE-2023-30861 expires:2026-11-15 owner:r2\n")
    dep = finding(tool="trivy", rule="CVE-2023-30861", file="requirements.txt", line=0, pkg="flask")
    _, rep = run_check([dep], b.load_baseline(tmp_path / "none.json"), tmp_path)
    assert rep["result"] == "pass" and rep["counts"]["excepted"] == 1


# ------------------------------------------------------------------ CLI end to end

def test_cli_create_then_check(tmp_path):
    findings_path = tmp_path / "findings.json"
    base_path = tmp_path / "security-baseline.json"
    repo = tmp_path / "repo"
    repo.mkdir()

    findings_path.write_text(json.dumps([finding()]))
    assert b.main(["create", "--findings", str(findings_path), "--baseline", str(base_path),
                   "--commit", "c1"]) == 0

    findings_path.write_text(json.dumps([finding(), finding(rule="r.new", line=30)]))
    out, report = tmp_path / "diffed.json", tmp_path / "report.json"
    args = ["check", "--findings", str(findings_path), "--baseline", str(base_path),
            "--repo", str(repo), "--commit", "c2", "--today", "2026-10-22",
            "-o", str(out), "--report", str(report)]
    assert b.main(args) == 1
    assert b.main(args + ["--warn-only"]) == 0

    diffed = json.loads(out.read_text())
    n.validate(diffed)                           # still valid against the shared schema
    assert [f["baseline"]["is_new"] for f in diffed] == [False, True]
    assert json.loads(report.read_text())["blocking"][0]["rule_id"] == "r.new"


def test_cli_bad_input_exits_2(tmp_path):
    assert b.main(["check", "--findings", str(tmp_path / "missing.json"),
                   "--baseline", str(tmp_path / "b.json")]) == 2
