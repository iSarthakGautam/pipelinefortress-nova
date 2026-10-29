"""Gate tuning from real data (docs/metrics/GATE_TUNING.md): planted classes rate HIGH,
exceptions warn before they expire, unscored CVEs block, a fixed finding's baseline slot cannot
hide a new one, and a known finding re-rated across the threshold blocks again."""
import datetime as dt
import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanners" / "normalize"))
sys.path.insert(0, str(ROOT / "scanners" / "baseline"))

import baseline as b  # noqa: E402
import normalize as n  # noqa: E402

TODAY = dt.date(2026, 10, 27)


class TestPlantedClassesBlock(unittest.TestCase):
    """Each planted TRUE_POSITIVE class must rate >= HIGH, or a new copy of it passes the gate."""

    def test_jinja_autoescape_rule_is_error(self):
        rule = yaml.safe_load((ROOT / "scanners/semgrep/rules/jinja-autoescape-bypass.yaml")
                              .read_text(encoding="utf-8"))["rules"][0]
        assert rule["severity"] == "ERROR"
        assert n.normalize_severity("semgrep", "error") == "HIGH"

    def test_root_pod_is_high_in_both_tools(self):
        assert n.normalize_severity("checkov", "error", "CKV_K8S_23") == "HIGH"
        assert n.normalize_severity("trivy", "MEDIUM", "KSV-0012") == "HIGH"

    def test_other_rules_keep_the_tool_rating(self):
        assert n.normalize_severity("checkov", "error", "CKV_K8S_40") == "MEDIUM"
        assert n.normalize_severity("trivy", "MEDIUM", "KSV-0104") == "MEDIUM"

    def test_unscored_vulnerability_blocks(self):
        for tool in ("trivy", "grype", "osv"):
            assert n.normalize_severity(tool, "UNKNOWN") == "HIGH", tool
        assert n.normalize_severity("grype", "Negligible") == "INFO"


def finding(file, line, rule="r.sqli", sev="HIGH"):
    return {"tool": "semgrep", "rule_id": rule, "severity_norm": sev, "package": None,
            "finding_id": n.make_finding_id("semgrep", rule, file, line, None),
            "location": {"file": file, "line": line},
            "baseline": {"is_new": True, "first_seen_commit": None}}


class TestMovedFindings(unittest.TestCase):
    """A leftover baseline slot only absorbs a finding on the same line of code."""

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)

    def write(self, *lines):
        (self.repo / "s.py").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def accept(self, *found):
        return b.build_baseline(list(found), "c1", None, self.repo)

    def test_moved_and_reindented_finding_stays_known(self):
        self.write("def f(db, q):", "    db.execute(f\"SELECT {q}\")")
        base = self.accept(finding("s.py", 2))
        self.write("import os", "", "class A:", "  def f(db, q):", "        db.execute( f\"SELECT {q}\" )")
        cur = [finding("s.py", 5)]
        b.apply_baseline(cur, base, "c2", self.repo)
        assert cur[0]["baseline"] == {"is_new": False, "first_seen_commit": "c1"}

    def test_fixed_finding_does_not_hide_a_new_one(self):
        self.write("def f(db, q):", "    db.execute(f\"SELECT {q}\")")
        base = self.accept(finding("s.py", 2))
        self.write("def f(db, q):", "    db.execute(\"SELECT ?\", (q,))", "",
                   "def g(db, u):", "    db.execute(f\"DELETE {u}\")")
        cur = [finding("s.py", 5)]
        stats = b.apply_baseline(cur, base, "c2", self.repo)
        assert cur[0]["baseline"]["is_new"] and stats["fixed_since_baseline"] == 1
        assert b.evaluate_gate(cur, [], "HIGH", stats)["result"] == "fail"

    def test_baseline_records_line_sha(self):
        self.write("x = 1", "db.execute(q)")
        entry = self.accept(finding("s.py", 2))["entries"][0]
        assert entry["line_sha"] == b.line_sha(self.repo, "s.py", 2, {})
        assert b.line_sha(self.repo, "s.py", 0, {}) is None

    def test_entry_without_line_sha_matches_by_group(self):
        """Baselines written before line_sha keep the old behaviour until they are recreated."""
        base = b.build_baseline([finding("s.py", 2)], "c1")
        assert "line_sha" not in base["entries"][0]
        cur = [finding("s.py", 40)]
        b.apply_baseline(cur, base, "c2", self.repo)
        assert not cur[0]["baseline"]["is_new"]

    def test_fixed_line_zero_slot_does_not_hide_a_new_finding(self):
        """A whole-file finding (line 0, no line_sha) is fixed and the same rule fires on a real
        line: that is new code, not the old finding moved."""
        base = self.accept(finding("s.py", 0))
        assert base["entries"][0]["line_sha"] is None
        self.write("FROM node", "USER root")
        cur = [finding("s.py", 2)]
        stats = b.apply_baseline(cur, base, "c2", self.repo)
        assert cur[0]["baseline"]["is_new"] and stats["fixed_since_baseline"] == 1

    def create(self, found, repo):
        path = self.repo / "findings.json"
        path.write_text(json.dumps(found), encoding="utf-8")
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            rc = b.main(["create", "--findings", str(path), "--baseline", str(self.repo / "base.json"),
                         "--commit", "c1", "--repo", str(repo)])
        return rc, err.getvalue()

    def test_create_warns_about_missing_flagged_lines(self):
        """Outside the repo root, or at another commit, line_sha would be null. It still writes
        the baseline: a secret gitleaks found in history may sit in a file deleted since."""
        self.write("x = 1", "db.execute(q)")
        rc, err = self.create([finding("s.py", 2)], self.repo / "elsewhere")
        assert rc == 0 and "WARNING 1 flagged line(s) not found" in err and "s.py:2" in err
        rc, err = self.create([finding("s.py", 40)], self.repo)            # older/other commit
        assert rc == 0 and "s.py:40" in err
        assert (self.repo / "base.json").exists()

    def test_warning_counts_distinct_lines_including_one_past_the_end(self):
        self.write("x = 1", "db.execute(q)")                              # ends with \n: 2 lines
        rc, err = self.create([finding("s.py", 3), finding("s.py", 3, rule="r.other")], self.repo)
        assert rc == 0 and "WARNING 1 flagged line(s)" in err and "s.py:3" in err
        assert err.count("s.py:3") == 1

    def test_create_is_quiet_for_line_zero_and_blank_lines(self):
        self.write("x = 1", "", "db.execute(q)")
        rc, err = self.create([finding("s.py", 0), finding("s.py", 2), finding("s.py", 3)], self.repo)
        assert rc == 0 and err == ""


class TestSeverityRaised(unittest.TestCase):
    """Known debt was accepted at a severity. Re-rated across --fail-on, it needs a new decision."""

    def gate(self, accepted, now, exception=None):
        base = b.build_baseline([finding("s.py", 2, sev=accepted)], "c1")
        cur = [finding("s.py", 2, sev=now)]
        stats = b.apply_baseline(cur, base, "c2")
        if exception:
            cur[0]["_exception_status"] = exception
        return b.evaluate_gate(cur, [], "HIGH", stats)

    def test_low_rerated_critical_blocks(self):
        rep = self.gate("LOW", "CRITICAL")
        assert rep["result"] == "fail" and rep["counts"]["raised"] == 1
        assert rep["blocking"][0]["raised_from"] == "LOW"
        assert "(known, but accepted at LOW)" in b.format_summary(rep)

    def test_already_blocking_level_or_below_threshold_passes(self):
        assert self.gate("HIGH", "CRITICAL")["result"] == "pass"
        assert self.gate("LOW", "MEDIUM")["result"] == "pass"

    def test_exception_covers_a_raised_finding(self):
        rep = self.gate("MEDIUM", "HIGH", exception="valid")
        assert rep["result"] == "pass" and rep["counts"]["excepted"] == 1

    def test_internal_fields_stay_out_of_the_output(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "base.json").write_text(json.dumps(
            b.build_baseline([finding("s.py", 2, sev="LOW")], "c1")), encoding="utf-8")
        (tmp / "f.json").write_text(json.dumps([finding("s.py", 2, sev="HIGH")]), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            rc = b.main(["check", "--findings", str(tmp / "f.json"), "--baseline", str(tmp / "base.json"),
                         "--repo", str(tmp), "-o", str(tmp / "out.json")])
        assert rc == 1
        out = json.loads((tmp / "out.json").read_text(encoding="utf-8"))[0]
        assert not [k for k in out if k.startswith("_")]


class TestExpiringExceptions(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def gate(self, expires, warn_days=14):
        (self.tmp / "requirements.txt").write_text(
            f"# security-exception: CVE-2024-1 expires:{expires} owner:r2\n", encoding="utf-8")
        f = {"tool": "osv", "rule_id": "CVE-2024-1", "finding_id": "0" * 16, "severity_norm": "HIGH",
             "location": {"file": "requirements.txt", "line": 0},
             "baseline": {"is_new": True, "first_seen_commit": None}}
        anns = b.scan_annotations(self.tmp, TODAY, 90)
        b.attach_exceptions([f], anns)
        stats = {"known": 0, "new": 1, "fixed_since_baseline": 0}
        return b.evaluate_gate([f], anns, "HIGH", stats, warn_days)

    def test_expiring_soon_warns_but_still_passes(self):
        rep = self.gate("2026-11-05")
        assert rep["result"] == "pass" and rep["counts"]["excepted"] == 1
        assert rep["counts"]["exceptions_expiring"] == 1
        assert rep["expiring_exceptions"][0]["days_left"] == 9
        assert "expires 2026-11-05 (in 9 days)" in b.format_summary(rep)

    def test_far_expiry_does_not_warn(self):
        rep = self.gate("2027-01-15")
        assert rep["result"] == "pass" and rep["counts"]["exceptions_expiring"] == 0
        assert "expires" not in b.format_summary(rep)

    def test_expires_today_warns_and_tomorrow_fails(self):
        assert self.gate(TODAY.isoformat())["counts"]["exceptions_expiring"] == 1
        rep = self.gate((TODAY - dt.timedelta(days=1)).isoformat())
        assert rep["result"] == "fail" and rep["counts"]["exceptions_expired"] == 1
        assert rep["counts"]["exceptions_expiring"] == 0

    def test_cli_flag(self):
        self.gate("2026-11-20")
        (self.tmp / "findings.json").write_text("[]", encoding="utf-8")
        args = ["check", "--findings", str(self.tmp / "findings.json"),
                "--baseline", str(self.tmp / "none.json"), "--repo", str(self.tmp),
                "--today", TODAY.isoformat()]
        for extra, warned in (([], False), (["--warn-expiring-days", "30"], True)):
            out = io.StringIO()
            with redirect_stdout(out):
                assert b.main(args + extra) == 0
            assert ("expires 2026-11-20" in out.getvalue()) is warned


if __name__ == "__main__":
    unittest.main()
