"""Gate tuning from real data (docs/metrics/GATE_TUNING.md): planted classes rate HIGH, and
exceptions warn before they expire."""
import datetime as dt
import io
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
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
