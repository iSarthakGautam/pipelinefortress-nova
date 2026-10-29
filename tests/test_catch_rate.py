import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval" / "metrics"))

import catch_rate as c  # noqa: E402
import yaml  # noqa: E402

PLANTED = yaml.safe_load((ROOT / "ground_truth" / "planted.yaml").read_text(encoding="utf-8"))["planted_vulnerabilities"]
SNAPSHOT = json.loads((ROOT / "docs/metrics/data/gate-tuning-2026-10-27/findings-main-1bb3381.json").read_text(encoding="utf-8"))


def f(tool, file, line, sev="HIGH", **kw):
    return {"tool": tool, "severity_norm": sev, "location": {"file": file, "line": line}, "cve": [], "package": {"name": None}, **kw}


class TestCatchRate(unittest.TestCase):

    def test_planted_yaml_lines_point_at_the_planted_code(self):
        # regression: PLANT-004 pointed at a comment (20, code on 22) and PLANT-005 at helmet (12, lodash on 13)
        for pid, file, needle in [("PLANT-004", "apps/vulnshop-api/routes/pay.py", "subprocess.run"),
                                  ("PLANT-005", "apps/vulnshop-api/package.json", '"lodash"'),
                                  ("PLANT-010", "apps/vulnshop-api/routes/search.py", "SELECT * FROM items"),
                                  ("PLANT-011", "apps/vulnshop-api/config.py", "AWS_SECRET"),
                                  ("PLANT-012", "apps/vulnshop-api/app.py", "app.run")]:
            e = next(x for x in PLANTED if x["id"] == pid)
            line = (ROOT / file).read_text(encoding="utf-8").splitlines()[e["location"]["line"] - 1]
            self.assertIn(needle, line, pid)

    def test_exact_hit_blocking_and_miss(self):
        rows = c.evaluate([f("semgrep", "apps/vulnshop-api/routes/search.py", 42)], PLANTED)
        s = c.summarise(rows)
        self.assertEqual(rows[0]["match"], "exact")
        self.assertEqual((s["caught"], s["blocking"], s["planted"]), (1, 1, 10))
        self.assertIn("PLANT-005", s["missed"])

    def test_dependency_matches_by_package_and_low_severity_does_not_block(self):
        dep = f("trivy", "apps/vulnshop-api/package-lock.json", 0, "MEDIUM", package={"name": "lodash"}, cve=["CVE-2020-8203"])
        s = c.summarise(c.evaluate([dep], PLANTED))
        self.assertEqual((s["caught"], s["blocking"]), (1, 0))

    def test_negative_control_flagged_only_on_its_own_line(self):
        elsewhere = c.summarise(c.evaluate([f("bandit", "apps/vulnshop-api/routes/user.py", 99)], PLANTED))
        on_line = c.summarise(c.evaluate([f("bandit", "apps/vulnshop-api/routes/user.py", 18)], PLANTED))
        self.assertEqual((elsewhere["false_alarms"], on_line["false_alarms"]), (0, 1))

    def test_real_snapshot_and_prometheus_output(self):
        s = c.summarise(c.evaluate(SNAPSHOT, PLANTED))
        self.assertEqual(s["planted"], 10)
        prom = c.to_prom(s)
        self.assertIn("pipelinefortress_planted_caught_total", prom)
        self.assertTrue(all(line.startswith("#") or line.count(" ") == 1 for line in prom.strip().splitlines()))


if __name__ == "__main__":
    unittest.main()
