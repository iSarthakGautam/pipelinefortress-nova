import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ai"))

from cluster import cluster_findings
from enrich import enrich_finding
from priority import compute_priority
from trace import REJECTION_FILE, TRACE_FILE, verify_chain, write_rejection, write_trace


class TestCluster(unittest.TestCase):

    def test_same_basename_in_different_dirs_do_not_collide(self):
        # regression (audit §4.6): apps/a/index.js and apps/b/index.js collapsed into one cluster
        fs = [{"tool": "semgrep", "rule_id": "r", "location": {"file": "apps/a/index.js"}},
              {"tool": "semgrep", "rule_id": "r", "location": {"file": "apps/b/index.js"}},
              {"tool": "semgrep", "rule_id": "r", "location": {"file": "./apps/a/index.js"}}]
        self.assertEqual(sorted(len(v) for v in cluster_findings(fs).values()), [1, 2])


class TestEnrich(unittest.TestCase):

    def test_unknown_values_are_none_not_invented(self):
        e = enrich_finding({"cwe": ["CWE-89"]})["enrichment"]
        self.assertIsNone(e["epss"])
        self.assertIsNone(e["reachable"])
        self.assertFalse(e["kev"])


class TestPriority(unittest.TestCase):

    def test_kev_is_always_p1(self):
        # regression (audit §3, gt-005): log4shell got P2 from the model
        self.assertEqual(compute_priority("TRUE_POSITIVE", "LOW", True, 0.97, None), "P1")

    def test_only_true_positives_get_a_priority(self):
        for v in ["FALSE_POSITIVE", "NEEDS_HUMAN_REVIEW"]:
            self.assertEqual(compute_priority(v, "CRITICAL", True, 0.9, True), "UNASSIGNED")

    def test_unknown_reachability_does_not_downgrade(self):
        self.assertEqual(compute_priority("TRUE_POSITIVE", "HIGH", False, None, None), "P2")
        self.assertEqual(compute_priority("TRUE_POSITIVE", "HIGH", False, None, False), "P3")


class TestTrace(unittest.TestCase):

    def test_hash_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(3):
                write_trace({"n": i}, d)
            write_rejection({"claim": "x"}, d)
            p = os.path.join(d, TRACE_FILE)
            self.assertTrue(verify_chain(p))
            self.assertTrue(verify_chain(os.path.join(d, REJECTION_FILE)))
            lines = open(p).read().splitlines()
            open(p, "w").write("\n".join([lines[0].replace('"n": 0', '"n": 9')] + lines[1:]) + "\n")
            self.assertFalse(verify_chain(p))

    def test_disabled_without_directory(self):
        os.environ.pop("LLM_TRACE_DIR", None)
        write_trace({"n": 1})  # must be a silent no-op


if __name__ == "__main__":
    unittest.main()


class TestClusterRobustness(unittest.TestCase):

    def test_malformed_findings_do_not_crash_clustering(self):
        # regression: found by tests/test_integration_stubs.py, an int file path raised AttributeError and killed the run
        weird = [{"location": {"file": 7}}, {"tool": None, "location": None}, "not-a-dict", None, {"dedupe": "x"}]
        self.assertEqual(sum(len(v) for v in cluster_findings(weird).values()), 5)

    def test_incoming_r2_cluster_id_is_honoured(self):
        fs = [{"tool": "a", "dedupe": {"cluster_id": "C-9"}, "location": {"file": "x"}},
              {"tool": "b", "dedupe": {"cluster_id": "C-9"}, "location": {"file": "y"}}]
        self.assertEqual(list(cluster_findings(fs)), ["C-9"])
