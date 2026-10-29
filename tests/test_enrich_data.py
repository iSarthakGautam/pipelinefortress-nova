import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "ai"))

import enrich
import validate


class TestEnrichmentData(unittest.TestCase):

    def test_full_kev_catalogue_is_loaded_and_pinned(self):
        self.assertGreater(len(enrich.KEV_IDS), 1000)
        with open(os.path.join(ROOT, "ai", "data", "kev_ids.txt"), encoding="utf-8") as f:
            header = f.readline()
        self.assertIn("raw_sha256=", header)   # the data says where it came from and how to check it

    def test_kev_and_epss_drive_enrichment(self):
        e = enrich.enrich_finding({"cve": ["CVE-2021-44228"]})["enrichment"]
        self.assertTrue(e["kev"])
        self.assertGreater(e["epss"], 0.9)

    def test_unknown_cve_is_none_not_zero(self):
        e = enrich.enrich_finding({"cve": ["CVE-2099-99999"]})["enrichment"]
        self.assertEqual((e["epss"], e["kev"]), (None, False))

    def test_validator_registry_includes_kev_but_not_invented_ids(self):
        self.assertIn("CVE-2021-44228", validate.OFFLINE_KNOWN_CVES)
        self.assertNotIn("CVE-2099-99999", validate.OFFLINE_KNOWN_CVES)
        self.assertGreater(len(validate.OFFLINE_KNOWN_CVES), 1000)


if __name__ == "__main__":
    unittest.main()
