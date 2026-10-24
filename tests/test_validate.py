import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ai"))

from validate import check_claims, extract_claims, load_cwe_catalogue, validate_triage_output

SCANNER = {"cve": ["CVE-2021-44228"], "cwe": ["CWE-502"], "location": {"file": "apps/api/pom.xml", "line": 34},
           "package": {"name": "log4j-core", "version": "2.14.1", "fixed_version": "2.17.1"}}


def run(triage, scanner=SCANNER, repo_root=None):
    f = {**scanner, "triage": triage}
    return validate_triage_output(f, scanner=scanner, repo_root=repo_root)["triage"]


class TestValidator(unittest.TestCase):

    def test_catalogue_has_real_ids_the_old_26_entry_list_rejected(self):
        cat = load_cwe_catalogue()
        for cwe in ["CWE-1021", "CWE-1333", "CWE-117", "CWE-601", "CWE-89"]:
            self.assertIn(cwe, cat)
        self.assertNotIn("CWE-99999", cat)
        self.assertGreater(len(cat), 1000)

    def test_grounded_claims_pass(self):
        t = run({"verdict": "TRUE_POSITIVE", "fix_summary": "Upgrade log4j-core to 2.17.1 (CVE-2021-44228).",
                 "claims": {"cves": ["CVE-2021-44228"], "cwes": ["CWE-502"], "package": "log4j-core",
                            "fixed_version": "2.17.1", "file": "apps/api/pom.xml", "line": 34}})
        self.assertTrue(t["grounding"]["validated"], t["grounding"])
        self.assertNotIn("claims", t)

    def test_cve_invented_in_fix_summary_is_rejected(self):
        # regression (audit §4.2): free text was never checked
        t = run({"verdict": "TRUE_POSITIVE", "fix_summary": "Upgrade to fix CVE-2031-12345", "claims": {}})
        self.assertFalse(t["grounding"]["validated"])
        self.assertEqual(t["verdict"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(t["priority"], "UNASSIGNED")

    def test_structured_hallucinated_cve_and_cwe_rejected(self):
        t = run({"verdict": "TRUE_POSITIVE", "fix_summary": "x", "claims": {"cves": ["CVE-2099-99999"], "cwes": ["CWE-99999"]}})
        self.assertEqual(len(t["grounding"]["rejected_claims"]), 2)

    def test_rejected_claim_text_not_echoed_into_fix_summary(self):
        t = run({"verdict": "TRUE_POSITIVE", "fix_summary": "fix CVE-2031-12345", "claims": {}})
        self.assertNotIn("CVE-2031-12345", t["fix_summary"])

    def test_missing_file_claim_is_rejected(self):
        # regression (audit §4.2): any missing file used to pass
        t = run({"verdict": "TRUE_POSITIVE", "fix_summary": "x", "claims": {"file": "made/up/file.py", "line": 99999}})
        self.assertFalse(t["grounding"]["validated"])

    def test_file_line_in_free_text_is_checked(self):
        t = run({"verdict": "TRUE_POSITIVE", "fix_summary": "see other.py:7", "claims": {}})
        self.assertFalse(t["grounding"]["validated"])

    def test_bare_basename_of_scanner_file_is_accepted(self):
        t = run({"verdict": "TRUE_POSITIVE", "fix_summary": "see pom.xml:34", "claims": {}})
        self.assertTrue(t["grounding"]["validated"], t["grounding"])

    def test_unproven_fixed_version_and_package_rejected(self):
        t = run({"verdict": "TRUE_POSITIVE", "fix_summary": "x", "claims": {"fixed_version": "9.9.9", "package": "other"}})
        self.assertEqual(len(t["grounding"]["rejected_claims"]), 2)

    def test_repo_root_checks_existence_and_exact_line_bounds(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "apps/api"))
            with open(os.path.join(root, "apps/api/pom.xml"), "w") as f:
                f.write("a\nb\n")  # 2 lines; scanner says line 34
            r = check_claims(SCANNER, extract_claims({"claims": {"file": "apps/api/pom.xml", "line": 34}}), repo_root=root)
            self.assertTrue(any("out of range" in x for x in r))  # no +10 slack any more
            r2 = check_claims(SCANNER, extract_claims({"claims": {"file": "apps/api/pom.xml", "line": 34}}), repo_root=root + "/nope")
            self.assertTrue(any("does not exist" in x for x in r2))

    def test_invalid_verdict_enum_rejected(self):
        self.assertFalse(run({"verdict": "MAYBE", "fix_summary": "x", "claims": {}})["grounding"]["validated"])


if __name__ == "__main__":
    unittest.main()
