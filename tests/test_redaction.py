import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ai"))
sys.path.insert(0, os.path.join(HERE, "..", "eval"))

from redaction.redactor import (
    CANARY_VALUES, apply_l1_structural, apply_l2_pattern, apply_l3_semantic, assert_no_leak,
    canary_selftest, egress_guard_check, redact_finding,
)
from redaction_eval import evaluate


class TestRedactionLayers(unittest.TestCase):

    def test_l1_structural_allowlist(self):
        raw = {"finding_id": "find-123", "tool": "semgrep", "severity_norm": "HIGH",
               "internal_runner_id": "runner-pod-456", "user_email": "developer@corp.local",
               "location": {"file": "/home/runner/work/repo/apps/api/auth.py", "line": 42},
               "evidence": {"snippet_raw": "token = 'secret'"}}
        res = apply_l1_structural(raw)
        self.assertEqual(res["file_name"], "auth.py")
        self.assertNotIn("internal_runner_id", res)
        self.assertNotIn("user_email", res)

    def test_l1_scrubs_attacker_controlled_strings(self):
        # regression (audit §4.3): rule_id and file name are chosen by the committer
        raw = {"rule_id": "x-AKIAIOSFODNN7EXAMPLE", "location": {"file": "a/ghp_" + "A" * 36 + ".py"}}
        res = apply_l1_structural(raw)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", res["rule_id"])
        self.assertNotIn("A" * 36, res["file_name"])

    def test_l2_known_shapes(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        self.assertIn("<REDACTED:AWS_ACCESS_KEY>", apply_l2_pattern("k = 'AKIAIOSFODNN7EXAMPLE'"))
        self.assertNotIn(jwt, apply_l2_pattern(f"h = 'Bearer {jwt}'"))
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y\n-----END RSA PRIVATE KEY-----"
        self.assertNotIn("MIIEowIBAAKCAQEA0Y", apply_l2_pattern(pem))

    def test_l2_unquoted_password(self):
        self.assertNotIn("SuperSecretPassw0rd!2024", apply_l2_pattern("password=SuperSecretPassw0rd!2024"))

    def test_l2_does_not_redact_secret_lookups(self):
        for s in ["password = os.environ['DB_PASSWORD']", "token = get_token()", "DB_PASSWORD=${DB_PASSWORD}"]:
            self.assertEqual(apply_l2_pattern(s), s)

    def test_l3_email_and_private_ip(self):
        out = apply_l3_semantic("Contact support@internal-domain.com at 10.142.1.25")
        self.assertIn("<REDACTED:EMAIL>", out)
        self.assertNotIn("10.142.1.25", out)

    def test_l3_version_string_not_treated_as_ip(self):
        # regression (audit §4.3): `lodash 4.17.21.0` was redacted as an IP address
        self.assertEqual(apply_l3_semantic("lodash 4.17.21.0"), "lodash 4.17.21.0")

    def test_l3_ipv6_and_internal_host(self):
        out = apply_l3_semantic("a 2001:0db8:85a3:0000:0000:8a2e:0370:7334 b payments-db.internal.corp")
        self.assertNotIn("2001:0db8", out)
        self.assertNotIn("payments-db.internal.corp", out)


class TestCanaryTripwire(unittest.TestCase):

    def test_selftest_passes_on_healthy_redactor(self):
        self.assertTrue(canary_selftest())

    def test_canary_is_not_added_to_the_payload(self):
        # regression (audit §4.3): the canary used to be put INTO the prompt, which proves nothing
        out = redact_finding({"finding_id": "f", "evidence": {"snippet_raw": "x = 1"}})
        self.assertNotIn("_canary", out)
        self.assertFalse(any(c in str(out) for c in CANARY_VALUES))

    def test_tripwire_catches_a_raw_secret_in_outbound_prompt(self):
        raw = {"evidence": {"snippet_raw": "k = 'AKIAIOSFODNN7EXAMPLE'"}}
        self.assertTrue(assert_no_leak(raw, "prompt contains AKIAIOSFODNN7EXAMPLE"))
        self.assertEqual(assert_no_leak(raw, "prompt contains <REDACTED:AWS_ACCESS_KEY>"), [])

    def test_tripwire_catches_canary_in_outbound_prompt(self):
        self.assertTrue(assert_no_leak({}, "oops " + CANARY_VALUES[0]))


class TestEgressGuard(unittest.TestCase):

    def test_allows_only_exact_loopback(self):
        for url in ["http://localhost:11434/v1", "http://127.0.0.1:11434/v1", "http://[::1]:11434"]:
            self.assertTrue(egress_guard_check(url), url)

    def test_denies_external_and_metadata(self):
        for url in ["https://api.openai.com/v1", "http://169.254.169.254/latest/meta-data/"]:
            self.assertFalse(egress_guard_check(url), url)

    def test_denies_prefix_bypasses(self):
        # regression (audit §4.4): startswith() allowed all three of these
        for url in ["http://localhost.evil.com/v1", "http://localhost@evil.com/v1",
                    "http://127.0.0.1.nip.io/v1", "ftp://localhost/x", "http://localhost:notaport/", ""]:
            self.assertFalse(egress_guard_check(url), url)


class TestRedactionFixtures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.r = evaluate()

    def test_every_adversarial_fixture_is_redacted(self):
        self.assertEqual(self.r["leaked"], [])

    def test_property_test_no_known_secret_survives(self):
        self.assertEqual(self.r["prop_leaks"], 0)

    def test_over_redaction_is_bounded(self):
        # measured 1/30 (a MAC address is treated like IPv6); fail if it gets worse
        self.assertLessEqual(len(self.r["over"]) / self.r["n_benign"], 0.05)


if __name__ == "__main__":
    unittest.main()
