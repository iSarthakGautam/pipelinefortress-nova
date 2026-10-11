import os
import sys
import unittest

# Ensure ai directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ai")))

from redaction.redactor import (
    apply_l1_structural,
    apply_l2_pattern,
    apply_l3_semantic,
    apply_l4_canary,
    redact_finding,
    egress_guard_check,
    CANARY_TOKEN
)

class TestRedactionPipeline(unittest.TestCase):

    def test_l1_structural_allowlist(self):
        """Test L1: Structural allowlist strips non-whitelisted CI/runner fields."""
        raw = {
            "finding_id": "find-123",
            "tool": "semgrep",
            "severity_norm": "HIGH",
            "internal_runner_id": "runner-pod-456",
            "user_email": "developer@corp.local",
            "location": {"file": "/home/runner/work/repo/apps/api/auth.py", "line": 42},
            "evidence": {"snippet_raw": "token = 'secret'"}
        }
        res = apply_l1_structural(raw)
        self.assertEqual(res["file_name"], "auth.py")
        self.assertNotIn("internal_runner_id", res)
        self.assertNotIn("user_email", res)
        self.assertEqual(res["finding_id"], "find-123")

    def test_l2_aws_key_redaction(self):
        """Test L2: AWS access keys are stripped."""
        text = "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
        redacted = apply_l2_pattern(text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertIn("<REDACTED:AWS_ACCESS_KEY>", redacted)

    def test_l2_jwt_token_redaction(self):
        """Test L2: JWT tokens are stripped."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        text = f"auth_header = 'Bearer {jwt}'"
        redacted = apply_l2_pattern(text)
        self.assertNotIn(jwt, redacted)
        self.assertIn("<REDACTED:JWT_TOKEN>", redacted)

    def test_l2_private_key_redaction(self):
        """Test L2: PEM private keys are stripped."""
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...\n-----END RSA PRIVATE KEY-----"
        redacted = apply_l2_pattern(pem)
        self.assertNotIn("MIIEowIBAAKCAQEA0Y", redacted)
        self.assertIn("<REDACTED:PRIVATE_KEY>", redacted)

    def test_l3_semantic_email_redaction(self):
        """Test L3: Semantic emails are stripped."""
        text = "Contact support@internal-domain.com for questions."
        redacted = apply_l3_semantic(text)
        self.assertNotIn("support@internal-domain.com", redacted)
        self.assertIn("<REDACTED:EMAIL>", redacted)

    def test_l3_semantic_ip_redaction(self):
        """Test L3: Semantic IP addresses are stripped."""
        text = "Connecting to internal host at 10.142.1.25..."
        redacted = apply_l3_semantic(text)
        self.assertNotIn("10.142.1.25", redacted)
        self.assertIn("<REDACTED:IP_ADDRESS>", redacted)

    def test_l4_canary_injection(self):
        """Test L4: Canary token tripwire is injected."""
        finding = {"finding_id": "f-1"}
        res = apply_l4_canary(finding)
        self.assertIn("_canary", res)
        self.assertEqual(res["_canary"], CANARY_TOKEN)

    def test_egress_guard(self):
        """Test Egress Guard: Only localhost/127.0.0.1 is permitted."""
        self.assertTrue(egress_guard_check("http://localhost:11434/v1"))
        self.assertTrue(egress_guard_check("http://127.0.0.1:11434/v1"))
        self.assertFalse(egress_guard_check("https://api.openai.com/v1"))
        self.assertFalse(egress_guard_check("http://169.254.169.254/latest/meta-data/"))

if __name__ == "__main__":
    unittest.main()
