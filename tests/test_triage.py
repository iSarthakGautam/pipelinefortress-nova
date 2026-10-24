import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "ai"))

import triage
from trace import TRACE_FILE, verify_chain

SECRET = "AKIAIOSFODNN7EXAMPLE"


def finding(fid="f1", file="apps/api/db.py", line=10, snippet="q = f\"SELECT {x}\"", rule="sqli", **kw):
    return {"finding_id": fid, "tool": "semgrep", "rule_id": rule, "severity_norm": "HIGH", "cwe": ["CWE-89"], "cve": [],
            "location": {"file": file, "line": line}, "evidence": {"snippet_raw": snippet, "raw_ref": "r"}, **kw}


def llm(parsed, ok=True):
    return {"ok": ok, "parsed": parsed, "raw": json.dumps(parsed), "latency_s": 0.1, "error": None if ok else "boom",
            "model": "m", "digest": "sha256:" + "ab" * 32, "lock_digest": "unlocked", "request_sha256": "0" * 64}


GOOD = {"verdict": "TRUE_POSITIVE", "confidence": 0.9, "fix_summary": "Use a parameterised query.", "claims": {}}


def run(findings, response, **kw):
    with mock.patch.object(triage.llm_client, "chat", return_value=response) as chat:
        res, tr = triage.triage_findings(findings, model="m", **kw)
    return res, tr, chat


class TestTriage(unittest.TestCase):

    def test_raw_secret_never_reaches_output(self):
        # regression (audit §4.5 #1): snippet_raw (with the AWS key) was copied into the output
        res, _, _ = run([finding(snippet=f"AWS_KEY = '{SECRET}'")], llm(GOOD))
        self.assertNotIn("snippet_raw", res[0]["evidence"])
        self.assertNotIn("snippet", res[0]["evidence"])
        self.assertNotIn(SECRET, json.dumps(res))
        self.assertIn("snippet_redacted", res[0]["evidence"])

    def test_evidence_snippet_adr001_supported_and_stripped(self):
        # ADR-001 compliant input carrying evidence.snippet (rather than snippet_raw)
        f = {"finding_id": "f2", "tool": "semgrep", "rule_id": "sqli", "severity_norm": "HIGH", "cwe": ["CWE-89"], "cve": [],
             "location": {"file": "apps/api/db.py", "line": 10}, "evidence": {"snippet": f"AWS_KEY = '{SECRET}'", "raw_ref": "r"}}
        res, _, chat = run([f], llm(GOOD))
        self.assertNotIn("snippet", res[0]["evidence"])
        self.assertNotIn("snippet_raw", res[0]["evidence"])
        self.assertNotIn(SECRET, json.dumps(res))
        self.assertIn("snippet_redacted", res[0]["evidence"])
        self.assertNotIn(SECRET, chat.call_args[0][1])

    def test_raw_secret_never_in_prompt(self):
        _, _, chat = run([finding(snippet=f"AWS_KEY = '{SECRET}'")], llm(GOOD))
        self.assertNotIn(SECRET, chat.call_args[0][1])

    def test_non_numeric_confidence_does_not_crash(self):
        # regression (audit §4.5 #2): float("high") killed the whole run
        res, _, _ = run([finding()], llm({**GOOD, "confidence": "high"}))
        self.assertEqual(res[0]["triage"]["confidence"], 0.0)
        self.assertEqual(res[0]["triage"]["verdict"], "TRUE_POSITIVE")

    def test_provenance_is_set_by_code_not_model(self):
        # regression (audit §4.5 #3): the model could claim "gpt-9-ultra"
        res, _, _ = run([finding()], llm({**GOOD, "model": "gpt-9-ultra", "prompt_version": "evil", "priority": "P1"}))
        t = res[0]["triage"]
        self.assertTrue(t["model"].startswith("m@sha256:"))
        self.assertEqual(t["prompt_version"], "triage_v2/2.0.0")
        self.assertEqual(t["priority"], "P2")  # HIGH severity, computed in code, not the model's P1

    def test_all_cluster_members_are_emitted(self):
        # regression (audit §4.5 #4): 2 findings in gave 1 record out
        res, _, chat = run([finding("a", line=1), finding("b", line=2)], llm(GOOD))
        self.assertEqual([r["finding_id"] for r in res], ["a", "b"])
        self.assertEqual(chat.call_count, 1)
        self.assertEqual(res[0]["dedupe"]["cluster_size"], 2)

    def test_hallucinated_claim_is_blocked_and_logged(self):
        with tempfile.TemporaryDirectory() as d:
            res, _, _ = run([finding()], llm({**GOOD, "fix_summary": "Fixes CVE-2031-12345"}), trace_dir=d)
            self.assertEqual(res[0]["triage"]["verdict"], "NEEDS_HUMAN_REVIEW")
            self.assertFalse(res[0]["triage"]["grounding"]["validated"])
            self.assertTrue(os.path.getsize(os.path.join(d, "rejections.jsonl")) > 0)
            self.assertTrue(verify_chain(os.path.join(d, TRACE_FILE)))

    def test_model_failure_degrades_to_needs_human_review(self):
        res, tr, _ = run([finding("a"), finding("b", file="x/y.py")], llm(None, ok=False))
        self.assertEqual([r["triage"]["verdict"] for r in res], ["NEEDS_HUMAN_REVIEW"] * 2)
        self.assertNotIn("boom", json.dumps(res))  # error text stays out of human-facing fields

    def test_unexpected_exception_does_not_crash_the_run(self):
        with mock.patch.object(triage.llm_client, "chat", side_effect=RuntimeError("x")):
            res, tr = triage.triage_findings([finding()], model="m")
        self.assertEqual(res[0]["triage"]["verdict"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(tr[0]["outcome"], "internal_error")

    def test_canary_in_model_output_is_blocked(self):
        from redaction.redactor import CANARY_VALUES
        res, tr, _ = run([finding()], llm({**GOOD, "fix_summary": "leak " + CANARY_VALUES[0]}))
        self.assertEqual(res[0]["triage"]["verdict"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(tr[0]["outcome"], "canary_in_output")

    def test_pre_egress_tripwire_blocks_call_when_redaction_fails(self):
        with mock.patch.object(triage, "redact_finding", side_effect=lambda f: {"snippet": f["evidence"]["snippet_raw"],
                               "finding_id": "f1", "tool": "t", "severity": "HIGH", "rule_id": "r", "cwe": [], "cve": [],
                               "file_name": "db.py", "line": 1}):
            res, tr, chat = run([finding(snippet=f"AWS_KEY = '{SECRET}'")], llm(GOOD))
        chat.assert_not_called()
        self.assertEqual(tr[0]["outcome"], "pre_egress_tripwire")
        self.assertNotIn(SECRET, json.dumps(tr))

    def test_model_json_with_wrong_types_is_coerced(self):
        res, _, _ = run([finding()], llm({"verdict": "BANANA", "confidence": [1], "fix_summary": 7, "claims": "x"}))
        self.assertEqual(res[0]["triage"]["verdict"], "NEEDS_HUMAN_REVIEW")

    def test_output_keeps_contract_keys(self):
        res, _, _ = run([finding()], llm(GOOD))
        self.assertEqual(set(res[0]["triage"]), {"verdict", "priority", "confidence", "fix_summary", "model",
                                                 "prompt_version", "grounding"})
        self.assertEqual(set(res[0]["triage"]["grounding"]), {"validated", "rejected_claims"})


class TestFallbackEndToEnd(unittest.TestCase):

    def test_model_down_cli_exits_zero_with_all_findings_needs_human_review(self):
        # hard rule 2, proven through the real CLI: nothing listens on port 1
        env = dict(os.environ, OLLAMA_BASE_URL="http://localhost:1/v1")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "ai", "triage.py")],
                           input=json.dumps([finding("a"), finding("b", file="z.py")]), capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual([r["triage"]["verdict"] for r in out], ["NEEDS_HUMAN_REVIEW"] * 2)

    def test_non_loopback_url_is_blocked_by_egress_guard_and_degrades(self):
        env = dict(os.environ, OLLAMA_BASE_URL="http://localhost.evil.com/v1")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "ai", "triage.py")],
                           input=json.dumps([finding()]), capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("EGRESS BLOCKED", p.stderr)
        self.assertEqual(json.loads(p.stdout)[0]["triage"]["verdict"], "NEEDS_HUMAN_REVIEW")


if __name__ == "__main__":
    unittest.main()


class TestTraceKeepsModelClaims(unittest.TestCase):

    def test_trace_records_pre_validator_claims_and_text(self):
        # regression: the validator strips `claims` from the shared dict, which emptied the trace
        # and made the eval report "0 hallucinations produced"
        bad = {**GOOD, "fix_summary": "see CVE-2031-12345", "claims": {"cwes": ["CWE-99999"]}}
        _, tr, _ = run([finding()], llm(bad))
        self.assertEqual(tr[0]["claims"], {"cwes": ["CWE-99999"]})
        self.assertIn("CVE-2031-12345", tr[0]["fix_summary_model"])
        self.assertEqual(tr[0]["verdict_final"], "NEEDS_HUMAN_REVIEW")


class TestStubTriage(unittest.TestCase):

    def test_stub_accepts_json_lines_and_echoes_ids(self):
        # regression: R1/R5 build against this stub; it errored on JSONL and ignored its input
        rows = "\n".join(json.dumps(finding(fid)) for fid in ("a", "b"))
        p = subprocess.run([sys.executable, os.path.join(ROOT, "ai", "stub_triage.py")], input=rows, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual([r["finding_id"] for r in json.loads(p.stdout)], ["a", "b"])
