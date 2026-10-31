import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "ai"))
sys.path.insert(0, os.path.join(ROOT, "eval", "stubs"))

import llm_client
import metrics
import pr_comment
import r2_normalizer_stub
import sarif_ref
import triage

# Contract tests against STUBS of the other roles' pieces (R2 normalizer output, R1 CI job, R5 metrics, R3 repo tree).
# They prove R4's side of each hand-off; they do not prove the other roles' real implementations.

# Note: TestR2Contract validates against ADR-001 finding.schema.json; r2_normalizer_stub provides the offline fixture.
# RESOLVED(R1): Live workflow runs in GitHub Actions (.github/workflows/baseline-pipeline.yml); stub retained for offline CI-less unit tests.
# RESOLVED(R5): Live ingest uses Pushgateway via eval/metrics/push_metrics.py; unit test verifies offline Prometheus exposition text.
PLAN_KEYS = {"finding_id", "tool", "severity_norm", "cwe", "cve", "location", "package", "evidence", "enrichment",
             "baseline", "dedupe", "triage"}
GOOD = {"verdict": "TRUE_POSITIVE", "confidence": 0.9, "fix_summary": "Use a parameterised query.", "claims": {}}


def fake_llm(parsed=GOOD, ok=True):
    return {"ok": ok, "parsed": parsed, "raw": json.dumps(parsed), "latency_s": 0.2, "error": None if ok else "x", "model": "m",
            "digest": "sha256:" + "cd" * 32, "lock_digest": "u", "request_sha256": "0" * 64}


class StubCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.findings_path = r2_normalizer_stub.build(self.tmp.name)
        self.findings = json.load(open(self.findings_path))
        os.environ["ARTIFACTS_BASE"] = self.tmp.name
        self.addCleanup(os.environ.pop, "ARTIFACTS_BASE", None)

    def run_triage(self, response=None, findings=None):
        with mock.patch.object(triage.llm_client, "chat", return_value=response or fake_llm()) as chat:
            res, tr = triage.triage_findings(findings or self.findings, model="m")
        return res, tr, chat


class TestR2Contract(StubCase):

    def test_stub_input_has_no_raw_snippet_or_rule_id(self):
        # the worst case R2 could hand us
        self.assertTrue(all("snippet_raw" not in f["evidence"] and "snippet" not in f["evidence"] and "rule_id" not in f for f in self.findings))

    def test_snippet_is_recovered_from_sarif_pointer_and_redacted(self):
        _, _, chat = self.run_triage()
        prompts = " ".join(c[0][1] for c in chat.call_args_list)
        self.assertIn("SELECT * FROM items", prompts)               # real snippet reached the (mock) model
        self.assertIn("sql-injection", prompts)                     # rule id recovered from SARIF
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", prompts)           # but redacted first
        self.assertNotIn("ops@corp-internal.example", prompts)

    def test_r2_cluster_ids_are_honoured_and_dedupe_to_one_call_each(self):
        res, _, chat = self.run_triage()
        self.assertEqual(len(res), 6)
        self.assertEqual(chat.call_count, 4)                         # 5 clusters; C-001 has 2 members (1 call); C-005 is injected (0 calls)
        self.assertEqual({r["dedupe"]["cluster_id"] for r in res}, {"C-001", "C-002", "C-003", "C-004", "C-005"})
        self.assertEqual([r["dedupe"]["cluster_size"] for r in res if r["dedupe"]["cluster_id"] == "C-001"], [2, 2])

    def test_output_matches_plan_schema_and_never_leaks_raw(self):
        res, _, _ = self.run_triage()
        for r in res:
            self.assertGreaterEqual(set(r), PLAN_KEYS)
            self.assertEqual(set(r["triage"]), {"verdict", "priority", "confidence", "fix_summary", "model", "prompt_version", "grounding"})
            self.assertIn(r["triage"]["verdict"], {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_HUMAN_REVIEW"})
            self.assertIn(r["triage"]["priority"], {"P1", "P2", "P3", "UNASSIGNED"})
            self.assertIsInstance(r["triage"]["confidence"], float)
            self.assertNotIn("snippet_raw", r["evidence"])
            self.assertNotIn("snippet", r["evidence"])
            self.assertEqual(r["evidence"]["raw_ref"].split("#")[0], "scanners.sarif")  # R2's pointer preserved
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(res))

    def test_output_validates_against_r2_finding_schema_json(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed in test runner environment")
        schema_path = os.path.join(ROOT, "scanners", "schema", "finding.schema.json")
        if not os.path.exists(schema_path):
            self.skipTest("finding.schema.json not found")
        schema = json.load(open(schema_path, encoding="utf-8"))
        res, _, _ = self.run_triage()
        for r in res:
            jsonschema.validate(instance=r, schema=schema)

    def test_injection_planted_in_sarif_never_reaches_model(self):
        res, tr, chat = self.run_triage()
        inj = [r for r in res if r["dedupe"]["cluster_id"] == "C-005"][0]
        self.assertEqual(inj["triage"]["verdict"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(inj["triage"]["priority"], "P1")
        self.assertEqual(chat.call_count, 4)                         # every cluster except the injected one
        self.assertNotIn("ignore previous instructions", " ".join(c[0][1].lower() for c in chat.call_args_list))

    def test_kev_finding_is_p1_by_code(self):
        res, _, _ = self.run_triage()
        log4j = [r for r in res if r["dedupe"]["cluster_id"] == "C-003"][0]
        self.assertEqual(log4j["triage"]["priority"], "P1")
        self.assertTrue(log4j["enrichment"]["kev"])

    def test_sarif_path_traversal_is_blocked(self):
        self.assertIsNone(sarif_ref.resolve("../../etc/passwd#/x", self.tmp.name))
        self.assertIsNone(sarif_ref.resolve("/etc/passwd#/x", self.tmp.name))
        self.assertIsNone(sarif_ref.resolve("missing.sarif#/runs/0/results/0", self.tmp.name))

    def test_garbage_and_minimal_findings_do_not_crash(self):
        weird = [{}, {"finding_id": 5, "tool": None, "location": None, "evidence": None, "cve": None},
                 {"location": {"file": 7, "line": "x"}, "evidence": {"raw_ref": "nope#/x"}}]
        res, _ = self.run_triage(findings=weird)[:2]
        self.assertEqual(len(res), 3)
        self.assertTrue(all(r["triage"]["verdict"] in {"TRUE_POSITIVE", "NEEDS_HUMAN_REVIEW", "FALSE_POSITIVE"} for r in res))


class TestR3RepoTree(StubCase):

    def test_validate_repo_root_checks_claims_against_a_stub_repo(self):
        repo = os.path.join(self.tmp.name, "repo", "apps", "vulnshop-api", "routes")
        os.makedirs(repo)
        open(os.path.join(repo, "search.py"), "w").write("\n".join(["x"] * 60))
        env = {"VALIDATE_REPO_ROOT": os.path.join(self.tmp.name, "repo")}
        claim = {**GOOD, "claims": {"file": "apps/vulnshop-api/routes/search.py", "line": 42, "cves": [], "cwes": [],
                                    "package": None, "fixed_version": None}}
        one = [self.findings[0]]
        with mock.patch.dict(os.environ, env):
            res, _, _ = self.run_triage(fake_llm(claim), one)
            self.assertTrue(res[0]["triage"]["grounding"]["validated"], res[0]["triage"]["grounding"])
        with mock.patch.dict(os.environ, {"VALIDATE_REPO_ROOT": os.path.join(self.tmp.name, "empty")}):
            res, _, _ = self.run_triage(fake_llm(claim), one)
            self.assertFalse(res[0]["triage"]["grounding"]["validated"])


class TestR1CommentAndCiJob(StubCase):

    def test_comment_renders_counts_and_neutralises_untrusted_model_text(self):
        evil = {**GOOD, "fix_summary": "see [click](http://evil.example) ![i](http://x) @everyone <script>x</script>"}
        res, _, _ = self.run_triage(fake_llm(evil))
        md = pr_comment.render(res)
        self.assertIn("**6** findings -> **5** clusters", md)
        for bad in ["](http", "<script>", "@everyone"]:
            self.assertNotIn(bad, md)
        self.assertNotIn("SELECT", md)                               # snippets never appear in the comment
        self.assertNotIn("AKIA", md)

    def test_ci_job_with_model_down_exits_zero_and_still_comments(self):
        out = os.path.join(self.tmp.name, "out")
        env = dict(os.environ, OLLAMA_BASE_URL="http://localhost:1/v1", HTTPS_PROXY="http://evil.example:3128", PYTHON=sys.executable)
        p = subprocess.run([os.path.join(ROOT, "eval/stubs/r1_ci_job_stub.sh"), self.findings_path, out], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        triaged = json.load(open(os.path.join(out, "findings.triaged.json")))
        self.assertEqual(len(triaged), 6)
        self.assertTrue(all(r["triage"]["verdict"] == "NEEDS_HUMAN_REVIEW" for r in triaged))
        md = open(os.path.join(out, "pr_comment.md")).read()
        self.assertIn("need a human", md)
        self.assertTrue(os.path.exists(os.path.join(out, "metrics.prom")))


class TestR5Metrics(StubCase):
    LINE = re.compile(r'^(#.*|[a-z_]+(\{[a-z_]+="[^"]*"(,[a-z_]+="[^"]*")*\})? -?[0-9.]+)$')

    def test_prometheus_text_is_well_formed_and_counts_match(self):
        bad = {**GOOD, "fix_summary": "fixes CVE-2031-12345"}
        res, tr, _ = self.run_triage(fake_llm(bad))
        text = metrics.render(res, tr)
        for line in text.strip().splitlines():
            self.assertRegex(line, self.LINE)
        self.assertIn("pipelinefortress_ai_findings_total 6", text)
        self.assertIn("pipelinefortress_ai_clusters_total 5", text)
        self.assertIn('pipelinefortress_ai_validator_rejections_total{type="cve"} 4', text)  # 4 model-called clusters, C-005 skipped
        self.assertIn('pipelinefortress_ai_verdict_total{verdict="NEEDS_HUMAN_REVIEW"} 5', text)  # abstentions are a metric

    def test_empty_run_renders_valid_text(self):
        for line in metrics.render([], []).strip().splitlines():
            self.assertRegex(line, self.LINE)


if __name__ == "__main__":
    unittest.main()


class TestOtherRolesStubs(StubCase):
    STUBS = os.path.join(ROOT, "eval", "stubs")

    def _run(self, script, *args):
        return subprocess.run([sys.executable, os.path.join(self.STUBS, script), *args], capture_output=True, text=True)

    def test_r1_post_comment_stub_records_the_command_without_network(self):
        md = os.path.join(self.tmp.name, "c.md")
        open(md, "w").write("## hi\n")
        p = self._run("r1_post_comment_stub.py", md, self.tmp.name, "42")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("gh pr comment 42", open(os.path.join(self.tmp.name, "posted_comment_stub.txt")).read())

    def test_r5_push_stub_accepts_real_metrics_and_rejects_garbage(self):
        res, tr, _ = self.run_triage()
        good = os.path.join(self.tmp.name, "m.prom")
        open(good, "w").write(metrics.render(res, tr))
        self.assertEqual(self._run("r5_metrics_push_stub.py", good, self.tmp.name).returncode, 0)
        bad = os.path.join(self.tmp.name, "bad.prom")
        open(bad, "w").write("not prometheus {{{\n")
        self.assertEqual(self._run("r5_metrics_push_stub.py", bad, self.tmp.name).returncode, 1)

    def test_r3_model_sbom_stub_reads_the_lock_file_despite_its_comment_header(self):
        out = os.path.join(self.tmp.name, "models.cdx.json")
        self.assertEqual(self._run("r3_model_sbom_stub.py", out).returncode, 0)
        comps = {c["name"]: c for c in json.load(open(out))["components"]}
        self.assertEqual(set(comps), {m["tag"] for m in llm_client.load_lock()})
        self.assertIn("hashes", comps["llama3:latest"])            # real digest pinned
        self.assertNotIn("hashes", comps["qwen2.5-coder:14b"])     # not installed, so no invented hash
        self.assertIn("hashes", comps["qwen2.5-coder:1.5b"])       # the CI model's manifest digest is pinned

    def test_committed_model_sbom_has_not_drifted_from_the_lock_file(self):
        # regression: the committed SBOM listed llama3.1:8b as not installed with no hash and lacked the CI model
        committed = json.load(open(os.path.join(ROOT, "artifacts", "sbom", "models.cdx.json")))
        out = os.path.join(self.tmp.name, "models.cdx.json")
        self.assertEqual(self._run("r3_model_sbom_stub.py", out).returncode, 0)
        self.assertEqual(committed, json.load(open(out)), "run: python3 eval/stubs/r3_model_sbom_stub.py")


class TestTodosNameAnOwner(unittest.TestCase):

    def test_every_todo_in_r4_files_names_an_owner(self):
        # a TODO nobody owns never gets done: require TODO(R1..R5) or TODO(team)
        bad = []
        for sub in ("ai", "eval", "tests"):
            for root, _, files in os.walk(os.path.join(ROOT, sub)):
                if "__pycache__" in root or os.sep + "results" in root:
                    continue
                for fn in files:
                    if fn.endswith((".py", ".sh", ".yaml")) and fn != "test_integration_stubs.py":
                        for n, line in enumerate(open(os.path.join(root, fn), encoding="utf-8", errors="ignore"), 1):
                            # real comment lines only (test fixtures contain TODO inside strings)
                            if line.lstrip().startswith("#") and re.search(r"\bTODO\b(?!\((?:R[1-5](?:/R[1-5])*|team)\))", line):
                                bad.append(f"{fn}:{n}")
        self.assertEqual(bad, [])
