import copy
import datetime as dt
import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanners" / "normalize"))
sys.path.insert(0, str(ROOT / "scanners" / "baseline"))

import baseline as b  # noqa: E402
import normalize as n  # noqa: E402

TODAY = dt.date(2026, 10, 22)


def finding(rule="r.sqli", file="app/search.py", line=10, sev="HIGH", tool="semgrep", pkg=None):
    return {
        "schema_version": "1.0.0",
        "finding_id": n.make_finding_id(tool, rule, file, line, pkg),
        "tool": tool, "rule_id": rule, "severity_raw": sev, "severity_norm": sev,
        "cwe": [], "cve": [],
        "location": {"file": file, "line": line},
        "package": {"name": pkg, "version": None, "fixed_version": None},
        "evidence": {"raw_ref": "x"},
        "baseline": {"is_new": True, "first_seen_commit": None},
    }


def run_check(findings, base, repo, fail_on="HIGH"):
    findings = copy.deepcopy(findings)
    stats = b.apply_baseline(findings, base, "c2")
    anns = b.scan_annotations(repo, TODAY, 90)
    b.attach_exceptions(findings, anns)
    return findings, b.evaluate_gate(findings, anns, fail_on, stats)


def write(repo, rel, text):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class TmpRepo(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def no_baseline(self):
        return b.load_baseline(self.tmp / "none.json")


class TestBaselineMatching(TmpRepo):

    def test_everything_new_without_baseline(self):
        fs, rep = run_check([finding()], self.no_baseline(), self.tmp)
        assert fs[0]["baseline"] == {"is_new": True, "first_seen_commit": "c2"}
        assert rep["result"] == "fail" and rep["counts"]["blocking"] == 1

    def test_baselined_finding_does_not_block(self):
        base = b.build_baseline([finding()], "c1")
        fs, rep = run_check([finding()], base, self.tmp)
        assert fs[0]["baseline"] == {"is_new": False, "first_seen_commit": "c1"}
        assert rep["result"] == "pass"

    def test_line_shift_is_not_new(self):
        """Inserting lines above a known finding changes finding_id but must not make it new."""
        base = b.build_baseline([finding(line=10)], "c1")
        fs, rep = run_check([finding(line=14)], base, self.tmp)
        assert fs[0]["finding_id"] != base["entries"][0]["finding_id"]
        assert fs[0]["baseline"]["is_new"] is False
        assert rep["result"] == "pass"

    def test_extra_occurrence_of_known_rule_is_new(self):
        base = b.build_baseline([finding(line=10)], "c1")
        fs, rep = run_check([finding(line=10), finding(line=50)], base, self.tmp)
        by_line = {f["location"]["line"]: f["baseline"]["is_new"] for f in fs}
        assert by_line == {10: False, 50: True}     # exact match claims the old slot first
        assert rep["counts"]["new"] == 1 and rep["result"] == "fail"

    def test_same_rule_other_file_is_new(self):
        base = b.build_baseline([finding(file="app/a.py")], "c1")
        fs, _ = run_check([finding(file="app/b.py")], base, self.tmp)
        assert fs[0]["baseline"]["is_new"] is True

    def test_fixed_findings_are_counted(self):
        base = b.build_baseline([finding(line=10), finding(rule="r.xss", line=20)], "c1")
        _, rep = run_check([finding(line=10)], base, self.tmp)
        assert rep["counts"]["fixed_since_baseline"] == 1

    def test_severity_threshold(self):
        _, rep = run_check([finding(sev="MEDIUM")], self.no_baseline(), self.tmp)
        assert rep["result"] == "pass" and rep["counts"]["new"] == 1
        _, rep = run_check([finding(sev="MEDIUM")], self.no_baseline(), self.tmp, fail_on="MEDIUM")
        assert rep["result"] == "fail"

    def test_rebaseline_preserves_first_seen(self):
        first = b.build_baseline([finding()], "c1")
        second = b.build_baseline([finding(), finding(rule="r.xss")], "c5", previous=first)
        seen = {e["rule_id"]: e["first_seen_commit"] for e in second["entries"]}
        assert seen == {"r.sqli": "c1", "r.xss": "c5"}

    def test_rebaseline_keeps_first_seen_when_lines_move(self):
        first = b.build_baseline([finding(line=10), finding(line=30)], "c1")
        moved = [finding(line=13), finding(line=33), finding(line=50)]   # 3 lines inserted above
        second = b.build_baseline(moved, "c5", previous=first)
        assert [(e["line"], e["first_seen_commit"]) for e in second["entries"]] == \
            [(13, "c1"), (33, "c1"), (50, "c5")]

    def test_dependency_version_bump_keeps_match(self):
        dep = finding(tool="trivy", rule="CVE-2023-30861", file="requirements.txt", line=0, pkg="flask")
        base = b.build_baseline([dep], "c1")
        fs, _ = run_check([dep], base, self.tmp)
        assert fs[0]["baseline"]["is_new"] is False


class TestExceptions(TmpRepo):

    def test_valid_exception_on_line_above_unblocks(self):
        lines = ["x = 1"] * 8 + ["# security-exception: r.sqli expires:2026-11-30 owner:r2", "db.execute(q)"]
        write(self.tmp, "app/search.py", "\n".join(lines))
        fs, rep = run_check([finding(line=10)], self.no_baseline(), self.tmp)
        assert fs[0]["baseline"]["exception"] == {"id": "r.sqli", "expires": "2026-11-30", "owner": "r2"}
        assert rep["result"] == "pass" and rep["counts"]["excepted"] == 1

    def test_exception_far_from_finding_does_not_apply(self):
        write(self.tmp, "app/search.py", "# security-exception: r.sqli expires:2026-11-30 owner:r2\n" + "x\n" * 20)
        _, rep = run_check([finding(line=10)], self.no_baseline(), self.tmp)
        assert rep["result"] == "fail"
        assert rep["counts"]["exceptions_stale"] == 1

    def test_expired_exception_fails_even_on_known_finding(self):
        write(self.tmp, "app/search.py", "\n" * 8 + "# security-exception: r.sqli expires:2026-10-01 owner:r2\nq\n")
        base = b.build_baseline([finding(line=10)], "c1")
        _, rep = run_check([finding(line=10)], base, self.tmp)
        assert rep["result"] == "fail"
        assert rep["counts"]["exceptions_expired"] == 1 and rep["counts"]["blocking"] == 0

    def test_malformed_and_too_long_exceptions_fail(self):
        write(self.tmp, "a.py", "# security-exception: r.sqli owner:r2\n")
        write(self.tmp, "b.py", "# security-exception: r.sqli expires:2026-02-30 owner:r2\n")
        write(self.tmp, "c.py", "# security-exception: r.sqli expires:2027-12-31 owner:r2\n")
        anns = b.scan_annotations(self.tmp, TODAY, 90)
        assert sorted(a["status"] for a in anns) == ["malformed", "malformed", "too_long"]
        _, rep = run_check([], self.no_baseline(), self.tmp)
        assert rep["result"] == "fail" and rep["counts"]["exceptions_invalid"] == 3

    def test_only_yyyy_mm_dd_dates_are_valid(self):
        write(self.tmp, "a.py", "# security-exception: r.sqli expires:20261130 owner:r2\n"
                                "# security-exception: r.sqli expires:2026-W48-1 owner:r2\n"
                                "# security-exception: r.sqli expires:2026-11-30 owner:r2\n")
        assert [a["status"] for a in b.scan_annotations(self.tmp, TODAY, 90)] == \
            ["malformed", "malformed", "valid"]

    def test_crlf_files_still_parse(self):
        (self.tmp / "app").mkdir()
        (self.tmp / "app/search.py").write_bytes(
            b"x = 1\r\n# security-exception: r.sqli expires:2026-12-31 owner:r2\r\ndb.execute(q)\r\n")
        fs, rep = run_check([finding(line=3)], self.no_baseline(), self.tmp)
        assert fs[0]["baseline"]["exception"] == {"id": "r.sqli", "expires": "2026-12-31", "owner": "r2"}

    def test_manifest_exception_applies_anywhere_in_file(self):
        write(self.tmp, "requirements.txt",
              "flask==2.2.2\n# security-exception: CVE-2023-30861 expires:2026-11-15 owner:r2\n")
        dep = finding(tool="trivy", rule="CVE-2023-30861", file="requirements.txt", line=0, pkg="flask")
        _, rep = run_check([dep], self.no_baseline(), self.tmp)
        assert rep["result"] == "pass" and rep["counts"]["excepted"] == 1


class TestCli(TmpRepo):

    def test_cli_create_then_check(self):
        findings_path = self.tmp / "findings.json"
        base_path = self.tmp / "security-baseline.json"
        repo = self.tmp / "repo"
        repo.mkdir()
        write(repo, "app/search.py", "x = 1\n" * 9 + "db.execute(q)\n")

        findings_path.write_text(json.dumps([finding()]))
        with redirect_stdout(io.StringIO()):
            assert b.main(["create", "--findings", str(findings_path), "--baseline", str(base_path),
                           "--commit", "c1", "--repo", str(repo)]) == 0

        findings_path.write_text(json.dumps([finding(), finding(rule="r.new", line=30)]))
        out, report = self.tmp / "diffed.json", self.tmp / "report.json"
        args = ["check", "--findings", str(findings_path), "--baseline", str(base_path),
                "--repo", str(repo), "--commit", "c2", "--today", "2026-10-22",
                "-o", str(out), "--report", str(report)]
        with redirect_stdout(io.StringIO()):
            assert b.main(args) == 1
            assert b.main(args + ["--warn-only"]) == 0

        diffed = json.loads(out.read_text())
        n.validate(diffed)                           # still valid against the shared schema
        assert [f["baseline"]["is_new"] for f in diffed] == [False, True]
        assert json.loads(report.read_text())["blocking"][0]["rule_id"] == "r.new"

    def test_cli_writes_lf_line_endings(self):
        fpath = self.tmp / "f.json"
        fpath.write_text(json.dumps([finding(line=0)]), encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            assert b.main(["create", "--findings", str(fpath), "--baseline", str(self.tmp / "base.json"),
                           "--commit", "c1", "--repo", str(self.tmp)]) == 0
        assert b"\r\n" not in (self.tmp / "base.json").read_bytes()

    def test_cli_rejects_a_compact_today(self):
        (self.tmp / "f.json").write_text("[]", encoding="utf-8")
        args = ["check", "--findings", str(self.tmp / "f.json"), "--baseline", str(self.tmp / "b.json"),
                "--repo", str(self.tmp)]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            assert b.main(args + ["--today", "2026-10-22"]) == 0
            assert b.main(args + ["--today", "20261022"]) == 2

    def test_cli_bad_input_exits_2(self):
        with redirect_stderr(io.StringIO()):
            assert b.main(["check", "--findings", str(self.tmp / "missing.json"),
                           "--baseline", str(self.tmp / "b.json")]) == 2


class TestAnnotationParsing(TmpRepo):

    def test_annotation_syntax_in_strings_and_docs_is_ignored(self):
        write(self.tmp, "a.py", 'ANN = "# security-exception: r.sqli owner:r2"\n')
        write(self.tmp, "b.json", '{"d": "\'# security-exception: <id> expires:<date> owner:<name>\'"}\n')
        write(self.tmp, "c.md", "Use security-exception: <id> expires:YYYY-MM-DD owner:<name>\n")
        assert b.scan_annotations(self.tmp, TODAY, 90) == []

    def test_trailing_comment_on_finding_line_applies(self):
        # Built in two parts so this test file does not itself contain a "trailing comment" annotation
        ann = "# " + "security-exception: r.sqli expires:2026-11-30 owner:r2"
        lines = ["x"] * 9 + ["db.execute(q)  " + ann]
        write(self.tmp, "app/search.py", "\n".join(lines))
        _, rep = run_check([finding(line=10)], self.no_baseline(), self.tmp)
        assert rep["result"] == "pass" and rep["counts"]["excepted"] == 1

    def test_common_comment_leaders(self):
        for leader in ["#", "//", "--", "/*", "<!--", ";"]:
            with self.subTest(leader=leader):
                write(self.tmp, "f.txt", f"{leader} security-exception: r.x expires:2026-11-30 owner:r2\n")
                assert [a["status"] for a in b.scan_annotations(self.tmp, TODAY, 90)] == ["valid"]


if __name__ == "__main__":
    unittest.main()
