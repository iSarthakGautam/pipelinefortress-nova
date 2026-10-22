"""Grype / OSV parsing and the SCA cross-check.

Fixtures in tests/fixtures/sca/ are trimmed from real output of Trivy 0.75.0, Grype 0.120.1 and
OSV-Scanner 2.6.0 on a sample project (apps/api/requirements.txt with Jinja2==2.10,
apps/web/package-lock.json with lodash 4.17.15). OSV's absolute path is rewritten to the
GitHub runner layout.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanners" / "normalize"))
sys.path.insert(0, str(ROOT / "scanners" / "crosscheck"))

import crosscheck as cc  # noqa: E402
import normalize as n  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "sca"
CI_ROOT = "/home/runner/work/pipelinefortress-nova/pipelinefortress-nova"


@pytest.fixture(scope="module")
def sca_findings():
    fs = (n.parse_trivy(FIX / "trivy.json")
          + n.parse_grype(FIX / "grype.json", root=CI_ROOT)
          + n.parse_osv(FIX / "osv.json", root=CI_ROOT))
    return n.dedupe_exact(fs)


def one(findings, tool, rule_id):
    hits = [f for f in findings if f["tool"] == tool and f["rule_id"] == rule_id]
    assert len(hits) == 1, (tool, rule_id, len(hits))
    return hits[0]


# ------------------------------------------------------------------ helpers

def test_canonical_id_prefers_cve_then_ghsa():
    assert n.canonical_vuln_id(["PYSEC-2019-217", "GHSA-462w-v97r-4m45", "CVE-2019-10906"]) == "CVE-2019-10906"
    assert n.canonical_vuln_id(["PYSEC-1", "GHSA-b", "GHSA-a"]) == "GHSA-a"
    assert n.canonical_vuln_id(["NSWG-ECO-516"]) == "NSWG-ECO-516"
    assert n.canonical_vuln_id([None, ""]) == "unknown"


@pytest.mark.parametrize("score,expected", [
    ("9.0", "CRITICAL"), ("8.9", "HIGH"), ("7.0", "HIGH"), ("6.9", "MEDIUM"),
    ("4.0", "MEDIUM"), ("0.1", "LOW"), ("0.0", "INFO"), ("", None), ("HIGH", None)])
def test_cvss_bucket_boundaries(score, expected):
    assert n.cvss_bucket(score) == expected


@pytest.mark.parametrize("uri,root,expected", [
    (f"{CI_ROOT}/apps/api/requirements.txt", CI_ROOT, "apps/api/requirements.txt"),
    ("/apps/web/package-lock.json", CI_ROOT, "apps/web/package-lock.json"),
    ("C:/Users/x/proj/apps/a.txt", "c:\\Users\\x\\proj", "apps/a.txt"),
    ("./apps/a.txt", None, "apps/a.txt"),
])
def test_norm_path_with_root(uri, root, expected):
    assert n.norm_path(uri, root) == expected


# ------------------------------------------------------------------ parsers

def test_all_three_tools_parse_and_validate(sca_findings):
    counts = {t: sum(f["tool"] == t for f in sca_findings) for t in ("trivy", "grype", "osv")}
    assert counts == {"trivy": 13, "grype": 12, "osv": 12}
    n.validate(sca_findings)
    assert {f["location"]["file"] for f in sca_findings} == \
        {"apps/api/requirements.txt", "apps/web/package-lock.json"}


def test_grype_finding(sca_findings):
    f = one(sca_findings, "grype", "CVE-2021-23337")      # Grype's own id is a GHSA
    assert f["severity_raw"] == "High" and f["severity_norm"] == "HIGH"
    assert f["package"] == {"name": "lodash", "version": "4.17.15", "fixed_version": "4.17.21"}
    assert f["cwe"] == ["CWE-94"] and f["cve"] == ["CVE-2021-23337"]
    assert f["location"] == {"file": "apps/web/package-lock.json", "line": 0}


def test_osv_finding_uses_group_and_cvss(sca_findings):
    f = one(sca_findings, "osv", "CVE-2019-10906")        # group ids are PYSEC + GHSA
    assert f["severity_raw"] == "8.6" and f["severity_norm"] == "HIGH"
    assert f["package"]["fixed_version"] == "2.10.1"
    assert f["location"]["file"] == "apps/api/requirements.txt"
    assert f["evidence"]["raw_ref"].endswith("#/results/0/packages/0/groups/0")


def test_osv_falls_back_to_ghsa_label_without_score(tmp_path):
    doc = {"results": [{"source": {"path": "/r/req.txt"}, "packages": [{
        "package": {"name": "x", "version": "1.0", "ecosystem": "PyPI"},
        "groups": [{"ids": ["GHSA-aaaa"], "aliases": ["GHSA-aaaa"], "max_severity": ""}],
        "vulnerabilities": [{"id": "GHSA-aaaa", "database_specific": {"severity": "MODERATE"},
                             "affected": [{"package": {"name": "x"},
                                           "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}]}],
    }]}]}
    p = tmp_path / "osv.json"
    p.write_text(json.dumps(doc))
    f = n.parse_osv(p, root="/r")[0]
    assert (f["rule_id"], f["severity_raw"], f["severity_norm"]) == ("GHSA-aaaa", "MODERATE", "MEDIUM")
    assert f["cve"] == [] and f["package"]["fixed_version"] == "1.1"


def test_trivy_vendor_ids_feed_canonical_id(tmp_path):
    doc = {"Results": [{"Target": "req.txt", "Vulnerabilities": [
        {"VulnerabilityID": "GHSA-zzzz", "VendorIDs": ["CVE-2020-1234"], "PkgName": "x",
         "InstalledVersion": "1", "Severity": "LOW"}]}]}
    p = tmp_path / "t.json"
    p.write_text(json.dumps(doc))
    f = n.parse_trivy(p)[0]
    assert f["rule_id"] == "CVE-2020-1234" and f["cve"] == ["CVE-2020-1234"]


def test_empty_scanner_outputs(tmp_path):
    (tmp_path / "g.json").write_text('{"matches": []}')
    (tmp_path / "o.json").write_text('{"results": []}')
    assert n.parse_grype(tmp_path / "g.json") == [] and n.parse_osv(tmp_path / "o.json") == []


# ------------------------------------------------------------------ cross-check

def test_crosscheck_on_real_fixtures(sca_findings):
    groups = cc.group_findings(sca_findings)
    s = cc.summarize(groups, cc.SCA_TOOLS)
    assert s["unique_vulns"] == 13 and s["found_by_all"] == 12
    assert s["per_tool"] == {"trivy": 13, "grype": 12, "osv": 12}
    assert s["found_by_one"] == {"trivy": 1, "grype": 0, "osv": 0}
    assert s["pairwise"]["grype|osv"] == {"both": 12, "jaccard": 1.0}
    assert s["severity_disagreements"] == 1 and s["fix_availability_disagreements"] == 0

    only_trivy = [g for g in groups if g["tools"] == ["trivy"]]
    assert [g["id"] for g in only_trivy] == ["NSWG-ECO-516"]      # no CVE alias to link on
    jinja = next(g for g in groups if g["id"] == "CVE-2024-56326")
    assert jinja["severity"] == {"grype": "MEDIUM", "osv": "HIGH", "trivy": "MEDIUM"}
    assert jinja["max_severity"] == "HIGH" and not jinja["severity_agrees"]


def sca(tool, rule_id, cve=(), file="req.txt", pkg="Flask", sev="HIGH", fixed="2.0"):
    return {"tool": tool, "rule_id": rule_id, "cve": list(cve), "severity_norm": sev,
            "finding_id": f"{tool}-{rule_id}-{file}", "location": {"file": file, "line": 0},
            "package": {"name": pkg, "version": "1.0", "fixed_version": fixed}}


def test_linking_is_transitive_and_name_normalized():
    fs = [sca("grype", "GHSA-x"),                                   # GHSA only
          sca("osv", "CVE-2020-9", cve=["CVE-2020-9"], pkg="flask"),  # CVE only
          sca("trivy", "CVE-2020-9", cve=["CVE-2020-9"], pkg="FLASK")]
    fs[1]["rule_id"] = "GHSA-x"                                     # osv carries both ids
    groups = cc.group_findings(fs)
    assert len(groups) == 1 and groups[0]["tools"] == ["grype", "osv", "trivy"]


def test_same_vuln_in_two_manifests_counts_twice():
    groups = cc.group_findings([sca("trivy", "CVE-1", file="a/req.txt"),
                                sca("trivy", "CVE-1", file="b/req.txt")])
    assert len(groups) == 2


def test_fix_availability_disagreement():
    groups = cc.group_findings([sca("trivy", "CVE-1"), sca("grype", "CVE-1", fixed=None)])
    assert cc.summarize(groups, ["trivy", "grype"])["fix_availability_disagreements"] == 1


def test_non_sca_findings_and_misconfigs_ignored():
    fs = [sca("semgrep", "r.sqli"), {**sca("trivy", "KSV017"), "package": {"name": None}}]
    assert cc.group_findings(fs) == []


def test_tool_with_zero_findings_still_counted():
    s = cc.summarize(cc.group_findings([sca("trivy", "CVE-1")]), cc.SCA_TOOLS)
    assert s["per_tool"]["osv"] == 0 and s["found_by_all"] == 0 and s["found_by_one"]["trivy"] == 1


def test_cli_and_markdown(tmp_path, sca_findings):
    src = tmp_path / "findings.json"
    src.write_text(json.dumps(sca_findings))
    out, md = tmp_path / "cc.json", tmp_path / "cc.md"
    assert cc.main(["--findings", str(src), "-o", str(out), "--markdown", str(md)]) == 0
    assert json.loads(out.read_text())["summary"]["unique_vulns"] == 13
    text = md.read_text()
    assert "NSWG-ECO-516" in text and "| grype + osv | 12 | 1.0 |" in text
    assert text.isascii()


def test_cli_empty_and_bad_input(tmp_path):
    src = tmp_path / "f.json"
    src.write_text("[]")
    assert cc.main(["--findings", str(src), "-o", str(tmp_path / "o.json")]) == 0
    assert cc.main(["--findings", str(src), "--tools", "trivy,snyk", "-o", str(tmp_path / "o.json")]) == 2
    assert cc.main(["--findings", str(tmp_path / "missing.json"), "-o", str(tmp_path / "o.json")]) == 2
