#!/usr/bin/env python3
"""Normalize scanner output (SARIF / Trivy JSON) into the unified finding schema.

Usage:
  python scanners/normalize/normalize.py \
      --semgrep artifacts/scans/semgrep.sarif \
      --trivy artifacts/scans/trivy.json \
      --gitleaks artifacts/scans/gitleaks.sarif \
      -o artifacts/findings.json

Output is a JSON array validated against scanners/schema/finding.schema.json.
Owner: R2. Deterministic: same input gives byte-identical output.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE.parent / "schema" / "finding.schema.json"
SEVERITY_MAP_PATH = HERE / "severity_map.yaml"
SCHEMA_VERSION = "1.0.0"

_CWE_RE = re.compile(r"CWE-(\d+)", re.I)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_severity_map = None


def _load_severity_map():
    global _severity_map
    if _severity_map is None:
        _severity_map = yaml.safe_load(SEVERITY_MAP_PATH.read_text(encoding="utf-8"))
    return _severity_map


def normalize_severity(tool: str, raw) -> str:
    smap = _load_severity_map()
    table = {str(k).lower(): v for k, v in (smap.get(tool) or {}).items()}
    key = str(raw).lower()
    if key in table:
        return table[key]
    if "*" in table:
        return table["*"]
    print(f"warning: unmapped severity {raw!r} for {tool}; using {smap['_default']}", file=sys.stderr)
    return smap["_default"]


def norm_path(uri: str) -> str:
    p = (uri or "").replace("\\", "/")
    if p.startswith("file:///"):
        p = p[len("file:///"):]
    elif p.startswith("file://"):
        p = p[len("file://"):]
    while p.startswith("./"):
        p = p[2:]
    return p


def make_finding_id(tool, rule_id, file, line, pkg) -> str:
    key = f"{tool}|{rule_id}|{file}|{line}|{pkg or ''}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def extract_cwes(values) -> list:
    out = []
    for v in values or []:
        for m in _CWE_RE.finditer(str(v)):
            cwe = f"CWE-{int(m.group(1))}"
            if cwe not in out:
                out.append(cwe)
    return sorted(out, key=lambda c: int(c[4:]))


def extract_cves(values) -> list:
    return sorted({v for v in values or [] if _CVE_RE.match(str(v))})


def build_finding(*, tool, rule_id, message, severity_raw, cwe, cve, file, line, package, snippet, raw_ref):
    pkg = package or {"name": None, "version": None, "fixed_version": None}
    evidence = {"raw_ref": raw_ref}
    if snippet:
        evidence["snippet"] = snippet
    finding = {
        "schema_version": SCHEMA_VERSION,
        "finding_id": make_finding_id(tool, rule_id, file, line, pkg["name"]),
        "tool": tool,
        "rule_id": rule_id,
        "severity_raw": str(severity_raw),
        "severity_norm": normalize_severity(tool, severity_raw),
        "cwe": cwe,
        "cve": cve,
        "location": {"file": file, "line": line},
        "package": pkg,
        "evidence": evidence,
        "baseline": {"is_new": True, "first_seen_commit": None},
    }
    if message:
        finding["message"] = message
    return finding


def parse_sarif(path: Path, tool: str, ref: str = None) -> list:
    """Generic SARIF 2.1.0 parser (Semgrep, gitleaks, Checkov, hadolint)."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    ref = ref or path.as_posix()
    findings = []
    for ri, run in enumerate(doc.get("runs", [])):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for i, res in enumerate(run.get("results", [])):
            rule_id = res.get("ruleId") or "unknown"
            rule = rules.get(rule_id, {})
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation", {})
            region = phys.get("region", {})
            snippet = (region.get("snippet") or {}).get("text") or (
                phys.get("contextRegion", {}).get("snippet", {}).get("text"))
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
            tags = rule.get("properties", {}).get("tags", [])
            findings.append(build_finding(
                tool=tool,
                rule_id=rule_id,
                message=(res.get("message") or {}).get("text"),
                severity_raw=level,
                cwe=extract_cwes(tags),
                cve=[],
                file=norm_path(phys.get("artifactLocation", {}).get("uri", "")),
                line=int(region.get("startLine", 0)),
                package=None,
                snippet=snippet,
                raw_ref=f"{ref}#/runs/{ri}/results/{i}",
            ))
    return findings


def parse_trivy(path: Path, ref: str = None) -> list:
    """Trivy JSON (`trivy fs|image -f json`): vulnerabilities and misconfigurations."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    ref = ref or path.as_posix()
    findings = []
    for ri, result in enumerate(doc.get("Results", [])):
        target = norm_path(result.get("Target", ""))
        for i, v in enumerate(result.get("Vulnerabilities") or []):
            vid = v.get("VulnerabilityID", "unknown")
            findings.append(build_finding(
                tool="trivy",
                rule_id=vid,
                message=v.get("Title") or v.get("Description"),
                severity_raw=v.get("Severity", "UNKNOWN"),
                cwe=extract_cwes(v.get("CweIDs")),
                cve=extract_cves([vid]),
                file=target,
                line=0,
                package={"name": v.get("PkgName"), "version": v.get("InstalledVersion"),
                         "fixed_version": v.get("FixedVersion") or None},
                snippet=None,
                raw_ref=f"{ref}#/Results/{ri}/Vulnerabilities/{i}",
            ))
        for i, m in enumerate(result.get("Misconfigurations") or []):
            line = (m.get("CauseMetadata") or {}).get("StartLine") or 0
            findings.append(build_finding(
                tool="trivy",
                rule_id=m.get("ID") or m.get("AVDID") or "unknown",
                message=m.get("Title") or m.get("Message"),
                severity_raw=m.get("Severity", "UNKNOWN"),
                cwe=[], cve=[],
                file=target, line=int(line), package=None, snippet=None,
                raw_ref=f"{ref}#/Results/{ri}/Misconfigurations/{i}",
            ))
    return findings


def dedupe_exact(findings: list) -> list:
    """Drop exact duplicates (same finding_id); keep first, sort for deterministic output."""
    seen, out = set(), []
    for f in findings:
        if f["finding_id"] in seen:
            continue
        seen.add(f["finding_id"])
        out.append(f)
    return sorted(out, key=lambda f: (f["location"]["file"], f["location"]["line"], f["tool"], f["rule_id"]))


def validate(findings: list) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = []
    for f in findings:
        for e in validator.iter_errors(f):
            errors.append(f"{f.get('finding_id')}: {'/'.join(map(str, e.path))}: {e.message}")
    if errors:
        raise ValueError("schema validation failed:\n  " + "\n  ".join(errors[:20]))


SARIF_TOOLS = ("semgrep", "gitleaks", "checkov", "hadolint")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for t in SARIF_TOOLS:
        ap.add_argument(f"--{t}", type=Path, action="append", default=[], help=f"{t} SARIF file")
    ap.add_argument("--trivy", type=Path, action="append", default=[], help="Trivy JSON file")
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args(argv)

    findings = []
    for t in SARIF_TOOLS:
        for p in getattr(args, t):
            findings += parse_sarif(p, t)
    for p in args.trivy:
        findings += parse_trivy(p)

    findings = dedupe_exact(findings)
    validate(findings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"normalized {len(findings)} findings -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
