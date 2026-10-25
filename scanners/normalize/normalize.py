#!/usr/bin/env python3
"""Normalize scanner output (SARIF / Trivy JSON) into the unified finding schema.

Usage:
  python scanners/normalize/normalize.py \
      --semgrep artifacts/scans/semgrep.sarif \
      --bandit artifacts/scans/bandit.json \
      --checkov artifacts/scans/checkov.sarif \
      --trivy artifacts/scans/trivy.json \
      --grype artifacts/scans/grype.json \
      --osv artifacts/scans/osv.json \
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
SCHEMA_VERSION = "1.1.0"

_CWE_RE = re.compile(r"CWE-(\d+)", re.I)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_severity_map = None


def _load_severity_map():
    global _severity_map
    if _severity_map is None:
        _severity_map = yaml.safe_load(SEVERITY_MAP_PATH.read_text(encoding="utf-8"))
    return _severity_map


def normalize_severity(tool: str, raw, rule_id: str = None) -> str:
    smap = _load_severity_map()
    overrides = (smap.get("_rule_overrides") or {}).get(tool) or {}
    if rule_id in overrides:
        return overrides[rule_id]
    table = {str(k).lower(): v for k, v in (smap.get(tool) or {}).items()}
    key = str(raw).lower()
    if key in table:
        return table[key]
    if "*" in table:
        return table["*"]
    print(f"warning: unmapped severity {raw!r} for {tool}; using {smap['_default']}", file=sys.stderr)
    return smap["_default"]


def norm_path(uri: str, root: str = None) -> str:
    """Repo-relative, forward-slash path. `root` strips absolute prefixes (OSV reports
    absolute paths); a leading '/' is dropped (Grype reports '/apps/x' for dir: scans)."""
    p = (uri or "").replace("\\", "/")
    if p.startswith("file:///"):
        p = p[len("file:///"):]
    elif p.startswith("file://"):
        p = p[len("file://"):]
    if root:
        r = str(root).replace("\\", "/").rstrip("/") + "/"
        if p.lower().startswith(r.lower()):
            p = p[len(r):]
    p = p.lstrip("/")
    while p.startswith("./"):
        p = p[2:]
    return p


_ID_PRIORITY = ("CVE-", "GHSA-")


def canonical_vuln_id(ids) -> str:
    """One ID per vulnerability across tools: lowest CVE, else lowest GHSA, else lowest other.
    Trivy, Grype and OSV lead with different IDs (CVE / GHSA / PYSEC) for the same flaw."""
    ids = sorted({i for i in ids if i})
    for prefix in _ID_PRIORITY:
        hit = [i for i in ids if i.upper().startswith(prefix)]
        if hit:
            return hit[0]
    return ids[0] if ids else "unknown"


def cvss_bucket(score):
    """CVSS base score -> qualitative rating (CVSS v3 table). None if not a number."""
    try:
        x = float(score)
    except (TypeError, ValueError):
        return None
    if x >= 9.0:
        return "CRITICAL"
    if x >= 7.0:
        return "HIGH"
    if x >= 4.0:
        return "MEDIUM"
    if x > 0.0:
        return "LOW"
    return "INFO"


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


def build_finding(*, tool, rule_id, message, severity_raw, cwe, cve, file, line, package, snippet, raw_ref,
                  severity_norm=None):
    pkg = package or {"name": None, "version": None, "fixed_version": None}
    evidence = {"raw_ref": raw_ref}
    if snippet:
        evidence["snippet_raw"] = snippet
    finding = {
        "schema_version": SCHEMA_VERSION,
        "finding_id": make_finding_id(tool, rule_id, file, line, pkg["name"]),
        "tool": tool,
        "rule_id": rule_id,
        "severity_raw": str(severity_raw),
        "severity_norm": severity_norm or normalize_severity(tool, severity_raw, rule_id),
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


_SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def parse_bandit(path: Path, ref: str = None) -> list:
    """Bandit JSON (`bandit -f json`). rule_id is the test id (B310). Bandit rates confidence
    separately from severity; a LOW-confidence result is one severity level lower."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    ref = ref or path.as_posix()
    findings = []
    for i, r in enumerate(doc.get("results", [])):
        sev = normalize_severity("bandit", r.get("issue_severity"))
        if str(r.get("issue_confidence")).upper() == "LOW" and sev in _SEVERITY_ORDER[1:]:
            sev = _SEVERITY_ORDER[_SEVERITY_ORDER.index(sev) - 1]
        line = int(r.get("line_number") or 0)
        # `code` is a few numbered lines of context; keep only the flagged line
        snippet = next((c.split(" ", 1)[1].strip() for c in (r.get("code") or "").splitlines()
                        if c.split(" ", 1)[0] == str(line) and " " in c), None)
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        findings.append(build_finding(
            tool="bandit",
            rule_id=r.get("test_id") or "unknown",
            message=f"{r.get('issue_text', '')} (confidence: {r.get('issue_confidence')})",
            severity_raw=r.get("issue_severity"),
            severity_norm=sev,
            cwe=[f"CWE-{int(cwe_id)}"] if cwe_id else [],
            cve=[],
            file=norm_path(r.get("filename", "")),
            line=line,
            package=None,
            snippet=snippet,
            raw_ref=f"{ref}#/results/{i}",
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
            ids = [vid] + list(v.get("VendorIDs") or [])
            findings.append(build_finding(
                tool="trivy",
                rule_id=canonical_vuln_id(ids),
                message=v.get("Title") or v.get("Description"),
                severity_raw=v.get("Severity", "UNKNOWN"),
                cwe=extract_cwes(v.get("CweIDs")),
                cve=extract_cves(ids),
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


def parse_grype(path: Path, ref: str = None, root: str = None) -> list:
    """Grype JSON (`grype dir:. -o json`)."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    ref = ref or path.as_posix()
    findings = []
    for i, m in enumerate(doc.get("matches") or []):
        v = m.get("vulnerability", {})
        art = m.get("artifact", {})
        ids = [v.get("id")] + [r.get("id") for r in m.get("relatedVulnerabilities") or []]
        locs = art.get("locations") or [{}]
        fix = v.get("fix") or {}
        fixed = ", ".join(fix.get("versions") or []) if fix.get("state") == "fixed" else ""
        findings.append(build_finding(
            tool="grype",
            rule_id=canonical_vuln_id(ids),
            message=v.get("description"),
            severity_raw=v.get("severity", "Unknown"),
            cwe=extract_cwes(c.get("cwe") for c in v.get("cwes") or []),
            cve=extract_cves(ids),
            file=norm_path(locs[0].get("path", ""), root),
            line=0,
            package={"name": art.get("name"), "version": art.get("version"), "fixed_version": fixed or None},
            snippet=None,
            raw_ref=f"{ref}#/matches/{i}",
        ))
    return findings


def _osv_fixed_versions(vulns: list, pkg_name: str) -> list:
    fixed = []
    for v in vulns:
        for aff in v.get("affected") or []:
            if (aff.get("package") or {}).get("name", "").lower() != pkg_name.lower():
                continue
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if ev.get("fixed") and ev["fixed"] not in fixed:
                        fixed.append(ev["fixed"])
    return fixed


def parse_osv(path: Path, ref: str = None, root: str = None) -> list:
    """OSV-Scanner v2 JSON (`osv-scanner scan source -r --format json`).
    One finding per alias group: OSV already merges PYSEC/GHSA/CVE records for one flaw."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    ref = ref or path.as_posix()
    findings = []
    for ri, result in enumerate(doc.get("results") or []):
        file = norm_path((result.get("source") or {}).get("path", ""), root)
        for pi, pkg in enumerate(result.get("packages") or []):
            meta = pkg.get("package") or {}
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
            for gi, group in enumerate(pkg.get("groups") or []):
                ids = list(group.get("ids") or []) + list(group.get("aliases") or [])
                members = [vulns[i] for i in group.get("ids") or [] if i in vulns]
                score = group.get("max_severity") or ""
                bucket = cvss_bucket(score)
                if bucket is None:   # no CVSS score: fall back to GHSA's qualitative label
                    labels = [(v.get("database_specific") or {}).get("severity") for v in members]
                    score = next((label for label in labels if label), "UNKNOWN")
                cwes = [c for v in members for c in (v.get("database_specific") or {}).get("cwe_ids") or []]
                fixed = _osv_fixed_versions(members, meta.get("name", ""))
                findings.append(build_finding(
                    tool="osv",
                    rule_id=canonical_vuln_id(ids),
                    message=next((v.get("summary") for v in members if v.get("summary")), None),
                    severity_raw=str(score),
                    severity_norm=bucket,
                    cwe=extract_cwes(cwes),
                    cve=extract_cves(ids),
                    file=file,
                    line=0,
                    package={"name": meta.get("name"), "version": meta.get("version"),
                             "fixed_version": ", ".join(fixed) or None},
                    snippet=None,
                    raw_ref=f"{ref}#/results/{ri}/packages/{pi}/groups/{gi}",
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
    ap.add_argument("--bandit", type=Path, action="append", default=[], help="Bandit JSON file")
    ap.add_argument("--trivy", type=Path, action="append", default=[], help="Trivy JSON file")
    ap.add_argument("--grype", type=Path, action="append", default=[], help="Grype JSON file")
    ap.add_argument("--osv", type=Path, action="append", default=[], help="OSV-Scanner JSON file")
    ap.add_argument("--root", default=str(Path.cwd()),
                    help="repo root, stripped from absolute paths (default: cwd)")
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args(argv)

    def ref(p: Path) -> str:
        # raw_ref is relative to the repo root: ai/sarif_ref.py (R4) resolves it against ARTIFACTS_BASE,
        # which defaults to the repo root, and refuses anything outside it
        try:
            return p.resolve().relative_to(Path(args.root).resolve()).as_posix()
        except ValueError:
            return p.as_posix()

    findings = []
    for t in SARIF_TOOLS:
        for p in getattr(args, t):
            findings += parse_sarif(p, t, ref=ref(p))
    for p in args.bandit:
        findings += parse_bandit(p, ref=ref(p))
    for p in args.trivy:
        findings += parse_trivy(p, ref=ref(p))
    for p in args.grype:
        findings += parse_grype(p, ref=ref(p), root=args.root)
    for p in args.osv:
        findings += parse_osv(p, ref=ref(p), root=args.root)

    findings = dedupe_exact(findings)
    validate(findings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"normalized {len(findings)} findings -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
