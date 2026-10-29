"""Candidate population for the ground-truth sample (GROUND_TRUTH_PROTOCOL.md §2.1, §5). Owner: R2.

  python docs/metrics/data/candidate-population-2026-10-29/build_population.py \
      --findings findings.json --osv osv.json --trivy trivy.json --commit <scanned sha> -o population.csv

Inputs are main's CI artifacts for one run (`findings` and `raw-scans`; they expire, so the output is
committed). One row per normalized finding, no snippets or messages, no labels: labelling is the two
reviewers' job (§3), and this file only freezes what they sample from.

first_seen (UTC), by finding type:
  code finding with a line   commit time of the flagged line (`git blame` at the scanned commit)
  dependency finding         later of the advisory's publish date and the manifest's first commit:
                             a lower bound, since the package may have been added after the manifest
  anything else              the file's first commit
advisory_published is kept separately: it says whether a model could have seen the advisory in
training (§2.3, post-cutoff findings), which first_seen cannot.
dup_group joins records that must stay on the same side of a time split (§5): the same vulnerability
in one manifest across Trivy/Grype/OSV (crosscheck's linking), or several tools on one file:line.
"""
import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scanners" / "crosscheck"))
sys.path.insert(0, str(ROOT / "ai"))
import crosscheck as cc  # noqa: E402
from cluster import generate_cluster_key  # noqa: E402

FAMILY = {"semgrep": "sast", "bandit": "sast", "gitleaks": "secrets", "checkov": "iac",
          "trivy": "sca", "grype": "sca", "osv": "sca"}


def family(f) -> str:
    """Trivy reports both vulnerabilities and misconfigurations; a misconfiguration has no package."""
    fam = FAMILY.get(f["tool"], "other")
    return "iac" if fam == "sca" and not (f.get("package") or {}).get("name") else fam
COLUMNS = ["finding_id", "tool", "rule_family", "rule_id", "severity_norm", "file", "line", "package",
           "version", "cluster_id", "dup_group", "first_seen", "first_seen_source", "advisory_published"]


def utc(ts: str) -> str:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(repo, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          encoding="utf-8").stdout


def blame_time(repo, commit, file, line):
    out = git(repo, "blame", "--porcelain", "-L", f"{line},{line}", commit, "--", file)
    for row in out.splitlines():
        if row.startswith("committer-time "):
            return datetime.fromtimestamp(int(row.split()[1]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def file_added(repo, commit, file, cache):
    if file not in cache:
        dates = git(repo, "log", "--format=%cI", "--diff-filter=A", commit, "--", file).split()
        cache[file] = utc(dates[-1]) if dates else None
    return cache[file]


def advisory_dates(osv_path, trivy_path) -> dict:
    """Vulnerability ID (and every alias) -> earliest publish date any source gives."""
    dates = {}

    def add(ids, ts):
        if ts:
            for i in ids:
                dates[i] = min(dates.get(i, utc(ts)), utc(ts))
    for result in json.loads(Path(osv_path).read_text(encoding="utf-8")).get("results") or []:
        for pkg in result.get("packages") or []:
            for v in pkg.get("vulnerabilities") or []:
                add([v.get("id")] + list(v.get("aliases") or []), v.get("published"))
    for result in json.loads(Path(trivy_path).read_text(encoding="utf-8")).get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            add([v.get("VulnerabilityID")] + list(v.get("VendorIDs") or []), v.get("PublishedDate"))
    return dates


def dup_groups(findings) -> dict:
    """finding_id -> group label. SCA: crosscheck's groups. Everything else: one group per file:line."""
    group = {}
    for g in cc.group_findings(findings):
        label = f"sca::{g['file']}::{cc.norm_pkg(g['package'])}::{g['id']}"
        ids = {g["id"], *g["aliases"]}
        for f in findings:
            pkg = (f.get("package") or {}).get("name")
            if (f["tool"] in cc.SCA_TOOLS and pkg and f["location"]["file"] == g["file"]
                    and cc.norm_pkg(pkg) == cc.norm_pkg(g["package"])
                    and ({f["rule_id"], *f.get("cve", [])} & ids)):
                group[f["finding_id"]] = label
    for f in findings:
        loc = f["location"]
        group.setdefault(f["finding_id"], f"loc::{loc['file']}::{loc['line'] or f['rule_id']}")
    return group


def build(findings, dates, repo, commit) -> list:
    groups, added, rows = dup_groups(findings), {}, []
    for f in findings:
        loc, pkg = f["location"], f.get("package") or {}
        known = [dates[i] for i in {f["rule_id"], *f.get("cve", [])} if i in dates]
        fam = family(f)
        if loc["line"] > 0 and fam != "sca":
            seen, source = blame_time(repo, commit, loc["file"], loc["line"]), "git_blame_line"
        elif fam == "sca":
            manifest = file_added(repo, commit, loc["file"], added)
            candidates = [d for d in (min(known) if known else None, manifest) if d]
            seen = max(candidates) if candidates else None
            source = "max(advisory_published,manifest_added)" if known else "manifest_added"
        else:
            seen, source = file_added(repo, commit, loc["file"], added), "file_added"
        rows.append({
            "finding_id": f["finding_id"], "tool": f["tool"], "rule_family": fam,
            "rule_id": f["rule_id"], "severity_norm": f["severity_norm"], "file": loc["file"],
            "line": loc["line"], "package": pkg.get("name") or "", "version": pkg.get("version") or "",
            "cluster_id": generate_cluster_key(f), "dup_group": groups[f["finding_id"]],
            "first_seen": seen or "", "first_seen_source": source if seen else "unknown",
            "advisory_published": min(known) if known else "",
        })
    return sorted(rows, key=lambda r: r["finding_id"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--findings", required=True)
    ap.add_argument("--osv", required=True)
    ap.add_argument("--trivy", required=True)
    ap.add_argument("--commit", required=True, help="the commit the findings were scanned at")
    ap.add_argument("--repo", default=str(ROOT))
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args(argv)
    findings = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    rows = build(findings, advisory_dates(args.osv, args.trivy), args.repo, args.commit)
    with open(args.output, "w", encoding="utf-8", newline="") as out:
        w = csv.DictWriter(out, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"population: {len(rows)} findings -> {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
