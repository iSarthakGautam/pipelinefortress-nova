#!/usr/bin/env python3
"""SCA detector cross-check: how much do Trivy, Grype and OSV-Scanner agree? Owner: R2.

Feeds the plan's "detector overlap" metric (PROJECT_PLAN §7): can we drop a redundant tool?
Metrics only. This never gates the build.

  python scanners/crosscheck/crosscheck.py --findings artifacts/findings.json \
      --tools trivy,grype,osv -o artifacts/sca-crosscheck.json --markdown artifacts/sca-crosscheck.md

Linking: two findings are the same vulnerability when they are in the same manifest, for the
same package (PEP 503-style name normalization), and share any ID (rule_id or a CVE alias).
Linking is transitive, so tool A's GHSA, tool B's CVE and tool C's CVE+GHSA end up in one group.
"""
import argparse
import itertools
import json
import re
import sys
from pathlib import Path

SCA_TOOLS = ("trivy", "grype", "osv")
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").lower())


class _UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, i):
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def group_findings(findings: list, tools=SCA_TOOLS) -> list:
    """Return one dict per distinct vulnerability, listing which tools found it."""
    sca = [f for f in findings if f["tool"] in tools and (f.get("package") or {}).get("name")]
    uf = _UnionFind(len(sca))
    first_seen = {}
    for i, f in enumerate(sca):
        scope = (f["location"]["file"], norm_pkg(f["package"]["name"]))
        for vid in {f["rule_id"], *f.get("cve", [])}:
            key = (scope, vid)
            if key in first_seen:
                uf.union(first_seen[key], i)
            else:
                first_seen[key] = i

    members = {}
    for i, f in enumerate(sca):
        members.setdefault(uf.find(i), []).append(f)

    groups = []
    for fs in members.values():
        by_tool = {}
        for f in sorted(fs, key=lambda x: (x["tool"], x["finding_id"])):
            by_tool.setdefault(f["tool"], f)          # one entry per tool is enough for metrics
        ids = sorted({f["rule_id"] for f in fs} | {c for f in fs for c in f.get("cve", [])})
        sev = {t: f["severity_norm"] for t, f in by_tool.items()}
        groups.append({
            "id": min((i for i in ids if i.startswith("CVE-")), default=ids[0]),
            "aliases": ids,
            "file": fs[0]["location"]["file"],
            "package": fs[0]["package"]["name"],
            "version": fs[0]["package"].get("version"),
            "tools": sorted(by_tool),
            "severity": sev,
            "severity_agrees": len(set(sev.values())) == 1,
            "max_severity": max(sev.values(), key=SEVERITY_ORDER.index),
            "fixed_version": {t: f["package"].get("fixed_version") for t, f in by_tool.items()},
        })
    groups.sort(key=lambda g: (g["file"], norm_pkg(g["package"]), g["id"]))
    return groups


def summarize(groups: list, tools) -> dict:
    tools = list(tools)
    sets = {t: {i for i, g in enumerate(groups) if t in g["tools"]} for t in tools}
    pairwise = {}
    for a, b in itertools.combinations(tools, 2):
        both, either = sets[a] & sets[b], sets[a] | sets[b]
        pairwise[f"{a}|{b}"] = {
            "both": len(both),
            "jaccard": round(len(both) / len(either), 3) if either else None,
        }
    multi = [g for g in groups if len(g["tools"]) > 1]
    fix_split = [g for g in multi if len({v is None for v in g["fixed_version"].values()}) > 1]
    return {
        "tools": tools,
        "unique_vulns": len(groups),
        "per_tool": {t: len(sets[t]) for t in tools},
        "found_by_all": sum(1 for g in groups if set(tools) <= set(g["tools"])),
        "found_by_one": {t: sum(1 for g in groups if g["tools"] == [t]) for t in tools},
        "pairwise": pairwise,
        "severity_disagreements": sum(1 for g in multi if not g["severity_agrees"]),
        "fix_availability_disagreements": len(fix_split),
    }


def to_markdown(summary: dict, groups: list, limit: int = 25) -> str:
    s = summary
    if not s["unique_vulns"]:
        return "### SCA cross-check\nNo dependency vulnerabilities found by any of: " + ", ".join(s["tools"]) + "\n"
    lines = [
        "### SCA cross-check",
        f"**{s['unique_vulns']}** distinct vulnerabilities ; found by all {len(s['tools'])}: "
        f"**{s['found_by_all']}** ; severity disagreements: **{s['severity_disagreements']}** ; "
        f"fix-availability disagreements: **{s['fix_availability_disagreements']}**",
        "",
        "| Tool | Found | Only this tool |",
        "|---|---|---|",
    ]
    for t in s["tools"]:
        lines.append(f"| {t} | {s['per_tool'][t]} | {s['found_by_one'][t]} |")
    lines += ["", "| Pair | Both | Jaccard |", "|---|---|---|"]
    for pair, v in s["pairwise"].items():
        lines.append(f"| {pair.replace('|', ' + ')} | {v['both']} | {v['jaccard']} |")
    odd = [g for g in groups if len(g["tools"]) < len(s["tools"]) or not g["severity_agrees"]]
    if odd:
        lines += ["", "**Disagreements**", "", "| Vulnerability | Package | Found by | Severity |", "|---|---|---|---|"]
        for g in odd[:limit]:
            sev = ", ".join(f"{t}:{v}" for t, v in sorted(g["severity"].items()))
            lines.append(f"| {g['id']} | {g['package']} {g['version'] or ''} | {', '.join(g['tools'])} | {sev} |")
        if len(odd) > limit:
            lines.append(f"| ... {len(odd) - limit} more in sca-crosscheck.json | | | |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", type=Path, required=True)
    ap.add_argument("--tools", default=",".join(SCA_TOOLS),
                    help="tools that ran (a tool with zero findings still counts)")
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--markdown", type=Path)
    args = ap.parse_args(argv)

    tools = [t for t in args.tools.split(",") if t]
    unknown = set(tools) - set(SCA_TOOLS)
    if unknown:
        print(f"error: unknown SCA tool(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    try:
        findings = json.loads(args.findings.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    groups = group_findings(findings, tools)
    summary = summarize(groups, tools)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # bytes, not text: write_text turns \n into \r\n on Windows
    args.output.write_bytes((json.dumps({"summary": summary, "vulnerabilities": groups},
                                        indent=2, sort_keys=True) + "\n").encode("utf-8"))
    md = to_markdown(summary, groups)
    if args.markdown:
        args.markdown.write_bytes(md.encode("utf-8"))
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
