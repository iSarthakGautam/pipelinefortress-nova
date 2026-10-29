#!/usr/bin/env python3
"""Pre-merge catch rate against the planted vulnerabilities (the plan's headline metric).

  python3 eval/metrics/catch_rate.py findings.json [--planted ground_truth/planted.yaml] [--prom out.prom] [--md out.md]

findings.json is the normalized list (CI artifact `findings.json` or `findings.diffed.json`). A planted TRUE_POSITIVE is
*caught* when a finding sits on it. How closely the finding sits is reported, never hidden:
  exact       same file and same line
  package     a dependency finding for the planted package (or CVE)
  file-level  same file, different line (only for checkov/trivy/zap plants, which report at resource level)
A planted item is *blocking* when a matching finding is HIGH or CRITICAL, i.e. when the merge gate would stop it.
Negative controls (FALSE_POSITIVE rows) are expected NOT to be flagged; a flag is a false alarm.
"""
import argparse
import json
import re
import sys
from pathlib import Path

import yaml

ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
PREFIX = "pipelinefortress_planted"


def _rank(sev) -> int:
    return ORDER.index(sev) if sev in ORDER else 0


def planted_package(entry: dict):
    m = re.search(r'"([@\w./-]+)"\s*:\s*"', entry.get("snippet") or "")
    return m.group(1) if m else None


def match(entry: dict, f: dict):
    """How finding f matches planted entry, or None."""
    loc, want = f.get("location") or {}, entry["location"]
    pkg = planted_package(entry)
    cves = set(entry.get("cve") or [])
    if cves and (cves & (set(f.get("cve") or []) | set(f.get("aliases") or []))):
        return "package"
    if pkg and (f.get("package") or {}).get("name") == pkg and (loc.get("file") or "").startswith(want["file"].rsplit("/", 1)[0]):
        return "package"
    if (loc.get("file") or "") != want["file"]:
        return None
    if loc.get("line") == want["line"]:
        return "exact"
    # IaC, container and DAST tools report at resource level, so the file is the best location they can give; a SAST
    # tool points at a line, so a hit elsewhere in the same file is a different finding and does not count
    return "file-level" if entry.get("tool") in ("checkov", "trivy", "zap") else None


def evaluate(findings: list, planted: list) -> list:
    rows = []
    for e in planted:
        hits = [(m, f) for f in findings if (m := match(e, f))]
        if e["ground_truth"] == "FALSE_POSITIVE":   # a control is "flagged" only on its own line, not anywhere in its file
            hits = [(m, f) for m, f in hits if m == "exact"]
        best = min((m for m, _ in hits), key=["exact", "package", "file-level"].index, default=None)
        rows.append({"id": e["id"], "name": e["name"], "expected": e["ground_truth"], "match": best,
                     "tools": sorted({f["tool"] for _, f in hits}),
                     "max_severity": max((f["severity_norm"] for _, f in hits), key=_rank, default=None)})
    return rows


def summarise(rows: list) -> dict:
    tps = [r for r in rows if r["expected"] == "TRUE_POSITIVE"]
    ctl = [r for r in rows if r["expected"] == "FALSE_POSITIVE"]
    return {"planted": len(tps), "caught": sum(bool(r["match"]) for r in tps),
            "caught_exact": sum(r["match"] in ("exact", "package") for r in tps),
            "blocking": sum(_rank(r["max_severity"]) >= _rank("HIGH") for r in tps),
            "missed": [r["id"] for r in tps if not r["match"]],
            "controls": len(ctl), "false_alarms": sum(bool(r["match"]) for r in ctl)}


def to_markdown(rows: list, s: dict) -> str:
    out = ["| Planted | Name | Expected | Matched as | Tools | Max severity |", "|---|---|---|---|---|---|"]
    out += [f"| {r['id']} | {r['name']} | {r['expected']} | {r['match'] or ('not flagged (good)' if r['expected'] == 'FALSE_POSITIVE' else '**missed**')} | {', '.join(r['tools']) or '-'} | "
            f"{r['max_severity'] or '-'} |" for r in rows]
    pct = lambda a, b: f"{100 * a / b:.0f}%" if b else "n/a"  # noqa: E731
    out += ["", f"**Catch rate: {s['caught']}/{s['planted']} ({pct(s['caught'], s['planted'])})**; "
                f"{s['caught_exact']} on the exact line or package; **{s['blocking']}/{s['planted']} would block the merge** (>= HIGH). "
                f"Negative controls flagged (false alarms): {s['false_alarms']}/{s['controls']}. "
                f"Missed: {', '.join(s['missed']) or 'none'}."]
    return "\n".join(out) + "\n"


def to_prom(s: dict) -> str:
    g = [("caught_total", "Planted vulnerabilities with a matching finding", s["caught"]),
         ("planted_total", "Planted true-positive vulnerabilities", s["planted"]),
         ("blocking_total", "Planted vulnerabilities rated HIGH or above (the gate would block)", s["blocking"]),
         ("false_alarms_total", "Negative controls that a scanner flagged", s["false_alarms"])]
    lines = []
    for name, help_, v in g:
        lines += [f"# HELP {PREFIX}_{name} {help_}", f"# TYPE {PREFIX}_{name} gauge", f"{PREFIX}_{name} {v}"]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings")
    ap.add_argument("--planted", default=str(Path(__file__).resolve().parents[2] / "ground_truth" / "planted.yaml"))
    ap.add_argument("--prom")
    ap.add_argument("--md")
    a = ap.parse_args(argv)
    findings = json.loads(Path(a.findings).read_text(encoding="utf-8"))
    planted = yaml.safe_load(Path(a.planted).read_text(encoding="utf-8"))["planted_vulnerabilities"]
    rows = evaluate(findings, planted)
    s = summarise(rows)
    md = to_markdown(rows, s)
    print(md)
    if a.md:
        Path(a.md).write_text(md, encoding="utf-8")
    if a.prom:
        Path(a.prom).write_text(to_prom(s), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
