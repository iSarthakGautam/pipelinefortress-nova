#!/usr/bin/env python3
"""Write docs/BASELINE_VULNERABILITY_REPORT.md (brief Week 1 deliverable) from committed data:
  - static: R2's frozen candidate population (264 real findings from CI run 40762500169)
  - runtime: artifacts/evidence/runtime/*-runtime-baseline.json (scripts/runtime_baseline.py)
  python3 scripts/build_baseline_report.py
"""
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POP = ROOT / "docs/metrics/data/candidate-population-2026-10-29/population.csv"
RUNTIME = sorted((ROOT / "artifacts/evidence/runtime").glob("*-runtime-baseline.json"))[-1]
ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def main() -> None:
    rows = list(csv.DictReader(open(POP, newline="", encoding="utf-8")))
    rt = json.loads(RUNTIME.read_text(encoding="utf-8"))
    by = defaultdict(Counter)
    for r in rows:
        by[(r["rule_family"], r["tool"])][r["severity_norm"]] += 1
    groups = defaultdict(list)
    for r in rows:
        groups[r["dup_group"]].append(r)
    out = ["# Baseline vulnerability report", "",
           "Brief, Week 1: *document the baseline vulnerabilities at runtime.* Two views of the same lab target "
           "(`apps/vulnshop-api` and its manifests): what the scanners report (static), and what a request actually does (runtime). "
           "Lab only: every request goes to a loopback copy of our own app.", "",
           "## 1. Static baseline (scanners)", "",
           f"Source: CI run 40762500169 on `main` @ `fbe9686`, normalized by R2 and frozen in `{POP.relative_to(ROOT)}` "
           f"(SHA-256 in its README). **{len(rows)} findings, {len(groups)} distinct issues** (the same CVE is reported by up to three SCA tools). "
           "Accepted as known debt in `scanners/baseline/security-baseline.json`; the gate only fails on new findings.", "",
           "| Family | Tool | " + " | ".join(ORDER[:4]) + " | Total |", "|---|---|" + "---:|" * 5]
    for (fam, tool), c in sorted(by.items()):
        out.append(f"| {fam} | {tool} | " + " | ".join(str(c.get(s, 0)) for s in ORDER[:4]) + f" | {sum(c.values())} |")
    tot = Counter(r["severity_norm"] for r in rows)
    out += ["", "Distinct issues by severity (highest severity per issue): " + ", ".join(
        f"{s} {n}" for s, n in ((s, sum(1 for g in groups.values() if max(g, key=lambda r: ORDER[::-1].index(r['severity_norm']) if r['severity_norm'] in ORDER else -1)['severity_norm'] == s)) for s in ORDER) if n) + ".",
        "", "Findings by severity: " + ", ".join(f"{s} {tot[s]}" for s in ORDER if tot[s]) + ".",
        "", "Not in this table: gitleaks (no findings: it cannot see the AWS documentation example key, only the custom Semgrep rule does), "
        "ZAP (advisory, runs in stage 60), and the Juice Shop target (a pinned pointer; it is not scanned in CI).", "",
        "## 2. Runtime baseline (what a request does)", "",
        f"Captured {rt['captured']} by `scripts/runtime_baseline.py` (evidence: `{RUNTIME.relative_to(ROOT)}`), Python {rt['python']}. "
        "The app is started from a temporary copy on 127.0.0.1 and probed twice: as shipped (`DEBUG=1`) and with the hardened image's setting (`DEBUG=0`).", ""]
    for label, probes in rt["runs"].items():
        out += [f"### {label}", "", "| Planted | Probe | Request | Observed | Exploitable |", "|---|---|---|---|---|"]
        for p in probes:
            out.append(f"| {p['planted']} | {p['name']} | `{p['request']}` | {p['observed']} | **{'yes' if p['exploitable'] else 'no'}** |")
        out.append("")
    out += ["## 3. What the two views say together", "",
            "- Every planted *code* vulnerability (SQL injection, XSS, command injection) is exploitable at runtime **and** reported by at least one scanner.",
            "- The two negative controls behave safely at runtime (parameterised lookup, `X-Frame-Options: DENY`), which is why a scanner flag on them would be a false positive.",
            "- The Werkzeug debug console is reachable only with `DEBUG=1`; the hardened image sets `DEBUG=0`, which the second run confirms.",
            "- Runtime proof is stronger than a scanner line number: the SQL injection reads the `users` table through the items endpoint, and the injected shell command really ran.",
            "- Not covered here: dependency CVEs (static only; whether they are reachable was not tested) and the Kubernetes/Docker findings (configuration, no request to make).",
            "", "Re-run: `python3 scripts/runtime_baseline.py && python3 scripts/build_baseline_report.py` (needs Flask)."]
    (ROOT / "docs/BASELINE_VULNERABILITY_REPORT.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print("wrote docs/BASELINE_VULNERABILITY_REPORT.md")


if __name__ == "__main__":
    main()
