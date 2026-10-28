"""Threshold simulation behind docs/metrics/GATE_TUNING.md section 3.

  python docs/metrics/data/gate-tuning-2026-10-27/threshold_sim.py [findings.json]

Default input: findings-main-1bb3381.json next to this script, main's 162 normalized findings
from run 40358495428 (messages and snippets removed; the CI artifact itself expires).

Treats every finding as new (an empty baseline) and counts what each --fail-on level would
block, before and after the severity changes in this PR. "Planted" rows are the static
TRUE_POSITIVE entries in ground_truth/planted.yaml, matched by the location of the planted
condition, not by any finding that happens to sit in the same file.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scanners" / "normalize"))
import json  # noqa: E402

import normalize as n  # noqa: E402

ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
TUNED = ("pf-jinja-autoescape-bypass", "CKV_K8S_23", "KSV-0012")

# planted id -> predicate on a finding that detects the planted condition itself
PLANTED = {
    "PLANT-001 SQLi": lambda f: f["location"]["file"].endswith("routes/search.py") and ("sql" in f["rule_id"].lower() or f["rule_id"] == "B608"),
    "PLANT-003 AWS key": lambda f: f["location"]["file"].endswith("vulnshop-api/config.py") and f["location"]["line"] == 12,
    "PLANT-004 cmd injection": lambda f: f["location"]["file"].endswith("routes/pay.py") and f["location"]["line"] == 22,
    "PLANT-005 lodash": lambda f: (f.get("package") or {}).get("name") == "lodash",
    "PLANT-006 root Dockerfile": lambda f: f["location"]["file"] == "docker/Dockerfile" and f["rule_id"] in ("CKV_DOCKER_3", "DS-0002", "dockerfile.security.missing-user.missing-user"),
    "PLANT-007 root pod": lambda f: f["location"]["file"] == "infra/k8s/deployment.yaml" and f["rule_id"] in ("CKV_K8S_23", "CKV_K8S_40", "KSV-0012"),
    "PLANT-008 XSS": lambda f: f["location"]["file"].endswith("views/profile.html"),
}
NEGATIVE = {
    "PLANT-002 parameterised query": lambda f: f["location"]["file"].endswith("routes/user.py") and f["location"]["line"] == 18,
    "PLANT-009 helmet frameguard": lambda f: f["location"]["file"].endswith("vulnshop-api/server.js") and f["location"]["line"] == 5,
}
HARDENED = "infra/k8s/deployment.hardened.yaml"


def tuned(findings):
    out = []
    for f in findings:
        f = dict(f)
        if f["rule_id"].endswith(TUNED):
            raw = "error" if f["tool"] == "semgrep" else f["severity_raw"]
            f["severity_norm"] = n.normalize_severity(f["tool"], raw, f["rule_id"])
        out.append(f)
    return out


def issues(fs):
    """Distinct issues: SCA collapses tools on (file, advisory); code on (file, line)."""
    return len({(f["location"]["file"], (f.get("cve") or [f["rule_id"]])[0]) if f["location"]["line"] == 0
                else (f["location"]["file"], f["location"]["line"]) for f in fs})


def table(findings, label):
    print(f"\n{label}")
    print("| fail on | findings | distinct issues | planted TPs blocked | negative controls blocked | hardened manifest blocked |")
    print("|---|---|---|---|---|---|")
    for th in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        blk = [f for f in findings if ORDER.index(f["severity_norm"]) >= ORDER.index(th)]
        tp = [k for k, p in PLANTED.items() if any(p(f) for f in blk)]
        neg = [k for k, p in NEGATIVE.items() if any(p(f) for f in blk)]
        hard = sum(f["location"]["file"] == HARDENED for f in blk)
        print(f"| {th} | {len(blk)} | {issues(blk)} | {len(tp)}/{len(PLANTED)} | {len(neg)}/{len(NEGATIVE)} | {hard} |")
    print("\nplanted, max severity of the findings that detect it:")
    for k, p in PLANTED.items():
        hits = [f for f in findings if p(f)]
        sev = max((f["severity_norm"] for f in hits), key=ORDER.index) if hits else "not detected"
        print(f"  {k:28} {sev:13} {len(hits)} finding(s)")


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("findings-main-1bb3381.json")
    findings = json.loads(path.read_text(encoding="utf-8"))
    table(findings, "BEFORE (main at 1bb3381)")
    table(tuned(findings), "AFTER (this PR's severity changes)")


if __name__ == "__main__":
    main()
