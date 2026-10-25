#!/usr/bin/env python3
"""Baseline diffing + exception annotations + the security gate. Owner: R2.

The gate fails only on findings that are NEW relative to security-baseline.json,
not on accepted existing debt (plan §4.2).

  # Accept current findings as the baseline (reviewed via PR, like any code change)
  python scanners/baseline/baseline.py create \
      --findings artifacts/findings.json --commit $SHA \
      --baseline scanners/baseline/security-baseline.json

  # Mark new vs known, attach exceptions, decide pass/fail
  python scanners/baseline/baseline.py check \
      --findings artifacts/findings.json --baseline scanners/baseline/security-baseline.json \
      --repo . --commit $SHA -o artifacts/findings.diffed.json --report artifacts/gate-report.json

Exit codes for `check`: 0 pass, 1 gate failed, 2 usage/input error.

Matching. finding_id hashes the line number, so matching on it alone would turn every
finding below an inserted line into a "new" one. Findings are instead grouped by a
line-independent match_key (tool|rule_id|file|package). Within a group, exact finding_id
matches are known first; remaining baseline slots then absorb moved findings in
line order; whatever is left over is new.

Exception annotation: a comment on the finding's line or the line above it, of the form
  security-exception: <rule_id|finding_id> expires:YYYY-MM-DD owner:<name>
behind a comment leader (#, //, --, ;, /*, <!--) that starts the line or follows whitespace,
so the syntax quoted in strings or docs is not mistaken for an annotation.
For line-0 findings (dependency manifests) the annotation may sit anywhere in that file.
Expired, malformed, or over-long exceptions fail the gate.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

BASELINE_SCHEMA_VERSION = "1.0.0"
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SKIP_DIRS = {".git", "node_modules", "artifacts", ".venv", "venv", "__pycache__", "dist", "build"}
MAX_SCAN_BYTES = 1_000_000

ANNOTATION_MARKER = "security-exception:"
# Comment leader at line start or after whitespace, then the marker. Excludes quoted text
# such as "# security-exception: ..." inside a string literal.
COMMENT_LEADER_RE = re.compile(r"(?:^|\s)(?:#|//|--|;|/\*|<!--)\s*security-exception:")
ANNOTATION_RE = re.compile(
    r"security-exception:\s*(?P<id>\S+)\s+expires:(?P<expires>\S+)\s+owner:(?P<owner>\S+)")


# --------------------------------------------------------------------------- matching

def match_key(f: dict) -> str:
    pkg = (f.get("package") or {}).get("name") or ""
    key = f"{f['tool']}|{f['rule_id']}|{f['location']['file']}|{pkg}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def load_baseline(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": BASELINE_SCHEMA_VERSION, "created_commit": None, "entries": []}
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError(f"unsupported baseline schema_version {doc.get('schema_version')!r}")
    return doc


def build_baseline(findings: list, commit: str, previous: dict = None) -> dict:
    """Snapshot current findings. first_seen_commit survives for findings already in `previous`,
    matched the same way as apply_baseline: exact finding_id first, then moved lines by match_key."""
    prev = (previous or {}).get("entries", [])
    prev_first_seen = {e["finding_id"]: e.get("first_seen_commit") for e in prev}
    current_ids = {f["finding_id"] for f in findings}
    moved = defaultdict(list)
    for e in sorted(prev, key=lambda e: e["line"]):
        if e["finding_id"] not in current_ids:
            moved[e["match_key"]].append(e.get("first_seen_commit"))
    entries = []
    for f in sorted(findings, key=lambda f: f["location"]["line"]):
        first_seen = prev_first_seen.get(f["finding_id"])
        if first_seen is None and moved[match_key(f)]:
            first_seen = moved[match_key(f)].pop(0)
        entries.append({
            "finding_id": f["finding_id"],
            "match_key": match_key(f),
            "tool": f["tool"],
            "rule_id": f["rule_id"],
            "file": f["location"]["file"],
            "line": f["location"]["line"],
            "package": (f.get("package") or {}).get("name"),
            "severity_norm": f["severity_norm"],
            "first_seen_commit": first_seen or commit,
        })
    entries.sort(key=lambda e: (e["file"], e["line"], e["tool"], e["rule_id"], e["finding_id"]))
    return {"schema_version": BASELINE_SCHEMA_VERSION, "created_commit": commit, "entries": entries}


def apply_baseline(findings: list, baseline: dict, commit: str = None) -> dict:
    """Set finding['baseline'] on every finding. Returns stats for the report."""
    by_key_base = defaultdict(list)
    for e in baseline.get("entries", []):
        by_key_base[e["match_key"]].append(e)
    by_key_cur = defaultdict(list)
    for f in findings:
        by_key_cur[match_key(f)].append(f)

    matched_entry_ids = set()
    for key, cur in by_key_cur.items():
        base = by_key_base.get(key, [])
        base_by_id = {e["finding_id"]: e for e in base}
        unclaimed = list(base)
        leftovers = []
        # Pass 1: exact finding_id matches (same line)
        for f in sorted(cur, key=lambda x: x["location"]["line"]):
            e = base_by_id.get(f["finding_id"])
            if e is not None and e in unclaimed:
                unclaimed.remove(e)
                _mark(f, False, e.get("first_seen_commit"))
                matched_entry_ids.add(e["finding_id"])
            else:
                leftovers.append(f)
        # Pass 2: moved findings take the remaining slots, both sides in line order
        unclaimed.sort(key=lambda e: e.get("line", 0))
        for f in leftovers:
            if unclaimed:
                e = unclaimed.pop(0)
                _mark(f, False, e.get("first_seen_commit"))
                matched_entry_ids.add(e["finding_id"])
            else:
                _mark(f, True, commit)

    fixed = [e for e in baseline.get("entries", []) if e["finding_id"] not in matched_entry_ids]
    return {
        "known": sum(1 for f in findings if not f["baseline"]["is_new"]),
        "new": sum(1 for f in findings if f["baseline"]["is_new"]),
        "fixed_since_baseline": len(fixed),
    }


def _mark(f: dict, is_new: bool, first_seen):
    prior_exc = (f.get("baseline") or {}).get("exception")
    f["baseline"] = {"is_new": is_new, "first_seen_commit": first_seen}
    if prior_exc is not None:
        f["baseline"]["exception"] = prior_exc


# --------------------------------------------------------------------------- exceptions

def _list_files(repo: Path) -> list:
    try:
        out = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"],
                             capture_output=True, check=True)
        names = [n for n in out.stdout.decode("utf-8", "replace").split("\0") if n]
        if names:
            return names
    except (OSError, subprocess.CalledProcessError):
        pass
    names = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            names.append(Path(root, name).relative_to(repo).as_posix())
    return names


def scan_annotations(repo: Path, today: dt.date, max_days: int) -> list:
    """Find every security-exception annotation in the repo and classify it."""
    found = []
    for rel in _list_files(repo):
        path = repo / rel
        try:
            if path.stat().st_size > MAX_SCAN_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if ANNOTATION_MARKER not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if ANNOTATION_MARKER not in line or not COMMENT_LEADER_RE.search(line):
                continue
            ann = {"file": rel, "line": lineno, "raw": line.strip()}
            m = ANNOTATION_RE.search(line)
            if not m:
                ann.update(status="malformed", problem="expected '<id> expires:YYYY-MM-DD owner:<name>'")
                found.append(ann)
                continue
            ann.update(id=m["id"], owner=m["owner"], expires=m["expires"])
            try:
                expires = dt.date.fromisoformat(m["expires"])
            except ValueError:
                ann.update(status="malformed", problem=f"invalid date {m['expires']!r}")
                found.append(ann)
                continue
            if expires < today:
                ann["status"] = "expired"
            elif (expires - today).days > max_days:
                ann.update(status="too_long", problem=f"expires more than {max_days} days out")
            else:
                ann["status"] = "valid"
            found.append(ann)
    return found


def attach_exceptions(findings: list, annotations: list) -> None:
    """Attach the matching annotation to each finding and mark annotations as used."""
    by_file = defaultdict(list)
    for a in annotations:
        if "id" in a:
            by_file[a["file"]].append(a)
    for f in findings:
        file, line = f["location"]["file"], f["location"]["line"]
        for a in by_file.get(file, []):
            if a["id"] not in (f["rule_id"], f["finding_id"]):
                continue
            if line == 0 or a["line"] in (line, line - 1):
                f["baseline"]["exception"] = {"id": a["id"], "expires": a["expires"], "owner": a["owner"]}
                f["_exception_status"] = a["status"]
                a.setdefault("applies_to", []).append(f["finding_id"])
                break


# --------------------------------------------------------------------------- gate

def evaluate_gate(findings: list, annotations: list, fail_on: str, stats: dict) -> dict:
    threshold = SEVERITY_ORDER.index(fail_on)
    blocking, excepted = [], []
    for f in findings:
        if not f["baseline"]["is_new"]:
            continue
        if SEVERITY_ORDER.index(f["severity_norm"]) < threshold:
            continue
        if f.get("_exception_status") == "valid":
            excepted.append(f["finding_id"])
        else:
            blocking.append(f)

    bad_annotations = [a for a in annotations if a["status"] in ("expired", "malformed", "too_long")]
    stale = [a for a in annotations if a["status"] == "valid" and not a.get("applies_to")]

    report = {
        "result": "fail" if (blocking or bad_annotations) else "pass",
        "fail_on": fail_on,
        "counts": {
            "total": len(findings),
            "known": stats["known"],
            "new": stats["new"],
            "fixed_since_baseline": stats["fixed_since_baseline"],
            "blocking": len(blocking),
            "excepted": len(excepted),
            "exceptions_total": len(annotations),
            "exceptions_expired": sum(a["status"] == "expired" for a in annotations),
            "exceptions_invalid": sum(a["status"] in ("malformed", "too_long") for a in annotations),
            "exceptions_stale": len(stale),
        },
        "blocking": [{
            "finding_id": f["finding_id"], "tool": f["tool"], "rule_id": f["rule_id"],
            "severity_norm": f["severity_norm"],
            "location": f"{f['location']['file']}:{f['location']['line']}",
            "exception_status": f.get("_exception_status"),
        } for f in blocking],
        "bad_exceptions": bad_annotations,
        "stale_exceptions": stale,
    }
    return report


def format_summary(report: dict) -> str:
    c = report["counts"]
    lines = [
        f"security gate: {report['result'].upper()} (fail on new >= {report['fail_on']})",
        f"  findings {c['total']} | known {c['known']} | new {c['new']} | "
        f"fixed since baseline {c['fixed_since_baseline']}",
        f"  blocking {c['blocking']} | excepted {c['excepted']} | exceptions expired "
        f"{c['exceptions_expired']}, invalid {c['exceptions_invalid']}, stale {c['exceptions_stale']}",
    ]
    for b in report["blocking"]:
        why = f" (exception {b['exception_status']})" if b["exception_status"] else ""
        lines.append(f"  BLOCK {b['severity_norm']:<8} {b['tool']}:{b['rule_id']} at {b['location']}{why}")
    for a in report["bad_exceptions"]:
        lines.append(f"  EXCEPTION {a['status'].upper()} {a['file']}:{a['line']} {a.get('problem', '')}".rstrip())
    for a in report["stale_exceptions"]:
        lines.append(f"  warning: exception {a['id']} at {a['file']}:{a['line']} matches no finding")
    return "\n".join(lines)


# --------------------------------------------------------------------------- CLI

def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cmd_create(args) -> int:
    findings = json.loads(args.findings.read_text(encoding="utf-8"))
    previous = load_baseline(args.baseline) if args.baseline.exists() else None
    baseline = build_baseline(findings, args.commit, previous)
    _write_json(args.baseline, baseline)
    print(f"baseline: {len(baseline['entries'])} accepted findings -> {args.baseline}")
    return 0


def cmd_check(args) -> int:
    findings = json.loads(args.findings.read_text(encoding="utf-8"))
    baseline = load_baseline(args.baseline)
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()

    stats = apply_baseline(findings, baseline, args.commit)
    annotations = scan_annotations(args.repo, today, args.max_exception_days)
    attach_exceptions(findings, annotations)
    report = evaluate_gate(findings, annotations, args.fail_on, stats)

    for f in findings:
        f.pop("_exception_status", None)
    if args.output:
        _write_json(args.output, findings)
    if args.report:
        _write_json(args.report, report)
    print(format_summary(report))
    if report["result"] == "fail" and not args.warn_only:
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="accept current findings as the baseline")
    c.add_argument("--findings", type=Path, required=True)
    c.add_argument("--baseline", type=Path, required=True)
    c.add_argument("--commit", required=True)
    c.set_defaults(func=cmd_create)

    k = sub.add_parser("check", help="diff against the baseline and run the gate")
    k.add_argument("--findings", type=Path, required=True)
    k.add_argument("--baseline", type=Path, required=True)
    k.add_argument("--repo", type=Path, default=Path("."))
    k.add_argument("--commit", default=None)
    k.add_argument("-o", "--output", type=Path, help="findings with baseline block filled in")
    k.add_argument("--report", type=Path, help="gate report JSON (for metrics)")
    k.add_argument("--fail-on", default="HIGH", choices=SEVERITY_ORDER)
    k.add_argument("--max-exception-days", type=int, default=90)
    k.add_argument("--today", help="override today's date (YYYY-MM-DD), for tests and replays")
    k.add_argument("--warn-only", action="store_true", help="report but always exit 0 (rollout mode)")
    k.set_defaults(func=cmd_check)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
