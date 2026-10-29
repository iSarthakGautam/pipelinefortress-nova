#!/usr/bin/env python3
"""Baseline diffing + exception annotations + the security gate. Owner: R2.

The gate fails only on findings that are NEW relative to security-baseline.json,
not on accepted existing debt (plan §4.2).

  # Accept current findings as the baseline (reviewed via PR, like any code change)
  python scanners/baseline/baseline.py create \
      --findings artifacts/findings.json --commit $SHA --repo . \
      --baseline scanners/baseline/security-baseline.json

  # Mark new vs known, attach exceptions, decide pass/fail
  python scanners/baseline/baseline.py check \
      --findings artifacts/findings.json --baseline scanners/baseline/security-baseline.json \
      --repo . --commit $SHA -o artifacts/findings.diffed.json --report artifacts/gate-report.json

Exit codes for `check`: 0 pass, 1 gate failed, 2 usage/input error or any crash. CI treats
only 1 as a security verdict, so a bug here must never exit 1.

Matching. finding_id hashes the line number, so matching on it alone would turn every
finding below an inserted line into a "new" one. Findings are instead grouped by a
line-independent match_key (tool|rule_id|file|package). Within a group, exact finding_id
matches are known first. A remaining baseline slot then absorbs a moved finding only if the
flagged source line has the same text (line_sha, whitespace ignored), so fixing one known
finding does not hide a new one elsewhere in the file. Whatever is left over is new.

Severity. A known finding still blocks if its severity has risen from below --fail-on (as
accepted in the baseline) to at or above it: the debt accepted was not this severe.

Exception annotation: a comment on the finding's line or the line above it, of the form
  security-exception: <rule_id|finding_id> expires:YYYY-MM-DD owner:<name>
behind a comment leader (#, //, --, ;, /*, <!--) that starts the line or follows whitespace,
so the syntax quoted in strings or docs is not mistaken for an annotation.
For line-0 findings (dependency manifests) the annotation may sit anywhere in that file.
Expired, malformed, or over-long exceptions fail the gate. One that expires within
--warn-expiring-days is reported as a warning first, so its expiry does not surprise every
open PR on the same day.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import traceback
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
ISO_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def iso_date(text: str) -> dt.date:
    """YYYY-MM-DD only. date.fromisoformat alone also takes 20261130 and 2026-W48-1 (3.11+)."""
    if not ISO_DATE_RE.fullmatch(text):
        raise ValueError(f"not YYYY-MM-DD: {text!r}")
    return dt.date.fromisoformat(text)


# --------------------------------------------------------------------------- matching

def match_key(f: dict) -> str:
    pkg = (f.get("package") or {}).get("name") or ""
    key = f"{f['tool']}|{f['rule_id']}|{f['location']['file']}|{pkg}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def line_sha(repo: Path, file: str, line: int, cache: dict):
    """Fingerprint of the flagged source line, whitespace ignored, so it survives moves and
    re-indents. None when there is no line to read (line 0, missing file, empty line)."""
    if repo is None or not file or line < 1:
        return None
    if file not in cache:
        try:
            cache[file] = (Path(repo) / file).read_text(encoding="utf-8", errors="replace").split("\n")
        except OSError:
            cache[file] = []
    lines = cache[file]
    text = "".join(lines[line - 1].split()) if line <= len(lines) else ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16] if text else None


def _same_code(entry: dict, sha) -> bool:
    """May a moved finding with fingerprint `sha` take this baseline slot? Entries written
    before line_sha existed fall back to matching by group only."""
    return "line_sha" not in entry or (sha is not None and entry["line_sha"] == sha)


def load_baseline(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": BASELINE_SCHEMA_VERSION, "created_commit": None, "entries": []}
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError(f"unsupported baseline schema_version {doc.get('schema_version')!r}")
    return doc


def build_baseline(findings: list, commit: str, previous: dict = None, repo: Path = None) -> dict:
    """Snapshot current findings. first_seen_commit survives for findings already in `previous`,
    matched the same way as apply_baseline: exact finding_id first, then moved lines by match_key.
    With `repo`, each entry records the line_sha of its flagged line."""
    prev = (previous or {}).get("entries", [])
    prev_first_seen = {e["finding_id"]: e.get("first_seen_commit") for e in prev}
    current_ids = {f["finding_id"] for f in findings}
    moved = defaultdict(list)
    for e in sorted(prev, key=lambda e: e["line"]):
        if e["finding_id"] not in current_ids:
            moved[e["match_key"]].append(e)
    cache = {}
    entries = []
    for f in sorted(findings, key=lambda f: f["location"]["line"]):
        sha = line_sha(repo, f["location"]["file"], f["location"]["line"], cache)
        first_seen = prev_first_seen.get(f["finding_id"])
        if first_seen is None:
            slot = next((e for e in moved[match_key(f)] if _same_code(e, sha)), None)
            if slot is not None:
                moved[match_key(f)].remove(slot)
                first_seen = slot.get("first_seen_commit")
        entry = {
            "finding_id": f["finding_id"],
            "match_key": match_key(f),
            "tool": f["tool"],
            "rule_id": f["rule_id"],
            "file": f["location"]["file"],
            "line": f["location"]["line"],
            "package": (f.get("package") or {}).get("name"),
            "severity_norm": f["severity_norm"],
            "first_seen_commit": first_seen or commit,
        }
        if repo is not None:
            entry["line_sha"] = sha
        entries.append(entry)
    entries.sort(key=lambda e: (e["file"], e["line"], e["tool"], e["rule_id"], e["finding_id"]))
    return {"schema_version": BASELINE_SCHEMA_VERSION, "created_commit": commit, "entries": entries}


def apply_baseline(findings: list, baseline: dict, commit: str = None, repo: Path = None) -> dict:
    """Set finding['baseline'] on every finding. Returns stats for the report. `repo` is needed
    to match moved findings by line_sha; without it, baseline entries that carry a line_sha
    never absorb a moved finding."""
    cache = {}
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
                _mark(f, False, e.get("first_seen_commit"), e.get("severity_norm"))
                matched_entry_ids.add(e["finding_id"])
            else:
                leftovers.append(f)
        # Pass 2: a moved finding takes the first remaining slot (line order) whose flagged
        # line has the same text. A finding on a different line of code is new.
        unclaimed.sort(key=lambda e: e.get("line", 0))
        for f in leftovers:
            sha = line_sha(repo, f["location"]["file"], f["location"]["line"], cache)
            e = next((e for e in unclaimed if _same_code(e, sha)), None)
            if e is not None:
                unclaimed.remove(e)
                _mark(f, False, e.get("first_seen_commit"), e.get("severity_norm"))
                matched_entry_ids.add(e["finding_id"])
            else:
                _mark(f, True, commit)

    fixed = [e for e in baseline.get("entries", []) if e["finding_id"] not in matched_entry_ids]
    return {
        "known": sum(1 for f in findings if not f["baseline"]["is_new"]),
        "new": sum(1 for f in findings if f["baseline"]["is_new"]),
        "fixed_since_baseline": len(fixed),
    }


def _mark(f: dict, is_new: bool, first_seen, accepted_severity=None):
    prior_exc = (f.get("baseline") or {}).get("exception")
    f["baseline"] = {"is_new": is_new, "first_seen_commit": first_seen}
    if accepted_severity is not None:
        f["_accepted_severity"] = accepted_severity   # internal; removed before output
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
        # Known limitation: scanners disagree on what ends a line. splitlines() matches checkov
        # (Dockerfiles) and YAML parsers, which also break on form feeds, \x85 and \u2028; Python's
        # ast and semgrep don't. In a file containing those characters an exception below them can
        # sit one line off its finding. No tracked file contains them.
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
                expires = iso_date(m["expires"])
            except ValueError:
                ann.update(status="malformed", problem=f"invalid date {m['expires']!r}")
                found.append(ann)
                continue
            ann["days_left"] = (expires - today).days
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

def evaluate_gate(findings: list, annotations: list, fail_on: str, stats: dict,
                  warn_days: int = 14) -> dict:
    threshold = SEVERITY_ORDER.index(fail_on)
    blocking, excepted = [], []
    for f in findings:
        if SEVERITY_ORDER.index(f["severity_norm"]) < threshold:
            continue
        if not f["baseline"]["is_new"]:
            accepted = f.get("_accepted_severity")
            if accepted not in SEVERITY_ORDER or SEVERITY_ORDER.index(accepted) >= threshold:
                continue
            f["_raised_from"] = accepted
        if f.get("_exception_status") == "valid":
            excepted.append(f["finding_id"])
        else:
            blocking.append(f)

    bad_annotations = [a for a in annotations if a["status"] in ("expired", "malformed", "too_long")]
    stale = [a for a in annotations if a["status"] == "valid" and not a.get("applies_to")]
    expiring = [a for a in annotations if a["status"] == "valid" and a["days_left"] <= warn_days]

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
            "exceptions_expiring": len(expiring),
            "raised": sum(1 for f in blocking if "_raised_from" in f),
        },
        "blocking": [{
            "finding_id": f["finding_id"], "tool": f["tool"], "rule_id": f["rule_id"],
            "severity_norm": f["severity_norm"],
            "location": f"{f['location']['file']}:{f['location']['line']}",
            "exception_status": f.get("_exception_status"),
            "raised_from": f.get("_raised_from"),
        } for f in blocking],
        "bad_exceptions": bad_annotations,
        "stale_exceptions": stale,
        "expiring_exceptions": expiring,
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
        if b.get("raised_from"):
            why += f" (known, but accepted at {b['raised_from']})"
        lines.append(f"  BLOCK {b['severity_norm']:<8} {b['tool']}:{b['rule_id']} at {b['location']}{why}")
    for a in report["bad_exceptions"]:
        lines.append(f"  EXCEPTION {a['status'].upper()} {a['file']}:{a['line']} {a.get('problem', '')}".rstrip())
    for a in report["stale_exceptions"]:
        lines.append(f"  warning: exception {a['id']} at {a['file']}:{a['line']} matches no finding")
    for a in report.get("expiring_exceptions", []):
        lines.append(f"  warning: exception {a['id']} at {a['file']}:{a['line']} expires {a['expires']} "
                     f"(in {a['days_left']} days): fix the finding or renew it in a reviewed PR")
    return "\n".join(lines)


# --------------------------------------------------------------------------- CLI

def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # bytes, not text: write_text turns \n into \r\n on Windows and the next Linux rebaseline
    # would rewrite every line of security-baseline.json
    path.write_bytes((json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def cmd_create(args) -> int:
    findings = json.loads(args.findings.read_text(encoding="utf-8"))
    previous = load_baseline(args.baseline) if args.baseline.exists() else None
    baseline = build_baseline(findings, args.commit, previous, args.repo)
    _write_json(args.baseline, baseline)
    print(f"baseline: {len(baseline['entries'])} accepted findings -> {args.baseline}")
    return 0


def cmd_check(args) -> int:
    findings = json.loads(args.findings.read_text(encoding="utf-8"))
    baseline = load_baseline(args.baseline)
    today = iso_date(args.today) if args.today else dt.date.today()

    stats = apply_baseline(findings, baseline, args.commit, args.repo)
    annotations = scan_annotations(args.repo, today, args.max_exception_days)
    attach_exceptions(findings, annotations)
    report = evaluate_gate(findings, annotations, args.fail_on, stats, args.warn_expiring_days)

    for f in findings:
        for k in ("_exception_status", "_accepted_severity", "_raised_from"):
            f.pop(k, None)
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
    c.add_argument("--repo", type=Path, default=Path("."),
                   help="checkout the findings came from; line_sha is read from it")
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
    k.add_argument("--warn-expiring-days", type=int, default=14,
                   help="warn (without failing) about exceptions that expire within this many days")
    k.add_argument("--today", help="override today's date (YYYY-MM-DD), for tests and replays")
    k.add_argument("--warn-only", action="store_true", help="report but always exit 0 (rollout mode)")
    k.set_defaults(func=cmd_check)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception:
        # Uncaught, Python would exit 1, which CI reads as "new findings": report a crash instead
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
