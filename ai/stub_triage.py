#!/usr/bin/env python3
import json
import sys
from datetime import datetime

# stub_triage.py
# This is a stub for the AI Triage subsystem to unblock R1 and R5.
# It reads findings from stdin (or a file) and outputs fake triaged JSON.

def main():
    try:
        # Check if we are running in an interactive terminal to prevent hanging
        if sys.stdin.isatty():
            input_data = ""
        else:
            input_data = sys.stdin.read()
            
        if not input_data.strip():
            # If no input, just use an empty array for the stub.
            findings = []
        else:
            try:
                findings = json.loads(input_data)
            except json.JSONDecodeError:  # also accept JSON Lines (one finding per line)
                findings = [json.loads(ln) for ln in input_data.splitlines() if ln.strip()]
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)

    # Return a mocked unified schema output
    mocked_output = {
        "finding_id": "sha256:example12345",
        "tool": "semgrep",
        "severity_norm": "HIGH",
        "cwe": ["CWE-89"],
        "cve": [],
        "location": {"file": "apps/vulnshop-api/routes/search.py", "line": 42},
        "package": {"name": None, "version": None, "fixed_version": None},
        "evidence": {
            "snippet_redacted": "<REDACTED:CODE>",
            "raw_ref": "artifacts/semgrep.sarif#/runs/0/results/17"
        },
        "enrichment": {"epss": 0.0421, "kev": False, "reachable": True},
        "baseline": {"is_new": True, "first_seen_commit": "a1b2c3d"},
        "dedupe": {"cluster_id": "C-014", "cluster_size": 1},
        "triage": {
            "verdict": "TRUE_POSITIVE",
            "priority": "P1",
            "confidence": 0.95,
            "fix_summary": "Use parameterized queries instead of f-strings for SQL.",
            "model": "stub-model",
            "prompt_version": "triage/stub",
            "grounding": {"validated": True, "rejected_claims": []}
        }
    }

    # One fake triaged finding per input finding (keeps the caller's id/tool/location), or one default if none given.
    def fake_for(f):
        out = json.loads(json.dumps(mocked_output))
        if isinstance(f, dict):
            out["finding_id"] = f.get("finding_id", out["finding_id"])
            out["tool"] = f.get("tool", out["tool"])
            out["location"] = f.get("location") or out["location"]
            out["cwe"] = f.get("cwe", out["cwe"])
        return out
    if isinstance(findings, dict):
        findings = [findings]
    results = [fake_for(f) for f in findings] or [mocked_output]
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()

