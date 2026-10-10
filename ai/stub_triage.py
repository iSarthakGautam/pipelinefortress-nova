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
            findings = json.loads(input_data)
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

    # If we received an array of findings, mock a response array.
    results = [mocked_output] if isinstance(findings, list) else mocked_output
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()

