#!/usr/bin/env python3
"""Print the vulnerability count per severity from a `trivy image --format json` report.

  python3 scripts/image_scan_summary.py artifacts/scans/trivy-image-hardened.json vulnshop-api:hardened
"""
import json
import sys
from collections import Counter


def summarise(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    counts = Counter(v.get("Severity", "UNKNOWN") for r in doc.get("Results") or []
                     for v in r.get("Vulnerabilities") or [])
    return dict(sorted(counts.items()))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    print(sys.argv[2] if len(sys.argv) > 2 else sys.argv[1], summarise(sys.argv[1]))
