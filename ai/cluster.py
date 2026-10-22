import json
import posixpath

# cluster.py
# Deterministic rule-based clustering to deduplicate findings before inference (one LLM call per cluster).
# Key: tool :: rule_id :: normalised full path. The full path (not the basename) keeps
# apps/a/index.js and apps/b/index.js apart.
# Honours an incoming dedupe.cluster_id from R2's normalizer; otherwise computes its own key.
# Rule-based only. Embedding clustering (mxbai-embed-large) is NOT implemented; see docs/R4_AUDIT_2026-10-21.md.


def normalise_path(path: str) -> str:
    if not path or not isinstance(path, str):
        return "unknown_file"
    path = path.replace("\\", "/")
    return posixpath.normpath(path).lstrip("./") or "unknown_file"


# TODO(R2): R2 owns dedupe keys. Once the normalizer always sets dedupe.cluster_id, the fallback key below is only a safety net.
def generate_cluster_key(finding: dict) -> str:
    # R2 owns dedupe keys (PLAN §5): if the normalizer already assigned a cluster id, honour it.
    dedupe = finding.get("dedupe") if isinstance(finding.get("dedupe"), dict) else {}
    existing = dedupe.get("cluster_id")
    if existing:
        return str(existing)
    tool = finding.get("tool") or "unknown"
    rule_id = finding.get("rule_id") or finding.get("rule") or "unknown_rule"
    loc = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    return f"{tool}::{rule_id}::{normalise_path(loc.get('file'))}"


def cluster_findings(raw_findings: list) -> dict:
    """Maps cluster_id -> list of member findings (insertion-ordered, so output is deterministic)."""
    clusters = {}
    for finding in raw_findings:
        if not isinstance(finding, dict):
            finding = {}
        clusters.setdefault(generate_cluster_key(finding), []).append(finding)
    return clusters


if __name__ == "__main__":
    sample = [
        {"finding_id": "1", "tool": "semgrep", "rule_id": "sql-injection", "location": {"file": "api/db.py", "line": 10}},
        {"finding_id": "2", "tool": "semgrep", "rule_id": "sql-injection", "location": {"file": "api/db.py", "line": 42}},
        {"finding_id": "3", "tool": "semgrep", "rule_id": "sql-injection", "location": {"file": "other/db.py", "line": 42}},
        {"finding_id": "4", "tool": "gitleaks", "rule_id": "aws-key", "location": {"file": "api/db.py", "line": 5}},
    ]
    clustered = cluster_findings(sample)
    print(f"Reduced {len(sample)} raw findings to {len(clustered)} clusters.")
    print(json.dumps({k: [f["finding_id"] for f in v] for k, v in clustered.items()}, indent=2))
