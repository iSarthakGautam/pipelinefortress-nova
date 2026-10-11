import json

# cluster.py
# Implements deterministic rule-based clustering to deduplicate findings before inference.
# As noted in the rubric, collapsing near-identical findings cuts cost ~8x.

def generate_cluster_key(finding: dict) -> str:
    """
    Generate a deterministic key for clustering.
    We cluster by: Tool + Rule ID + File Name
    """
    tool = finding.get("tool", "unknown")
    rule_id = finding.get("rule_id", "unknown_rule")
    
    # We group by file, so if the same rule flags 10 times in one file, it's 1 cluster.
    file_path = finding.get("location", {}).get("file", "unknown_file")
    file_name = file_path.split("/")[-1]
    
    return f"{tool}::{rule_id}::{file_name}"

def cluster_findings(raw_findings: list) -> dict:
    """
    Takes a list of raw findings and groups them into clusters.
    Returns a dict mapping cluster_id to a list of findings.
    """
    clusters = {}
    for finding in raw_findings:
        key = generate_cluster_key(finding)
        if key not in clusters:
            clusters[key] = []
        clusters[key].append(finding)
        
    return clusters

if __name__ == "__main__":
    # Quick test
    sample_data = [
        {"finding_id": "1", "tool": "semgrep", "rule_id": "sql-injection", "location": {"file": "api/db.py", "line": 10}},
        {"finding_id": "2", "tool": "semgrep", "rule_id": "sql-injection", "location": {"file": "api/db.py", "line": 42}},
        {"finding_id": "3", "tool": "gitleaks", "rule_id": "aws-key", "location": {"file": "api/db.py", "line": 5}}
    ]
    
    clustered = cluster_findings(sample_data)
    print(f"Reduced {len(sample_data)} raw findings to {len(clustered)} clusters.")
    print(json.dumps(clustered, indent=2))

