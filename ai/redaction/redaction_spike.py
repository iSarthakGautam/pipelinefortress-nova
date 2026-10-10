import re
import json

# redaction/layer1_structural.py and layer2_pattern.py combined for the spike
# L1: Structural - allowlist fields (code -> shape, summary only)
# L2: Pattern - gitleaks-style regex rules + entropy

def apply_l1_structural_redaction(raw_finding: dict) -> dict:
    """
    L1 Redaction: Structural Allowlisting
    We ONLY pass specific fields to the LLM. 
    Drops local file paths, CI run IDs, user names, and extraneous metadata.
    """
    safe_finding = {
        "finding_id": raw_finding.get("finding_id", "UNKNOWN"),
        "tool": raw_finding.get("tool", "UNKNOWN"),
        "severity": raw_finding.get("severity_norm", "INFO"),
        "rule_id": raw_finding.get("rule_id", ""),
        "cwe": raw_finding.get("cwe", []),
        # Extract just the filename, not the full CI path
        "file_name": raw_finding.get("location", {}).get("file", "").split("/")[-1],
        "line": raw_finding.get("location", {}).get("line", 0),
        "snippet": raw_finding.get("evidence", {}).get("snippet_raw", "")
    }
    return safe_finding

# Basic set of patterns for L2 spike
SECRET_PATTERNS = [
    (re.compile(r'(?i)(?:api_key|apikey|secret|token|password)[\s:=]+[\'"]([a-zA-Z0-9_\-\.]{16,})[\'"]'), "<REDACTED:SECRET_TOKEN>"),
    (re.compile(r'(?i)AKIA[0-9A-Z]{16}'), "<REDACTED:AWS_ACCESS_KEY>")
]

def apply_l2_pattern_redaction(text: str) -> str:
    """
    L2 Redaction: Pattern Matching
    Uses regex to strip recognizable secrets from code snippets before LLM ingestion.
    """
    if not text:
        return text
    
    redacted_text = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted_text = pattern.sub(replacement, redacted_text)
        
    return redacted_text

def redact_finding(raw_finding: dict) -> dict:
    """
    Applies L1 and L2 redaction sequentially.
    """
    # 1. Structural Allowlist
    l1_safe = apply_l1_structural_redaction(raw_finding)
    
    # 2. Pattern Redaction on the code snippet
    if l1_safe.get("snippet"):
        l1_safe["snippet"] = apply_l2_pattern_redaction(l1_safe["snippet"])
        
    return l1_safe

if __name__ == "__main__":
    # Test the redaction spike
    sample_finding = {
        "finding_id": "sha256:1234",
        "tool": "semgrep",
        "severity_norm": "HIGH",
        "user": "gautamsmac", # Should be dropped by L1
        "ci_job": "build-192", # Should be dropped by L1
        "location": {"file": "/Users/runner/work/repo/apps/api/auth.py", "line": 42},
        "evidence": {
            "snippet_raw": "def login():\n    api_key = 'AKIAIOSFODNN7EXAMPLE'\n    db.connect(api_key)"
        }
    }
    
    print("Raw Finding:")
    print(json.dumps(sample_finding, indent=2))
    
    print("\nRedacted Finding (L1 + L2):")
    print(json.dumps(redact_finding(sample_finding), indent=2))
