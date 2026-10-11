import re
import json

# redaction/redactor.py
# Full L1-L4 Redaction Pipeline

# L4 Canary token used to detect prompt leaks
CANARY_TOKEN = "CANARY_4bf3a9_SECRET"

SECRET_PATTERNS = [
    (re.compile(r'(?i)(?:api_key|apikey|secret|token|password)[\s:=]+[\'"]([a-zA-Z0-9_\-\.]{16,})[\'"]'), "<REDACTED:SECRET_TOKEN>"),
    (re.compile(r'(?i)AKIA[0-9A-Z]{16}'), "<REDACTED:AWS_ACCESS_KEY>"),
    (re.compile(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----'), "<REDACTED:PRIVATE_KEY>"),
    (re.compile(r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b'), "<REDACTED:JWT_TOKEN>"),
    (re.compile(r'\bghp_[a-zA-Z0-9]{36}\b'), "<REDACTED:GITHUB_TOKEN>")
]

# L3 Semantic Mock (Presidio-lite for capstone scope)
SEMANTIC_PATTERNS = [
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "<REDACTED:EMAIL>"),
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), "<REDACTED:IP_ADDRESS>")
]

def apply_l1_structural(raw_finding: dict) -> dict:
    """L1: Structural Allowlisting"""
    return {
        "finding_id": raw_finding.get("finding_id", "UNKNOWN"),
        "tool": raw_finding.get("tool", "UNKNOWN"),
        "severity": raw_finding.get("severity_norm", "INFO"),
        "rule_id": raw_finding.get("rule_id", ""),
        "cwe": raw_finding.get("cwe", []),
        "cve": raw_finding.get("cve", []),
        "file_name": raw_finding.get("location", {}).get("file", "").split("/")[-1],
        "line": raw_finding.get("location", {}).get("line", 0),
        "snippet": raw_finding.get("evidence", {}).get("snippet_raw", "")
    }

def apply_l2_pattern(text: str) -> str:
    """L2: Regex Pattern Stripping"""
    if not text: return text
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

def apply_l3_semantic(text: str) -> str:
    """L3: Semantic Entity Stripping (Emails, IPs)"""
    if not text: return text
    for pattern, replacement in SEMANTIC_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

def apply_l4_canary(finding: dict) -> dict:
    """L4: Inject Canary Token"""
    finding["_canary"] = CANARY_TOKEN
    return finding

def redact_finding(raw_finding: dict) -> dict:
    """Runs L1-L4 sequentially."""
    finding = apply_l1_structural(raw_finding)
    
    if finding.get("snippet"):
        text = finding["snippet"]
        text = apply_l2_pattern(text)
        text = apply_l3_semantic(text)
        finding["snippet"] = text
        
    return apply_l4_canary(finding)

def egress_guard_check(url: str) -> bool:
    """
    Simulated-cloud mode egress guard.
    Denies any request not targeting localhost or specific allowlisted IPs.
    """
    allowlist = ["http://localhost", "http://127.0.0.1"]
    for allowed in allowlist:
        if url.startswith(allowed):
            return True
    print(f"EGRESS BLOCKED: Attempted to reach {url}")
    return False

if __name__ == "__main__":
    sample = {
        "finding_id": "1",
        "evidence": {
            "snippet_raw": "Contact dev@company.com at 192.168.1.5 if api_key='AKIAIOSFODNN7EXAMPLE' fails."
        }
    }
    print("Redacted:\n", json.dumps(redact_finding(sample), indent=2))

