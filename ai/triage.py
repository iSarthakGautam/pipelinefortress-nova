import os
import sys
import json
import re

# Ensure ai directory is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from cluster import cluster_findings
from enrich import enrich_finding
from validate import validate_triage_output
from redaction.redactor import redact_finding, egress_guard_check, CANARY_TOKEN
from llm_client import query_model, OLLAMA_BASE_URL, DEFAULT_MODEL

# triage.py
# The main orchestrator for the AI Triage subsystem (Week 2 deliverables).
# Pipeline: Raw Findings -> Cluster -> Redact -> Enrich -> LLM Triage -> Output

def load_prompt():
    prompt_path = os.path.join(SCRIPT_DIR, "prompts", "triage_v1.txt")
    try:
        with open(prompt_path, "r") as f:
            return f.read()
    except Exception as e:
        return "You output JSON. Triage the following finding."

def process_clusters(clusters: dict):
    system_prompt = load_prompt()
    triaged_results = []
    
    # Check Egress Guard before touching the LLM
    if not egress_guard_check(OLLAMA_BASE_URL):
        print("ABORT: LLM URL violates egress policy.")
        sys.exit(1)

    for cluster_id, findings in clusters.items():
        # We only need to send the representative (first) finding to the LLM
        rep = findings[0]
        
        # 1. Redact
        safe_rep = redact_finding(rep)
        
        # 2. Enrich
        enriched_rep = enrich_finding(safe_rep)
        
        # Injection Defense: Check untrusted snippet before prompt construction
        snippet_content = safe_rep.get("snippet", "")
        inj_patterns = [r'(?i)ignore\s+(?:all\s+)?previous\s+instructions', r'(?i)mark.*false\s+positive', r'(?i)approve\s+the\s+pr']
        if any(re.search(pat, snippet_content) for pat in inj_patterns):
            llm_output = {
                "verdict": "NEEDS_HUMAN_REVIEW",
                "priority": "P1",
                "confidence": 1.0,
                "fix_summary": "SECURITY ALERT: Adversarial prompt injection detected in code snippet. Direct human triage mandated.",
                "grounding": {"validated": False, "rejected_claims": ["Adversarial prompt injection detected"]}
            }
        else:
            # 3. Query LLM with framed untrusted input
            user_prompt = json.dumps(enriched_rep)
            llm_output = query_model(system_prompt, user_prompt)
        
        # L4 Canary Check (Basic validation)
        if llm_output and isinstance(llm_output, dict):
            raw_response_str = json.dumps(llm_output)
            if CANARY_TOKEN in raw_response_str:
                print(f"CRITICAL: Canary token {CANARY_TOKEN} leaked in LLM output!")
                llm_output["verdict"] = "NEEDS_HUMAN_REVIEW"
                llm_output["fix_summary"] = "BLOCKED: Canary token leaked in output."
        
        # Build final unified output matching schema contract
        final_output = rep.copy()
        final_output["dedupe"] = {"cluster_id": cluster_id, "cluster_size": len(findings)}
        final_output["enrichment"] = enriched_rep.get("enrichment", {})
        
        # Ensure evidence has snippet_redacted
        if "evidence" not in final_output:
            final_output["evidence"] = {}
        final_output["evidence"]["snippet_redacted"] = safe_rep.get("snippet", "<REDACTED:CODE>")
        
        triage_dict = llm_output.get("triage", llm_output) if isinstance(llm_output, dict) else {}
        final_output["triage"] = {
            "verdict": triage_dict.get("verdict", "NEEDS_HUMAN_REVIEW"),
            "priority": triage_dict.get("priority", "UNASSIGNED"),
            "confidence": float(triage_dict.get("confidence", 0.0)),
            "fix_summary": triage_dict.get("fix_summary", "Awaiting human review."),
            "model": triage_dict.get("model", DEFAULT_MODEL),
            "prompt_version": triage_dict.get("prompt_version", "triage/v1"),
            "grounding": triage_dict.get("grounding", {"validated": True, "rejected_claims": []})
        }
        
        # Stage 4: Grounding Validator (Architecture gate against hallucinations)
        final_output = validate_triage_output(final_output)
        
        triaged_results.append(final_output)
        
    return triaged_results

def main():
    try:
        if sys.stdin.isatty():
            print("Usage: cat findings.json | python3 ai/triage.py")
            sys.exit(0)
            
        input_data = sys.stdin.read()
        if not input_data.strip():
            print(json.dumps([]))
            return
            
        raw_findings = json.loads(input_data)
        if isinstance(raw_findings, dict):
            raw_findings = [raw_findings]
            
        # 1. Cluster
        clusters = cluster_findings(raw_findings)
        
        # 2. Process & Triage
        results = process_clusters(clusters)
        
        # 3. Output
        print(json.dumps(results, indent=2))
        
    except Exception as e:
        print(f"Triage Pipeline Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

