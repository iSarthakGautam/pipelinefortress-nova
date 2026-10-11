import json

# enrich.py
# Offline enrichment layer. Attaches EPSS scores and CISA KEV status to findings.
# Real world: this uses offline OSV dumps and CSVs to prevent network calls at inference time.

# Mocking the offline CVE databases for the capstone scope
OFFLINE_KEV = {
    "CVE-2021-44228": True, # log4shell is exploited
    "CVE-2023-38408": True
}

OFFLINE_EPSS = {
    "CVE-2021-44228": 0.97,
    "CVE-2023-38408": 0.55,
    "CWE-89": 0.05 # Baseline for generic SQLi if no CVE exists
}

def enrich_finding(finding: dict) -> dict:
    """
    Mutates the finding to add an enrichment block.
    """
    cves = finding.get("cve", [])
    cwes = finding.get("cwe", [])
    
    # Defaults
    is_kev = False
    max_epss = 0.0
    
    # Check CVEs
    for cve in cves:
        if OFFLINE_KEV.get(cve):
            is_kev = True
        epss = OFFLINE_EPSS.get(cve, 0.0)
        if epss > max_epss:
            max_epss = epss
            
    # Fallback to CWE baseline if no CVE (common in SAST)
    if max_epss == 0.0 and cwes:
        for cwe in cwes:
            epss = OFFLINE_EPSS.get(cwe, 0.01)
            if epss > max_epss:
                max_epss = epss

    finding["enrichment"] = {
        "epss": max_epss,
        "kev": is_kev,
        "reachable": True # Placeholder for reachability analysis
    }
    return finding

if __name__ == "__main__":
    sample = {"finding_id": "1", "cve": ["CVE-2021-44228"]}
    print(json.dumps(enrich_finding(sample), indent=2))

