import json
import os

# enrich.py
# Offline enrichment. Attaches EPSS and CISA KEV facts per CVE. Never fetched at inference time.
# Data: ai/data/kev_ids.txt (the full CISA KEV catalogue) and ai/data/epss_subset.json (EPSS for the CVEs this repo can meet),
# both written by scripts/fetch_enrichment_data.py with the source, date and sha256 of the raw download in the file.
# A CVE with no EPSS score gets epss=None (unknown), not 0. If the data files are missing, the two-entry sample below is used.
# EPSS only exists per CVE, so there is no EPSS value for a bare CWE (the earlier CWE prior was invented).
# `reachable` is None because reachability analysis is not implemented. None means "not computed".

# RESOLVED(team): Scanner reports provide live CVE/CWE facts; offline EPSS/KEV samples are frozen for zero-egress demo.
#                 Reachability analysis is explicitly out of scope per Plan §2.
SAMPLE_KEV = {"CVE-2021-44228", "CVE-2023-38408"}

SAMPLE_EPSS = {
    "CVE-2021-44228": 0.97,
    "CVE-2023-38408": 0.55,
}


DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _load():
    kev, epss = set(SAMPLE_KEV), dict(SAMPLE_EPSS)
    try:
        with open(os.path.join(DATA_DIR, "kev_ids.txt"), encoding="utf-8") as f:
            kev = {ln.strip() for ln in f if ln.strip() and not ln.startswith("#")}
        with open(os.path.join(DATA_DIR, "epss_subset.json"), encoding="utf-8") as f:
            epss = {k: float(v) for k, v in json.load(f).get("scores", {}).items()}
    except (OSError, ValueError):
        pass   # fall back to the sample: enrichment must never stop a run
    return kev, epss


KEV_IDS, EPSS_SCORES = _load()


def enrich_finding(finding: dict) -> dict:
    """Adds an `enrichment` block to the finding (mutates and returns it)."""
    cves = finding.get("cve", []) or []
    known = [EPSS_SCORES[c] for c in cves if c in EPSS_SCORES]
    finding["enrichment"] = {
        "epss": max(known) if known else None,
        "kev": any(c in KEV_IDS for c in cves),
        "reachable": None,
    }
    return finding


if __name__ == "__main__":
    print(json.dumps(enrich_finding({"finding_id": "1", "cve": ["CVE-2021-44228"]}), indent=2))
    print(json.dumps(enrich_finding({"finding_id": "2", "cwe": ["CWE-89"]}), indent=2))
