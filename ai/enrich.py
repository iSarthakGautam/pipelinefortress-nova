import json

# enrich.py
# Offline enrichment. Attaches EPSS and CISA KEV facts per CVE. Never fetched at inference time.
# The tables below are a HAND-PICKED SAMPLE, not the full KEV/EPSS feeds. Until ai/data/ gets the real
# CISA KEV JSON and EPSS CSV (with sha256 pins), CVEs not listed here get epss=None (unknown), not 0.
# EPSS only exists per CVE, so there is no EPSS value for a bare CWE (the earlier CWE prior was invented).
# `reachable` is None because reachability analysis is not implemented. None means "not computed".

# TODO(team): decide who owns the enricher inputs (PLAN §2 lists EPSS, CISA KEV, offline OSV/NVD, CWE map, reachability).
#             Until the real CISA KEV JSON / EPSS CSV snapshots are added to ai/data/, these are hand-picked samples.
# TODO(R2): if R2's normalizer computes reachability, fill enrichment.reachable upstream and drop the null below.
SAMPLE_KEV = {"CVE-2021-44228", "CVE-2023-38408"}

SAMPLE_EPSS = {
    "CVE-2021-44228": 0.97,
    "CVE-2023-38408": 0.55,
}


def enrich_finding(finding: dict) -> dict:
    """Adds an `enrichment` block to the finding (mutates and returns it)."""
    cves = finding.get("cve", []) or []
    known = [SAMPLE_EPSS[c] for c in cves if c in SAMPLE_EPSS]
    finding["enrichment"] = {
        "epss": max(known) if known else None,
        "kev": any(c in SAMPLE_KEV for c in cves),
        "reachable": None,
    }
    return finding


if __name__ == "__main__":
    print(json.dumps(enrich_finding({"finding_id": "1", "cve": ["CVE-2021-44228"]}), indent=2))
    print(json.dumps(enrich_finding({"finding_id": "2", "cwe": ["CWE-89"]}), indent=2))
