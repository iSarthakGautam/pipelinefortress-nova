#!/usr/bin/env python3
"""Refresh the OFFLINE enrichment data used by ai/enrich.py and ai/validate.py. Run by a person, never at inference.

  python3 scripts/fetch_enrichment_data.py

Writes (with the source URL, release date and sha256 of the raw download in each file, so the data is checkable):
  ai/data/kev_ids.txt       every CVE id in the CISA Known Exploited Vulnerabilities catalogue
  ai/data/epss_subset.json  EPSS scores for the CVEs this repo can meet: the candidate population, planted.yaml, the old samples
"""
import csv
import gzip
import hashlib
import io
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "ai" / "data"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def repo_cves() -> set:
    found = set()
    for rel in ("docs/metrics/data/candidate-population-2026-10-29/population.csv", "ground_truth/planted.yaml",
                "eval/ground_truth.jsonl", "docs/metrics/data/gate-tuning-2026-10-27/findings-main-1bb3381.json"):
        p = ROOT / rel
        if p.is_file():
            found |= set(CVE.findall(p.read_text(encoding="utf-8", errors="ignore")))
    return found | {"CVE-2021-44228", "CVE-2023-38408"}


def main() -> None:
    raw = get(KEV_URL)
    kev = json.loads(raw)
    ids = sorted({v["cveID"] for v in kev["vulnerabilities"]})
    header = (f"# CISA KEV CVE ids. source={KEV_URL} catalogVersion={kev.get('catalogVersion')} "
              f"dateReleased={kev.get('dateReleased')} count={len(ids)} raw_sha256={hashlib.sha256(raw).hexdigest()}\n")
    (DATA / "kev_ids.txt").write_text(header + "\n".join(ids) + "\n", encoding="utf-8")

    gz = get(EPSS_URL)
    text = gzip.decompress(gz).decode("utf-8")
    meta = text.splitlines()[0].lstrip("#")
    wanted = repo_cves()
    scores = {row["cve"]: float(row["epss"]) for row in csv.DictReader(io.StringIO("\n".join(text.splitlines()[1:])))
              if row["cve"] in wanted}
    doc = {"_meta": {"source": EPSS_URL, "model": meta, "raw_gz_sha256": hashlib.sha256(gz).hexdigest(),
                     "cves_requested": len(wanted), "cves_found": len(scores)}, "scores": dict(sorted(scores.items()))}
    (DATA / "epss_subset.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"KEV: {len(ids)} ids ({kev.get('catalogVersion')}); EPSS: {len(scores)}/{len(wanted)} repo CVEs scored ({meta})")


if __name__ == "__main__":
    main()
