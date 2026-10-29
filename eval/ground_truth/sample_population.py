#!/usr/bin/env python3
"""Draw the ground-truth sample from R2's frozen candidate population and write the labelling sheets.

  python3 eval/ground_truth/sample_population.py docs/metrics/data/candidate-population-2026-10-29/population.csv \
      --out-dir eval/ground_truth/data/sample-2026-10-29 [--n 98] [--seed 20261029]

The unit is a DUPLICATE GROUP (`dup_group`), never a finding: the same CVE reported by three SCA tools is one item, and the
split must keep it on one side (GROUND_TRUTH_PROTOCOL.md section 5). One representative row per group (highest severity, then
lowest finding_id). If --n is smaller than the number of groups the draw is stratified by rule_family x severity and seeded.
Outputs: sample.csv, labels_reviewer_a.csv, labels_reviewer_b.csv (separate files so nobody sees the other's label),
sample.jsonl (input for split_and_freeze.py), sampling_manifest.json (seed, population sha256, counts per stratum).
"""
import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
TEMPLATE = ["finding_id", "reviewer_a_label", "reviewer_a_rationale", "reviewer_a_evidence", "reviewer_a_timestamp",
            "reviewer_b_label", "reviewer_b_rationale", "reviewer_b_evidence", "reviewer_b_timestamp",
            "adjudicated_label", "adjudication_rationale", "adjudicator", "adjudication_timestamp",
            "first_seen_utc", "duplicate_group", "split_notes"]
CONTEXT = ["tool", "rule_family", "rule_id", "severity_norm", "file", "line", "package", "version"]


def rank(row) -> int:
    return ORDER.index(row["severity_norm"]) if row["severity_norm"] in ORDER else -1


def representatives(rows: list) -> list:
    groups = defaultdict(list)
    for r in rows:
        groups[r["dup_group"]].append(r)
    return [sorted(g, key=lambda r: (-rank(r), r["finding_id"]))[0] for _, g in sorted(groups.items())]


def draw(reps: list, n: int, seed: int) -> list:
    if n >= len(reps):
        return reps
    rng = random.Random(seed)
    strata = defaultdict(list)
    for r in reps:
        strata[(r["rule_family"], r["severity_norm"])].append(r)
    picked = []
    quota = {k: max(1, round(n * len(v) / len(reps))) for k, v in strata.items()}
    for k in sorted(strata):
        picked += rng.sample(strata[k], min(quota[k], len(strata[k])))
    rng.shuffle(picked)
    return sorted(picked[:n], key=lambda r: r["finding_id"])


def time_field(r: dict) -> str:
    """SCA rows: the advisory publish date is the honest age of the issue. Everything else: when the code first appeared."""
    return (r["advisory_published"] if r["rule_family"] == "sca" and r.get("advisory_published") else r["first_seen"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("population")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--n", type=int, default=0, help="items to draw; 0 = every duplicate group")
    ap.add_argument("--seed", type=int, default=20261029)
    a = ap.parse_args(argv)
    src = Path(a.population)
    with open(src, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    reps = representatives(rows)
    chosen = draw(reps, a.n or len(reps), a.seed)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    for name in ("a", "b"):
        with open(out / f"labels_reviewer_{name}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=TEMPLATE + CONTEXT)
            w.writeheader()
            for r in chosen:
                w.writerow({"finding_id": r["finding_id"], "first_seen_utc": time_field(r), "duplicate_group": r["dup_group"],
                            **{c: r.get(c, "") for c in CONTEXT}})
    with open(out / "sample.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(chosen)
    with open(out / "sample.jsonl", "w", encoding="utf-8") as f:
        for r in chosen:
            f.write(json.dumps({"finding_id": r["finding_id"], "first_seen_utc": time_field(r),
                                "duplicate_group": r["dup_group"], **{c: r.get(c, "") for c in CONTEXT}}, sort_keys=True) + "\n")
    strata = defaultdict(int)
    for r in chosen:
        strata[f"{r['rule_family']}|{r['severity_norm']}"] += 1
    manifest = {"population": str(src), "population_sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
                "population_findings": len(rows), "duplicate_groups": len(reps), "drawn": len(chosen), "seed": a.seed,
                "method": "all duplicate groups" if len(chosen) == len(reps) else "stratified by rule_family x severity, seeded",
                "time_field": "advisory_published for SCA, first_seen otherwise", "strata": dict(sorted(strata.items()))}
    (out / "sampling_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
