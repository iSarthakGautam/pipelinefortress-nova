#!/usr/bin/env python3
"""Merge two independent label sheets (+ optional adjudication) into the frozen-ground-truth input.

  python3 eval/ground_truth/merge_labels.py A.csv B.csv --sample sample.jsonl --out ground_truth_v1.jsonl [--adjudicated adj.csv]

final label = the shared label when A == B; otherwise the adjudicated label for that finding_id (adj.csv needs finding_id and
adjudicated_label). Unresolved disagreements stop the merge and are listed. The original A/B labels are kept in the output,
never overwritten (compute kappa from A and B with cohen_kappa.py, not from the final label).
"""
import argparse
import csv
import json
import sys
from pathlib import Path

VALID = {"TRUE_POSITIVE", "FALSE_POSITIVE"}


def read(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return {r["finding_id"]: r for r in csv.DictReader(f)}


def merge(a: dict, b: dict, sample: list, adjudicated: dict):
    out, unresolved, invalid = [], [], []
    for row in sample:
        fid = row["finding_id"]
        la = (a.get(fid, {}).get("reviewer_a_label") or "").strip()
        lb = (b.get(fid, {}).get("reviewer_b_label") or "").strip()
        if not la or not lb:
            unresolved.append(f"{fid}: missing a label (A={la or '-'}, B={lb or '-'})")
            continue
        final, how = (la, "agreed") if la == lb else ((adjudicated.get(fid, {}).get("adjudicated_label") or "").strip(), "adjudicated")
        if not final:
            unresolved.append(f"{fid}: A={la} B={lb}, needs adjudication")
            continue
        if final not in VALID:
            invalid.append(f"{fid}: {final!r}")
            continue
        out.append({**row, "ground_truth": final, "label_source": how, "reviewer_a_label": la, "reviewer_b_label": lb})
    return out, unresolved, invalid


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a_csv")
    ap.add_argument("b_csv")
    ap.add_argument("--sample", required=True)
    ap.add_argument("--adjudicated")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    sample = [json.loads(ln) for ln in Path(args.sample).read_text(encoding="utf-8").splitlines() if ln.strip()]
    adjudicated = read(args.adjudicated) if args.adjudicated else {}
    rows, unresolved, invalid = merge(read(args.a_csv), read(args.b_csv), sample, adjudicated)
    if unresolved or invalid:
        print("NOT FROZEN. Fix these first:\n  " + "\n  ".join(unresolved + [f"invalid label {i}" for i in invalid]), file=sys.stderr)
        return 1
    Path(args.out).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    print(f"wrote {args.out}: {len(rows)} rows ({sum(r['label_source'] == 'adjudicated' for r in rows)} adjudicated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
